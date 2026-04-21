// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

pub mod p2p_service;

use crate::node::SwarmSend;
use crate::service::p2p_service::{P2PService, RequestContext};
use crate::utils::time_provider::TimeProvider;
use libp2p::PeerId;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tower::limit::RateLimit;
use tower::{Service, ServiceBuilder, ServiceExt, limit::RateLimitLayer};
use tracing::{debug, error, info};

/// Minimum per-peer channel capacity, matching the block fetcher's
/// maximum in-flight requests per peer so a legitimate sync burst
/// always fits without dropping.
const MIN_PEER_CHANNEL_CAPACITY: u64 = 16;

/// Handle to a per-peer service task.
///
/// Wraps the sender half of the channel used to forward inbound
/// requests to the peer's dedicated processing task.
pub struct PeerHandle<C, T> {
    sender: mpsc::Sender<RequestContext<C, T>>,
}

impl<C, T> PeerHandle<C, T> {
    /// Try to forward a request to the peer's task without blocking.
    ///
    /// Returns an error if the channel is full, meaning the peer's
    /// task cannot keep up with the inbound request rate.
    pub fn try_send(
        &self,
        request: RequestContext<C, T>,
    ) -> Result<(), mpsc::error::TrySendError<RequestContext<C, T>>> {
        self.sender.try_send(request)
    }
}

/// Calculate the per-peer channel capacity.
///
/// Uses the larger of the configured rate limit and the minimum
/// capacity needed for block sync bursts.
fn peer_channel_capacity(max_requests_per_second: u64) -> usize {
    std::cmp::max(max_requests_per_second, MIN_PEER_CHANNEL_CAPACITY) as usize
}

/// Build a rate-limited service for a single peer.
fn build_rate_limited_service(max_requests_per_second: u64) -> RateLimit<P2PService> {
    ServiceBuilder::new()
        .layer(RateLimitLayer::new(
            max_requests_per_second,
            Duration::from_secs(1),
        ))
        .service(P2PService::new())
}

/// Spawn a per-peer service task and return a handle to send requests.
///
/// Creates a bounded channel and a rate-limited service, then spawns
/// a tokio task that processes requests from the channel. The task
/// exits when the channel closes (peer disconnected) or when the
/// service fails (rate limit timeout or processing error), sending a
/// disconnect command in the latter case.
pub fn spawn_peer_service<C, T>(
    peer_id: PeerId,
    max_requests_per_second: u64,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> PeerHandle<C, T>
where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    let capacity = peer_channel_capacity(max_requests_per_second);
    let service = build_rate_limited_service(max_requests_per_second);
    let (sender, receiver) = mpsc::channel(capacity);

    tokio::spawn(run_peer_service(service, receiver, peer_id, swarm_tx));

    PeerHandle { sender }
}

/// Run the per-peer service loop.
///
/// Receives requests from the channel and processes each through the
/// rate-limited service. Applies a 1-second timeout on service
/// readiness to detect sustained overload.
///
/// Exits when:
/// - The channel closes (sender dropped, peer disconnected)
/// - The rate limiter is not ready within 1 second (sustained flood)
/// - The service returns an error on call
///
/// On service failure, sends a disconnect command before exiting.
async fn run_peer_service<C, T>(
    mut service: RateLimit<P2PService>,
    mut receiver: mpsc::Receiver<RequestContext<C, T>>,
    peer_id: PeerId,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    while let Some(request) = receiver.recv().await {
        let ready_future = ServiceExt::<RequestContext<C, T>>::ready(&mut service);
        match tokio::time::timeout(Duration::from_secs(1), ready_future).await {
            Ok(Ok(_)) => {
                if let Err(err) = service.call(request).await {
                    error!("Service call failed for peer {}: {}", peer_id, err);
                    let _ = swarm_tx.send(SwarmSend::Disconnect(peer_id)).await;
                    return;
                }
            }
            Ok(Err(err)) => {
                error!("Service not ready for peer {}: {}", peer_id, err);
                info!("Disconnecting peer {} due to service error", peer_id);
                let _ = swarm_tx.send(SwarmSend::Disconnect(peer_id)).await;
                return;
            }
            Err(_) => {
                error!("Rate limit timeout for peer {}", peer_id);
                info!(
                    "Disconnecting peer {} due to sustained rate limit violation",
                    peer_id
                );
                let _ = swarm_tx.send(SwarmSend::Disconnect(peer_id)).await;
                return;
            }
        }
    }
    debug!(
        "Peer service task exiting for peer {} -- channel closed",
        peer_id
    );
}

/// Build a boxed service stack with rate limiting.
///
/// Used by RequestResponseHandler until per-peer services are wired in.
pub fn build_service<C, T>(
    config: crate::config::NetworkConfig,
) -> tower::util::BoxService<RequestContext<C, T>, (), Box<dyn Error + Send + Sync>>
where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    let service = build_rate_limited_service(config.max_requests_per_second);
    tower::util::BoxService::new(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use crate::node::p2p_message_handlers::receivers::block_receiver::BlockReceiverHandle;
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    use crate::node::request_response_handler::block_fetcher;
    use crate::node::validation_worker;
    use crate::service::p2p_service::{P2PService, RequestContext};
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::utils::time_provider::TestTimeProvider;
    use libp2p::PeerId;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Instant;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::Sender;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, advance, timeout};
    use tower::limit::RateLimit;
    use tower::{Service, ServiceBuilder, ServiceExt, limit::RateLimitLayer};

    fn fetcher_validation_handles_for_tests() -> (
        block_fetcher::BlockFetcherHandle,
        validation_worker::ValidationSender,
        BlockReceiverHandle,
    ) {
        let (block_fetcher_tx, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let (block_receiver_handle, _) = create_block_receiver_channel();
        (block_fetcher_tx, validation_tx, block_receiver_handle)
    }

    // This struct simulates a service that always fails on poll_ready()
    struct AlwaysFailReadyService;

    impl<C, T> tower::Service<RequestContext<C, T>> for AlwaysFailReadyService {
        type Response = ();
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err("simulated readiness failure".into()))
        }

        fn call(&mut self, _req: RequestContext<C, T>) -> Self::Future {
            Box::pin(async { Ok(()) }) // Won't be called in this test
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_blocks_excess_requests() {
        //! Verifies that Tower's RateLimitLayer enforces backpressure by making the service
        //! not ready after the allowed rate is exceeded, and that readiness resumes after the interval.

        const RATE: u64 = 1;
        const INTERVAL: Duration = Duration::from_secs(1);
        const TIMEOUT_MS: u64 = 100;

        let svc = tower::service_fn(|_req| async {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(RATE, INTERVAL))
            .service(svc);

        // First request should succeed
        let result1 = service.ready().await.unwrap().call(()).await;
        assert!(result1.is_ok(), "First request should succeed");

        // All further requests within the interval should be rate limited (not ready)
        for i in 1..=3 {
            let not_ready = timeout(Duration::from_millis(TIMEOUT_MS), service.ready()).await;
            assert!(
                not_ready.is_err(),
                "Request {i} should be rate limited (not ready yet), got: {not_ready:?}"
            );
        }

        // Advance time and verify service becomes ready again
        for i in 1..=3 {
            advance(INTERVAL).await;
            let ready = timeout(Duration::from_millis(TIMEOUT_MS), service.ready()).await;
            assert!(ready.is_ok(), "Service should be ready after interval {i}");
            let result = service.call(()).await;
            assert!(result.is_ok(), "Request {i} after interval should succeed");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_tower_rate_limiter_with_inline_request_context() {
        // Setup a channel for the swarm sender
        let (swarm_tx, _rx) = mpsc::channel(8);

        // Create a response channel for the request context
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();

        let (response_channel_tx1, _response_channel_rx1) = oneshot::channel::<Message>();

        let (response_channel_tx2, _response_channel_rx2) = oneshot::channel::<Message>();

        // Create a dummy ChainHandle and TimeProvider
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        // Create a TestTimeProvider with the current system time
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Configure Tower RateLimitLayer: 2 requests per second
        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(2, Duration::from_secs(1)))
            .service(P2PService::new());

        // Inline RequestContext construction
        let (block_fetcher_handle, validation_tx, block_receiver_handle) =
            fetcher_validation_handles_for_tests();
        let ctx1 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle: block_fetcher_handle.clone(),
            validation_tx: validation_tx.clone(),
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        let ctx2 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx1,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle: block_fetcher_handle.clone(),
            validation_tx: validation_tx.clone(),
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        let ctx3 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx2,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        // First request should succeed
        assert!(
            <RateLimit<P2PService> as tower::ServiceExt<
                p2p_service::RequestContext<
                    tokio::sync::oneshot::Sender<Message>,
                    TestTimeProvider,
                >,
            >>::ready(&mut service)
            .await
            .is_ok()
        );

        assert!(service.call(ctx1).await.is_ok());

        // Second request should succeed
        assert!(
            <RateLimit<P2PService> as tower::ServiceExt<
                p2p_service::RequestContext<
                    tokio::sync::oneshot::Sender<Message>,
                    TestTimeProvider,
                >,
            >>::ready(&mut service)
            .await
            .is_ok()
        );

        assert!(service.call(ctx2).await.is_ok());

        // Third request should be rate limited (not ready)
        assert!(
            <RateLimit<P2PService> as tower::ServiceExt<
                p2p_service::RequestContext<
                    tokio::sync::oneshot::Sender<Message>,
                    TestTimeProvider,
                >,
            >>::ready(&mut service)
            .await
            .is_ok()
        );

        // Advance time window
        tokio::time::advance(Duration::from_secs(1)).await;

        // Should be ready again
        assert!(
            <RateLimit<P2PService> as tower::ServiceExt<
                p2p_service::RequestContext<
                    tokio::sync::oneshot::Sender<Message>,
                    TestTimeProvider,
                >,
            >>::ready(&mut service)
            .await
            .is_ok()
        );
        assert!(service.call(ctx3).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn test_service_disconnects_peer_on_ready_failure() {
        // Setup a channel to observe swarm events
        let (swarm_tx, mut swarm_rx) = mpsc::channel(8);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();

        // Dummy chain handle
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Wrap with rate limit (though here rate limit is not really triggered)
        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(1, Duration::from_secs(1)))
            .service(AlwaysFailReadyService);

        // Build a request context
        let peer_id = PeerId::random();
        let (block_fetcher_handle, validation_tx, block_receiver_handle) =
            fetcher_validation_handles_for_tests();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        // Try service.ready(), and on failure, trigger disconnect manually

        if <RateLimit<AlwaysFailReadyService> as ServiceExt<
            RequestContext<tokio::sync::oneshot::Sender<Message>, TestTimeProvider>,
        >>::ready(&mut service)
        .await
        .is_err()
        {
            let _ = swarm_tx.send(SwarmSend::Disconnect(ctx.peer)).await;
        }

        // Verify that a Disconnect command was sent
        let received = swarm_rx.try_recv().expect("Expected a SwarmSend message");
        if let SwarmSend::Disconnect(received_peer) = received {
            assert_eq!(
                received_peer, peer_id,
                "Expected Disconnect for the correct peer"
            );
        } else {
            panic!("Expected SwarmSend::Disconnect, got {:?}", received);
        }

        // Ensure no additional messages were sent
        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional SwarmSend messages expected"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_limits_requests() {
        // Setup a channel to observe swarm events
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<mpsc::Sender<Message>>>(10);
        let (response_channel_tx, _response_channel_rx) = mpsc::channel::<Message>(10);

        // Dummy chain handle
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(|| ChainStoreHandle::default());

        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Create a config with a low rate limit
        let network_config = NetworkConfig {
            max_requests_per_second: 1,
            ..NetworkConfig::default()
        };

        let peer_id = PeerId::random();
        let (block_fetcher_handle, validation_tx, block_receiver_handle) =
            fetcher_validation_handles_for_tests();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx.clone(),
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle: block_fetcher_handle.clone(),
            validation_tx: validation_tx.clone(),
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        let ctx1 = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx.clone(),
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        let mut service = build_service::<Sender<Message>, _>(network_config.clone());

        // First request should succeed immediately
        assert!(
            service.ready().await.is_ok(),
            "First request should be ready"
        );
        assert!(service.call(ctx).await.is_ok(), "First call should succeed");

        // Second request should wait due to rate limit (1 req/sec)
        let start = Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), service.ready())
                .await
                .is_ok(),
            "Second request should be ready within 2 seconds"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed <= Duration::from_millis(1100),
            "Expected wait of ~1 second due to rate limit, got {:?}",
            elapsed
        );
        assert!(
            service.call(ctx1).await.is_ok(),
            "Second call should succeed"
        );

        // No disconnect should occur
        assert!(swarm_rx.try_recv().is_err(), "No disconnect expected");
    }

    #[tokio::test]
    async fn test_rate_limiter_disconnects_on_timeout() {
        // Setup a channel to observe swarm events
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<mpsc::Sender<Message>>>(10);

        let (response_channel_tx, _response_channel_rx) = mpsc::channel::<Message>(10);

        // Dummy chain handle
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Create a network_config with a low rate limit
        let network_config = NetworkConfig {
            max_requests_per_second: 1,
            ..NetworkConfig::default()
        };

        let peer_id = PeerId::random();
        let (block_fetcher_handle, validation_tx, block_receiver_handle) =
            fetcher_validation_handles_for_tests();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_store_handle: chain_store_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle: block_receiver_handle.clone(),
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        };

        let mut service = build_service::<Sender<Message>, _>(network_config.clone());

        // First request succeeds
        assert!(
            service.ready().await.is_ok(),
            "First request should be ready"
        );
        assert!(service.call(ctx).await.is_ok(), "First call should succeed");

        // Second request should timeout due to rate limit
        let result = tokio::time::timeout(Duration::from_millis(500), service.ready()).await;
        assert!(
            result.is_err(),
            "Second request should timeout due to rate limit"
        );

        if result.is_err() {
            // Simulate a disconnect due to timeout
            let _ = swarm_tx.send(SwarmSend::Disconnect(peer_id)).await;
        }

        // Check that a disconnect was sent
        let received = swarm_rx.try_recv().expect("Expected a SwarmSend message");
        if let SwarmSend::Disconnect(received_peer) = received {
            assert_eq!(
                received_peer, peer_id,
                "Expected Disconnect for the correct peer"
            );
        } else {
            panic!("Expected SwarmSend::Disconnect, got {:?}", received);
        }
    }
}
