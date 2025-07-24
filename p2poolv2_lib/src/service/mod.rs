// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use crate::config::NetworkConfig;
use crate::middleware::inactivity::InactivityLayer;
use crate::node::SwarmSend;
use crate::service::p2p_service::{P2PService, RequestContext};
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tower::{ServiceBuilder, limit::RateLimitLayer, util::BoxService};

// Build the full service stack
pub fn build_service<C, T>(
    config: NetworkConfig,
    swarm_tx: Sender<SwarmSend<C>>,
) -> BoxService<RequestContext<C, T>, (), Box<dyn Error + Send + Sync>>
where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    let base_service = P2PService::new(swarm_tx.clone());

    let inactivity_layer = InactivityLayer::new(
        Duration::from_secs(config.peer_inactivity_timeout_secs),
        swarm_tx,
    );

    let builder = ServiceBuilder::new()
        .layer(RateLimitLayer::new(
            config.max_requests_per_second,
            Duration::from_secs(1),
        ))
        .layer(inactivity_layer);

    let service = builder.service(base_service);

    BoxService::new(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use crate::service::p2p_service::{P2PService, RequestContext};
    #[mockall_double::double]
    use crate::shares::chain::actor::ChainHandle;
    use crate::utils::time_provider::TestTimeProvider;
    use libp2p::PeerId;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Instant;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::Sender;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, advance, timeout};
    use tower::limit::RateLimit;
    use tower::{Service, ServiceBuilder, ServiceExt, limit::RateLimitLayer};

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
        let mut chain_handle = ChainHandle::default();
        chain_handle
            .expect_clone()
            .returning(|| ChainHandle::default());

        // Create a TestTimeProvider with the current system time
        let time_provider = TestTimeProvider(SystemTime::now());

        // Configure Tower RateLimitLayer: 2 requests per second
        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(2, Duration::from_secs(1)))
            .service(P2PService::new(swarm_tx.clone()));

        // Inline RequestContext construction
        let ctx1 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        let ctx2 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx1,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        let ctx3 = RequestContext {
            peer: PeerId::random(),
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx2,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        // First request should succeed
        assert!(
            <RateLimit<P2PService<tokio::sync::oneshot::Sender<Message>>> as tower::ServiceExt<
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
            <RateLimit<P2PService<tokio::sync::oneshot::Sender<Message>>> as tower::ServiceExt<
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
            <RateLimit<P2PService<tokio::sync::oneshot::Sender<Message>>> as tower::ServiceExt<
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
            <RateLimit<P2PService<tokio::sync::oneshot::Sender<Message>>> as tower::ServiceExt<
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
        let mut chain_handle = ChainHandle::default();
        chain_handle
            .expect_clone()
            .returning(|| ChainHandle::default());

        let time_provider = TestTimeProvider(SystemTime::now());

        // Wrap with rate limit (though here rate limit is not really triggered)
        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(1, Duration::from_secs(1)))
            .service(AlwaysFailReadyService);

        // Build a request context
        let peer_id = PeerId::random();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
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
        let mut chain_handle = ChainHandle::default();
        chain_handle
            .expect_clone()
            .returning(|| ChainHandle::default());

        let time_provider = TestTimeProvider(SystemTime::now());

        // Create a config with a low rate limit
        let network_config = NetworkConfig {
            listen_address: "127.0.0.1:0".to_string(),
            dial_peers: vec![],
            max_pending_incoming: 0,
            max_pending_outgoing: 0,
            max_established_incoming: 0,
            max_established_outgoing: 0,
            max_established_per_peer: 0,
            max_workbase_per_second: 0,
            max_userworkbase_per_second: 0,
            max_miningshare_per_second: 0,
            max_inventory_per_second: 0,
            max_transaction_per_second: 0,
            rate_limit_window_secs: 1,
            max_requests_per_second: 1,
            peer_inactivity_timeout_secs: 30,
        };

        let peer_id = PeerId::random();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx.clone(),
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        let ctx1 = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx.clone(),
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        let mut service =
            build_service::<Sender<Message>, _>(network_config.clone(), swarm_tx.clone());

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
        let mut chain_handle = ChainHandle::default();
        chain_handle
            .expect_clone()
            .returning(|| ChainHandle::default());

        let time_provider = TestTimeProvider(SystemTime::now());

        // Create a network_config with a low rate limit
        let network_config = NetworkConfig {
            listen_address: "127.0.0.1:0".to_string(),
            dial_peers: vec![],
            max_pending_incoming: 0,
            max_pending_outgoing: 0,
            max_established_incoming: 0,
            max_established_outgoing: 0,
            max_established_per_peer: 0,
            max_workbase_per_second: 0,
            max_userworkbase_per_second: 0,
            max_miningshare_per_second: 0,
            max_inventory_per_second: 0,
            max_transaction_per_second: 0,
            rate_limit_window_secs: 1,
            max_requests_per_second: 1,
            peer_inactivity_timeout_secs: 30,
        };

        let peer_id = PeerId::random();
        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_handle: chain_handle.clone(),
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider: time_provider.clone(),
        };

        let mut service =
            build_service::<Sender<Message>, _>(network_config.clone(), swarm_tx.clone());

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
