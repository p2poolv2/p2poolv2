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
pub mod peer_state;

use crate::node::SwarmSend;
use crate::service::p2p_service::{P2PService, RequestContext};
use crate::utils::time_provider::TimeProvider;
use libp2p::PeerId;
use std::error::Error;
use std::fmt::Debug;
use std::time::Duration;
use tokio::sync::mpsc;
use tower::limit::RateLimit;
use tower::{Service, ServiceBuilder, ServiceExt, limit::RateLimitLayer};
use tracing::{debug, error, info};

/// Minimum per-peer channel capacity, matching the block fetcher's
/// maximum in-flight requests per peer so a legitimate sync burst
/// always fits without dropping.
const MIN_PEER_CHANNEL_CAPACITY: u64 = 16;

/// How long to wait for a peer's service to become ready before
/// declaring the peer is flooding and disconnecting it. Must be
/// longer than the rate limit refill interval to avoid false
/// positives from legitimate rate limit backpressure.
const READY_TIMEOUT: Duration = Duration::from_secs(2);

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

    /// Create a PeerHandle from a raw sender. Used in tests to
    /// simulate a handle whose task has already exited.
    #[cfg(test)]
    pub fn new_for_test(sender: mpsc::Sender<RequestContext<C, T>>) -> Self {
        Self { sender }
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

    tokio::spawn(run_peer_service(
        service,
        receiver,
        peer_id,
        swarm_tx,
        READY_TIMEOUT,
    ));

    PeerHandle { sender }
}

/// Run the per-peer service loop.
///
/// Receives requests from the channel and processes each through the
/// rate-limited service. Applies a configurable timeout on service
/// readiness to detect sustained overload.
///
/// Exits when:
/// - The channel closes (sender dropped, peer disconnected)
/// - The rate limiter is not ready within `ready_timeout` (sustained flood)
/// - The service returns an error on call
///
/// On service failure, sends a disconnect command before exiting.
async fn run_peer_service<C, T>(
    mut service: RateLimit<P2PService>,
    mut receiver: mpsc::Receiver<RequestContext<C, T>>,
    peer_id: PeerId,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    ready_timeout: Duration,
) where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    while let Some(request) = receiver.recv().await {
        let ready_future = ServiceExt::<RequestContext<C, T>>::ready(&mut service);
        match tokio::time::timeout(ready_timeout, ready_future).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::{GetData, Message};
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    use crate::node::request_response_handler::block_fetcher;
    use crate::node::validation_worker;
    use crate::service::p2p_service::{P2PService, RequestContext};
    use crate::service::peer_state::PeerState;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash as _;
    use libp2p::PeerId;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use tokio::time::Duration;

    /// Build a RequestContext for testing with a oneshot response channel.
    fn make_test_context(
        peer: PeerState,
        swarm_tx: mpsc::Sender<SwarmSend<oneshot::Sender<Message>>>,
        response_channel: oneshot::Sender<Message>,
    ) -> RequestContext<oneshot::Sender<Message>, TestTimeProvider> {
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let (block_fetcher_tx, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let (block_receiver_handle, _) = create_block_receiver_channel();

        RequestContext {
            peer: peer.into(),
            request: Message::NotFound(GetData::Block(BlockHash::all_zeros())),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider: TestTimeProvider::new(SystemTime::now()),
            block_fetcher_handle: block_fetcher_tx,
            validation_tx,
            block_receiver_handle,
            share_validator: Arc::new(MockDefaultShareValidator::default()),
        }
    }

    #[tokio::test]
    async fn test_rate_limit_timeout_disconnects_peer() {
        //! Uses run_peer_service directly with rate=1/s and a 500ms
        //! ready timeout. The rate refills at 1s but the timeout fires
        //! at 500ms, guaranteeing the Disconnect path is taken.
        let (swarm_tx, mut swarm_rx) = mpsc::channel(8);
        let peer_id = PeerId::random();
        let peer_state = PeerState::new(peer_id);

        let service = build_rate_limited_service(1);
        let (sender, receiver) = mpsc::channel(16);
        let ready_timeout = Duration::from_millis(500);
        tokio::spawn(run_peer_service(
            service,
            receiver,
            peer_id,
            swarm_tx.clone(),
            ready_timeout,
        ));

        // First request -- consumes the rate limit bucket
        let (response_tx, _response_rx) = oneshot::channel::<Message>();
        let ctx = make_test_context(peer_state.clone(), swarm_tx.clone(), response_tx);
        sender.send(ctx).await.unwrap();

        // Give the task time to process the first request
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second request -- rate limiter is exhausted
        let (response_tx2, _response_rx2) = oneshot::channel::<Message>();
        let ctx2 = make_test_context(peer_state, swarm_tx.clone(), response_tx2);
        sender.send(ctx2).await.unwrap();

        // Wait for the 500ms timeout to fire (well before 1s refill)
        let received = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv())
            .await
            .expect("Timed out waiting for Disconnect")
            .expect("Channel closed unexpectedly");

        if let SwarmSend::Disconnect(disconnected_peer) = received {
            assert_eq!(disconnected_peer, peer_id);
        } else {
            panic!("Expected SwarmSend::Disconnect, got {:?}", received);
        }
    }

    #[tokio::test]
    async fn test_dropped_handle_stops_peer_task() {
        //! Verifies that dropping the PeerHandle closes the channel,
        //! causing the peer's service task to exit cleanly without
        //! sending a Disconnect.
        let (swarm_tx, mut swarm_rx) = mpsc::channel(8);
        let peer_id = PeerId::random();

        let handle: PeerHandle<oneshot::Sender<Message>, TestTimeProvider> =
            spawn_peer_service(peer_id, 10, swarm_tx.clone());

        // Drop the handle -- channel closes, task should exit
        drop(handle);

        // Give the task a moment to notice the closed channel
        tokio::task::yield_now().await;

        // No Disconnect should be sent -- this is a clean shutdown
        assert!(
            swarm_rx.try_recv().is_err(),
            "No Disconnect expected on clean handle drop"
        );
    }

    #[tokio::test]
    async fn test_per_peer_rate_limit_independence() {
        //! Two peers each get their own rate limiter (rate=1/s) with
        //! a 500ms ready timeout. Peer A exhausts its rate limit and
        //! gets disconnected, but Peer B processes its request fine.
        let (swarm_tx, mut swarm_rx) = mpsc::channel(16);
        let peer_a = PeerId::random();
        let peer_state_a = PeerState::new(peer_a);
        let peer_b = PeerId::random();
        let peer_state_b = PeerState::new(peer_b);
        let ready_timeout = Duration::from_millis(500);

        let service_a = build_rate_limited_service(1);
        let (sender_a, receiver_a) = mpsc::channel(16);
        tokio::spawn(run_peer_service(
            service_a,
            receiver_a,
            peer_a,
            swarm_tx.clone(),
            ready_timeout,
        ));

        let service_b = build_rate_limited_service(1);
        let (sender_b, receiver_b) = mpsc::channel(16);
        tokio::spawn(run_peer_service(
            service_b,
            receiver_b,
            peer_b,
            swarm_tx.clone(),
            ready_timeout,
        ));

        // Peer A -- first request consumes its rate bucket
        let (response_tx_a, _) = oneshot::channel::<Message>();
        let ctx_a = make_test_context(peer_state_a.clone(), swarm_tx.clone(), response_tx_a);
        sender_a.send(ctx_a).await.unwrap();

        // Give task A time to process
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Peer A -- second request, will be rate limited
        let (response_tx_a2, _) = oneshot::channel::<Message>();
        let ctx_a2 = make_test_context(peer_state_a, swarm_tx.clone(), response_tx_a2);
        sender_a.send(ctx_a2).await.unwrap();

        // Peer B -- should process immediately despite A being rate limited
        let (response_tx_b, _) = oneshot::channel::<Message>();
        let ctx_b = make_test_context(peer_state_b, swarm_tx.clone(), response_tx_b);
        sender_b.send(ctx_b).await.unwrap();

        // Wait for A's timeout to fire (500ms) plus some margin
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Collect all messages -- expect a Disconnect for peer A only
        let mut disconnect_peers = Vec::new();
        while let Ok(message) = swarm_rx.try_recv() {
            if let SwarmSend::Disconnect(peer) = message {
                disconnect_peers.push(peer);
            }
        }

        assert!(
            disconnect_peers.contains(&peer_a),
            "Peer A should be disconnected due to rate limit timeout"
        );
        assert!(
            !disconnect_peers.contains(&peer_b),
            "Peer B should NOT be disconnected"
        );

        drop(sender_a);
        drop(sender_b);
    }

    #[tokio::test]
    async fn test_spawn_peer_service_processes_single_request() {
        //! Minimal test: spawn a peer service, send one request, verify
        //! the task processes it without panicking.
        let (swarm_tx, _swarm_rx) = mpsc::channel(8);
        let peer_id = PeerId::random();
        let peer_state = PeerState::new(peer_id);

        let handle: PeerHandle<oneshot::Sender<Message>, TestTimeProvider> =
            spawn_peer_service(peer_id, 10, swarm_tx.clone());

        let (response_tx, _response_rx) = oneshot::channel::<Message>();
        let ctx = make_test_context(peer_state, swarm_tx.clone(), response_tx);
        handle.try_send(ctx).unwrap();

        // Drop the handle to close the channel, causing the task to exit
        drop(handle);

        // Give the task time to process and exit
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_peer_channel_capacity_calculation() {
        //! Verifies channel capacity is max(rate, MIN_PEER_CHANNEL_CAPACITY).
        assert_eq!(peer_channel_capacity(1), 16);
        assert_eq!(peer_channel_capacity(16), 16);
        assert_eq!(peer_channel_capacity(50), 50);
        assert_eq!(peer_channel_capacity(100), 100);
    }
}
