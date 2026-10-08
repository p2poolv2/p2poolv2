// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod block_fetcher;
pub mod peer_block_knowledge;

use self::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use self::peer_block_knowledge::PeerBlockKnowledge;
use crate::config::NetworkConfig;
use crate::node::SwarmSend;
use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::{InventoryMessage, Message};
use crate::node::p2p_message_handlers::receivers::block_receiver::BlockReceiverHandle;
use crate::node::request_sender::RequestSender;
use crate::node::response_worker::{ResponseWorkerEvent, ResponseWorkerSender};
use crate::node::validation_worker::ValidationSender;
use crate::service::PeerHandle;
use crate::service::p2p_service::RequestContext;
use crate::service::spawn_peer_service;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::validation::ShareValidator;
use crate::utils::time_provider::SystemTimeProvider;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use libp2p::swarm::ConnectionId;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Handles request-response events from the libp2p network.
///
/// Generic over the channel type `C` to allow testing with substitute
/// types.  In production, `C` is `ResponseChannel<Message>` from
/// libp2p. In tests, `C` can be any `Send + Sync` type such as
/// `oneshot::Sender<Message>`.
///
/// We need to do this as ResponseChannel is an opaque type and we
/// can't write tests for modules that directly use these types.
///
/// Each connected peer gets a dedicated service task with its own
/// rate limiter. Inbound requests are forwarded to the peer's task
/// via a bounded channel. Responses are handled directly without
/// the service layers since they are solicited by us and do not
/// need peer-protection middleware.
pub struct RequestResponseHandler<C: Send + Sync> {
    peer_handles: HashMap<PeerId, PeerHandle<C, SystemTimeProvider>>,
    max_requests_per_second: u64,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
    block_receiver_handle: BlockReceiverHandle,
    peer_block_knowledge: PeerBlockKnowledge,
    share_validator: Arc<dyn ShareValidator + Send + Sync>,
    /// Inbound responses are handed to the response worker rather than processed
    /// on the swarm-driver task, keeping the node actor loop free for other events.
    response_worker_handle: ResponseWorkerSender,
    /// Requests sent by this node that failed, for P2P health metrics.
    outbound_failures_total: u64,
    /// Peer requests this node failed to answer, for P2P health metrics.
    inbound_failures_total: u64,
    /// Responses dropped on a full or closed worker queue, for P2P health metrics.
    responses_dropped_total: u64,
}

/// Implementation of ResponseChannel<Message>, used in production.
/// The only part left out of tests is the type based dispatching. The
/// dispatch.* functions are tested for the generic implementation.
impl RequestResponseHandler<ResponseChannel<Message>> {
    /// Create a new RequestResponseHandler with per-peer service support.
    #[allow(clippy::too_many_arguments)] // wiring constructor: each parameter is a distinct collaborator, a params struct would only move the list
    pub fn new(
        network_config: NetworkConfig,
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
        block_receiver_handle: BlockReceiverHandle,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
        response_worker_handle: ResponseWorkerSender,
    ) -> Self {
        Self {
            peer_handles: HashMap::new(),
            max_requests_per_second: network_config.max_requests_per_second,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle,
            peer_block_knowledge: PeerBlockKnowledge::default(),
            share_validator,
            response_worker_handle,
            outbound_failures_total: 0,
            inbound_failures_total: 0,
            responses_dropped_total: 0,
        }
    }

    /// Handle a request-response event from the libp2p network.
    ///
    /// Inbound requests are dispatched through the Tower service
    /// stack (rate limiting, inactivity tracking). If the service is
    /// not ready within 1 second, the peer is disconnected.
    ///
    /// Inbound responses are dispatched directly to handle_response
    /// without the service layers.
    pub fn handle_event(
        &mut self,
        event: RequestResponseEvent,
        request_sender: &mut impl RequestSender,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            RequestResponseEvent::Message {
                peer,
                connection_id,
                message:
                    libp2p::request_response::Message::Request {
                        request_id: _,
                        request,
                        channel,
                    },
            } => self.dispatch_request(peer, connection_id, request, channel, request_sender),
            RequestResponseEvent::Message {
                peer,
                connection_id,
                message:
                    libp2p::request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                debug!(
                    "Received response {} for request {} from peer {} on connection {}",
                    response, request_id, peer, connection_id
                );
                self.dispatch_response(peer, connection_id, response)
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error: failure_error,
            } => {
                self.outbound_failures_total += 1;
                warn!(
                    "Outbound failure from peer {} on connection {}, request_id: {}, error: {:?}",
                    peer, connection_id, request_id, failure_error
                );
                Ok(())
            }
            RequestResponseEvent::InboundFailure {
                peer,
                connection_id,
                request_id,
                error: failure_error,
            } => {
                self.inbound_failures_total += 1;
                warn!(
                    "Inbound failure from peer {} on connection {}, request_id: {}, error: {:?}",
                    peer, connection_id, request_id, failure_error
                );
                Ok(())
            }
            RequestResponseEvent::ResponseSent {
                peer,
                connection_id,
                request_id,
            } => {
                debug!(
                    "Response sent to peer {} on connection {}, request_id: {}",
                    peer, connection_id, request_id
                );
                Ok(())
            }
        }
    }
}

/// Generic implementation. The dispatch.* functions can be tested as
/// here we don't depend on the the tokio opaque types.
impl<C: Send + Sync + 'static> RequestResponseHandler<C> {
    /// Returns a reference to the peer block knowledge tracker.
    pub fn peer_block_knowledge(&self) -> &PeerBlockKnowledge {
        &self.peer_block_knowledge
    }

    /// Returns a mutable reference to the peer block knowledge tracker.
    ///
    /// Used by the actor to record outbound block broadcasts so that
    /// subsequent broadcast attempts for the same block are suppressed.
    pub fn peer_block_knowledge_mut(&mut self) -> &mut PeerBlockKnowledge {
        &mut self.peer_block_knowledge
    }

    /// Spawn a per-peer service task for a newly connected peer.
    ///
    /// If a handle already exists for this peer (e.g. duplicate
    /// ConnectionEstablished), the old one is replaced and its task
    /// will exit when the dropped sender closes the channel.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        let handle =
            spawn_peer_service(peer_id, self.max_requests_per_second, self.swarm_tx.clone());
        self.peer_handles.insert(peer_id, handle);
    }

    /// Requests sent by this node that failed, since start.
    pub fn outbound_failures_total(&self) -> u64 {
        self.outbound_failures_total
    }

    /// Peer requests this node failed to answer, since start.
    pub fn inbound_failures_total(&self) -> u64 {
        self.inbound_failures_total
    }

    /// Responses dropped on a full or closed worker queue, since start.
    pub fn responses_dropped_total(&self) -> u64 {
        self.responses_dropped_total
    }

    /// Responses waiting in the response worker queue.
    pub fn response_queue_depth(&self) -> u64 {
        (self.response_worker_handle.max_capacity() - self.response_worker_handle.capacity()) as u64
    }

    /// Whether the peer has a request service.
    #[cfg(test)]
    pub(crate) fn has_peer(&self, peer_id: &PeerId) -> bool {
        self.peer_handles.contains_key(peer_id)
    }

    /// Remove all state for a disconnected peer.
    ///
    /// Drops the peer handle, which closes the channel and causes
    /// the peer's service task to exit. Also removes peer block
    /// knowledge and notifies the block fetcher so it stops sending
    /// requests to this peer.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peer_handles.remove(peer_id);
        self.peer_block_knowledge.remove_peer(peer_id);
        // try_send, not an awaited send: this runs on the node's event loop, so
        // it must not block. A full or closed fetcher channel is tolerable --
        // its in-flight requests to the peer time out and are retried, and the
        // PeersUpdated snapshot re-syncs the selector.
        if let Err(send_error) = self
            .block_fetcher_handle
            .try_send(BlockFetcherEvent::PeerRemoved(*peer_id))
        {
            warn!("Failed to notify block fetcher of peer removal for {peer_id}: {send_error}");
        }
    }

    /// Records which blocks a peer knows about based on a message.
    ///
    /// Called before dispatching both requests and responses so that
    /// subsequent inv sends can avoid redundant announcements.
    fn record_peer_knowledge(&mut self, peer: &PeerId, message: &Message) {
        match message {
            Message::Inventory(InventoryMessage::BlockHashes(hashes)) => {
                for hash in hashes {
                    self.peer_block_knowledge.record_block_known(peer, *hash);
                }
            }
            Message::ShareBlock(block) => {
                self.peer_block_knowledge
                    .record_block_known(peer, block.block_hash());
            }
            _ => {}
        }
    }

    /// Dispatch an inbound request to the peer's service task.
    ///
    /// Records peer block knowledge, then forwards the request
    /// context to the peer's channel via try_send.
    ///
    /// `connection_id` identifies the libp2p connection the request arrived on
    /// and is logged with each failure, so a peer with several concurrent
    /// connections can be told apart in the logs.
    ///
    /// - Full: peer is overwhelming us, disconnect.
    /// - Closed: task exited (rate limit or error), remove the stale
    ///   handle so the next request spawns a fresh one.
    /// - No handle: create one on the fly (defensive fallback).
    fn dispatch_request(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        request: Message,
        channel: C,
        request_sender: &mut impl RequestSender,
    ) -> Result<(), Box<dyn Error>> {
        self.record_peer_knowledge(&peer, &request);

        let ctx = RequestContext::<C, _> {
            peer,
            request,
            chain_store_handle: self.chain_store_handle.clone(),
            response_channel: channel,
            swarm_tx: self.swarm_tx.clone(),
            time_provider: SystemTimeProvider,
            block_fetcher_handle: self.block_fetcher_handle.clone(),
            validation_tx: self.validation_tx.clone(),
            block_receiver_handle: self.block_receiver_handle.clone(),
            share_validator: self.share_validator.clone(),
        };

        let peer_handle = match self.peer_handles.get(&peer) {
            Some(handle) => handle,
            None => {
                warn!(
                    "No service handle for peer {} on connection {}, creating one on the fly",
                    peer, connection_id
                );
                self.add_peer(peer);
                self.peer_handles.get(&peer).unwrap()
            }
        };

        match peer_handle.try_send(ctx) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                error!(
                    "Peer {} service channel full on connection {}, disconnecting",
                    peer, connection_id
                );
                request_sender.disconnect_peer(peer);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(
                    "Peer {} service task exited on connection {}, removing stale handle",
                    peer, connection_id
                );
                self.peer_handles.remove(&peer);
            }
        }

        Ok(())
    }

    /// Dispatch a response by calling handle_response directly.
    ///
    /// Records peer block knowledge before processing. Responses bypass
    /// the Tower service layers (rate limiting, inactivity tracking)
    /// because they are solicited by us and libp2p only delivers them
    /// for matching outstanding requests.
    ///
    /// `connection_id` identifies the libp2p connection the response arrived
    /// on and is logged on the error path.
    fn dispatch_response(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        response: Message,
    ) -> Result<(), Box<dyn Error>> {
        self.record_peer_knowledge(&peer, &response);

        // Hand the response to the response worker rather than processing it
        // here: handle_response can be heavy (a ShareHeaders batch runs many
        // organise_header calls) and this runs on the swarm-driver task. A full
        // or closed channel drops the response; every response kind has a retry
        // path (header sync re-requests, the fetcher's request timeout).
        let message_type = response.message_type();
        match self
            .response_worker_handle
            .try_send(ResponseWorkerEvent { peer, response })
        {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.responses_dropped_total += 1;
                warn!(
                    "Response worker channel full on connection {}, dropping {} from peer {}",
                    connection_id, message_type, peer
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.responses_dropped_total += 1;
                warn!(
                    "Response worker channel closed on connection {}, dropping {} from peer {}",
                    connection_id, message_type, peer
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::{GetData, InventoryMessage, Message};
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    use crate::node::request_sender::MockRequestSender;
    #[mockall_double::double]
    use crate::pool_difficulty::PoolDifficulty;
    use crate::service::PeerHandle;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::test_utils::{
        TestShareBlockBuilder, share_header_batch_with_empty_branches,
        valid_share_block_from_fixture,
    };
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget};
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;

    type TestChannel = oneshot::Sender<Message>;

    const TEST_RATE_LIMIT: u64 = 10;

    fn build_test_handler(
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<TestChannel>>,
    ) -> RequestResponseHandler<TestChannel> {
        build_test_handler_with_validator(
            chain_store_handle,
            swarm_tx,
            Arc::new(MockDefaultShareValidator::default()),
        )
    }

    fn build_test_handler_with_validator(
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<TestChannel>>,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> RequestResponseHandler<TestChannel> {
        let (handler, response_worker_rx) =
            build_test_handler_parts(chain_store_handle, swarm_tx, share_validator);
        // Drain the response worker channel so dispatch_response's try_send
        // succeeds in tests that only assert the dispatch result.
        tokio::spawn(async move {
            let mut response_worker_rx = response_worker_rx;
            while response_worker_rx.recv().await.is_some() {}
        });
        handler
    }

    /// Build a handler and return the response worker receiver so a test can
    /// assert what `dispatch_response` enqueues.
    fn build_test_handler_parts(
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<TestChannel>>,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> (
        RequestResponseHandler<TestChannel>,
        crate::node::response_worker::ResponseWorkerReceiver,
    ) {
        let (block_fetcher_tx, _block_fetcher_rx) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _validation_rx) =
            crate::node::validation_worker::create_validation_channel();
        let (block_receiver_handle, _block_receiver_rx) = create_block_receiver_channel();
        let (response_worker_handle, response_worker_rx) =
            crate::node::response_worker::create_response_worker_channel();
        let handler = RequestResponseHandler {
            peer_handles: HashMap::new(),
            max_requests_per_second: TEST_RATE_LIMIT,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle: block_fetcher_tx,
            validation_tx,
            block_receiver_handle,
            peer_block_knowledge: PeerBlockKnowledge::default(),
            share_validator,
            response_worker_handle,
            outbound_failures_total: 0,
            inbound_failures_total: 0,
            responses_dropped_total: 0,
        };
        (handler, response_worker_rx)
    }

    #[tokio::test]
    async fn test_dispatch_response_share_headers() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_organise_header().returning(|_| Ok(None));
            cloned
                .expect_find_fork_point_height()
                .returning(|_| Ok(Some(0)));
            cloned
                .expect_get_candidate_blocks_missing_data()
                .returning(|_| Ok(Vec::new()));
            crate::test_utils::setup_header_chain_validation_mocks(&mut cloned);
            cloned
        });

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_header_minimum_difficulty()
            .returning(|_| Ok(()));
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| {
                CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });
        mock_validator
            .expect_pool_difficulty()
            .return_const(pool_difficulty);

        let mut handler = build_test_handler_with_validator(
            chain_store_handle,
            swarm_tx,
            Arc::new(mock_validator),
        );

        let peer_id = libp2p::PeerId::random();
        let mut header1 = TestShareBlockBuilder::new().build().header;
        header1.bits = CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let mut header2 = TestShareBlockBuilder::new()
            .nonce(0xe9695792) // doesn't matter, as we don't compare block hash to target
            .build()
            .header;
        header2.bits = CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        header2.prev_share_blockhash = header1.block_hash();
        let share_headers = vec![header1, header2];

        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::ShareHeaders(share_header_batch_with_empty_branches(share_headers)),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_not_found() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();

        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::NotFound(GetData::Block(BlockHash::all_zeros())),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_inventory() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let block_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<BlockHash>()
                .unwrap(),
        ];
        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::Inventory(inventory),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_unexpected_message() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::GetData(crate::node::messages::GetData::Block(BlockHash::all_zeros())),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_enqueues_to_worker() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let (mut handler, mut response_worker_rx) = build_test_handler_parts(
            chain_store_handle,
            swarm_tx,
            Arc::new(MockDefaultShareValidator::default()),
        );

        let peer_id = libp2p::PeerId::random();
        handler
            .dispatch_response(
                peer_id,
                ConnectionId::new_unchecked(1),
                Message::NotFound(GetData::Block(BlockHash::all_zeros())),
            )
            .unwrap();

        let event = response_worker_rx
            .try_recv()
            .expect("response handed to the worker, not processed on the driver");
        assert_eq!(event.peer, peer_id);
        assert!(matches!(event.response, Message::NotFound(_)));
    }

    #[tokio::test]
    async fn test_dispatch_response_drops_when_worker_full() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let (mut handler, mut response_worker_rx) = build_test_handler_parts(
            chain_store_handle,
            swarm_tx,
            Arc::new(MockDefaultShareValidator::default()),
        );

        // Dispatch far more than the worker channel can hold, without draining
        // it. Every dispatch must return Ok without blocking (it is a try_send),
        // and the overflow must be dropped rather than queued.
        let peer_id = libp2p::PeerId::random();
        let mut dispatched = 0;
        while dispatched < 2000 {
            handler
                .dispatch_response(
                    peer_id,
                    ConnectionId::new_unchecked(1),
                    Message::NotFound(GetData::Block(BlockHash::all_zeros())),
                )
                .expect("dispatch never blocks or errors, even when the worker is full");
            dispatched += 1;
        }

        let mut received = 0;
        while response_worker_rx.try_recv().is_ok() {
            received += 1;
        }
        assert!(
            received < dispatched,
            "some responses were dropped when the worker channel was full"
        );
        assert_eq!(
            handler.responses_dropped_total(),
            (dispatched - received) as u64,
            "every dropped response is counted"
        );
    }

    // A plain `#[test]` (not `#[tokio::test]`): dispatch_response must be callable
    // with no runtime, which is only possible because it does not await -- the
    // property that keeps the node event loop from blocking on swarm_tx.
    #[test]
    fn test_dispatch_response_is_synchronous() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let (mut handler, _response_worker_rx) = build_test_handler_parts(
            chain_store_handle,
            swarm_tx,
            Arc::new(MockDefaultShareValidator::default()),
        );

        let result = handler.dispatch_response(
            PeerId::random(),
            ConnectionId::new_unchecked(1),
            Message::NotFound(GetData::Block(BlockHash::all_zeros())),
        );
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_request_disconnects_on_full_peer_channel() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        // A capacity-1 peer channel whose receiver is kept alive (so sends fail
        // Full, not Closed). The first dispatch fills it; the second must
        // disconnect the peer via the request sender rather than await swarm_tx.
        let peer_id = PeerId::random();
        let (sender, _receiver) = mpsc::channel(1);
        handler
            .peer_handles
            .insert(peer_id, PeerHandle::new_for_test(sender));

        let mut request_sender = MockRequestSender::new();
        request_sender
            .expect_disconnect_peer()
            .times(1)
            .return_const(());

        let (channel_tx_first, _first) = oneshot::channel::<Message>();
        handler
            .dispatch_request(
                peer_id,
                ConnectionId::new_unchecked(1),
                Message::NotFound(GetData::Block(BlockHash::all_zeros())),
                channel_tx_first,
                &mut request_sender,
            )
            .unwrap();

        let (channel_tx_second, _second) = oneshot::channel::<Message>();
        handler
            .dispatch_request(
                peer_id,
                ConnectionId::new_unchecked(1),
                Message::NotFound(GetData::Block(BlockHash::all_zeros())),
                channel_tx_second,
                &mut request_sender,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn test_dispatch_request_calls_service() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();

        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash()];
        let stop_block_hash = block2.block_hash();

        chain_store_handle.expect_clone().returning(|| {
            let mut mock = ChainStoreHandle::default();
            let headers = vec![
                TestShareBlockBuilder::new().build().header,
                TestShareBlockBuilder::new().build().header,
            ];
            mock.expect_get_headers_for_locator()
                .returning(move |_, _, _| Ok(headers.clone()));
            mock.expect_get_template_merkle_branches()
                .returning(|_| Ok(Vec::new()));
            mock
        });

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = PeerId::random();
        handler.add_peer(peer_id);
        let (response_tx, _response_rx) = oneshot::channel::<Message>();

        let result = handler.dispatch_request(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::GetShareHeaders(block_hashes, stop_block_hash),
            response_tx,
            &mut MockRequestSender::new(),
        );

        assert!(result.is_ok());

        // The per-peer task processes asynchronously, wait for response
        if let Some(SwarmSend::Response(_, Message::ShareHeaders(headers))) = swarm_rx.recv().await
        {
            assert_eq!(headers.len(), 2);
        } else {
            panic!("Expected SwarmSend::Response with ShareHeaders message");
        }
    }

    #[tokio::test]
    async fn test_dispatch_request_creates_handle_on_the_fly() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_is_current().returning(|| true);
            cloned
                .expect_get_missing_blockhashes()
                .returning(|_| Vec::with_capacity(0));
            cloned
        });

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        // Do NOT call add_peer -- dispatch_request should create the handle
        let peer_id = PeerId::random();
        let (channel_tx, _channel_rx) = oneshot::channel::<Message>();

        let result = handler.dispatch_request(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::Inventory(InventoryMessage::BlockHashes(vec![BlockHash::all_zeros()])),
            channel_tx,
            &mut MockRequestSender::new(),
        );
        assert!(result.is_ok());

        // Verify the handle was created
        assert!(handler.peer_handles.contains_key(&peer_id));
    }

    #[tokio::test]
    async fn test_dispatch_request_removes_stale_handle_on_closed() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = PeerId::random();

        // Create a channel where the receiver is immediately dropped,
        // simulating a task that has exited.
        let (sender, receiver) = mpsc::channel(16);
        drop(receiver);
        handler
            .peer_handles
            .insert(peer_id, PeerHandle::new_for_test(sender));

        let (channel_tx, _channel_rx) = oneshot::channel::<Message>();
        let result = handler.dispatch_request(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::NotFound(GetData::Block(BlockHash::all_zeros())),
            channel_tx,
            &mut MockRequestSender::new(),
        );
        assert!(result.is_ok());

        // Stale handle should have been removed on Closed
        assert!(
            !handler.peer_handles.contains_key(&peer_id),
            "Stale handle should be removed after Closed error"
        );
    }

    #[tokio::test]
    async fn test_dispatch_request_records_inventory_knowledge() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_is_current().returning(|| true);
            cloned
                .expect_get_missing_blockhashes()
                .returning(|_| Vec::with_capacity(0));
            cloned
        });
        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = PeerId::random();
        handler.add_peer(peer_id);
        let block_hash = BlockHash::all_zeros();
        let inventory = InventoryMessage::BlockHashes(vec![block_hash]);
        let (channel_tx, _channel_rx) = oneshot::channel::<Message>();

        let result = handler.dispatch_request(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::Inventory(inventory),
            channel_tx,
            &mut MockRequestSender::new(),
        );
        assert!(result.is_ok());

        assert!(
            handler
                .peer_block_knowledge()
                .peer_knows_block(&peer_id, &block_hash)
        );
    }

    #[tokio::test]
    async fn test_dispatch_response_records_share_block_knowledge() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();

        // The cloned handle is used by handle_response -> handle_share_block,
        // which checks for duplicates, validates header, and stores the block.
        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_share_block_exists().returning(|_| false);
            cloned.expect_is_candidate().returning(|_| false);
            cloned.expect_add_share_block().returning(|_| Ok(()));
            cloned
        });

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| Ok(()));
        mock_validator
            .expect_validate_block_size()
            .returning(|_| Ok(()));
        mock_validator
            .expect_validate_merkle_root()
            .returning(|_| Ok(()));
        mock_validator
            .expect_validate_with_pool_difficulty()
            .returning(|_, _| Ok(()));

        let mut handler = build_test_handler_with_validator(
            chain_store_handle,
            swarm_tx,
            Arc::new(mock_validator),
        );

        let peer_id = libp2p::PeerId::random();
        let block = valid_share_block_from_fixture();
        let block_hash = block.block_hash();

        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::ShareBlock(block),
        );
        assert!(result.is_ok());

        // Knowledge is recorded before handle_response processes the block
        assert!(
            handler
                .peer_block_knowledge()
                .peer_knows_block(&peer_id, &block_hash)
        );
    }

    #[tokio::test]
    async fn test_dispatch_response_records_inventory_knowledge() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let block_hash = BlockHash::all_zeros();
        let inventory = InventoryMessage::BlockHashes(vec![block_hash]);

        let result = handler.dispatch_response(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::Inventory(inventory),
        );
        assert!(result.is_ok());

        assert!(
            handler
                .peer_block_knowledge()
                .peer_knows_block(&peer_id, &block_hash)
        );
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_is_current().returning(|| true);
            cloned
                .expect_get_missing_blockhashes()
                .returning(|_| Vec::with_capacity(0));
            cloned
        });
        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = PeerId::random();
        handler.add_peer(peer_id);
        let block_hash = BlockHash::all_zeros();
        let inventory = InventoryMessage::BlockHashes(vec![block_hash]);
        let (channel_tx, _channel_rx) = oneshot::channel::<Message>();

        let _ = handler.dispatch_request(
            peer_id,
            ConnectionId::new_unchecked(1),
            Message::Inventory(inventory),
            channel_tx,
            &mut MockRequestSender::new(),
        );
        assert!(
            handler
                .peer_block_knowledge()
                .peer_knows_block(&peer_id, &block_hash)
        );
        assert!(handler.peer_handles.contains_key(&peer_id));

        handler.remove_peer(&peer_id);
        assert!(
            !handler
                .peer_block_knowledge()
                .peer_knows_block(&peer_id, &block_hash)
        );
        assert!(!handler.peer_handles.contains_key(&peer_id));
    }
}
