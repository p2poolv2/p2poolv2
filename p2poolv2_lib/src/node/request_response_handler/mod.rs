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

pub mod block_fetcher;
pub mod peer_block_knowledge;

use self::block_fetcher::BlockFetcherHandle;
use self::peer_block_knowledge::PeerBlockKnowledge;
use crate::config::NetworkConfig;
use crate::node::SwarmSend;
use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::{InventoryMessage, Message};
use crate::node::p2p_message_handlers::handle_response;
use crate::node::p2p_message_handlers::receivers::block_receiver::BlockReceiverHandle;
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
}

/// Implementation of ResponseChannel<Message>, used in production.
/// The only part left out of tests is the type based dispatching. The
/// dispatch.* functions are tested for the generic implementation.
impl RequestResponseHandler<ResponseChannel<Message>> {
    /// Create a new RequestResponseHandler with per-peer service support.
    pub fn new(
        network_config: NetworkConfig,
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
        block_receiver_handle: BlockReceiverHandle,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
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
    pub async fn handle_event(
        &mut self,
        event: RequestResponseEvent,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            RequestResponseEvent::Message {
                peer,
                message:
                    libp2p::request_response::Message::Request {
                        request_id: _,
                        request,
                        channel,
                    },
            } => self.dispatch_request(peer, request, channel).await,
            RequestResponseEvent::Message {
                peer,
                message:
                    libp2p::request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                debug!(
                    "Received response {} for request {} from peer {}",
                    response, request_id, peer
                );
                self.dispatch_response(peer, response).await
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error: failure_error,
            } => {
                debug!(
                    "Outbound failure from peer {}, request_id: {}, error: {:?}",
                    peer, request_id, failure_error
                );
                Ok(())
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error: failure_error,
            } => {
                debug!(
                    "Inbound failure from peer {}, request_id: {}, error: {:?}",
                    peer, request_id, failure_error
                );
                Ok(())
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                debug!("Response sent to peer {}, request_id: {}", peer, request_id);
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

    /// Remove all state for a disconnected peer.
    ///
    /// Drops the peer handle, which closes the channel and causes
    /// the peer's service task to exit. Also removes peer block
    /// knowledge.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peer_handles.remove(peer_id);
        self.peer_block_knowledge.remove_peer(peer_id);
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
    /// - Full: peer is overwhelming us, disconnect.
    /// - Closed: task exited (rate limit or error), remove the stale
    ///   handle so the next request spawns a fresh one.
    /// - No handle: create one on the fly (defensive fallback).
    async fn dispatch_request(
        &mut self,
        peer: PeerId,
        request: Message,
        channel: C,
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
                    "No service handle for peer {}, creating one on the fly",
                    peer
                );
                self.add_peer(peer);
                self.peer_handles.get(&peer).unwrap()
            }
        };

        match peer_handle.try_send(ctx) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                error!("Peer {} service channel full, disconnecting", peer);
                let _ = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("Peer {} service task exited, removing stale handle", peer);
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
    async fn dispatch_response(
        &mut self,
        peer: PeerId,
        response: Message,
    ) -> Result<(), Box<dyn Error>> {
        self.record_peer_knowledge(&peer, &response);

        if let Err(err) = handle_response(
            peer,
            response,
            self.chain_store_handle.clone(),
            self.swarm_tx.clone(),
            self.block_fetcher_handle.clone(),
            self.validation_tx.clone(),
            self.block_receiver_handle.clone(),
            self.share_validator.clone(),
        )
        .await
        {
            error!("Error handling response from peer {}: {}", peer, err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::{InventoryMessage, Message};
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    #[mockall_double::double]
    use crate::pool_difficulty::PoolDifficulty;
    use crate::service::PeerHandle;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::test_utils::{TestShareBlockBuilder, valid_share_block_from_fixture};
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
        let (block_fetcher_tx, _block_fetcher_rx) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _validation_rx) =
            crate::node::validation_worker::create_validation_channel();
        let (block_receiver_handle, _block_receiver_rx) = create_block_receiver_channel();
        RequestResponseHandler {
            peer_handles: HashMap::new(),
            max_requests_per_second: TEST_RATE_LIMIT,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle: block_fetcher_tx,
            validation_tx,
            block_receiver_handle,
            peer_block_knowledge: PeerBlockKnowledge::default(),
            share_validator,
        }
    }

    #[tokio::test]
    async fn test_dispatch_response_share_headers() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle.expect_clone().returning(|| {
            let mut cloned = ChainStoreHandle::default();
            cloned.expect_organise_header().returning(|_| Ok(None));
            cloned
                .expect_get_candidate_blocks_missing_data()
                .returning(|| Ok(Vec::new()));
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

        let result = handler
            .dispatch_response(peer_id, Message::ShareHeaders(share_headers))
            .await;

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

        let result = handler
            .dispatch_response(peer_id, Message::NotFound(()))
            .await;

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

        let result = handler
            .dispatch_response(peer_id, Message::Inventory(inventory))
            .await;

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
        let result = handler
            .dispatch_response(
                peer_id,
                Message::GetData(crate::node::messages::GetData::Block(BlockHash::all_zeros())),
            )
            .await;

        assert!(result.is_ok());
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
            mock
        });

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = PeerId::random();
        handler.add_peer(peer_id);
        let (response_tx, _response_rx) = oneshot::channel::<Message>();

        let result = handler
            .dispatch_request(
                peer_id,
                Message::GetShareHeaders(block_hashes, stop_block_hash),
                response_tx,
            )
            .await;

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

        let result = handler
            .dispatch_request(
                peer_id,
                Message::Inventory(InventoryMessage::BlockHashes(vec![BlockHash::all_zeros()])),
                channel_tx,
            )
            .await;
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
        let result = handler
            .dispatch_request(peer_id, Message::NotFound(()), channel_tx)
            .await;
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

        let result = handler
            .dispatch_request(peer_id, Message::Inventory(inventory), channel_tx)
            .await;
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

        let result = handler
            .dispatch_response(peer_id, Message::ShareBlock(block))
            .await;
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

        let result = handler
            .dispatch_response(peer_id, Message::Inventory(inventory))
            .await;
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

        let _ = handler
            .dispatch_request(peer_id, Message::Inventory(inventory), channel_tx)
            .await;
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
