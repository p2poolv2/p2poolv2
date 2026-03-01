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

pub mod receivers;
pub mod senders;

use crate::node::SwarmSend;
use crate::node::messages::{GetData, Message};
use crate::node::request_response_handler::block_fetcher::BlockFetcherHandle;
use crate::node::validation_worker::ValidationSender;
use crate::service::p2p_service::RequestContext;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::utils::time_provider::TimeProvider;
use receivers::getblocks::handle_getblocks;
use receivers::getdata::handle_getdata_block;
use receivers::getheaders::handle_getheaders;
use receivers::inventory::handle_inventory;
use receivers::share_blocks::handle_share_block;
use receivers::share_headers::handle_share_headers;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

const MAX_HEADERS_IN_RESPONSE: usize = 2000;

/// The Tower service that processes inbound P2P requests.
pub async fn handle_request<C: Send + Sync, T: TimeProvider + Send + Sync>(
    ctx: RequestContext<C, T>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Handling request {} from peer: {}", ctx.request, ctx.peer);
    match ctx.request {
        Message::GetShareHeaders(block_hashes, stop_block_hash) => {
            handle_getheaders(
                block_hashes,
                stop_block_hash,
                ctx.chain_store_handle,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::GetShareBlocks(block_hashes, stop_block_hash) => {
            handle_getblocks(
                block_hashes,
                stop_block_hash,
                ctx.chain_store_handle,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::Inventory(inventory) => {
            handle_inventory(inventory, ctx.peer, ctx.chain_store_handle, ctx.swarm_tx).await
        }
        Message::NotFound(_) => {
            info!("Received not found message");
            Ok(())
        }
        Message::GetData(get_data) => {
            info!("Received get data: {:?}", get_data);
            match get_data {
                GetData::Block(block_hash) => {
                    handle_getdata_block(
                        block_hash,
                        ctx.chain_store_handle,
                        ctx.response_channel,
                        ctx.swarm_tx,
                    )
                    .await
                }
                GetData::Txid(txid) => {
                    info!("Received txid: {:?}", txid);
                    Ok(())
                }
            }
        }
        Message::Transaction(transaction) => {
            info!("Received transaction: {:?}", transaction);
            Ok(())
        }
        Message::ShareBlock(share_block) => handle_share_block(
            ctx.peer,
            share_block,
            &ctx.chain_store_handle,
            ctx.block_fetcher_handle,
            ctx.validation_tx,
        )
        .await
        .map_err(|e| {
            error!("Failed to add share from request: {}", e);
            format!("Failed to add share from request: {e}").into()
        }),
        other => {
            info!("Unexpected request type {other}");
            Ok(())
        }
    }
}

/// Handle a response message received from a peer.
///
/// Unlike handle_request, this is called directly without the Tower service
/// layers (rate limiting, inactivity tracking). Responses are solicited by
/// us and libp2p only delivers them for matching outstanding requests, so
/// peer-protection middleware is unnecessary.
///
/// The swarm_tx channel is provided so that individual response handlers can
/// send follow-up messages (e.g. GetShareBlocks after receiving ShareHeaders)
/// back to the peer.
pub async fn handle_response<C: Send + Sync>(
    peer: libp2p::PeerId,
    response: Message,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Handling response {} from peer: {}", response, peer);
    match response {
        Message::ShareHeaders(share_headers) => handle_share_headers(
            peer,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
        )
        .await
        .map_err(|e| {
            error!("Error handling received share headers: {}", e);
            e
        }),
        Message::ShareBlock(share_block) => handle_share_block(
            peer,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
        .await
        .map_err(|e| {
            error!("Failed to add share from response: {}", e);
            format!("Failed to add share from response: {e}").into()
        }),
        Message::NotFound(_) => {
            info!("Received not found response from peer: {}", peer);
            Ok(())
        }
        other => {
            info!("Unexpected response type from peer {}: {}", peer, other);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::InventoryMessage;
    use crate::node::request_response_handler::block_fetcher::BlockFetcherHandle;
    use crate::node::request_response_handler::block_fetcher::create_block_fetcher_channel;
    use crate::node::validation_worker::ValidationSender;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::share_block::Txids;
    use crate::test_utils::TestShareBlockBuilder;
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash as _;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;

    /// Create test block fetcher and validation handles for handle_response tests.
    fn test_handles() -> (BlockFetcherHandle, ValidationSender) {
        let (block_fetcher_tx, _) = create_block_fetcher_channel();
        let (validation_tx, _) = crate::node::validation_worker::create_validation_channel();
        (block_fetcher_tx, validation_tx)
    }

    #[tokio::test]
    async fn test_handle_request_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        // Mock the response headers
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash()];
        let stop_block_hash = block2.block_hash();

        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        chain_store_handle
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| Ok(response_headers.clone()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareHeaders(block_hashes, stop_block_hash),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        // Verify swarm message
        if let Some(SwarmSend::Response(channel, Message::ShareHeaders(headers))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(headers, vec![block1.header, block2.header]);
        } else {
            panic!("Expected SwarmSend::Response with ShareHeaders message");
        }
    }

    #[tokio::test]
    async fn test_handle_get_share_blocks() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let (response_channel, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        // Create test blocks that will be returned
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes: Vec<BlockHash> = vec![block1.block_hash(), block2.block_hash()];
        let stop_block_hash = block2.block_hash();

        // Set up mock expectations
        chain_store_handle
            .expect_get_blockhashes_for_locator()
            .returning(move |_, _, _| Ok(vec![block1.block_hash(), block2.block_hash()]));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareBlocks(block_hashes.clone(), stop_block_hash),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());

        // Verify swarm message
        if let Some(SwarmSend::Response(
            _,
            Message::Inventory(InventoryMessage::BlockHashes(hashes)),
        )) = swarm_rx.recv().await
        {
            assert_eq!(hashes, block_hashes);
        } else {
            panic!("Expected SwarmSend::Response with Inventory message");
        }
    }

    #[tokio::test]
    async fn test_handle_request_inventory_for_blocks() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let block_hash1 = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();
        let block_hash2 = "0000000000000000000000000000000000000000000000000000000000000002"
            .parse::<BlockHash>()
            .unwrap();

        let block_hashes = vec![block_hash1, block_hash2];
        let missing = vec![block_hash1];

        chain_store_handle
            .expect_get_missing_blockhashes()
            .returning(move |_| missing.clone());

        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Inventory(inventory),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Request(sent_peer, Message::GetData(GetData::Block(hash)))) =
            swarm_rx.recv().await
        {
            assert_eq!(sent_peer, peer_id);
            assert_eq!(hash, block_hash1);
        } else {
            panic!("Expected SwarmSend::Request with GetData::Block message");
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No additional messages expected"
        );
    }

    #[tokio::test]
    async fn test_handle_request_inventory_for_txns() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let tx_hashes: Vec<bitcoin::Txid> = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
        ];
        let inventory = InventoryMessage::TransactionHashes(Txids(tx_hashes));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Inventory(inventory),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages expected for TransactionHashes inventory"
        );
    }

    #[tokio::test]
    async fn test_handle_request_not_found() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_block_confirmed() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let expected_block = block.clone();

        chain_store_handle
            .expect_get_share()
            .returning(move |_| Some(block.clone()));
        chain_store_handle
            .expect_is_confirmed_or_confirmed_uncle()
            .returning(|_| true);

        let get_data = GetData::Block(block_hash);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::ShareBlock(share_block))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(share_block, expected_block);
        } else {
            panic!("Expected SwarmSend::Response with ShareBlock message");
        }
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_block_not_found() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();

        chain_store_handle.expect_get_share().returning(|_| None);

        let get_data = GetData::Block(block_hash);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::NotFound(()))) = swarm_rx.recv().await {
            assert_eq!(channel, response_channel);
        } else {
            panic!("Expected SwarmSend::Response with NotFound message");
        }
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_txn() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        // Test GetData message with txid
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let get_data = GetData::Txid(txid);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_transaction() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        // Create a test transaction
        let transaction = crate::test_utils::test_coinbase_transaction();

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Transaction(transaction),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_share_headers() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        // Create test share headers
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let share_headers = vec![block1.header.clone(), block2.header.clone()];

        // Set up mock expectations for processing headers
        chain_store_handle
            .expect_get_headers_for_locator()
            .returning(|_, _, _| Ok(vec![]));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareHeaders(share_headers),
            chain_store_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_share_block() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_tx, _) =
            crate::node::request_response_handler::block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) =
            crate::node::validation_worker::create_validation_channel();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        // Mock storage: add block succeeds
        chain_store_handle
            .expect_add_share_block()
            .returning(|_, _| Ok(()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle: block_fetcher_tx,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());

        // Verify validation event was sent after successful store
        if let Some(crate::node::validation_worker::ValidationEvent::ValidateBlock(
            sent_block_hash,
        )) = validation_rx.recv().await
        {
            assert_eq!(sent_block_hash, block_hash);
        } else {
            panic!("Expected ValidationEvent::ValidateBlock after successful ShareBlock handling");
        }
    }

    #[tokio::test]
    async fn test_handle_request_share_block_store_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());
        let (block_fetcher_handle, validation_tx) = test_handles();

        let share_block = TestShareBlockBuilder::new().build();

        // Mock storage: add block fails
        chain_store_handle
            .expect_add_share_block()
            .returning(|_, _| {
                Err(crate::store::writer::StoreError::Database(
                    "test error".to_string(),
                ))
            });

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block),
            chain_store_handle,
            response_channel,
            swarm_tx,
            time_provider,
            block_fetcher_handle,
            validation_tx,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_response_share_headers() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_organise_header()
            .returning(|_| Ok(None));
        chain_store_handle
            .expect_get_candidate_blocks_missing_data()
            .returning(|| Ok(Vec::new()));
        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();
        let share_headers = vec![block1.header.clone(), block2.header.clone()];

        let (block_fetcher_handle, validation_tx) = test_handles();
        let result = handle_response(
            peer_id,
            Message::ShareHeaders(share_headers),
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_response_not_found() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let (block_fetcher_handle, validation_tx) = test_handles();
        let result = handle_response(
            peer_id,
            Message::NotFound(()),
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_response_inventory() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let block_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<BlockHash>()
                .unwrap(),
        ];
        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let (block_fetcher_handle, validation_tx) = test_handles();
        let result = handle_response(
            peer_id,
            Message::Inventory(inventory),
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_response_unexpected_message() {
        let peer_id = libp2p::PeerId::random();
        let chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);

        let (block_fetcher_handle, validation_tx) = test_handles();
        let result = handle_response(
            peer_id,
            Message::GetData(GetData::Block(BlockHash::all_zeros())),
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
        )
        .await;

        assert!(result.is_ok());
    }
}
