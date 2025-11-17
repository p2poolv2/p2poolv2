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

use crate::node::messages::{GetData, InventoryMessage, Message};
use crate::service::p2p_service::RequestContext;
use crate::utils::time_provider::TimeProvider;
use receivers::getblocks::handle_getblocks;
use receivers::getheaders::handle_getheaders;
use receivers::share_blocks::handle_share_block;
use receivers::share_headers::handle_share_headers;
use std::error::Error;
use tracing::{error, info};

/// The Tower service that processes inbound P2P requests.
pub async fn handle_request<C: Send + Sync + 'static, T: TimeProvider + Send + Sync + 'static>(
    ctx: RequestContext<C, T>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Handling request {} from peer: {}", ctx.request, ctx.peer);
    match ctx.request {
        Message::GetShareHeaders(block_hashes, stop_block_hash) => {
            handle_getheaders(
                block_hashes,
                stop_block_hash,
                ctx.store,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::GetShareBlocks(block_hashes, stop_block_hash) => {
            handle_getblocks(
                block_hashes,
                stop_block_hash,
                ctx.store,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::ShareHeaders(share_headers) => {
            handle_share_headers(share_headers, ctx.store, &ctx.time_provider).await
        }
        Message::ShareBlock(share_block) => {
            if let Err(e) = handle_share_block(share_block, ctx.store, &ctx.time_provider).await {
                error!("Failed to add share: {}", e);
                return Err(format!("Failed to add share: {e}").into());
            }
            Ok(())
        }
        Message::Inventory(inventory) => {
            info!("Received inventory: {:?}", inventory);
            match inventory {
                InventoryMessage::BlockHashes(have_blocks) => {
                    info!("Received share block inventory: {:?}", have_blocks);
                }
                InventoryMessage::TransactionHashes(have_transactions) => {
                    info!(
                        "Received share transaction inventory: {:?}",
                        have_transactions
                    );
                }
            }
            Ok(())
        }
        Message::NotFound(_) => {
            info!("Received not found message");
            Ok(())
        }
        Message::GetData(get_data) => {
            info!("Received get data: {:?}", get_data);
            match get_data {
                GetData::Block(block_hash) => {
                    info!("Received block hash: {:?}", block_hash);
                }
                GetData::Txid(txid) => {
                    info!("Received txid: {:?}", txid);
                }
            }
            Ok(())
        }
        Message::Transaction(transaction) => {
            info!("Received transaction: {:?}", transaction);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    #[mockall_double::double]
    use crate::shares::chain::chain_store::ChainStore;
    use crate::shares::share_block::Txids;
    use crate::test_utils::{
        TestShareBlockBuilder, build_block_from_work_components, genesis_for_tests,
    };
    use crate::utils::time_provider::TestTimeProvider;
    use crate::utils::time_provider::TimeProvider;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash as _;
    use mockall::predicate::*;
    use std::sync::Arc;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_handle_share_block_request() {
        let mut store = ChainStore::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let peer_id = libp2p::PeerId::random();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());

        let _pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<bitcoin::PublicKey>()
            .unwrap();

        let share_block =
            build_block_from_work_components("../tests/test_data/validation/stratum/a/");

        store
            .expect_add_share()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Ok(()));
        store
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        store
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);

        time_provider.set_time(
            bitcoin::absolute::Time::from_consensus(share_block.header.bitcoin_header.time)
                .unwrap(),
        );

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block.clone()),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_share_block_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        let share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        store
            .expect_add_share()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Err("Failed to add share".into()));

        store
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to add share: Share block validation failed"
        );
    }

    #[tokio::test]
    async fn test_handle_request_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Mock the response headers
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash()];
        let stop_block_hash = block2.block_hash();

        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        store
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| response_headers.clone());

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareHeaders(block_hashes, stop_block_hash),
            store: Arc::new(store),
            response_channel,
            swarm_tx,
            time_provider,
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
        let mut store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Create test blocks that will be returned
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes: Vec<BlockHash> = vec![block1.block_hash(), block2.block_hash()];
        let stop_block_hash = block2.block_hash();

        // Set up mock expectations
        store
            .expect_get_blockhashes_for_locator()
            .returning(move |_, _, _| vec![block1.block_hash(), block2.block_hash()]);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareBlocks(block_hashes.clone(), stop_block_hash),
            store: Arc::new(store),
            response_channel,
            swarm_tx,
            time_provider,
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
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Test BlockHashes inventory
        let block_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<BlockHash>()
                .unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse::<BlockHash>()
                .unwrap(),
        ];
        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Inventory(inventory),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_inventory_for_txns() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Test TransactionHashes inventory
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
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_not_found() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_block() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();
        let get_data = GetData::Block(block_hash);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_txn() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Test GetData message with txid
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let get_data = GetData::Txid(txid);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_transaction() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Create a test transaction
        let transaction = crate::test_utils::test_coinbase_transaction();

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Transaction(transaction),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_share_headers() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut store = ChainStore::default();
        let time_provider = TestTimeProvider::new(SystemTime::now());

        // Create test share headers
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let share_headers = vec![block1.header.clone(), block2.header.clone()];

        // Set up mock expectations for processing headers
        store
            .expect_get_headers_for_locator()
            .returning(|_, _, _| vec![]);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareHeaders(share_headers),
            store: Arc::new(store),
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }
}
