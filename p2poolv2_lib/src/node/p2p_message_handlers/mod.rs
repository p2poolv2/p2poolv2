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
                ctx.chain_handle,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::GetShareBlocks(block_hashes, stop_block_hash) => {
            handle_getblocks(
                block_hashes,
                stop_block_hash,
                ctx.chain_handle,
                ctx.response_channel,
                ctx.swarm_tx,
            )
            .await
        }
        Message::ShareHeaders(share_headers) => {
            handle_share_headers(share_headers, ctx.chain_handle, &ctx.time_provider).await
        }
        Message::ShareBlock(share_block) => {
            if let Err(e) =
                handle_share_block(share_block, ctx.chain_handle, &ctx.time_provider).await
            {
                error!("Failed to add share: {}", e);
                return Err(format!("Failed to add share: {}", e).into());
            }
            Ok(())
        }
        Message::Workbase(workbase) => {
            info!("Received workbase: {:?}", workbase);
            if let Err(e) = ctx.chain_handle.add_workbase(workbase.clone()).await {
                error!("Failed to store workbase: {}", e);
                return Err(format!("Error storing workbase: {}", e).into());
            }
            Ok(())
        }
        Message::UserWorkbase(userworkbase) => {
            info!("Received user workbase: {:?}", userworkbase);
            if let Err(e) = ctx
                .chain_handle
                .add_user_workbase(userworkbase.clone())
                .await
            {
                error!("Failed to store user workbase: {}", e);
                return Err("Error storing user workbase".into());
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
        Message::MiningShare(share_block) => {
            info!("Received mining share from ckpool: {:?}", share_block);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::shares::ShareBlockHash;
    #[mockall_double::double]
    use crate::shares::chain::actor::ChainHandle;
    use crate::test_utils::simple_miner_workbase;
    use crate::test_utils::{TestBlockBuilder, load_valid_workbases_userworkbases_and_shares};
    use crate::utils::time_provider::TestTimeProvider;
    use crate::utils::time_provider::TimeProvider;
    use tokio::sync::mpsc;

    use mockall::predicate::*;
    use std::time::SystemTime;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_handle_share_block_request() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let peer_id = libp2p::PeerId::random();
        let mut time_provider = TestTimeProvider(SystemTime::now());
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<bitcoin::PublicKey>()
            .unwrap();
        let share_header = crate::shares::miner_message::builders::build_share_header(
            &workbases[0],
            &shares[0],
            &userworkbases[0],
            pubkey,
        )
        .unwrap();

        let share_block = crate::shares::miner_message::builders::build_share_block(
            &workbases[0],
            &userworkbases[0],
            &shares[0],
            share_header,
        )
        .unwrap();

        chain_handle
            .expect_add_share()
            .with(eq(share_block.clone()))
            .returning(|_| Ok(()));

        chain_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);
        chain_handle
            .expect_get_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(workbases[0].clone()));
        chain_handle
            .expect_get_user_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(userworkbases[0].clone()));

        time_provider.set_time(shares[0].ntime);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block.clone()),
            chain_handle,
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
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let share_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7459044800742817807)
            .build();

        chain_handle
            .expect_add_share()
            .with(eq(share_block.clone()))
            .returning(|_| Err("Failed to add share".into()));

        chain_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);

        chain_handle
            .expect_get_workbase()
            .with(eq(7459044800742817807))
            .returning(|_| Some(simple_miner_workbase()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareBlock(share_block),
            chain_handle,
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
    async fn test_handle_request_workbase_success() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let workbase = simple_miner_workbase();

        chain_handle
            .expect_add_workbase()
            .with(eq(workbase.clone()))
            .returning(|_| Ok(()));

        chain_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Workbase(workbase),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_workbase_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let workbase = simple_miner_workbase();

        // Set up mock to return error
        chain_handle
            .expect_add_workbase()
            .with(eq(workbase.clone()))
            .returning(|_| Err("Failed to add workbase".into()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Workbase(workbase),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error storing workbase: Failed to add workbase"
        );
    }

    #[tokio::test]
    async fn test_handle_request_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let response_channel = 1u32;
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let block_hashes =
            vec!["0000000000000000000000000000000000000000000000000000000000000001".into()];
        let stop_block_hash =
            "0000000000000000000000000000000000000000000000000000000000000002".into();

        // Mock the response headers
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();
        let block2 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
            .build();
        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        chain_handle
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| response_headers.clone());

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareHeaders(block_hashes, stop_block_hash),
            chain_handle,
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
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let stop_block_hash =
            "0000000000000000000000000000000000000000000000000000000000000002".into();

        // Create test blocks that will be returned
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();
        let block2 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
            .build();

        let block_hashes: Vec<ShareBlockHash> = vec![
            block1.cached_blockhash.unwrap(),
            block2.cached_blockhash.unwrap(),
        ];

        // Set up mock expectations
        chain_handle
            .expect_get_blockhashes_for_locator()
            .returning(move |_, _, _| {
                vec![
                    block1.cached_blockhash.unwrap(),
                    block2.cached_blockhash.unwrap(),
                ]
            });

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetShareBlocks(block_hashes.clone(), stop_block_hash),
            chain_handle,
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
    async fn test_handle_request_user_workbase_success() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase = user_workbases[0].clone();

        // Set up mock to return success
        chain_handle
            .expect_add_user_workbase()
            .with(eq(user_workbase.clone()))
            .returning(|_| Ok(()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::UserWorkbase(user_workbase),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_user_workbase_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase = user_workbases[0].clone();

        // Set up mock to return error
        chain_handle
            .expect_add_user_workbase()
            .with(eq(user_workbase.clone()))
            .returning(|_| Err("Failed to add user workbase".into()));

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::UserWorkbase(user_workbase),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_request_inventory_for_blocks() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Test BlockHashes inventory
        let block_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001".into(),
            "0000000000000000000000000000000000000000000000000000000000000002".into(),
        ];
        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Inventory(inventory),
            chain_handle,
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
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Test TransactionHashes inventory
        let tx_hashes: Vec<bitcoin::Txid> = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
        ];
        let inventory = InventoryMessage::TransactionHashes(tx_hashes);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Inventory(inventory),
            chain_handle,
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
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::NotFound(()),
            chain_handle,
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
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001".into();
        let get_data = GetData::Block(block_hash);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            chain_handle,
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
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Test GetData message with txid
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let get_data = GetData::Txid(txid);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::GetData(get_data),
            chain_handle,
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
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Create a test transaction
        let transaction = crate::test_utils::test_coinbase_transaction();

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Transaction(transaction),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_mining_share() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Create a test share block
        let share_block = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::MiningShare(share_block),
            chain_handle,
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
        let mut chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Create test share headers
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();
        let block2 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
            .build();

        let share_headers = vec![block1.header.clone(), block2.header.clone()];

        // Set up mock expectations for processing headers
        chain_handle
            .expect_get_headers_for_locator()
            .returning(|_, _, _| vec![]);

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::ShareHeaders(share_headers),
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx,
            time_provider,
        };

        let result = handle_request(ctx).await;

        assert!(result.is_ok());
    }
}
