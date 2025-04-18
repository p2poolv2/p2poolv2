// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::utils::time_provider::TimeProvider;
use receivers::getblocks::handle_getblocks;
use receivers::getheaders::handle_getheaders;
use receivers::share_blocks::handle_share_block;
use receivers::share_headers::handle_share_headers;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

pub async fn handle_request<C: 'static>(
    peer: libp2p::PeerId,
    request: Message,
    chain_handle: ChainHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Handling request from peer: {}", peer);
    match request {
        Message::GetShareHeaders(block_hashes, stop_block_hash) => {
            handle_getheaders(
                block_hashes,
                stop_block_hash,
                chain_handle,
                response_channel,
                swarm_tx,
            )
            .await
        }
        Message::GetShareBlocks(block_hashes, stop_block_hash) => {
            handle_getblocks(
                block_hashes,
                stop_block_hash,
                chain_handle,
                response_channel,
                swarm_tx,
            )
            .await
        }
        Message::ShareHeaders(share_headers) => {
            handle_share_headers(share_headers, chain_handle, time_provider).await
        }
        Message::ShareBlock(share_block) => {
            let peer_clone = peer.clone();
            
            // Define a simple closure that doesn't attempt to send through the channel
            // This avoids the need to send the generic C type across threads
            let disconnect_fn = Box::new(move |peer_to_disconnect: libp2p::PeerId| {
                // We only log the intent to disconnect - the actual disconnection happens below
                if peer_clone == peer_to_disconnect {
                    error!("Peer {} sent invalid share block and will be disconnected", peer_clone);
                }
            });
            
            // Handle the share block, passing peer_id and disconnect function
            let result = handle_share_block(share_block, chain_handle, time_provider, Some(peer), Some(disconnect_fn)).await;
            
            if let Err(e) = result {
                error!("Failed to add share: {}", e);
                // Always try to disconnect the peer on any share validation or addition error
                // This happens in the current thread context, not in the closure
                if let Err(send_err) = swarm_tx.try_send(SwarmSend::DisconnectPeer(peer)) {
                    error!("Failed to send disconnect peer message: {}", send_err);
                }
                return Err(format!("Failed to add share: {}", e).into());
            }
            Ok(())
        }
        Message::Workbase(workbase) => {
            info!("Received workbase: {:?}", workbase);
            let peer_clone = peer.clone();
            if let Err(e) = chain_handle.add_workbase(workbase.clone()).await {
                error!("Failed to store workbase: {}", e);
                error!("Peer {} sent invalid blocktemplate and will be disconnected", peer_clone);
                // Signal through a channel that this peer should be disconnected
                if let Err(e) = swarm_tx.try_send(SwarmSend::DisconnectPeer(peer_clone)) {
                    error!("Failed to send disconnect peer message: {}", e);
                }
                return Err(format!("Error storing workbase: {}", e).into());
            }
            if let Err(e) = swarm_tx
                .send(SwarmSend::Gossip(Message::Workbase(workbase)))
                .await
            {
                error!("Failed to send share: {}", e);
                return Err("Error sending share to network".into());
            }
            Ok(())
        }
        Message::UserWorkbase(userworkbase) => {
            info!("Received user workbase: {:?}", userworkbase);
            let peer_clone = peer.clone();
            if let Err(e) = chain_handle.add_user_workbase(userworkbase.clone()).await {
                error!("Failed to store user workbase: {}", e);
                error!("Peer {} sent invalid user workbase and will be disconnected", peer_clone);
                // Signal through a channel that this peer should be disconnected
                if let Err(e) = swarm_tx.try_send(SwarmSend::DisconnectPeer(peer_clone)) {
                    error!("Failed to send disconnect peer message: {}", e);
                }
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
    #[mockall_double::double]
    use crate::shares::chain::actor::ChainHandle;
    use crate::shares::ShareBlockHash;
    use crate::test_utils::simple_miner_workbase;
    use crate::test_utils::{load_valid_workbases_userworkbases_and_shares, TestBlockBuilder};
    use crate::utils::time_provider::TestTimeProvider;
    use mockall::predicate::*;
    use std::time::SystemTime;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_handle_share_block_request() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let peer_id = libp2p::PeerId::random();

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

        // Set up mock expectations
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

        let mut time_provider = TestTimeProvider(SystemTime::now());
        time_provider.set_time(shares[0].ntime);

        // Test handle_request directly without request_id
        let result = handle_request(
            peer_id,
            Message::ShareBlock(share_block.clone()),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_share_block_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();

        let share_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7459044800742817807)
            .build();

        // Set up mock to return error
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

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::ShareBlock(share_block),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let workbase = simple_miner_workbase();

        // Set up mock to return success
        chain_handle
            .expect_add_workbase()
            .with(eq(workbase.clone()))
            .returning(|_| Ok(()));

        chain_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::Workbase(workbase),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_workbase_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();

        let workbase = simple_miner_workbase();

        // Set up mock to return error
        chain_handle
            .expect_add_workbase()
            .with(eq(workbase.clone()))
            .returning(|_| Err("Failed to add workbase".into()));

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::Workbase(workbase),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        // Set up mock expectations
        chain_handle
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| response_headers.clone());

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::GetShareHeaders(block_hashes, stop_block_hash),
            chain_handle,
            response_channel,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::GetShareBlocks(block_hashes.clone(), stop_block_hash),
            chain_handle,
            response_channel,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase = user_workbases[0].clone();

        // Set up mock to return success
        chain_handle
            .expect_add_user_workbase()
            .with(eq(user_workbase.clone()))
            .returning(|_| Ok(()));

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::UserWorkbase(user_workbase),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_user_workbase_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let mut chain_handle = ChainHandle::default();

        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase = user_workbases[0].clone();

        // Set up mock to return error
        chain_handle
            .expect_add_user_workbase()
            .with(eq(user_workbase.clone()))
            .returning(|_| Err("Failed to add user workbase".into()));

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::UserWorkbase(user_workbase),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let result = handle_request(
            peer_id,
            Message::Inventory(inventory),
            chain_handle,
            response_channel_tx,
            swarm_tx.clone(),
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_inventory_for_txns() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (_response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
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

        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();

        let result = handle_request(
            peer_id,
            Message::Inventory(inventory),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_not_found() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_request(
            peer_id,
            Message::NotFound(()),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_get_data_for_block() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();
        let chain_handle = ChainHandle::default();
        let time_provider = TestTimeProvider(SystemTime::now());

        // Test GetData message with block hash
        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001".into();
        let get_data = GetData::Block(block_hash);

        let result = handle_request(
            peer_id,
            Message::GetData(get_data),
            chain_handle,
            response_channel_tx,
            swarm_tx.clone(),
            &time_provider,
        )
        .await;

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

        let result = handle_request(
            peer_id,
            Message::GetData(get_data),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let result = handle_request(
            peer_id,
            Message::Transaction(transaction),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let result = handle_request(
            peer_id,
            Message::MiningShare(share_block),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

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

        let result = handle_request(
            peer_id,
            Message::ShareHeaders(share_headers),
            chain_handle,
            response_channel_tx,
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());
    }
}
