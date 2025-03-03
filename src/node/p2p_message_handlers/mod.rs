// Copyright (C) 2024 [Kulpreet Singh]
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

pub mod handle_requests;
pub mod handle_responses;
pub mod known_blocks_lookup;

use crate::node::messages::{GetData, InventoryMessage, Message};
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

pub async fn handle_request(
    peer: libp2p::PeerId,
    request: Message,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend>,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Handling request from peer: {}", peer);
    match request {
        Message::GetShareHeaders(block_hashes, stop_block_hash) => {
            handle_requests::handle_getheaders(
                block_hashes,
                stop_block_hash,
                chain_handle,
                swarm_tx,
            )
            .await
        }
        Message::GetShareBlocks(block_hashes, stop_block_hash) => {
            handle_requests::handle_getblocks(block_hashes, stop_block_hash, chain_handle, swarm_tx)
                .await
        }
        Message::ShareHeaders(share_headers) => {
            handle_responses::handle_share_headers(share_headers, chain_handle, time_provider).await
        }
        Message::ShareBlock(share_block) => {
            handle_responses::handle_share_block(share_block, chain_handle, swarm_tx, time_provider)
                .await
        }
        Message::Workbase(workbase) => {
            info!("Received workbase: {:?}", workbase);
            if let Err(e) = chain_handle.add_workbase(workbase.clone()).await {
                error!("Failed to store workbase: {}", e);
                return Err("Error storing workbase".into());
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
            if let Err(e) = chain_handle.store_user_workbase(userworkbase.clone()).await {
                error!("Failed to store user workbase: {}", e);
                return Err("Error storing user workbase".into());
            }
            Ok(())
        }
        Message::Inventory(inventory) => {
            info!("Received inventory: {:?}", inventory);
            match inventory {
                InventoryMessage::ShareHeader(have_shares) => {
                    info!("Received share header inventory: {:?}", have_shares);
                }
                InventoryMessage::ShareBlock(have_blocks) => {
                    info!("Received share block inventory: {:?}", have_blocks);
                }
                InventoryMessage::ShareTransaction(have_transactions) => {
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
    use crate::test_utils::simple_miner_workbase;
    use crate::test_utils::{load_valid_workbases_userworkbases_and_shares, TestBlockBuilder};
    use crate::utils::time_provider::TestTimeProvider;
    use mockall::predicate::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_handle_share_block_request() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
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
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());

        // Verify gossip message was sent
        if let Some(SwarmSend::Gossip(message)) = swarm_rx.try_recv().ok() {
            match message {
                Message::Inventory(inventory) => match inventory {
                    InventoryMessage::ShareBlock(received_shares) => {
                        assert_eq!(
                            received_shares.contains(&share_block.header.blockhash),
                            true
                        );
                    }
                    _ => panic!("Expected Inventory message with ShareBlock"),
                },
                _ => panic!("Expected Inventory message"),
            }
        } else {
            panic!("Expected gossip message");
        }
    }

    #[tokio::test]
    async fn test_handle_request_share_block_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
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
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_err());

        // Verify no gossip message was sent
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_request_workbase_success() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
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
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_ok());

        // Verify gossip message was sent
        if let Some(SwarmSend::Gossip(_)) = swarm_rx.try_recv().ok() {
            // Success
        } else {
            panic!("Expected gossip message");
        }
    }

    #[tokio::test]
    async fn test_handle_request_workbase_error() {
        let peer_id = libp2p::PeerId::random();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
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
            swarm_tx,
            &time_provider,
        )
        .await;

        assert!(result.is_err());

        // Verify no gossip message was sent
        assert!(swarm_rx.try_recv().is_err());
    }
}
