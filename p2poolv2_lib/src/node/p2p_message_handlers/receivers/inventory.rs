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

use crate::node::Message;
use crate::node::SwarmSend;
use crate::node::messages::InventoryMessage;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Handle Inventory message request from a peer.
/// inv is sent unsolicited, or in response to getblocks message,
/// therefore we include this message in the handle_requests module.
///
/// We wrap all inventory update messages in the same message type
/// - Depending on the type of the inventory, we query the database for the relevant data
/// - Send the data to the peer via the swarm_tx channel
/// - We send one message for each found object. See block and tx messages.
///   Note: At the moment, we only support sending blockhashes as inventory.
pub async fn handle_inventory<C: Clone + 'static>(
    inventory: Vec<InventoryMessage>,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    response_channel: C,
) -> Result<(), Box<dyn Error>> {
    info!("Received inventory update: {:?}", inventory);

    for inv_item in inventory {
        match inv_item {
            InventoryMessage::BlockHashes(locator) => {
                info!("Received block hashes locator: {:?}", locator);

                // Check which blocks we're missing and request them
                let missing_blocks = chain_store_handle.get_missing_blockhashes(&locator);

                // Request missing blocks from the peer
                if !missing_blocks.is_empty() {
                    info!(
                        "Requesting {} missing blocks from peer",
                        missing_blocks.len()
                    );
                    // Send individual GetBlock requests for each missing block
                    for block_hash in missing_blocks {
                        let get_block_request =
                            Message::GetData(crate::node::messages::GetData::Block(block_hash));
                        swarm_tx
                            .send(SwarmSend::Response(
                                response_channel.clone(),
                                get_block_request,
                            ))
                            .await?;
                    }
                }
            }
            // Handle other inventory types as needed
            _ => {
                info!("Unsupported inventory type: {:?}", inv_item);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ChainStoreHandle;
    use crate::node::messages::{GetData, InventoryMessage};
    use crate::node::p2p_message_handlers::receivers::inventory::handle_inventory;
    use crate::node::{Message, SwarmSend};
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::BlockHash;
    use mockall::predicate::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_inventory_block_hashes() {
        let mut chain_store_handle = ChainStoreHandle::default(); // Setup

        let block1 = TestShareBlockBuilder::new().build();

        let block2 = TestShareBlockBuilder::new().build();

        let block3 = TestShareBlockBuilder::new().build();

        // Create some test block hashes
        let block_hash1: BlockHash = block1.block_hash();
        let block_hash2: BlockHash = block2.block_hash();
        let block_hash3: BlockHash = block3.block_hash();

        let locator = vec![block_hash1, block_hash2, block_hash3];
        let missing_blocks = vec![block_hash1, block_hash3]; // Assume we're missing blocks 1 and 3

        // Mock the store.get_missing_blockhashes call
        chain_store_handle
            .expect_get_missing_blockhashes()
            .with(eq(locator.clone()))
            .returning(move |_| missing_blocks.clone());

        // Create channels for swarm communication
        let (swarm_tx, mut swarm_rx) = mpsc::channel(10);
        let response_channel = "test_peer_id".to_string(); // Using String as the channel type for simplicity

        // Execute
        let inventory = vec![InventoryMessage::BlockHashes(locator)];
        let result = handle_inventory(
            inventory,
            chain_store_handle,
            swarm_tx,
            response_channel.clone(),
        )
        .await;

        // Verify
        assert!(result.is_ok(), "handle_inventory should return Ok");

        // Verify that GetData messages were sent for each missing block
        let message1 = swarm_rx.recv().await.unwrap();
        match message1 {
            SwarmSend::Response(channel, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(channel, response_channel);
                assert_eq!(hash, block_hash1);
            }
            _ => panic!("Expected GetData::Block message for block_hash1"),
        }

        let message2 = swarm_rx.recv().await.unwrap();
        match message2 {
            SwarmSend::Response(channel, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(channel, response_channel);
                assert_eq!(hash, block_hash3);
            }
            _ => panic!("Expected GetData::Block message for block_hash3"),
        }

        // Verify no more messages were sent
        assert!(
            swarm_rx.try_recv().is_err(),
            "No more messages should have been sent"
        );
    }
}
