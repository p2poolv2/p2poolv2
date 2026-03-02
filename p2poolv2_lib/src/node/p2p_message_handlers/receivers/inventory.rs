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

use crate::node::SwarmSend;
use crate::node::messages::{GetData, InventoryMessage, Message};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Handle an Inventory message received from a peer.
///
/// Inventory is sent unsolicited when a node becomes aware of a
/// block, or in response to a getblocks message.  For BlockHashes, we
/// check which blocks we are missing and send GetData requests back
/// to the originating peer for each missing block.
///
/// The inventory supports list of blockhashes and transactions. Even
/// though for now we only ever send a vector with a single blockhash.
pub async fn handle_inventory<C: Send + Sync>(
    inventory: InventoryMessage,
    peer: libp2p::PeerId,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received inventory update: {:?}", inventory);

    match inventory {
        InventoryMessage::BlockHashes(blockhashes) => {
            debug!("Received block hashes locator: {:?}", blockhashes);

            let missing_blocks = chain_store_handle.get_missing_blockhashes(&blockhashes);

            if !missing_blocks.is_empty() {
                debug!(
                    "Requesting {} missing blocks from peer {}",
                    missing_blocks.len(),
                    peer
                );
                for block_hash in missing_blocks {
                    let get_block_request = Message::GetData(GetData::Block(block_hash));
                    swarm_tx
                        .send(SwarmSend::Request(peer, get_block_request))
                        .await
                        .map_err(|send_error| {
                            format!(
                                "Failed to send GetData request for block {block_hash}: {send_error}"
                            )
                        })?;
                }
            }
        }
        InventoryMessage::TransactionHashes(transaction_hashes) => {
            debug!(
                "Received transaction hashes inventory: {:?}",
                transaction_hashes
            );
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
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();
        let block3 = TestShareBlockBuilder::new().build();

        let block_hash1: BlockHash = block1.block_hash();
        let block_hash2: BlockHash = block2.block_hash();
        let block_hash3: BlockHash = block3.block_hash();

        let blockhashes = vec![block_hash1, block_hash2, block_hash3];
        let missing_blocks = vec![block_hash1, block_hash3];

        chain_store_handle
            .expect_get_missing_blockhashes()
            .with(eq(blockhashes.clone()))
            .returning(move |_| missing_blocks.clone());

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let inventory = InventoryMessage::BlockHashes(blockhashes);
        let result = handle_inventory(inventory, peer_id, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok(), "handle_inventory should return Ok");

        let message1 = swarm_rx.recv().await.unwrap();
        match message1 {
            SwarmSend::Request(sent_peer, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(hash, block_hash1);
            }
            _ => panic!("Expected SwarmSend::Request with GetData::Block for block_hash1"),
        }

        let message2 = swarm_rx.recv().await.unwrap();
        match message2 {
            SwarmSend::Request(sent_peer, Message::GetData(GetData::Block(hash))) => {
                assert_eq!(sent_peer, peer_id);
                assert_eq!(hash, block_hash3);
            }
            _ => panic!("Expected SwarmSend::Request with GetData::Block for block_hash3"),
        }

        assert!(
            swarm_rx.try_recv().is_err(),
            "No more messages should have been sent"
        );
    }

    #[tokio::test]
    async fn test_handle_inventory_no_missing_blocks() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let block1 = TestShareBlockBuilder::new().build();
        let block_hash1: BlockHash = block1.block_hash();

        chain_store_handle
            .expect_get_missing_blockhashes()
            .returning(|_| Vec::with_capacity(0));

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let inventory = InventoryMessage::BlockHashes(vec![block_hash1]);
        let result = handle_inventory(inventory, peer_id, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok());
        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent when no blocks are missing"
        );
    }

    #[tokio::test]
    async fn test_handle_inventory_transaction_hashes() {
        let chain_store_handle = ChainStoreHandle::default();
        let peer_id = libp2p::PeerId::random();

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);

        let tx_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
        ];
        let inventory =
            InventoryMessage::TransactionHashes(crate::shares::share_block::Txids(tx_hashes));
        let result = handle_inventory(inventory, peer_id, chain_store_handle, swarm_tx).await;

        assert!(result.is_ok());
        assert!(
            swarm_rx.try_recv().is_err(),
            "No messages should be sent for transaction inventory"
        );
    }
}
