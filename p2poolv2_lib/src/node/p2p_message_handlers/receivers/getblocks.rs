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
use bitcoin::BlockHash;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

const MAX_BLOCKS: usize = 500;

/// Handle a GetBlocks request from a peer
/// - use the locator to find the blockhashes to respond with
/// - limit the number of blocks to MAX_BLOCKS
/// - generate an inventory message to send blockhashes
pub async fn handle_getblocks<C: 'static + Send + Sync>(
    locator: Vec<BlockHash>,
    stop_block_hash: BlockHash,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Received getblocks: {:?}", locator);
    let response_block_hashes =
        chain_store_handle.get_blockhashes_for_locator(&locator, &stop_block_hash, MAX_BLOCKS)?;
    let inventory_message =
        Message::Inventory(InventoryMessage::BlockHashes(response_block_hashes));
    swarm_tx
        .send(SwarmSend::Response(response_channel, inventory_message))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;

    #[tokio::test]
    async fn test_handle_getblocks() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(1);
        let response_channel = 1u32;

        // Mock response headers
        let block1 = TestShareBlockBuilder::new().build();

        let block2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000000000000000000000000000000000000000000000000000000000001".into(),
            )
            .build();

        let block_hashes = vec![block1.block_hash()];
        let stop_block_hash = block2.block_hash();

        let response_block_hashes = vec![block1.block_hash(), block2.block_hash()];

        // Set up mock expectations
        chain_store_handle
            .expect_get_blockhashes_for_locator()
            .returning(move |_, _, _| Ok(response_block_hashes.clone()));

        // Call the handler
        handle_getblocks(
            block_hashes,
            stop_block_hash,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await
        .unwrap();

        // Verify swarm message
        if let Some(SwarmSend::Response(
            channel,
            Message::Inventory(InventoryMessage::BlockHashes(hashes)),
        )) = swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(hashes.len(), 2);
            assert_eq!(hashes[0], block1.block_hash());
            assert_eq!(hashes[1], block2.block_hash());
        } else {
            panic!("Expected SwarmSend::Response with Inventory message");
        }
    }
}
