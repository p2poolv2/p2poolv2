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

use crate::node::SwarmSend;
use crate::node::{InventoryMessage, Message};
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

const MAX_BLOCKS: usize = 500;

/// Handle a GetBlocks request from a peer
/// - start from chain tip, find blockhashes up to the stop block hash
/// - limit the number of blocks to MAX_BLOCKS
/// - generate an inventory message to send blockhashes
pub async fn handle_getblocks<C: 'static>(
    block_hashes: Vec<bitcoin::BlockHash>,
    stop_block_hash: bitcoin::BlockHash,
    chain_handle: ChainHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error>> {
    info!("Received getblocks: {:?}", block_hashes);
    let response_block_hashes = chain_handle
        .get_headers_for_locator(block_hashes, stop_block_hash, MAX_BLOCKS)
        .await;
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(
        response_block_hashes
            .into_iter()
            .map(|h| h.miner_share.hash)
            .collect(),
    ));
    swarm_tx
        .send(SwarmSend::Response(response_channel, inventory_message))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_utils::TestBlockBuilder;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_handle_getblocks() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(1);
        let response_channel = 1u32;

        let block_hashes = vec![bitcoin::BlockHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap()];
        let stop_block_hash = bitcoin::BlockHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();

        // Mock response headers
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
            .prev_share_blockhash(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .build();

        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        // Set up mock expectations
        chain_handle
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| response_headers.clone());

        // Call the handler
        handle_getblocks(
            block_hashes,
            stop_block_hash,
            chain_handle,
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
            assert_eq!(hashes[0], block1.header.miner_share.hash);
            assert_eq!(hashes[1], block2.header.miner_share.hash);
        } else {
            panic!("Expected SwarmSend::Response with Inventory message");
        }
    }
}
