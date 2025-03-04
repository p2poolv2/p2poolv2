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
pub async fn handle_getblocks(
    block_hashes: Vec<bitcoin::BlockHash>,
    stop_block_hash: bitcoin::BlockHash,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend>,
) -> Result<(), Box<dyn Error>> {
    info!("Received getblocks: {:?}", block_hashes);
    // start from the chain tip, skip uncles tips
    let mut block_hashes = Vec::with_capacity(MAX_BLOCKS);

    let mut current_hash = chain_handle.get_chain_tip().await.unwrap();
    while block_hashes.len() < MAX_BLOCKS && current_hash != stop_block_hash {
        block_hashes.push(current_hash);
        let previous_block = chain_handle.get_share(current_hash).await.unwrap();
        current_hash = previous_block.header.prev_share_blockhash.unwrap();
    }
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(
        block_hashes.into_iter().collect(),
    ));
    swarm_tx.send(SwarmSend::Gossip(inventory_message)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_utils::TestBlockBuilder;

    use super::*;
    use bitcoin::BlockHash;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_handle_getblocks() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        // Create 5 block hashes
        let block_hashes: Vec<BlockHash> = vec![
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", // stop block
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
        ]
        .into_iter()
        .map(|h| BlockHash::from_str(h).unwrap())
        .collect();

        let stop_block = block_hashes[2];

        // Mock chain_handle.get_chain_tip() to return first block
        let tip = block_hashes[0];
        chain_handle
            .expect_get_chain_tip()
            .times(1)
            .returning(move || Some(tip));

        // Mock chain_handle.get_share() to return blocks in sequence
        chain_handle
            .expect_get_share()
            .times(2)
            .returning(move |hash| {
                let mut prev_hash = None;
                for i in 0..block_hashes.len() - 1 {
                    if hash == block_hashes[i] {
                        prev_hash = Some(block_hashes[i + 1]);
                        break;
                    }
                }
                let block = TestBlockBuilder::new()
                    .prev_share_blockhash(prev_hash.unwrap().to_string().as_str())
                    .blockhash(hash.to_string().as_str())
                    .build();
                Some(block)
            });

        // Call handle_getblocks
        let result = handle_getblocks(vec![], stop_block, chain_handle, swarm_tx).await;
        assert!(result.is_ok());

        // Verify the inventory message contains expected blocks
        if let Some(SwarmSend::Gossip(Message::Inventory(InventoryMessage::BlockHashes(
            sent_hashes,
        )))) = swarm_rx.try_recv().ok()
        {
            assert_eq!(sent_hashes.len(), 2);
            assert!(sent_hashes.contains(
                &"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                    .parse::<BlockHash>()
                    .unwrap()
            ));
            assert!(sent_hashes.contains(
                &"00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
                    .parse::<BlockHash>()
                    .unwrap()
            ));
            assert!(!sent_hashes.contains(
                &"000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
                    .parse::<BlockHash>()
                    .unwrap()
            ));
        } else {
            panic!("Expected inventory message");
        }
    }
}
