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

#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use std::error::Error;

const MAX_BLOCKS: usize = 500;

/// Get block hashes from the chain tip up to the stop block hash
/// Limit the number of blocks to MAX_BLOCKS
/// Used by handle_getblocks and handle_getheaders to get block hashes from the chain tip up to the stop block hash
pub async fn get_block_hashes_from_chain_tip(
    chain_handle: ChainHandle,
    stop_block_hash: bitcoin::BlockHash,
) -> Result<Vec<bitcoin::BlockHash>, Box<dyn Error>> {
    let mut block_hashes = Vec::with_capacity(MAX_BLOCKS);
    if let Some(tip) = chain_handle.get_chain_tip().await {
        let mut current_hash = tip;
        while block_hashes.len() < MAX_BLOCKS && current_hash != stop_block_hash {
            block_hashes.push(current_hash);
            let previous_block = chain_handle.get_share(current_hash).await.unwrap();
            if let Some(prev_hash) = previous_block.header.prev_share_blockhash {
                current_hash = prev_hash;
            } else {
                break;
            }
        }
    }
    Ok(block_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[mockall_double::double]
    use crate::shares::chain::actor::ChainHandle;
    use crate::test_utils::TestBlockBuilder;
    use bitcoin::BlockHash;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_get_block_hashes_from_chain_tip_should_find_matching_blocks() {
        let mut chain_handle = ChainHandle::default();

        // Create 5 block hashes
        let block_hashes: Vec<BlockHash> = vec![
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", // stop block
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485", // tip
        ]
        .into_iter()
        .map(|h| BlockHash::from_str(h).unwrap())
        .collect();

        let stop_block = block_hashes[2];

        // Mock chain_handle.get_chain_tip() to return first block
        let tip = block_hashes[4];
        chain_handle
            .expect_get_chain_tip()
            .times(1)
            .returning(move || Some(tip));

        let mut blocks = Vec::new();

        // We don't need to mock the first three blocks because they are past the stop block (inclusive)
        for i in 3..5 {
            let hash = block_hashes[i];

            let mut builder = TestBlockBuilder::new().blockhash(hash.to_string().as_str());
            if i > 0 {
                builder = builder.prev_share_blockhash(block_hashes[i - 1].to_string().as_str());
            }
            let block = builder.build();

            blocks.push(block.clone());
            chain_handle
                .expect_get_share()
                .with(mockall::predicate::eq(hash))
                .times(1)
                .returning(move |_| Some(block.clone()));
        }

        // Call handle_getblocks
        let result = get_block_hashes_from_chain_tip(chain_handle, stop_block).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(
            &"000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485"
                .parse::<BlockHash>()
                .unwrap()
        ));
        assert!(result.contains(
            &"0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449"
                .parse::<BlockHash>()
                .unwrap()
        ));
    }

    #[test_log::test(tokio::test)]
    async fn test_get_block_hashes_from_chain_tip_stop_block_not_found() {
        let mut chain_handle = ChainHandle::default();

        // Create 5 block hashes that will be in our chain
        let block_hashes: Vec<BlockHash> = vec![
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485", // tip
        ]
        .into_iter()
        .map(|h| BlockHash::from_str(h).unwrap())
        .collect();

        let mut blocks = Vec::new();

        for i in 0..5 {
            let hash = block_hashes[i];

            let mut builder = TestBlockBuilder::new().blockhash(hash.to_string().as_str());
            if i > 0 {
                builder = builder.prev_share_blockhash(block_hashes[i - 1].to_string().as_str());
            }
            let block = builder.build();

            blocks.push(block.clone());
            chain_handle
                .expect_get_share()
                .with(mockall::predicate::eq(hash))
                .times(1)
                .returning(move |_| Some(block.clone()));
        }

        let tip = block_hashes[4];
        chain_handle
            .expect_get_chain_tip()
            .times(1)
            .returning(move || Some(tip));

        // Use a stop block hash that doesn't exist in our chain
        let non_existent_stop_block =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse::<BlockHash>()
                .unwrap();

        // Call get_block_hashes_from_chain_tip with non-existent stop block
        let result = get_block_hashes_from_chain_tip(chain_handle, non_existent_stop_block).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 5);
        for i in 0..4 {
            assert!(result.contains(&block_hashes[i]));
        }
    }
}
