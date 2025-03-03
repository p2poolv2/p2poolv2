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

/// Find the first block hash from a vector of block hashes that exists in our store
/// Returns None if none of the block hashes exist in our store
async fn find_first_known_block(
    block_hashes: Vec<bitcoin::BlockHash>,
    chain_handle: &ChainHandle,
) -> Option<bitcoin::BlockHash> {
    for hash in block_hashes {
        if chain_handle.get_share(hash).await.is_some() {
            return Some(hash);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestBlockBuilder;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_find_first_known_block() {
        let mut chain_handle = ChainHandle::default();

        let hash1 = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<bitcoin::BlockHash>()
            .unwrap();
        let hash2 = "0000000000000000000000000000000000000000000000000000000000000002"
            .parse::<bitcoin::BlockHash>()
            .unwrap();
        let hash3 = "0000000000000000000000000000000000000000000000000000000000000003"
            .parse::<bitcoin::BlockHash>()
            .unwrap();

        // Set up expectations
        chain_handle
            .expect_get_share()
            .with(eq(hash1))
            .times(1)
            .return_const(None);

        chain_handle
            .expect_get_share()
            .with(eq(hash2))
            .times(1)
            .return_const(
                TestBlockBuilder::new()
                    .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
                    .build(),
            );

        // hash3 should not be called since we found hash2

        let block_hashes = vec![hash1, hash2, hash3];
        let result = find_first_known_block(block_hashes, &chain_handle).await;

        assert_eq!(result, Some(hash2));
    }

    #[tokio::test]
    async fn test_find_first_known_block_none_found() {
        let mut chain_handle = ChainHandle::default();

        let hash1 = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<bitcoin::BlockHash>()
            .unwrap();
        let hash2 = "0000000000000000000000000000000000000000000000000000000000000002"
            .parse::<bitcoin::BlockHash>()
            .unwrap();

        // Set up expectations - no blocks found
        chain_handle
            .expect_get_share()
            .with(eq(hash1))
            .times(1)
            .return_const(None);

        chain_handle
            .expect_get_share()
            .with(eq(hash2))
            .times(1)
            .return_const(None);

        let block_hashes = vec![hash1, hash2];
        let result = find_first_known_block(block_hashes, &chain_handle).await;

        assert_eq!(result, None);
    }
}
