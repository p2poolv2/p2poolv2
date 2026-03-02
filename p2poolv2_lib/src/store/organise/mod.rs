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

use super::{ColumnFamily, Store, writer::StoreError};
use bitcoin::{BlockHash, Work, consensus::encode};
use std::collections::VecDeque;

mod candidate;
mod confirmed;
pub mod organise_block;
pub mod organise_header;

const BRANCH_INITIAL_CAPACITY: usize = 16;

/// Type to capture candidate and confirmed chains as vector of
/// height, blockhash pairs
type Chain = Vec<(u32, BlockHash)>;

/// Height type to avoid using u32
type Height = u32;

/// Top of a candidate or confirmed chain: blockhash, height, and cumulative work.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TopResult {
    pub hash: BlockHash,
    pub height: Height,
    pub work: Work,
}

/// Returns key for height with provided suffix
pub(super) fn height_to_key_with_suffix(height: Height, suffix: &str) -> Vec<u8> {
    [&height.to_be_bytes(), suffix.as_bytes()].concat()
}

impl Store {
    /// Fetch blockhashes from the BlockHeight CF for a given height range
    /// and key suffix. Filters iterator results to only include keys whose
    /// suffix matches, avoiding cross-contamination between candidate (":c")
    /// and confirmed (":f") entries that share the same height prefix.
    pub(super) fn get_chain_range(
        &self,
        from: Height,
        to: Height,
        suffix: &str,
    ) -> Result<Chain, StoreError> {
        if from > to {
            return Ok(Vec::new());
        }

        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let suffix_bytes = suffix.as_bytes();

        let lower_key = height_to_key_with_suffix(from, suffix);
        // Upper bound is exclusive, so use to+1
        let upper_key = height_to_key_with_suffix(to + 1, suffix);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower_key.clone());
        read_opts.set_iterate_upper_bound(upper_key);

        let iter = self.db.iterator_cf_opt(
            &block_height_cf,
            read_opts,
            rocksdb::IteratorMode::From(&lower_key, rocksdb::Direction::Forward),
        );

        let capacity = (to - from + 1) as usize;
        let mut results = Vec::with_capacity(capacity);
        for item in iter.flatten() {
            let (key, value) = item;
            if key.ends_with(suffix_bytes) {
                let height_bytes: [u8; 4] = key[..4]
                    .try_into()
                    .map_err(|_| StoreError::Database("Invalid height key length".into()))?;
                let height = u32::from_be_bytes(height_bytes);
                let blockhash = encode::deserialize(&value)?;
                results.push((height, blockhash));
            }
        }
        Ok(results)
    }

    /// Get branch from a blockhash back to the first ancestor on a target chain.
    ///
    /// Walks backwards through the chain collecting blockhashes until finding
    /// one where `is_on_chain` returns true. Returns the branch including
    /// that ancestor. The predicate allows reuse for both candidate and
    /// confirmed chains.
    pub fn get_branch_to_chain(
        &self,
        blockhash: &BlockHash,
        is_on_chain: impl Fn(&BlockHash) -> bool,
    ) -> Result<Option<VecDeque<BlockHash>>, StoreError> {
        let mut branch = VecDeque::with_capacity(BRANCH_INITIAL_CAPACITY);

        let mut current = *blockhash;
        loop {
            if is_on_chain(&current) {
                // Found ancestor on target chain, include it and return
                branch.push_front(current);
                return Ok(Some(branch));
            }

            // Get the share to find its parent
            let Some(share_header) = self.get_share_header(&current)? else {
                // Share not found, branch doesn't terminate on target chain
                return Ok(None);
            };

            branch.push_front(current);
            current = share_header.prev_share_blockhash;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    // ── get_branch_to_chain tests ─────────────────────────────────────────

    #[test]
    fn test_get_branch_to_chain_returns_single_entry_when_already_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share and make it a candidate
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share).unwrap();

        // Branch should contain just the share since it is already a candidate
        let branch = store
            .get_branch_to_chain(&share.block_hash(), |h| store.is_candidate(h))
            .unwrap();
        assert!(branch.is_some());
        assert_eq!(branch, Some(VecDeque::from([share.block_hash()])));
    }

    #[test]
    fn test_get_branch_to_chain_returns_branch_to_candidate_ancestor() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup: genesis -> share1 (candidate) -> share2 -> share3
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1 is a candidate at height 1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2 extends share1 but is NOT on candidate chain
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share3 extends share2 and is NOT on candidate chain
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share3, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Branch from share3 should be [share1, share2, share3]
        let branch = store
            .get_branch_to_chain(&share3.block_hash(), |h| store.is_candidate(h))
            .unwrap()
            .unwrap();
        assert_eq!(branch.len(), 3);
        assert_eq!(branch[0], share1.block_hash());
        assert_eq!(branch[1], share2.block_hash());
        assert_eq!(branch[2], share3.block_hash());
    }

    #[test]
    fn test_get_branch_to_chain_returns_single_share_branch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup: genesis -> share1 (candidate) -> share2 (not on candidate chain)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Branch from share2 should be just [share1, share2]
        let branch = store
            .get_branch_to_chain(&share2.block_hash(), |h| store.is_candidate(h))
            .unwrap()
            .unwrap();
        assert_eq!(branch.len(), 2);
        assert_eq!(branch[0], share1.block_hash());
        assert_eq!(branch[1], share2.block_hash());
    }
}
