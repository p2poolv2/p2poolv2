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

use super::{ColumnFamily, Store};
use crate::shares::chain::chain_store::COMMON_ANCESTOR_DEPTH;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::shares::validation::MAX_UNCLES;
use bitcoin::BlockHash;
use bitcoin::consensus::{self, Encodable, encode};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use tracing::debug;

/// Max depth to look for uncles when building new share blocks
const MAX_UNCLES_DEPTH: u8 = 3;

impl Store {
    /// Iterate over the store from provided start blockhash
    ///
    /// Returns all shares along all branches from the genesis into
    /// chain and all the shares without children as tips
    pub fn load_chain(
        &self,
        genesis: BlockHash,
    ) -> Result<(Vec<BlockHash>, HashSet<BlockHash>), Box<dyn Error + Send + Sync>> {
        let mut chain = vec![genesis];
        let mut tips = HashSet::new();
        let mut to_visit = VecDeque::new();
        to_visit.push_back(genesis);

        while !to_visit.is_empty() {
            if let Some(current) = to_visit.pop_front() {
                match self.get_children_blockhashes(&current)? {
                    Some(children) => {
                        for child in children.iter() {
                            if !to_visit.contains(child) {
                                to_visit.push_back(*child);
                            }
                            if !chain.contains(child) {
                                chain.push(*child);
                            }
                        }
                    }
                    None => {
                        tips.insert(current);
                    }
                }
            }
        }
        Ok((chain, tips))
    }

    /// Update the block index so that we can easily find all the children of a block
    /// We store the next blockhashes for a block in a separate column family
    /// Uses merge operator for atomic append without read-modify-write
    pub(crate) fn update_block_index(
        &self,
        prev_blockhash: &BlockHash,
        next_blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!(
            "Updating block index {} to {}",
            prev_blockhash, next_blockhash
        );

        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut prev_blockhash_bytes = consensus::serialize(prev_blockhash);
        prev_blockhash_bytes.extend_from_slice(b"_bi");

        // Serialize the single BlockHash to merge
        let mut serialized = Vec::new();
        next_blockhash.consensus_encode(&mut serialized)?;

        // Use merge operator to atomically append
        batch.merge_cf(&block_index_cf, prev_blockhash_bytes, serialized);

        debug!(
            "Block index from parent to child: {} -> {}",
            prev_blockhash, next_blockhash
        );
        Ok(())
    }

    /// Load children BlockHashes for a blockhash from the block index
    /// These are tracked in a separate index in rocksdb as relations from
    /// blockhash -> next blockhashes
    pub fn get_children_blockhashes(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<Vec<BlockHash>>, Box<dyn Error + Send + Sync>> {
        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut blockhash_bytes = consensus::serialize(blockhash);
        blockhash_bytes.extend_from_slice(b"_bi");

        match self
            .db
            .get_cf::<&[u8]>(&block_index_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(existing)) => {
                if let Ok(existing_blockhashes) = encode::deserialize::<Vec<BlockHash>>(&existing) {
                    Ok(Some(existing_blockhashes))
                } else {
                    tracing::warn!("Failed to deseriliaze child blockhash");
                    Err("Failed to deseriliaze child blockhash".into())
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                tracing::error!("Error querying existing children shares");
                Err(e.into())
            }
        }
    }

    /// Get blockhashes to satisfy the locator query.
    /// Returns a list of blockhashes from the earliest block from the block hashes
    /// We assume the list of blocks in the locator is ordered by height, so we stop when we find the first block in the locator
    /// Find blockhashes up to the stop blockhash, or the limit provided
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[BlockHash],
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let start_blockhash = self.get_first_existing_blockhash(locator);
        // If no blockhash found, return vector with genesis block
        let start_blockhash = match start_blockhash {
            Some(hash) => hash,
            None => return Ok(vec![self.get_genesis_blockhash()]),
        };

        self.get_descendant_blockhashes(&start_blockhash, stop_blockhash, limit)
    }

    /// Get headers to satisy the locator query.
    pub fn get_headers_for_locator(
        &self,
        locator: &[BlockHash],
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<ShareHeader>, Box<dyn Error + Send + Sync>> {
        let blockhashes = self.get_blockhashes_for_locator(locator, stop_blockhash, limit)?;
        self.get_share_headers(&blockhashes)
    }

    /// Get descendants headers of a share
    /// We stop looking after we have found limit number of descendants or have hit stop blockhash
    pub fn get_descendants(
        &self,
        share: BlockHash,
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<ShareHeader>, Box<dyn Error + Send + Sync>> {
        let mut descendants = Vec::with_capacity(limit);

        let mut next_children = vec![];
        let mut current_blockhash = share;
        while descendants.len() < limit && current_blockhash != *stop_blockhash {
            if let Ok(Some(children)) = self.get_children_blockhashes(&current_blockhash) {
                for child in children {
                    if descendants.len() < limit {
                        descendants.push(child);
                        next_children.push(child);
                    }
                }
            }
            current_blockhash = match next_children.pop() {
                Some(hash) => hash,
                None => break,
            };
        }
        self.get_share_headers(&descendants)
    }

    /// Get the parent of a share as a ShareBlock
    pub fn get_parent(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        let share = self.get_share(blockhash)?;
        let parent_blockhash = share.header.prev_share_blockhash;
        self.get_share(&parent_blockhash)
    }

    /// Get the uncles of a share as pointed to by the ShareHeader
    /// Returns an error if an uncle hash is not found in the store
    ///
    /// This is not used to find uncles from the chain that should be
    /// included in the ShareHeader. For that look at
    /// ChainStore::find_uncles
    pub fn get_uncles(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<ShareBlock>, Box<dyn Error + Send + Sync>> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return Ok(vec![]);
        }
        let share = share.unwrap();
        let uncle_blocks = self.get_shares(&share.header.uncles)?;
        Ok(uncle_blocks.into_values().collect())
    }

    /// Get the main chain and the uncles from the tips to the provided blockhash
    /// All shares are collected in a single vector
    /// Returns an error if blockhash is not found
    pub fn get_shares_from_tip_to_blockhash(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<ShareBlock>, Box<dyn Error + Send + Sync>> {
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        if !self
            .db
            .key_may_exist_cf::<&[u8]>(&share_cf, blockhash.as_ref())
        {
            return Err(format!("Blockhash {blockhash} not found in chain").into());
        };

        let tips = self.get_tips();
        let mut all_shares = Vec::new();
        let mut visited = HashSet::new();
        let mut to_visit: VecDeque<BlockHash> = tips.into_iter().collect();

        while let Some(hash) = to_visit.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            if let Some(share) = self.get_share(&hash) {
                visited.insert(hash);
                all_shares.push(share.clone());

                if hash != *blockhash {
                    to_visit.push_back(share.header.prev_share_blockhash);
                    // Also traverse uncles
                    for uncle_hash in share.header.uncles.iter() {
                        to_visit.push_back(*uncle_hash);
                    }
                }
            }
        }

        Ok(all_shares)
    }

    /// Find the shares from the given share up to depth from that share
    ///
    /// Returns a chain of blockhashes starting from start and going
    /// backward up to depth main chain ancestors (newest to oldest).
    /// Includes all uncles referenced by those main chain blocks.
    /// Uncles do not count toward the depth limit.
    pub(crate) fn get_dag_for_depth(
        &self,
        start: &BlockHash,
        depth: usize,
    ) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let mut to_visit: VecDeque<(BlockHash, bool)> = VecDeque::with_capacity(depth);
        to_visit.push_back((*start, true)); // (blockhash, is_main_chain)

        let mut results = Vec::with_capacity(depth);
        let mut visited = HashSet::new();
        let mut remaining_depth = depth;

        // Walk backward through parents and uncles
        while let Some((next, is_main_chain)) = to_visit.pop_front() {
            // Skip already visited blocks to avoid duplicates
            if visited.contains(&next) {
                continue;
            }

            // Get the share to find its parent
            let Ok(Some(next_share_header)) = self.get_share_header(&next) else {
                // Can't find share, stop here
                break;
            };

            visited.insert(next);
            results.push(next_share_header.block_hash());

            if is_main_chain {
                remaining_depth -= 1;

                // Only continue main chain if depth not exhausted
                if remaining_depth > 0 {
                    to_visit.push_back((next_share_header.prev_share_blockhash, true));
                }

                // Always include uncles of main chain blocks we've processed
                for uncle in next_share_header.uncles.iter() {
                    to_visit.push_back((*uncle, false));
                }
            }
        }

        Ok(results)
    }

    /// Get common ancestor of two blockhashes
    /// We first find chain from each blockhashes provided and then find the common ancestor
    ///
    /// If one of the blockhashes is an ancestor of the other, it is
    /// returned as the common ancestor
    pub fn get_common_ancestor(
        &self,
        blockhash1: &BlockHash,
        blockhash2: &BlockHash,
    ) -> Result<Option<BlockHash>, Box<dyn Error + Send + Sync>> {
        debug!("Looking for common ancestor between {blockhash1} and {blockhash2}");
        // Get chains up to COMMON_ANCESTOR_DEPTH (ordered from newest to oldest)
        let chain1 = self.get_dag_for_depth(blockhash1, COMMON_ANCESTOR_DEPTH)?;
        let chain2 = self.get_dag_for_depth(blockhash2, COMMON_ANCESTOR_DEPTH)?;

        // Build a set from chain1 for O(1) lookup
        let chain1_set: HashSet<BlockHash> = chain1.into_iter().collect();

        // Find first common blockhash by iterating chain2
        // chain2 is ordered from newest to oldest, so first match is the most recent common ancestor
        for blockhash in chain2 {
            if chain1_set.contains(&blockhash) {
                return Ok(Some(blockhash));
            }
        }

        Ok(None)
    }

    /// Add a blockhash to the uncles index, marking it as used as an uncle
    /// by the given nephew blockhash.
    ///
    /// Uses merge operator to support multiple nephews including the same uncle.
    pub(crate) fn add_to_uncles_index(
        &self,
        uncle: &BlockHash,
        nephew: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let uncles_cf = self.db.cf_handle(&ColumnFamily::Uncles).unwrap();
        let mut serialized_nephew = Vec::new();
        nephew.consensus_encode(&mut serialized_nephew)?;
        batch.merge_cf(&uncles_cf, AsRef::<[u8]>::as_ref(uncle), serialized_nephew);
        Ok(())
    }

    /// Check if a blockhash has been used as an uncle
    pub fn is_already_uncle(&self, blockhash: &BlockHash) -> bool {
        let uncles_cf = self.db.cf_handle(&ColumnFamily::Uncles).unwrap();
        matches!(
            self.db.get_cf::<&[u8]>(&uncles_cf, blockhash.as_ref()),
            Ok(Some(_))
        )
    }

    /// Get the nephews that have included a blockhash as an uncle
    pub fn get_nephews(&self, uncle: &BlockHash) -> Option<Vec<BlockHash>> {
        let uncles_cf = self.db.cf_handle(&ColumnFamily::Uncles).unwrap();
        match self.db.get_cf::<&[u8]>(&uncles_cf, uncle.as_ref()) {
            Ok(Some(bytes)) => encode::deserialize(&bytes).ok(),
            Ok(None) | Err(_) => None,
        }
    }

    /// Find uncles up to max depth and return a vector of all found
    /// uncle BlockHashes.
    ///
    /// Find ancestors up to max uncle depth on the confirmed chain,
    /// not counting the parent. Find all children of these ancestors
    /// that are not on the confirmed chain and that are not already
    /// included as uncles in other blocks.
    pub fn find_uncles(&self) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let Some(top_confirmed_height) = self.get_top_confirmed_height() else {
            return Err("No top confirmation found".into());
        };

        // get all ancestors up to required depth on the confirmed index
        let ancestors = (top_confirmed_height.saturating_sub(MAX_UNCLES_DEPTH as u32)
            ..top_confirmed_height)
            .filter_map(|height| self.get_confirmed_at_height(height));

        // get all children for the ancestors, will give us all uncles and confirmed blocks
        let children = ancestors
            .filter_map(|blockhash| self.get_children_blockhashes(&blockhash).ok())
            .flatten()
            .flatten();

        // Only keep the non-confirmed blocks that are not used as uncles already
        // Collect with height for sorting
        let mut uncles_with_height: Vec<(BlockHash, u32)> = children
            .filter_map(|blockhash| {
                if !self.is_confirmed(&blockhash) && !self.is_already_uncle(&blockhash) {
                    // Get height from metadata for sorting
                    self.get_block_metadata(&blockhash)
                        .ok()
                        .and_then(|m| m.expected_height)
                        .map(|height| Some((blockhash, height)))
                } else {
                    None
                }
            })
            .flatten()
            .collect();

        // Sort by height descending and take top 3
        uncles_with_height.sort_by(|a, b| b.1.cmp(&a.1));
        let uncles = uncles_with_height
            .into_iter()
            .take(MAX_UNCLES)
            .map(|(hash, _)| hash)
            .collect();

        Ok(uncles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test]
    fn test_get_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
            .build();

        // Create share3
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        // Add all shares to store
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle1_share2,
                1,
                share1.header.get_work() + uncle1_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle2_share2,
                1,
                share1.header.get_work() + uncle2_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();

        store.commit_batch(batch).unwrap();

        // Verify children of share1
        let children_share1 = store
            .get_children_blockhashes(&share1.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.block_hash()));
        assert!(children_share1.contains(&uncle1_share2.block_hash()));
        assert!(children_share1.contains(&uncle2_share2.block_hash()));

        // Verify children of share2
        let children_share2 = store
            .get_children_blockhashes(&share2.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(children_share2.len(), 1);
        assert!(children_share2.contains(&share3.block_hash()));

        // Verify children of share3
        let children_share3 = store
            .get_children_blockhashes(&share3.block_hash())
            .unwrap();
        assert!(children_share3.is_none());

        // Verify children of uncle1_share2
        let children_uncle1_share2 = store
            .get_children_blockhashes(&uncle1_share2.block_hash())
            .unwrap()
            .unwrap();
        assert!(children_uncle1_share2.contains(&share2.block_hash()));

        // Verify children of uncle2_share2
        let children_uncle2_share2 = store
            .get_children_blockhashes(&uncle2_share2.block_hash())
            .unwrap()
            .unwrap();
        assert!(children_uncle2_share2.contains(&share2.block_hash()));
    }

    #[test]
    fn test_get_descendants() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
            .build();

        // Create share3
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let genesis_work = share1.header.get_work();

        let mut batch = rocksdb::WriteBatch::default();
        // Add all shares to store
        store
            .add_share(&share1, 0, genesis_work, true, &mut batch)
            .unwrap();
        store
            .add_share(
                &uncle1_share2,
                1,
                genesis_work + uncle1_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle2_share2,
                1,
                genesis_work + uncle2_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                genesis_work + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share3,
                2,
                genesis_work + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();

        store.commit_batch(batch).unwrap();

        // Verify descendants of share1
        let descendants_share1 = store
            .get_descendants(share1.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_share1.len(), 4);
        assert!(descendants_share1.contains(&share2.header));
        assert!(descendants_share1.contains(&share3.header));
        assert!(descendants_share1.contains(&uncle1_share2.header));
        assert!(descendants_share1.contains(&uncle2_share2.header));

        // Verify descendants of share2
        let descendants_share2 = store
            .get_descendants(share2.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_share2.len(), 1);
        assert_eq!(descendants_share2[0], share3.header);

        // Verify no descendants for share3
        let descendants_share3 = store
            .get_descendants(share3.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert!(descendants_share3.is_empty());

        // Verify descendants with limit
        let descendants_with_limit = store
            .get_descendants(share1.block_hash(), &share3.block_hash(), 1)
            .unwrap();
        assert_eq!(descendants_with_limit.len(), 1);
        assert_eq!(descendants_with_limit[0], uncle1_share2.header);

        // Verify descendants with stop blockhash
        let descendants_with_limit = store
            .get_descendants(share1.block_hash(), &share2.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_with_limit.len(), 3);
        assert!(descendants_with_limit.contains(&share2.header));
        assert!(descendants_with_limit.contains(&uncle1_share2.header));
        assert!(descendants_with_limit.contains(&uncle2_share2.header));
    }

    #[test_log::test]
    fn test_get_headers_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let num_blockhashes = 5;
        let mut hashes: Vec<BlockHash> = vec![];
        let mut prev_blockhash = BlockHash::all_zeros();

        for height in 0..num_blockhashes {
            let mut batch = rocksdb::WriteBatch::default();
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            store
                .add_share(&block, height, block.header.get_work(), true, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();

            prev_blockhash = block.block_hash();
            hashes.push(prev_blockhash);
        }

        let stop_block = store.get_blockhashes_for_height(2)[0];
        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store
            .get_headers_for_locator(locator.as_slice(), &stop_block, 10)
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].block_hash(), hashes[1]);
        assert_eq!(result[1].block_hash(), hashes[2]);
    }

    #[test]
    fn test_get_headers_for_block_locator_stop_block_not_found() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut blocks = Vec::new();
        let mut locator = vec![];

        let num_blockhashes = 3;
        let mut hashes: Vec<BlockHash> = vec![];

        let mut prev_blockhash = BlockHash::all_zeros();

        for height in 0..num_blockhashes {
            let mut batch = rocksdb::WriteBatch::default();
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            blocks.push(block.clone());
            store
                .add_share(
                    &block,
                    height as u32,
                    block.header.get_work(),
                    true,
                    &mut batch,
                )
                .unwrap();
            prev_blockhash = block.block_hash();
            hashes.push(prev_blockhash);
            store.commit_batch(batch).unwrap();
        }

        locator.push(blocks[0].block_hash()); // locator = tip

        // Use a stop block hash that doesn't exist in our chain
        let non_existent_stop_block =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse::<BlockHash>()
                .unwrap();

        // Call get_headers_for_block_locator with non-existent stop block
        let result = store
            .get_headers_for_locator(&locator, &non_existent_stop_block, 10)
            .unwrap();
        assert_eq!(result.len(), 2);
        // start block not in response
        assert_eq!(result[0], blocks[1].header);
        assert_eq!(result[1], blocks[2].header);
    }

    #[test]
    fn test_get_blockhashes_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut block_hashes = Vec::new();

        let num_blockhashes = 5;

        let mut prev_blockhash = BlockHash::all_zeros();

        let mut batch = rocksdb::WriteBatch::default();

        for height in 0..num_blockhashes {
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            let blockhash = block.block_hash();
            block_hashes.push(blockhash);
            let work = block.header.get_work();
            store
                .add_share(&block, height as u32, work, true, &mut batch)
                .unwrap();
            prev_blockhash = blockhash;
        }

        store.commit_batch(batch).unwrap();

        let stop_block = store.get_blockhashes_for_height(2)[0];

        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store
            .get_blockhashes_for_locator(locator.as_slice(), &stop_block, 10)
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], block_hashes[1]);
        assert_eq!(result[1], block_hashes[2]);
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create linear chain: share1 -> share2 -> share3
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Set share3 as the tip
        store.add_tip(share3.block_hash());

        // Get chain from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all three shares
        assert_eq!(chain.len(), 3);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
    }

    #[test_log::test]
    fn test_get_shares_from_tip_to_blockhash_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1.block_hash(), uncle2.block_hash()])
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle2,
                1,
                share1.header.get_work() + uncle2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Set share2 as the tip
        store.add_tip(share2.block_hash());

        // Get chain from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain share2, share1, and both uncles
        assert_eq!(chain.len(), 4);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&uncle1.block_hash()));
        assert!(chain_hashes.contains(&uncle2.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_multiple_tips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a chain that splits into two tips
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();

        // Two competing tips at height 2
        let tip1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(100)
            .build();

        let tip2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(200)
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &tip1,
                2,
                share1.header.get_work() + share2.header.get_work() + tip1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &tip2,
                2,
                share1.header.get_work() + share2.header.get_work() + tip2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Set both as tips
        store.add_tip(tip1.block_hash());
        store.add_tip(tip2.block_hash());

        // Get chain from tips to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all shares from both tips down to share1
        assert_eq!(chain.len(), 4);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&tip1.block_hash()));
        assert!(chain_hashes.contains(&tip2.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = rocksdb::WriteBatch::default();

        let share1 = TestShareBlockBuilder::new().build();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.add_tip(share1.block_hash());

        // Try to get chain to a non-existent blockhash
        let nonexistent_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .parse::<BlockHash>()
            .unwrap();

        let result = store.get_shares_from_tip_to_blockhash(&nonexistent_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_stops_at_target() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create chain: share1 -> share2 -> share3 -> share4
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share4,
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        store.add_tip(share4.block_hash());

        // Get chain from tip to share2 (should stop at share2)
        let chain = store
            .get_shares_from_tip_to_blockhash(&share2.block_hash())
            .unwrap();

        // Should contain share4, share3, and share2, but not share1
        assert_eq!(chain.len(), 3);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
        assert!(chain_hashes.contains(&share4.block_hash()));
        assert!(!chain_hashes.contains(&share1.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_no_tips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = rocksdb::WriteBatch::default();

        let share1 = TestShareBlockBuilder::new().build();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Don't set any tips - should return empty vector
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_complex_uncle_tree() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a more complex tree with multiple levels of uncles
        let share1 = TestShareBlockBuilder::new().build();

        // Level 1 uncles
        let uncle1_1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle1_2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_1.block_hash(), uncle1_2.block_hash()])
            .build();

        // Level 2 uncles
        let uncle2_1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        // Share3 with uncle
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle2_1.block_hash()])
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle1_1,
                1,
                share1.header.get_work() + uncle1_1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle1_2,
                1,
                share1.header.get_work() + uncle1_2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &uncle2_1,
                2,
                share1.header.get_work() + share2.header.get_work() + uncle2_1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        store.add_tip(share3.block_hash());

        // Get all shares from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all 6 shares
        assert_eq!(chain.len(), 6);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
        assert!(chain_hashes.contains(&uncle1_1.block_hash()));
        assert!(chain_hashes.contains(&uncle1_2.block_hash()));
        assert!(chain_hashes.contains(&uncle2_1.block_hash()));
    }

    #[test]
    fn test_get_descendant_blockhashes_with_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create four shares: a -> b -> c and b -> d (fork at b)
        let share_a = TestShareBlockBuilder::new().build();
        let share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .build();
        let share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .nonce(100)
            .build();
        let share_d = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .nonce(200)
            .build();

        // Add share a
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share_a, 0, share_a.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share b
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share_b,
                1,
                share_a.header.get_work() + share_b.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share c
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share_c,
                2,
                share_a.header.get_work() + share_b.header.get_work() + share_c.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share d (fork from b)
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                &share_d,
                2,
                share_a.header.get_work() + share_b.header.get_work() + share_d.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test getting all descendants from a (should get b, c, d)
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &BlockHash::all_zeros(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&share_b.block_hash()));
        assert!(descendants.contains(&share_c.block_hash()));
        assert!(descendants.contains(&share_d.block_hash()));

        // Test getting descendants from b (should get c and d)
        let descendants = store
            .get_descendant_blockhashes(&share_b.block_hash(), &BlockHash::all_zeros(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 2);
        assert!(descendants.contains(&share_c.block_hash()));
        assert!(descendants.contains(&share_d.block_hash()));

        // Test with limit
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &BlockHash::all_zeros(), 2)
            .unwrap();
        assert_eq!(descendants.len(), 2);

        // Test with stop_blockhash - should return just share_b
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &share_b.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&share_b.block_hash()));
    }

    #[test]
    fn test_find_chain_for_depth_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a linear chain of 10 blocks
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut prev_hash = genesis.block_hash();
        let mut blocks = vec![genesis.block_hash()];

        for i in 1..10 {
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .nonce(0xe9695791 + i)
                .build();

            let mut batch = Store::get_write_batch();
            store
                .add_share(&share, i, share.header.get_work(), true, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();

            blocks.push(share.block_hash());
            prev_hash = share.block_hash();
        }

        // Test finding chain from tip with depth 5
        let chain = store.get_dag_for_depth(&blocks[9], 5).unwrap();

        // Should return blocks 9, 8, 7, 6, 5 (from newest to oldest)
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0], blocks[9]);
        assert_eq!(chain[1], blocks[8]);
        assert_eq!(chain[2], blocks[7]);
        assert_eq!(chain[3], blocks[6]);
        assert_eq!(chain[4], blocks[5]);

        // Test finding chain with depth greater than chain length
        let chain = store.get_dag_for_depth(&blocks[5], 10).unwrap();

        // Should return blocks 5, 4, 3, 2, 1, 0 (6 blocks total)
        assert_eq!(chain.len(), 6);
        assert_eq!(chain[0], blocks[5]);
        assert_eq!(chain[5], blocks[0]);

        // Test finding chain from genesis
        let chain = store.get_dag_for_depth(&blocks[0], 5).unwrap();

        // Should return only genesis (height 0, depth 0)
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], blocks[0]);
    }

    #[test]
    fn test_get_common_ancestor_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a linear chain: genesis -> share1 -> share2 -> share3
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of share3 and share2
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &share2.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share2.block_hash()));

        // Test common ancestor of share3 and share1
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));

        // Test common ancestor of share3 and genesis
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &genesis.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share2 and share1
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));
    }

    #[test]
    fn test_get_common_ancestor_with_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a chain with a fork:
        //        genesis
        //         /  \
        //    share1  uncle1
        //      |
        //    share2
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&uncle1, 1, uncle1.header.get_work(), false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of share2 and uncle1 (should be genesis)
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &uncle1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share1 and uncle1 (should be genesis)
        let ancestor = store
            .get_common_ancestor(&share1.block_hash(), &uncle1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share2 and share1 (should be share1)
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));
    }

    #[test]
    fn test_get_common_ancestor_no_common_within_depth() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create two separate chains (only for testing - wouldn't happen in real usage)
        let genesis1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&genesis1, 0, genesis1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let genesis2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&genesis2, 0, genesis2.header.get_work(), false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of two different genesis blocks (should be None)
        let ancestor = store
            .get_common_ancestor(&genesis1.block_hash(), &genesis2.block_hash())
            .unwrap();
        assert_eq!(ancestor, None);
    }

    #[test]
    fn test_get_dag_for_depth_no_duplicates_with_uncle() {
        // This test verifies that get_dag_for_depth does not return duplicate blocks
        // when uncles and main chain blocks share a common parent.
        //
        // DAG structure:
        //       share1
        //      /      \
        //   uncle1    share2
        //              |
        //            share3 (uncles=[uncle1])
        //
        // uncle1 is a sibling of share2 (both have share1 as parent).
        // share3 references uncle1 as its uncle.
        // When traversing from share3, both share2's parent (share1) and
        // uncle1's parent (share1) point to the same block. Without visited
        // tracking, share1 would appear twice in the results.

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create genesis
        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create uncle1 - sibling of share2
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create share2 - sibling of uncle1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create share3 with uncle1 as uncle (uncle1 is sibling of share3's parent)
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Get DAG from share3 with depth 10 (more than enough to include all blocks)
        let chain = store.get_dag_for_depth(&share3.block_hash(), 10).unwrap();

        // Verify no duplicates by checking that all blockhashes are unique
        let unique_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();
        assert_eq!(
            chain.len(),
            unique_hashes.len(),
            "get_dag_for_depth returned duplicate blocks"
        );

        // Should contain exactly 4 unique blocks: share3, share2, uncle1, share1
        assert_eq!(chain.len(), 4);
        assert!(unique_hashes.contains(&share3.block_hash()));
        assert!(unique_hashes.contains(&share2.block_hash()));
        assert!(unique_hashes.contains(&uncle1.block_hash()));
        assert!(unique_hashes.contains(&share1.block_hash()));
    }

    #[test]
    fn test_get_dag_for_depth_no_duplicates_with_multiple_uncles() {
        // More complex test with multiple uncles
        //
        // DAG structure:
        //              share1
        //           /    |    \
        //      uncle1  uncle2  share2
        //                        |
        //                      share3 (uncles=[uncle1, uncle2])
        //
        // uncle1, uncle2, and share2 are all siblings (share1 as parent).
        // share3 references both uncle1 and uncle2 as uncles.
        // Without visited tracking, share1 would be added to the queue 3 times.

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle2,
                1,
                share1.header.get_work() + uncle2.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash(), uncle2.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let chain = store.get_dag_for_depth(&share3.block_hash(), 10).unwrap();

        // Verify no duplicates
        let unique_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();
        assert_eq!(
            chain.len(),
            unique_hashes.len(),
            "get_dag_for_depth returned duplicate blocks"
        );

        // Should contain exactly 5 unique blocks
        assert_eq!(chain.len(), 5);
        assert!(unique_hashes.contains(&share3.block_hash()));
        assert!(unique_hashes.contains(&share2.block_hash()));
        assert!(unique_hashes.contains(&uncle1.block_hash()));
        assert!(unique_hashes.contains(&uncle2.block_hash()));
        assert!(unique_hashes.contains(&share1.block_hash()));
    }

    #[test]
    fn test_get_dag_for_depth_no_duplicates_deep_uncle_chain() {
        // Test with uncles at multiple levels of the chain
        //
        // DAG structure:
        //       share1
        //      /      \
        //   uncle1    share2
        //            /      \
        //         uncle2    share3 (uncles=[uncle1])
        //                     |
        //                   share4 (uncles=[uncle2])
        //
        // This creates multiple opportunities for duplicate parent references.

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // uncle1 is sibling of share2
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // uncle2 is sibling of share3
        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(200)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle2,
                2,
                share1.header.get_work() + share2.header.get_work() + uncle2.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share3 has uncle1 as uncle (sibling of its parent share2)
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share4 has uncle2 as uncle (sibling of its parent share3)
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .uncles(vec![uncle2.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share4,
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let chain = store.get_dag_for_depth(&share4.block_hash(), 10).unwrap();

        // Verify no duplicates
        let unique_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();
        assert_eq!(
            chain.len(),
            unique_hashes.len(),
            "get_dag_for_depth returned duplicate blocks"
        );

        // Should contain exactly 6 unique blocks
        assert_eq!(chain.len(), 6);
        assert!(unique_hashes.contains(&share4.block_hash()));
        assert!(unique_hashes.contains(&share3.block_hash()));
        assert!(unique_hashes.contains(&share2.block_hash()));
        assert!(unique_hashes.contains(&share1.block_hash()));
        assert!(unique_hashes.contains(&uncle1.block_hash()));
        assert!(unique_hashes.contains(&uncle2.block_hash()));
    }

    #[test]
    fn test_get_dag_for_depth_uncles_do_not_count_toward_depth() {
        // This test verifies that uncles do not count toward the main chain depth.
        // With depth=2, we should get 2 main chain blocks plus all their uncles.
        //
        // DAG structure:
        //       share1
        //      /      \
        //   uncle1    share2
        //              |
        //            share3 (uncles=[uncle1])
        //
        // With depth=2 starting from share3:
        // - Main chain blocks: share3, share2 (2 blocks = depth)
        // - Uncles: uncle1 (referenced by share3)
        // Result should be [share3, share2, uncle1] - NOT missing share2 due to uncle

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // With depth=2, we should get exactly 2 main chain blocks + uncles
        let chain = store.get_dag_for_depth(&share3.block_hash(), 2).unwrap();

        let chain_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();

        // Must include both main chain blocks (share3 and share2)
        assert!(
            chain_hashes.contains(&share3.block_hash()),
            "share3 should be in result"
        );
        assert!(
            chain_hashes.contains(&share2.block_hash()),
            "share2 should be in result - uncle should not consume depth"
        );

        // Must include the uncle
        assert!(
            chain_hashes.contains(&uncle1.block_hash()),
            "uncle1 should be in result"
        );

        // Should NOT include share1 (beyond depth=2)
        assert!(
            !chain_hashes.contains(&share1.block_hash()),
            "share1 should NOT be in result - beyond depth"
        );

        // Total: 3 blocks (2 main chain + 1 uncle)
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_get_dag_for_depth_multiple_uncles_do_not_affect_main_chain_depth() {
        // Test that even with many uncles, we still get the correct number of main chain blocks.
        //
        // DAG structure:
        //              share1
        //           /    |    \
        //      uncle1  uncle2  share2
        //                        |
        //                      share3 (uncles=[uncle1, uncle2])
        //                        |
        //                      share4
        //
        // With depth=2 starting from share4:
        // - Main chain: share4, share3
        // - Uncles of share3: uncle1, uncle2
        // Result: [share4, share3, uncle1, uncle2]

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle2,
                1,
                share1.header.get_work() + uncle2.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash(), uncle2.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share4,
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // With depth=2, we should get share4, share3 (main chain) + uncle1, uncle2
        let chain = store.get_dag_for_depth(&share4.block_hash(), 2).unwrap();

        let chain_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();

        // Main chain blocks
        assert!(chain_hashes.contains(&share4.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));

        // Uncles of share3
        assert!(chain_hashes.contains(&uncle1.block_hash()));
        assert!(chain_hashes.contains(&uncle2.block_hash()));

        // Should NOT include share2 or share1 (beyond depth)
        assert!(!chain_hashes.contains(&share2.block_hash()));
        assert!(!chain_hashes.contains(&share1.block_hash()));

        // Total: 4 blocks (2 main chain + 2 uncles)
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn test_get_dag_for_depth_uncles_at_multiple_levels() {
        // Test with uncles at each level of the main chain.
        //
        // DAG structure:
        //       share1
        //      /      \
        //   uncle1    share2
        //            /      \
        //         uncle2    share3 (uncles=[uncle1])
        //                     |
        //                   share4 (uncles=[uncle2])
        //
        // With depth=3 starting from share4:
        // - Main chain: share4, share3, share2 (3 blocks)
        // - Uncles: uncle2 (from share4), uncle1 (from share3)
        // Result: [share4, share3, share2, uncle2, uncle1]

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle1,
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(200)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &uncle2,
                2,
                share1.header.get_work() + share2.header.get_work() + uncle2.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .uncles(vec![uncle2.block_hash()])
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share4,
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // With depth=3, we should get share4, share3, share2 (main chain) + uncle2, uncle1
        let chain = store.get_dag_for_depth(&share4.block_hash(), 3).unwrap();

        let chain_hashes: HashSet<BlockHash> = chain.iter().cloned().collect();

        // Main chain blocks (exactly 3)
        assert!(chain_hashes.contains(&share4.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));

        // Uncles from the processed main chain blocks
        assert!(chain_hashes.contains(&uncle1.block_hash())); // uncle of share3
        assert!(chain_hashes.contains(&uncle2.block_hash())); // uncle of share4

        // Should NOT include share1 (beyond depth)
        assert!(!chain_hashes.contains(&share1.block_hash()));

        // Total: 5 blocks (3 main chain + 2 uncles)
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn test_get_dag_for_depth_exact_depth_boundary() {
        // Test that depth is exact - we get exactly N main chain blocks.
        //
        // Chain: share1 -> share2 -> share3 -> share4 -> share5
        //
        // With depth=3 from share5: should get share5, share4, share3 (exactly 3)

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share2,
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share3,
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share4,
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share5,
                4,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work()
                    + share5.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // With depth=3, should get exactly 3 main chain blocks
        let chain = store.get_dag_for_depth(&share5.block_hash(), 3).unwrap();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], share5.block_hash());
        assert_eq!(chain[1], share4.block_hash());
        assert_eq!(chain[2], share3.block_hash());

        // With depth=1, should get exactly 1 main chain block
        let chain = store.get_dag_for_depth(&share5.block_hash(), 1).unwrap();

        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], share5.block_hash());
    }

    #[test]
    fn test_is_already_uncle_returns_false_for_new_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().build();
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share, 0, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // A share that has not been used as an uncle should return false
        assert!(!store.is_already_uncle(&share.block_hash()));
    }

    #[test]
    fn test_add_to_uncles_index_and_is_already_uncle() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let uncle = TestShareBlockBuilder::new().nonce(100).build();
        let nephew = TestShareBlockBuilder::new().nonce(200).build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle, 0, uncle.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .add_share(&nephew, 0, nephew.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Before adding to uncles index
        assert!(!store.is_already_uncle(&uncle.block_hash()));

        // Add uncle to uncles index
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_uncles_index(&uncle.block_hash(), &nephew.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // After adding to uncles index
        assert!(store.is_already_uncle(&uncle.block_hash()));
    }

    #[test]
    fn test_get_nephews_returns_none_for_unused_uncle() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().build();
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share, 0, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // A share that has not been used as an uncle should return None
        assert!(store.get_nephews(&share.block_hash()).is_none());
    }

    #[test]
    fn test_get_nephews_returns_nephews_for_used_uncle() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let uncle = TestShareBlockBuilder::new().nonce(100).build();
        let nephew1 = TestShareBlockBuilder::new().nonce(200).build();
        let nephew2 = TestShareBlockBuilder::new().nonce(300).build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle, 0, uncle.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .add_share(&nephew1, 0, nephew1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .add_share(&nephew2, 0, nephew2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add uncle to uncles index with two nephews
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_uncles_index(&uncle.block_hash(), &nephew1.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_uncles_index(&uncle.block_hash(), &nephew2.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Get nephews
        let nephews = store.get_nephews(&uncle.block_hash()).unwrap();
        assert_eq!(nephews.len(), 2);
        assert!(nephews.contains(&nephew1.block_hash()));
        assert!(nephews.contains(&nephew2.block_hash()));
    }

    #[test]
    fn test_find_uncles_returns_error_when_no_confirmed_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().build();
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share, 0, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // No confirmed blocks, should return error
        let result = store.find_uncles();
        assert!(result.is_err());
    }

    #[test]
    fn test_find_uncles_returns_empty_when_no_uncles_available() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a linear chain of confirmed blocks with no forks
        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm all blocks sequentially
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // No unconfirmed children exist, so find_uncles should return empty
        let uncles = store.find_uncles().unwrap();
        assert!(uncles.is_empty());
    }

    #[test]
    fn test_find_uncles_finds_single_uncle() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain:
        //   share0 (confirmed)
        //   /    \
        // share1  uncle1 (not confirmed)
        // (confirmed)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(100)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle1, 1, uncle1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm share0 and share1 only
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // find_uncles should find uncle1
        let uncles = store.find_uncles().unwrap();
        assert_eq!(uncles.len(), 1);
        assert!(uncles.contains(&uncle1.block_hash()));
    }

    #[test]
    fn test_find_uncles_finds_multiple_uncles_at_different_heights() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain:
        //   share0 (confirmed, height 0)
        //   /    \
        // share1  uncle0 (not confirmed, height 1)
        // (confirmed, height 1)
        //   |    \
        // share2  uncle1 (not confirmed, height 2)
        // (confirmed, height 2)
        //   |    \
        // share3  uncle2 (not confirmed, height 3)
        // (confirmed, height 3)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle0 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(100)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(101)
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(3)
            .build();
        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(102)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle0, 1, uncle0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle1, 2, uncle1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle2, 3, uncle2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm main chain only
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share3.block_hash(), 3, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // find_uncles should find uncle0, uncle1, uncle2
        // Sorted by height descending: uncle2 (3), uncle1 (2), uncle0 (1)
        let uncles = store.find_uncles().unwrap();
        assert_eq!(uncles.len(), 3);
        // Verify order - highest height first
        assert_eq!(uncles[0], uncle2.block_hash());
        assert_eq!(uncles[1], uncle1.block_hash());
        assert_eq!(uncles[2], uncle0.block_hash());
    }

    #[test]
    fn test_find_uncles_excludes_uncles_beyond_depth_3() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain with 6 blocks (heights 0-5) and uncles at various depths
        // Uncle at height 1 will be beyond depth 3 when looking from height 5
        //
        // share0 (confirmed, height 0)
        //   |    \
        // share1  uncle_deep (height 1, beyond depth 3 from height 5)
        //   |
        // share2 (confirmed, height 2)
        //   |    \
        // share3  uncle_within (height 3, within depth 3 from height 5)
        //   |
        // share4 (confirmed, height 4)
        //   |
        // share5 (confirmed, height 5)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle_deep = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(100)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(3)
            .build();
        let uncle_within = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(101)
            .build();
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .nonce(4)
            .build();
        let share5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .nonce(5)
            .build();

        // Add all shares
        for (share, height) in [
            (&share0, 0u32),
            (&share1, 1),
            (&uncle_deep, 1),
            (&share2, 2),
            (&share3, 3),
            (&uncle_within, 3),
            (&share4, 4),
            (&share5, 5),
        ] {
            let mut batch = rocksdb::WriteBatch::default();
            store
                .add_share(&share, height, share.header.get_work(), true, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // Confirm main chain (share0 through share5)
        for (share, height) in [
            (&share0, 0u32),
            (&share1, 1),
            (&share2, 2),
            (&share3, 3),
            (&share4, 4),
            (&share5, 5),
        ] {
            let mut batch = rocksdb::WriteBatch::default();
            store
                .make_confirmed(&share.block_hash(), height, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // find_uncles from share5 (height 5)
        // Should only find uncle_within (at height 3, within depth 3: heights 2,3,4)
        // Should NOT find uncle_deep (at height 1, beyond the range we look at)
        let uncles = store.find_uncles().unwrap();

        assert_eq!(uncles.len(), 1);
        assert!(uncles.contains(&uncle_within.block_hash()));
        assert!(!uncles.contains(&uncle_deep.block_hash()));
    }

    #[test]
    fn test_find_uncles_excludes_already_used_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain:
        //   share0 (confirmed)
        //   /    \
        // share1  uncle1 (not confirmed, but already used as uncle)
        // (confirmed)
        //   |    \
        // share2  uncle2 (not confirmed, available)
        // (confirmed)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(100)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();
        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(101)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle1, 1, uncle1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle2, 2, uncle2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm main chain
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Mark uncle1 as already used as uncle
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_uncles_index(&uncle1.block_hash(), &share2.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // find_uncles should only find uncle2, not uncle1
        let uncles = store.find_uncles().unwrap();
        assert_eq!(uncles.len(), 1);
        assert!(uncles.contains(&uncle2.block_hash()));
        assert!(!uncles.contains(&uncle1.block_hash()));
    }

    #[test]
    fn test_find_uncles_excludes_confirmed_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain where all children are confirmed (no uncles)
        //   share0 (confirmed)
        //   /
        // share1 (confirmed)
        //   |
        // share2 (confirmed)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm all
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // find_uncles should return empty - share1 is child of share0 but is confirmed
        let uncles = store.find_uncles().unwrap();
        assert!(uncles.is_empty());
    }

    #[test]
    fn test_find_uncles_returns_max_3_uncles_by_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build chain with 4 uncles - should only return top 3 by height
        //   share0 (confirmed, height 0)
        //   / | \ \
        // share1 uncle_a uncle_b uncle_c (height 1)
        // (confirmed)
        //   |    \
        // share2  uncle_d (height 2)
        // (confirmed)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(100)
            .build();
        let uncle_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(101)
            .build();
        let uncle_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(102)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();
        let uncle_d = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(103)
            .build();

        // Add all shares
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share0, 0, share0.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle_a, 1, uncle_a.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle_b, 1, uncle_b.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle_c, 1, uncle_c.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(&uncle_d, 2, uncle_d.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm main chain only
        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share0.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share1.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .make_confirmed(&share2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // find_uncles should return exactly 3 uncles, prioritizing higher heights
        // uncle_d is at height 2, uncle_a/b/c are at height 1
        let uncles = store.find_uncles().unwrap();
        assert_eq!(uncles.len(), 3);

        // uncle_d should be first (height 2)
        assert_eq!(uncles[0], uncle_d.block_hash());

        // The remaining 2 should be from uncle_a, uncle_b, uncle_c (all height 1)
        let height_1_uncles: HashSet<BlockHash> = [
            uncle_a.block_hash(),
            uncle_b.block_hash(),
            uncle_c.block_hash(),
        ]
        .into_iter()
        .collect();
        assert!(height_1_uncles.contains(&uncles[1]));
        assert!(height_1_uncles.contains(&uncles[2]));
    }

    #[test]
    fn test_find_uncles_with_deep_chain_only_looks_at_last_3_heights() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build a chain of 7 blocks (heights 0-6)
        // with uncles at heights 1, 2, 3, 4, 5
        // find_uncles from height 6 should only look at heights 3, 4, 5 (last 3)

        let share0 = TestShareBlockBuilder::new().nonce(0).build();
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(1)
            .build();
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share0.block_hash().to_string())
            .nonce(101)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(2)
            .build();
        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(102)
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(3)
            .build();
        let uncle3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(103)
            .build();
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .nonce(4)
            .build();
        let uncle4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .nonce(104)
            .build();
        let share5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .nonce(5)
            .build();
        let uncle5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .nonce(105)
            .build();
        let share6 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share5.block_hash().to_string())
            .nonce(6)
            .build();

        // Add all shares
        for (share, height) in [
            (&share0, 0u32),
            (&share1, 1),
            (&uncle1, 1),
            (&share2, 2),
            (&uncle2, 2),
            (&share3, 3),
            (&uncle3, 3),
            (&share4, 4),
            (&uncle4, 4),
            (&share5, 5),
            (&uncle5, 5),
            (&share6, 6),
        ] {
            let mut batch = rocksdb::WriteBatch::default();
            store
                .add_share(&share, height, share.header.get_work(), true, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // Confirm main chain
        for (share, height) in [
            (&share0, 0u32),
            (&share1, 1),
            (&share2, 2),
            (&share3, 3),
            (&share4, 4),
            (&share5, 5),
            (&share6, 6),
        ] {
            let mut batch = rocksdb::WriteBatch::default();
            store
                .make_confirmed(&share.block_hash(), height, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // find_uncles from share6 (height 6) looks at confirmed blocks at heights 3, 4, 5
        // and finds their non-confirmed children.
        // - share3 (height 3) has children: share4, uncle4 -> uncle4 found
        // - share4 (height 4) has children: share5, uncle5 -> uncle5 found
        // - share5 (height 5) has children: share6 only -> no uncles
        // uncle3 is NOT found because it's a child of share2 (height 2), which is outside the range
        let uncles = store.find_uncles().unwrap();

        assert_eq!(uncles.len(), 2);
        // Should be sorted by height descending: uncle5 (5), uncle4 (4)
        assert_eq!(uncles[0], uncle5.block_hash());
        assert_eq!(uncles[1], uncle4.block_hash());

        // Verify uncle1, uncle2, and uncle3 are NOT included (parents outside depth range)
        assert!(!uncles.contains(&uncle1.block_hash()));
        assert!(!uncles.contains(&uncle2.block_hash()));
        assert!(!uncles.contains(&uncle3.block_hash()));
    }
}
