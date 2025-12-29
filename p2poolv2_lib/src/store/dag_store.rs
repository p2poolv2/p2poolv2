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
use bitcoin::BlockHash;
use bitcoin::consensus::{self, Encodable, encode};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use tracing::debug;

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
            "Queued merge operation: {} -> {}",
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

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
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
    /// backward up to depth ancestors (newest to oldest). Include
    /// parents and uncles.
    pub(crate) fn get_dag_for_depth(
        &self,
        start: &BlockHash,
        depth: usize,
    ) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let mut to_visit = VecDeque::with_capacity(depth);
        to_visit.push_back(*start);

        let mut results = Vec::with_capacity(depth);
        let mut remaining_depth = depth;

        // Walk backward through parents and uncles
        while let Some(next) = to_visit.pop_front() {
            // Get the share to find its parent
            match self.get_share(&next) {
                Some(next_share) => {
                    to_visit.push_back(next_share.header.prev_share_blockhash);
                    for uncle in next_share.header.uncles.iter() {
                        to_visit.push_back(*uncle);
                    }

                    results.push(next_share.block_hash());

                    remaining_depth -= 1;
                    if remaining_depth == 0 {
                        break;
                    }
                }
                None => {
                    // Can't find share, stop here
                    break;
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
}
