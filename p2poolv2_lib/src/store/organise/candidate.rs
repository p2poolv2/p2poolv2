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

use crate::{
    shares::share_block::ShareHeader,
    store::{
        ColumnFamily, Store,
        block_tx_metadata::{BlockMetadata, Status},
        writer::StoreError,
    },
};
use bitcoin::{
    BlockHash,
    consensus::{self, encode},
};
use tracing::debug;

use std::collections::VecDeque;

use super::{Chain, Height, TopResult, height_to_key_with_suffix};

const CANDIDATE_SUFFIX: &str = ":c";
const TOP_CANDIDATE_KEY: &str = "meta:top_candidate_height";

impl Store {
    /// Increment top candidate key if height is one more than current height
    ///
    /// Only updates top if it is more than one higher.
    fn increment_top_candidate(
        &self,
        height: Height,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Height, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();

        let use_height = match self.get_top_candidate_height() {
            Ok(current_top_height) => {
                if height.saturating_sub(current_top_height) == 1 {
                    height
                } else {
                    return Err(StoreError::Database("Mismatch in top height".into()));
                }
            }
            Err(StoreError::NotFound(_reason)) => height, // Use share height if no candidate top present
            Err(e) => return Err(e),
        };
        let serialized_height = consensus::serialize(&use_height);
        batch.put_cf(
            &block_height_cf,
            TOP_CANDIDATE_KEY.as_bytes().as_ref(),
            serialized_height,
        );
        Ok(use_height)
    }

    /// Directly set top candidate height without consecutive-height validation.
    ///
    /// Used by `reorg_candidate` which computes the correct final height
    /// locally instead of reading stale DB state within a single WriteBatch.
    fn set_top_candidate_height(&self, height: Height, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let serialized_height = consensus::serialize(&height);
        batch.put_cf(
            &block_height_cf,
            TOP_CANDIDATE_KEY.as_bytes().as_ref(),
            serialized_height,
        );
    }

    /// Delete top candidate height.
    /// Used when entire candidate chain has been moved to confirmed chain.
    pub(super) fn delete_top_candidate_height(&self, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        batch.delete_cf(&block_height_cf, TOP_CANDIDATE_KEY.as_bytes().as_ref());
    }

    /// Get top candidate height from candidates index
    pub fn get_top_candidate_height(&self) -> Result<Height, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        match self
            .db
            .get_cf(&block_height_cf, TOP_CANDIDATE_KEY.as_bytes().as_ref())
        {
            Ok(Some(height_bytes)) => Ok(encode::deserialize(&height_bytes)?),
            Ok(None) => Err(StoreError::NotFound("No candidate found at top".into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Write a candidate index entry directly into the batch.
    fn put_candidate_entry(
        &self,
        height: Height,
        blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);
        let serialized = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized);
    }

    /// Delete a candidate index entry from the batch.
    pub(super) fn delete_candidate_entry(&self, height: Height, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);
        batch.delete_cf(&block_height_cf, key);
    }

    /// Get top candidate after looking up top candidate height
    pub(crate) fn get_top_candidate(&self) -> Result<TopResult, StoreError> {
        let height = self.get_top_candidate_height()?;
        let hash = self.get_candidate_at_height(height)?;
        let metadata = self.get_block_metadata(&hash)?;
        Ok(TopResult {
            hash,
            height,
            work: metadata.chain_work,
        })
    }

    /// Add blockhash as a candidate at provided height.
    ///
    /// Also Updates the metadata status to Candidate.
    pub(crate) fn append_to_candidates(
        &self,
        blockhash: &BlockHash,
        height: Height,
        metadata: &mut BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);

        let serialized_blockhash = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized_blockhash);

        self.increment_top_candidate(height, batch)?;

        metadata.status = Status::Candidate;
        self.update_block_metadata(blockhash, metadata, batch)?;
        Ok(Some(height))
    }

    /// Get list of (height, blockhash) pairs from given blockhash up to top candidate.
    /// The blockhash is known to be on the candidates chain.
    pub(crate) fn get_candidates_chain(
        &self,
        blockhash: &BlockHash,
        top_candidate: Option<&TopResult>,
    ) -> Result<Chain, StoreError> {
        let Ok(metadata) = self.get_block_metadata(blockhash) else {
            return Err(StoreError::NotFound(
                "Block metadata not found for branch point".into(),
            ));
        };
        let Some(height) = metadata.expected_height else {
            return Err(StoreError::NotFound(
                "Block metadata doesn't have an expected height".into(),
            ));
        };
        let Some(top) = top_candidate else {
            return Err(StoreError::NotFound(
                "No top candidate height found when reorging candidate chain".into(),
            ));
        };
        self.get_candidates(height, top.height)
    }

    /// Fetch a list of (height, blockhash) pairs on the candidates chain between
    /// the given heights, inclusive.
    pub(crate) fn get_candidates(&self, from: Height, to: Height) -> Result<Chain, StoreError> {
        debug!("Get candidates from {from} to {to}");
        self.get_chain_range(from, to, CANDIDATE_SUFFIX)
    }

    /// Get the candidate blockhash at a specific height
    pub fn get_candidate_at_height(&self, height: Height) -> Result<BlockHash, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);

        match self.db.get_cf::<&[u8]>(&block_height_cf, key.as_ref()) {
            Ok(Some(blockhash_bytes)) => Ok(encode::deserialize(&blockhash_bytes)?),
            Ok(None) => Err(StoreError::NotFound(format!(
                "No candidate found at height {height}"
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Return blockhashes of all shares between confirmed top and
    /// candidate top that are missing full block data, including any
    /// uncle blocks referenced by candidate headers.
    ///
    /// When `min_scan_height` is provided, the scan starts from
    /// `min(min_scan_height, confirmed_top + 1)` instead of
    /// `confirmed_top + 1`. This allows detection of fork blocks at
    /// or below the confirmed height that need fetching for a
    /// potential reorg.
    ///
    /// Queries every height from the scan start to candidate_top
    /// using the BlockHeight index, which stores all blockhashes at
    /// each height including uncle blocks that are not on the
    /// candidate chain. A share is included if its metadata status is
    /// Candidate or HeaderValid, meaning it still needs block data.
    ///
    /// Uncle blocks typically sit at heights already covered by the
    /// confirmed chain, so the height scan alone misses them. A
    /// second pass reads the header of each candidate block and adds
    /// any referenced uncle that lacks block data.
    pub fn get_candidate_blocks_missing_data(
        &self,
        min_scan_height: Option<u32>,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let scan_start = self.missing_data_scan_start(min_scan_height)?;
        let candidate_height = match self.get_top_candidate_height() {
            Ok(height) => height,
            Err(StoreError::NotFound(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        if candidate_height < scan_start {
            return Ok(Vec::new());
        }

        let (all_blockhashes, missing) =
            self.scan_heights_for_missing_blocks(scan_start, candidate_height);

        let missing_uncles = self.collect_missing_uncle_blocks(&all_blockhashes);
        debug!(
            "get_candidate_blocks_missing_data: scan_start={scan_start}, candidate_height={candidate_height}, all_blocks={}, missing_blocks={}, missing_uncles={}",
            all_blockhashes.len(),
            missing.len(),
            missing_uncles.len()
        );

        let mut result = Vec::with_capacity(missing_uncles.len() + missing.len());
        result.extend(missing_uncles);
        result.extend(missing);
        Ok(result)
    }

    /// Compute the starting height for the missing-data scan.
    ///
    /// Defaults to `confirmed_top + 1`. When `min_scan_height` is
    /// provided, uses the lower of the two so that fork blocks below
    /// the confirmed tip are included.
    fn missing_data_scan_start(&self, min_scan_height: Option<u32>) -> Result<u32, StoreError> {
        let confirmed_height = match self.get_top_confirmed_height() {
            Ok(height) => height,
            Err(StoreError::NotFound(_)) => 0,
            Err(error) => return Err(error),
        };
        let default_start = confirmed_height + 1;
        Ok(match min_scan_height {
            Some(hint) => std::cmp::min(hint, default_start),
            None => default_start,
        })
    }

    /// Walk heights from `scan_start` to `candidate_height`, collecting
    /// all blockhashes and identifying those that need block data.
    ///
    /// Returns `(all_blockhashes, missing)` where `missing` contains
    /// hashes whose block body is not stored and whose status is not
    /// yet BlockValid or Confirmed.
    fn scan_heights_for_missing_blocks(
        &self,
        scan_start: u32,
        candidate_height: u32,
    ) -> (Vec<BlockHash>, Vec<BlockHash>) {
        let height_range = (candidate_height - scan_start + 1) as usize;
        let mut all_blockhashes = Vec::with_capacity(height_range);
        let mut missing = Vec::with_capacity(height_range);

        let mut height = scan_start;
        while height <= candidate_height {
            let blockhashes = self.get_blockhashes_for_height(height);
            for blockhash in blockhashes {
                all_blockhashes.push(blockhash);
                if !self.share_block_exists(&blockhash)
                    && !self.is_block_valid_or_confirmed(&blockhash)
                {
                    missing.push(blockhash);
                }
            }
            height += 1;
        }

        (all_blockhashes, missing)
    }

    /// Collect uncle blocks whose bodies are missing, recursively
    /// following each uncle's own uncles until no new missing bodies
    /// are found.
    fn collect_missing_uncle_blocks(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        let mut missing_uncles: Vec<BlockHash> = Vec::new();

        // First pass: scan uncles of all provided blockhashes
        for blockhash in blockhashes {
            let Ok(Some(header)) = self.get_share_header(blockhash) else {
                continue;
            };
            for uncle_hash in &header.uncles {
                if !self.share_block_exists(uncle_hash)
                    && !missing_uncles.contains(uncle_hash)
                    && !blockhashes.contains(uncle_hash)
                {
                    debug!(
                        "collect_missing_uncle_blocks: uncle {uncle_hash} missing body (referenced by {blockhash})"
                    );
                    missing_uncles.push(*uncle_hash);
                }
            }
        }

        // Recursive passes: each newly discovered missing uncle may
        // itself reference further uncles whose bodies are also missing.
        let mut scan_start = 0;
        loop {
            let scan_end = missing_uncles.len();
            if scan_start >= scan_end {
                return missing_uncles;
            }

            let mut new_uncles: Vec<BlockHash> = Vec::new();
            for index in scan_start..scan_end {
                let uncle_hash = missing_uncles[index];
                let Ok(Some(header)) = self.get_share_header(&uncle_hash) else {
                    continue;
                };
                for nested_uncle in &header.uncles {
                    if !self.share_block_exists(nested_uncle)
                        && !missing_uncles.contains(nested_uncle)
                        && !blockhashes.contains(nested_uncle)
                        && !new_uncles.contains(nested_uncle)
                    {
                        debug!(
                            "collect_missing_uncle_blocks: nested uncle {nested_uncle} missing body (referenced by {uncle_hash})"
                        );
                        new_uncles.push(*nested_uncle);
                    }
                }
            }
            scan_start = scan_end;
            missing_uncles.extend(new_uncles);
        }
    }

    /// Check if a blockhash has BlockValid or Confirmed status.
    fn is_block_valid_or_confirmed(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.status == Status::BlockValid || m.status == Status::Confirmed)
            .unwrap_or(false)
    }

    /// Check if a blockhash has Candidate status in its metadata.
    pub fn is_candidate(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.status == Status::Candidate)
            .unwrap_or(false)
    }

    /// Extends candidate chain, if:
    /// 1. new share's height is one more than top candidate
    /// 2. new share's prev hash is top candidate hash
    /// 3. new share's chain work is more than top candidate's chain work.
    /// 4. Or, adds to candidate chain if it is empty.
    ///
    /// The same function is used to check if the share extending the
    /// top_candidate or top_confirmed chains using `top_at_chain` param.
    ///
    /// Returns true if candidate chain is extended.
    pub(super) fn should_extend_candidates(
        &self,
        header: &ShareHeader,
        metadata: &BlockMetadata,
        top_at_chain: Option<&TopResult>,
    ) -> Result<Option<Height>, StoreError> {
        match top_at_chain {
            None => Ok(metadata.expected_height),
            Some(top) => {
                let expected_height = metadata.expected_height.unwrap_or_default();
                if top.hash == header.prev_share_blockhash
                    && expected_height == top.height + 1
                    && metadata.chain_work > top.work
                {
                    Ok(Some(expected_height))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Returns true if the share being organised has more cumulative
    /// work than the top candidate. This identifies the case where
    /// share is not building on the current top_candidate, but is a
    /// different branch that needs to be reorged in.
    pub(super) fn should_reorg_candidate(
        &self,
        share_blockhash: &BlockHash,
        metadata: &BlockMetadata,
        top_candidate: Option<&TopResult>,
    ) -> bool {
        match top_candidate {
            Some(top) => metadata.chain_work > top.work && top.hash != *share_blockhash,
            None => false,
        }
    }

    /// Reorgs the candidate chain to the branch ending at `blockhash`.
    ///
    /// Walks back from `blockhash` to the first ancestor on the
    /// candidate or confirmed chain. Delegates to
    /// `reorg_candidate_from_candidate` or
    /// `reorg_candidate_from_confirmed` depending on the branch point.
    pub(super) fn reorg_candidate(
        &self,
        blockhash: &BlockHash,
        top_candidate: Option<&TopResult>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(Height, Chain), StoreError> {
        let branch = self
            .get_branch_to_chain(blockhash, |h| self.is_candidate(h) || self.is_confirmed(h))?
            .ok_or_else(|| {
                StoreError::NotFound(format!(
                    "Branch point {blockhash} to reorg candidate chain not found."
                ))
            })?;
        let branch_point = branch.front().ok_or_else(|| {
            StoreError::NotFound("Empty branch returned from get_branch_to_chain.".into())
        })?;

        if self.is_confirmed(branch_point) {
            self.reorg_candidate_from_confirmed(&branch, batch)
        } else {
            self.reorg_candidate_from_candidate(&branch, top_candidate, batch)
        }
    }

    /// Reorg when the branch point is on the candidate chain.
    ///
    /// Removes old candidate entries from the branch point to the
    /// current top, resetting their status to HeaderValid. Then writes
    /// the new branch as candidates.
    fn reorg_candidate_from_candidate(
        &self,
        branch: &VecDeque<BlockHash>,
        top_candidate: Option<&TopResult>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(Height, Chain), StoreError> {
        let branch_point = branch.front().ok_or_else(|| {
            StoreError::NotFound("Empty branch in reorg_candidate_from_candidate.".into())
        })?;
        let reorged_out_chain = self.get_candidates_chain(branch_point, top_candidate)?;
        for (height, uncandidate) in &reorged_out_chain {
            self.delete_candidate_entry(*height, batch);
            let mut metadata = self.get_block_metadata(uncandidate)?;
            metadata.status = Status::HeaderValid;
            self.update_block_metadata(uncandidate, &metadata, batch)?;
        }

        self.write_branch_as_candidates(branch, batch)
    }

    /// Reorg when the branch point is on the confirmed chain.
    ///
    /// No old candidate entries need removal. Writes all branch
    /// members above the confirmed branch point as candidates.
    fn reorg_candidate_from_confirmed(
        &self,
        branch: &VecDeque<BlockHash>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(Height, Chain), StoreError> {
        let mut entries = branch.iter();
        entries.next(); // skip the confirmed branch point
        let above_confirmed: VecDeque<BlockHash> = entries.copied().collect();
        self.write_branch_as_candidates(&above_confirmed, batch)
    }

    /// Write a sequence of blockhashes as candidate entries, updating
    /// their metadata to Candidate and setting the top candidate height.
    ///
    /// Returns the new top height and the candidate chain.
    fn write_branch_as_candidates(
        &self,
        branch: &VecDeque<BlockHash>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(Height, Chain), StoreError> {
        let mut new_top_height = 0u32;
        let mut new_chain = Vec::with_capacity(branch.len());
        for candidate in branch {
            let mut metadata = self.get_block_metadata(candidate)?;
            let height = metadata.expected_height.ok_or_else(|| {
                StoreError::NotFound("Block metadata missing expected_height for candidate".into())
            })?;
            self.put_candidate_entry(height, candidate, batch);
            metadata.status = Status::Candidate;
            self.update_block_metadata(candidate, &metadata, batch)?;
            new_chain.push((height, *candidate));
            new_top_height = height;
        }
        self.set_top_candidate_height(new_top_height, batch);
        Ok((new_top_height, new_chain))
    }

    /// Walk forward from the current candidate tip, discovering
    /// children already stored and appending them to the candidate
    /// chain in the same WriteBatch.
    ///
    /// Among multiple children at the same height, selects the one with
    /// the highest `chain_work`. Verifies parent hash to exclude uncle
    /// relationships from the block index. Overwrites `top_candidate_height`
    /// only if at least one child was appended.
    pub(super) fn extend_candidates_with_children(
        &self,
        current_top_height: Height,
        current_top_hash: &BlockHash,
        candidates: &mut Chain,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Height, StoreError> {
        let mut height = current_top_height;
        let mut tip_hash = *current_top_hash;
        let mut found_child = true;

        while found_child {
            found_child = false;

            let children = self
                .get_children_blockhashes(&tip_hash)?
                .unwrap_or_default();

            if let Some((best_hash, mut best_metadata)) =
                self.pick_best_child(&children, &tip_hash, height + 1)?
            {
                let next_height = height + 1;
                self.put_candidate_entry(next_height, &best_hash, batch);
                best_metadata.status = Status::Candidate;
                self.update_block_metadata(&best_hash, &best_metadata, batch)?;
                candidates.push((next_height, best_hash));

                height = next_height;
                tip_hash = best_hash;
                found_child = true;
            }
        }

        if height > current_top_height {
            self.set_top_candidate_height(height, batch);
        }
        Ok(height)
    }

    /// Select the best qualifying child from a list of children.
    ///
    /// Filters for `Valid` status, correct `expected_height`, and matching
    /// parent hash (to exclude uncle links in the block index). Among
    /// qualifying children, returns the one with the highest `chain_work`.
    fn pick_best_child(
        &self,
        children: &[BlockHash],
        parent_hash: &BlockHash,
        expected_height: Height,
    ) -> Result<Option<(BlockHash, BlockMetadata)>, StoreError> {
        let mut top_work_child: Option<(BlockHash, BlockMetadata)> = None;

        for child_hash in children {
            let all_children = self
                .get_block_metadata(child_hash)
                .ok()
                .filter(|m| m.status == Status::HeaderValid)
                .filter(|m| m.expected_height == Some(expected_height))
                .and_then(|m| {
                    self.get_share_header(child_hash)
                        .ok()
                        .flatten()
                        .filter(|h| h.prev_share_blockhash == *parent_hash)
                        .map(|_| (*child_hash, m))
                });

            if let Some((child_hash, child_metadata)) = all_children {
                let has_more_work = top_work_child
                    .as_ref()
                    .map(|(_, current_top_metadata)| {
                        child_metadata.chain_work > current_top_metadata.chain_work
                    })
                    .unwrap_or(true);
                if has_more_work {
                    top_work_child = Some((child_hash, child_metadata));
                }
            }
        }

        Ok(top_work_child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::Work;
    use tempfile::tempdir;

    #[test]
    fn test_increment_top_candidate_sets_initial_top_from_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        assert!(store.get_top_candidate_height().is_err());

        let mut batch = Store::get_write_batch();
        let result = store.increment_top_candidate(5, &mut batch);
        store.commit_batch(batch).unwrap();

        assert_eq!(result.unwrap(), 5);
        assert_eq!(store.get_top_candidate_height().unwrap(), 5);
    }

    #[test]
    fn test_increment_top_candidate_increments_consecutive_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Bootstrap top to 3
        let mut batch = Store::get_write_batch();
        store.increment_top_candidate(3, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Height 4 is exactly 1 more than current top (3)
        let mut batch = Store::get_write_batch();
        let result = store.increment_top_candidate(4, &mut batch);
        store.commit_batch(batch).unwrap();

        assert_eq!(result.unwrap(), 4);
        assert_eq!(store.get_top_candidate_height().unwrap(), 4);
    }

    #[test]
    fn test_increment_top_candidate_errors_on_skipped_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = Store::get_write_batch();
        store.increment_top_candidate(1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Height 3 skips over 2
        let mut batch = Store::get_write_batch();
        let result = store.increment_top_candidate(3, &mut batch);

        assert!(result.is_err());
        assert_eq!(store.get_top_candidate_height().unwrap(), 1);
    }

    #[test]
    fn test_increment_top_candidate_errors_on_same_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = Store::get_write_batch();
        store.increment_top_candidate(2, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // 2 - 2 = 0, not 1
        let mut batch = Store::get_write_batch();
        let result = store.increment_top_candidate(2, &mut batch);

        assert!(result.is_err());
        assert_eq!(store.get_top_candidate_height().unwrap(), 2);
    }

    // ── append_to_candidate tests ─────────────────────────────────────────

    #[test]
    fn test_append_to_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .work(1)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .work(2)
            .build();

        // Make share1 candidate at height 1
        store.push_to_candidate_chain(&share1).unwrap();

        // Verify we can retrieve it
        let candidate = store.get_candidate_at_height(1).unwrap();
        assert_eq!(candidate, share1.block_hash());

        // Make share2 candidate at height 2
        store.push_to_candidate_chain(&share2).unwrap();

        // Verify both heights
        assert_eq!(
            store.get_candidate_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_candidate_at_height(2).unwrap(),
            share2.block_hash()
        );

        // Non-existent height should return None
        assert!(store.get_candidate_at_height(999).is_err());

        // Top candidate height is changed
        assert_eq!(store.get_top_candidate_height().unwrap(), 2);

        // Top candidate is changed
        let top = store.get_top_candidate().unwrap();
        assert_eq!(top.hash, share2.block_hash());
        assert_eq!(top.height, 2);
    }

    #[test]
    fn test_append_to_candidate_on_overwrite_previous_should_not_extend() {
        // Two sibling shares at the same height: push_to_candidate_chain should not
        // extend the candidate chain for the second share (equal work, same
        // height as existing candidate).
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        // Organise share1 -- becomes candidate at height 1
        store.push_to_candidate_chain(&share1).unwrap();

        assert_eq!(
            store.get_candidate_at_height(1).unwrap(),
            share1.block_hash()
        );

        // Organise share2 at same height with equal work -- should not extend or reorg
        let result = store.push_to_candidate_chain(&share2).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_push_to_candidate_chain_does_not_extend_when_parent_is_not_top_candidate() {
        // A share whose parent is not the current top candidate and
        // whose cumulative work is not greater should not extend or
        // reorg the candidate chain.
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1 extends genesis to height 1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2 extends share1 to height 2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        assert_eq!(store.get_top_candidate_height().unwrap(), 2);

        // orphan_share has an unknown parent (not in store), so
        // organise_header returns an error for missing parent.
        let orphan_share = TestShareBlockBuilder::new().nonce(0xe9695793).build();
        let result = store.push_to_candidate_chain(&orphan_share);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        assert_eq!(store.get_top_candidate_height().unwrap(), 2);
    }

    // ── get_candidates / get_candidates_chain tests ───────────────────

    #[test]
    fn test_get_candidates_returns_blockhashes_in_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695793)
            .build();

        // Add and organise each share sequentially
        for share in [&share1, &share2, &share3] {
            store.push_to_candidate_chain(share).unwrap();
        }

        // Full range (heights 1, 2, 3)
        let result = store.get_candidates(1, 3).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], (1, share1.block_hash()));
        assert_eq!(result[1], (2, share2.block_hash()));
        assert_eq!(result[2], (3, share3.block_hash()));

        // Sub-range
        let result = store.get_candidates(2, 3).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (2, share2.block_hash()));
        assert_eq!(result[1], (3, share3.block_hash()));

        // Single height
        let result = store.get_candidates(2, 2).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (2, share2.block_hash()));
    }

    #[test]
    fn test_get_candidates_returns_empty_when_from_greater_than_to() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let result = store.get_candidates(5, 3).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_candidates_chain_returns_candidates_from_blockhash_to_top() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();

        // Add and organise each share sequentially
        for share in [&share1, &share2] {
            store.push_to_candidate_chain(share).unwrap();
        }

        let top = store.get_top_candidate().ok();
        let result = store
            .get_candidates_chain(&share1.block_hash(), top.as_ref())
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (1, share1.block_hash()));
        assert_eq!(result[1], (2, share2.block_hash()));
    }

    #[test]
    fn test_get_candidates_chain_errors_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let result = store.get_candidates_chain(&genesis.block_hash(), None);
        assert!(result.is_err());
    }

    // ── is_candidate tests ────────────────────────────────────────────

    #[test]
    fn test_is_candidate_returns_true_when_candidate() {
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

        assert!(store.is_candidate(&share.block_hash()));
    }

    #[test]
    fn test_is_candidate_returns_false_when_not_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share but don't make it a candidate (no push_to_candidate_chain call)
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(!store.is_candidate(&share.block_hash()));
    }

    // ── extend_candidates_at unit tests ──────────────────────────────

    #[test]
    fn test_extend_candidates_at_returns_share_expected_height_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: share.header.get_work(),
            status: Status::Pending,
        };

        let result = store.should_extend_candidates(&share.header, &metadata, None);
        assert_eq!(result.unwrap(), metadata.expected_height);
    }

    #[test]
    fn test_extend_candidates_at_returns_height_when_conditions_match() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let parent = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let parent_hash = parent.block_hash();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();

        let metadata = BlockMetadata {
            expected_height: Some(6),
            chain_work: share.header.get_work(),
            status: Status::Pending,
        };

        // height == top candidate height + 1 → 6 == 5 + 1
        let top_candidate = Some(TopResult {
            hash: parent_hash,
            height: 5,
            work: Work::from_hex("0x05").unwrap(),
        });

        let result =
            store.should_extend_candidates(&share.header, &metadata, top_candidate.as_ref());
        assert_eq!(result.unwrap(), Some(6));
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_hash_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let different_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let different_hash = different_share.block_hash();

        let metadata = BlockMetadata {
            expected_height: Some(6),
            chain_work: share.header.get_work(),
            status: Status::Pending,
        };

        // Height condition met (6 == 5+1), but hash differs from prev_share_blockhash
        let top_candidate = Some(TopResult {
            hash: different_hash,
            height: 5,
            work: Work::from_hex("0x05").unwrap(),
        });

        let result =
            store.should_extend_candidates(&share.header, &metadata, top_candidate.as_ref());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_height_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let parent = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let parent_hash = parent.block_hash();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();

        let metadata = BlockMetadata {
            expected_height: Some(7),
            chain_work: share.header.get_work(),
            status: Status::Pending,
        };

        // Hash matches but height doesn't (7 != 5+1)
        let top_candidate = Some(TopResult {
            hash: parent_hash,
            height: 5,
            work: Work::from_hex("0x05").unwrap(),
        });

        let result =
            store.should_extend_candidates(&share.header, &metadata, top_candidate.as_ref());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_extend_candidates_at_returns_none_when_both_mismatch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let different_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let different_hash = different_share.block_hash();

        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: share.header.get_work(),
            status: Status::Pending,
        };

        // Neither hash nor height matches
        let top_candidate = Some(TopResult {
            hash: different_hash,
            height: 10,
            work: Work::from_hex("0x05").unwrap(),
        });

        let result =
            store.should_extend_candidates(&share.header, &metadata, top_candidate.as_ref());
        assert_eq!(result.unwrap(), None);
    }

    // ── should_reorg_candidate unit tests ──────────────────────────────

    #[test]
    fn test_should_reorg_candidate_true_when_more_work_different_hash() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let top_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        let metadata = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_hex("0x10").unwrap(),
            status: Status::HeaderValid,
        };

        let top_candidate = Some(TopResult {
            hash: top_share.block_hash(),
            height: 2,
            work: Work::from_hex("0x05").unwrap(),
        });

        assert!(store.should_reorg_candidate(
            &share.block_hash(),
            &metadata,
            top_candidate.as_ref()
        ));
    }

    #[test]
    fn test_should_reorg_candidate_false_when_less_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let top_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        let metadata = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_hex("0x03").unwrap(),
            status: Status::HeaderValid,
        };

        let top_candidate = Some(TopResult {
            hash: top_share.block_hash(),
            height: 2,
            work: Work::from_hex("0x05").unwrap(),
        });

        assert!(!store.should_reorg_candidate(
            &share.block_hash(),
            &metadata,
            top_candidate.as_ref()
        ));
    }

    #[test]
    fn test_should_reorg_candidate_false_when_equal_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let top_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        let metadata = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_hex("0x05").unwrap(),
            status: Status::HeaderValid,
        };

        let top_candidate = Some(TopResult {
            hash: top_share.block_hash(),
            height: 2,
            work: Work::from_hex("0x05").unwrap(),
        });

        assert!(!store.should_reorg_candidate(
            &share.block_hash(),
            &metadata,
            top_candidate.as_ref()
        ));
    }

    #[test]
    fn test_should_reorg_candidate_false_when_same_hash() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();

        let metadata = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_hex("0x10").unwrap(),
            status: Status::Candidate,
        };

        // Same blockhash as share — should not reorg against itself
        let top_candidate = Some(TopResult {
            hash: share.block_hash(),
            height: 2,
            work: Work::from_hex("0x05").unwrap(),
        });

        assert!(!store.should_reorg_candidate(
            &share.block_hash(),
            &metadata,
            top_candidate.as_ref()
        ));
    }

    #[test]
    fn test_should_reorg_candidate_false_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();

        let metadata = BlockMetadata {
            expected_height: Some(2),
            chain_work: Work::from_hex("0x10").unwrap(),
            status: Status::HeaderValid,
        };

        assert!(!store.should_reorg_candidate(&share.block_hash(), &metadata, None));
    }

    // ── pick_best_child unit tests ──────────────────────────────────

    #[test]
    fn test_pick_best_child_returns_none_for_empty_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let result = store
            .pick_best_child(&[], &genesis.block_hash(), 1)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_returns_none_when_no_metadata() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // A blockhash that was never added to the store
        let fake_hash = TestShareBlockBuilder::new()
            .nonce(0xe9695799)
            .build()
            .block_hash();
        let parent = TestShareBlockBuilder::new().nonce(0xe9695791).build();

        let result = store
            .pick_best_child(&[fake_hash], &parent.block_hash(), 1)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_skips_candidate_status() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        // Mark as Candidate via push_to_candidate_chain -- should be skipped by pick_best_child
        store.push_to_candidate_chain(&child).unwrap();

        let result = store
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 1)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_skips_wrong_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        // Use push_to_candidate_chain to set metadata (height 1, status Candidate)
        // then manually reset status to Valid so pick_best_child sees it
        store.push_to_candidate_chain(&child).unwrap();
        let mut metadata = store.get_block_metadata(&child.block_hash()).unwrap();
        metadata.status = Status::HeaderValid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Ask for height 5 -- child is at height 1
        let result = store
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 5)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_skips_wrong_parent() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // child's prev_share_blockhash is genesis, not some_other
        let child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        // Use push_to_candidate_chain to set metadata, then reset status to Valid
        store.push_to_candidate_chain(&child).unwrap();
        let mut metadata = store.get_block_metadata(&child.block_hash()).unwrap();
        metadata.status = Status::HeaderValid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let wrong_parent = TestShareBlockBuilder::new().nonce(0xe9695799).build();
        let result = store
            .pick_best_child(&[child.block_hash()], &wrong_parent.block_hash(), 1)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_returns_valid_child() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        // Store block data and create Valid metadata directly
        store.store_with_valid_metadata(&child);

        let result = store
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 1)
            .unwrap();
        assert!(result.is_some());
        let (hash, result_metadata) = result.unwrap();
        assert_eq!(hash, child.block_hash());
        assert_eq!(result_metadata.expected_height, Some(1));
    }

    #[test]
    fn test_pick_best_child_selects_heaviest_among_multiple() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let light = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(1)
            .nonce(0xe9695792)
            .build();
        let heavy = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(3)
            .nonce(0xe9695793)
            .build();

        // Store block data and create Valid metadata directly (avoids
        // candidate chain side effects from push_to_candidate_chain).
        store.store_with_valid_metadata(&light);
        store.store_with_valid_metadata(&heavy);

        // Both are valid children at height 1 -- heavy has more work
        let result = store
            .pick_best_child(
                &[light.block_hash(), heavy.block_hash()],
                &genesis.block_hash(),
                1,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());

        // Order should not matter -- reverse the input
        let result = store
            .pick_best_child(
                &[heavy.block_hash(), light.block_hash()],
                &genesis.block_hash(),
                1,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());
    }

    // -- get_candidate_blocks_missing_data tests --

    #[test]
    fn test_missing_data_returns_empty_when_no_candidates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let result = store.get_candidate_blocks_missing_data(None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_missing_data_returns_all_candidates_when_none_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        store.push_to_candidate_chain(&share1).unwrap();
        store.push_to_candidate_chain(&share2).unwrap();

        // Both candidates have Candidate status (not BlockValid), so both are missing data
        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0], share1.block_hash());
        assert_eq!(missing[1], share2.block_hash());
    }

    #[test]
    fn test_missing_data_skips_block_valid_candidates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        store.push_to_candidate_chain(&share1).unwrap();
        store.push_to_candidate_chain(&share2).unwrap();

        // Mark share1 as BlockValid
        let mut metadata = store.get_block_metadata(&share1.block_hash()).unwrap();
        metadata.status = Status::BlockValid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&share1.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], share2.block_hash());
    }

    #[test]
    fn test_missing_data_returns_empty_when_all_block_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // Mark as BlockValid
        let mut metadata = store.get_block_metadata(&share1.block_hash()).unwrap();
        metadata.status = Status::BlockValid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&share1.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn test_missing_data_returns_empty_when_candidate_at_or_below_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // Set confirmed height to match candidate height (both at 1)
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(1, &mut batch);
        store.commit_batch(batch).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn test_missing_data_only_returns_candidates_above_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695793)
            .build();

        store.push_to_candidate_chain(&share1).unwrap();
        store.push_to_candidate_chain(&share2).unwrap();
        store.push_to_candidate_chain(&share3).unwrap();

        // Confirmed height is 1, so only candidates at height 2 and 3 are checked
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(1, &mut batch);
        store.commit_batch(batch).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0], share2.block_hash());
        assert_eq!(missing[1], share3.block_hash());
    }

    #[test]
    fn test_missing_data_includes_uncle_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // uncle_block: fork child of genesis at h:1, not on candidate chain.
        // organise_header stores it in BlockHeight at h:1 with HeaderValid
        // status but does not put it on the candidate chain since share1
        // already occupies that slot and has equal or greater work.
        let uncle_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.create_valid_metadata_only(&uncle_block);

        // share2: candidate at h:2, includes uncle_block as uncle
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle_block.block_hash()])
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();

        // All three should be missing: share1 and uncle_block at h:1, share2 at h:2
        assert_eq!(missing.len(), 3);
        assert!(missing.contains(&share1.block_hash()));
        assert!(missing.contains(&uncle_block.block_hash()));
        assert!(missing.contains(&share2.block_hash()));
    }

    /// Uncle at a confirmed height is missed by the height scan but
    /// should be included because a candidate header references it.
    ///
    /// Scenario: genesis -> share1(h:1, confirmed) -> share2(h:2, candidate).
    /// uncle_block is a fork child of genesis at h:1 (same height as
    /// the confirmed share1). share2 declares uncle_block as an uncle.
    /// Only the uncle's header exists, not its block data.
    /// get_candidate_blocks_missing_data should return uncle_block.
    #[test]
    fn test_missing_data_includes_uncle_at_confirmed_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: confirmed at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // uncle_block: fork child of genesis at h:1, only header stored
        let uncle_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_header(&uncle_block.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: candidate at h:2, references uncle_block
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle_block.block_hash()])
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let missing = store.get_candidate_blocks_missing_data(None).unwrap();

        // share2 is missing block data (candidate above confirmed),
        // uncle_block is missing block data (referenced by share2's header)
        assert!(
            missing.contains(&share2.block_hash()),
            "share2 should be in missing list"
        );
        assert!(
            missing.contains(&uncle_block.block_hash()),
            "uncle_block at confirmed height should be in missing list"
        );
    }

    /// When min_scan_height is below the confirmed height, blocks at
    /// that height should be included in the missing data result.
    ///
    /// Scenario: genesis -> share1(h:1, confirmed) -> share2(h:2, candidate).
    /// fork_block is a competing block at h:1 with Candidate status.
    /// Without min_scan_height, the scan starts at h:2 and misses
    /// fork_block. With min_scan_height=1, fork_block is found.
    #[test]
    fn test_missing_data_scans_from_min_height_when_below_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: confirmed at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695791)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // fork_block: competing block at h:1, only header stored with Candidate status
        let fork_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.create_valid_metadata_only(&fork_block);

        // share2: candidate at h:2, extends share1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        // Without min_scan_height: fork_block at h:1 is skipped
        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert!(
            !missing.contains(&fork_block.block_hash()),
            "fork_block should NOT be returned without min_scan_height"
        );
        assert!(missing.contains(&share2.block_hash()));

        // With min_scan_height=1: fork_block at h:1 is found
        let missing = store.get_candidate_blocks_missing_data(Some(1)).unwrap();
        assert!(
            missing.contains(&fork_block.block_hash()),
            "fork_block should be returned with min_scan_height=1"
        );
        assert!(missing.contains(&share2.block_hash()));
    }

    #[test]
    fn test_pick_best_child_skips_invalid_among_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // valid_child: stored with Status::Valid
        let valid_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(1)
            .nonce(0xe9695792)
            .build();
        store.store_with_valid_metadata(&valid_child);

        // candidate_child: stored with Status::Valid initially, then set to Candidate
        let candidate_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(3)
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&candidate_child);

        // Override candidate_child status to Candidate (more work but ineligible)
        let mut metadata = store
            .get_block_metadata(&candidate_child.block_hash())
            .unwrap();
        metadata.status = Status::Candidate;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&candidate_child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // candidate_child has more work but is Candidate status -- should be skipped
        let result = store
            .pick_best_child(
                &[candidate_child.block_hash(), valid_child.block_hash()],
                &genesis.block_hash(),
                1,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, valid_child.block_hash());
    }
}
