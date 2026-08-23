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
        block_tx_metadata::{BlockMetadata, ChainMembership, Status},
        writer::StoreError,
    },
};
use bitcoin::{
    BlockHash,
    consensus::{self, encode},
};
use tracing::debug;

use std::collections::{HashSet, VecDeque};

use super::{Chain, Height, TopResult, height_to_key_with_suffix};
use crate::accounting::payout::sharechain_pplns::pplns_window::PRUNE_DEPTH;

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

        metadata.chain = ChainMembership::Candidate;
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
    /// When `fork_height` is provided, the scan starts from
    /// `min(fork_height, confirmed_top + 1)` instead of
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
        fork_height: Option<u32>,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let scan_start = self.missing_data_scan_start(fork_height)?;
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
    /// Defaults to `confirmed_top + 1`. When `fork_height` is
    /// provided, uses the lower of the two so that fork blocks below
    /// the confirmed tip are included.
    ///
    /// The result is clamped upward to the prune boundary
    /// (candidate_tip - PRUNE_DEPTH) so blocks under the prune zone are
    /// never fetched. Their PoW is already validated at header sync
    /// time and they don't need block bodies.
    fn missing_data_scan_start(&self, fork_height: Option<u32>) -> Result<u32, StoreError> {
        let confirmed_height = match self.get_top_confirmed_height() {
            Ok(height) => height,
            Err(StoreError::NotFound(_)) => 0,
            Err(error) => return Err(error),
        };
        let next_confirmed_height = confirmed_height + 1;
        let min_fork_and_confirmed_height = match fork_height {
            Some(fork_height) => std::cmp::min(fork_height, next_confirmed_height),
            None => next_confirmed_height,
        };

        let candidate_height = match self.get_top_candidate_height() {
            Ok(height) => height,
            Err(StoreError::NotFound(_)) => return Ok(min_fork_and_confirmed_height),
            Err(error) => return Err(error),
        };
        let prune_floor = candidate_height.saturating_sub(PRUNE_DEPTH as u32);

        Ok(std::cmp::max(min_fork_and_confirmed_height, prune_floor))
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
        let height_entries = self.get_blockhashes_for_height_range(scan_start, candidate_height);

        let total_blocks: usize = height_entries.iter().map(|(_, hashes)| hashes.len()).sum();
        let mut all_blockhashes = Vec::with_capacity(total_blocks);
        for (_, blockhashes) in &height_entries {
            all_blockhashes.extend(blockhashes);
        }

        let metadata_results = self.get_block_metadata_batch(&all_blockhashes);
        let already_valid: HashSet<BlockHash> = metadata_results
            .into_iter()
            .filter(|(_, metadata)| {
                metadata.status == Status::BlockValid
                    || metadata.chain == ChainMembership::Confirmed
            })
            .map(|(blockhash, _)| blockhash)
            .collect();

        let candidates_to_check: Vec<BlockHash> = all_blockhashes
            .iter()
            .filter(|hash| !already_valid.contains(*hash))
            .copied()
            .collect();
        let missing = self.missing_share_blocks(&candidates_to_check);

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

    /// Check if a blockhash is both on the candidate chain and BlockValid.
    ///
    /// This is the promotion gate inside the PPLNS zone (at or above the
    /// prune boundary): a block may only be confirmed there once its
    /// chain-context validation has completed, so nothing reaches the
    /// confirmed chain before it is fully validated.
    pub(super) fn is_candidate_and_block_valid(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.chain == ChainMembership::Candidate && m.status == Status::BlockValid)
            .unwrap_or(false)
    }

    /// Check if a blockhash is on the candidate chain.
    pub fn is_candidate(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.chain == ChainMembership::Candidate)
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

    /// Whether the reorg branch ending at `blockhash` passes through an
    /// `Invalid` block.
    ///
    /// `reorg_candidate` walks `get_branch_to_chain` back to the first
    /// candidate/confirmed ancestor and writes every block above it as a
    /// candidate. A detached `Invalid` block has `chain == None`, so it does not
    /// stop that walk and would be silently re-admitted. This lets the caller
    /// refuse such a reorg, so an invalid-by-descent branch never becomes the
    /// candidate chain.
    pub(super) fn reorg_branch_has_invalid(
        &self,
        blockhash: &BlockHash,
    ) -> Result<bool, StoreError> {
        let Some(branch) =
            self.get_branch_to_chain(blockhash, |h| self.is_candidate(h) || self.is_confirmed(h))?
        else {
            return Ok(false);
        };
        for hash in &branch {
            if self.get_block_metadata(hash)?.status == Status::Invalid {
                return Ok(true);
            }
        }
        Ok(false)
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

    /// Reorg the candidate chain after invalidating `invalid_hash`.
    ///
    /// The invalid block and every candidate above it leave the candidate
    /// chain (`chain = None`), then the best surviving branch is rebuilt from
    /// the invalid block's parent (the branch point, a candidate or the
    /// confirmed tip). The now-invalid block is filtered out of the parent's
    /// children before `pick_best_child` runs -- so we never re-read its
    /// (still-uncommitted) Invalid status -- and `pick_best_child` also skips
    /// any non-HeaderValid block, so the best valid alternative is chosen.
    ///
    /// The caller (`mark_invalid`) has already set `invalid_hash` to
    /// `Invalid` + `chain = None` in the same batch.
    pub(crate) fn reorg_candidate_after_invalidation(
        &self,
        invalid_hash: &BlockHash,
        invalid_metadata: &BlockMetadata,
        confirmed_top: Height,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let invalid_height = invalid_metadata.expected_height.ok_or_else(|| {
            StoreError::NotFound("Invalidated candidate missing expected_height".into())
        })?;
        self.detach_candidate_branch(invalid_hash, invalid_height, batch)?;
        let final_top = self.rebuild_candidate_from_parent(invalid_hash, invalid_height, batch)?;
        self.set_or_clear_top_candidate_height(final_top, confirmed_top, batch);
        Ok(())
    }

    /// Remove the invalid block and every candidate above it from the
    /// candidate index, clearing their candidate membership.
    ///
    /// The invalid block's own metadata was already set to `Invalid` +
    /// `chain = None` by the caller in this same (uncommitted) batch, so it
    /// is only deleted from the index here -- re-reading it would return the
    /// stale committed metadata and clobber that write.
    fn detach_candidate_branch(
        &self,
        invalid_hash: &BlockHash,
        from_height: Height,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let top = self.get_top_candidate_height()?;
        for height in from_height..=top {
            let hash = self.get_candidate_at_height(height)?;
            self.delete_candidate_entry(height, batch);
            if hash != *invalid_hash {
                let mut metadata = self.get_block_metadata(&hash)?;
                metadata.chain = ChainMembership::None;
                self.update_block_metadata(&hash, &metadata, batch)?;
            }
        }
        Ok(())
    }

    /// Rebuild the best-work candidate branch from the invalid block's parent
    /// (the branch point, a candidate or the confirmed tip).
    ///
    /// Walks forward from the parent with `extend_candidates_with_children`,
    /// excluding the invalid block so its still-uncommitted Invalid status is
    /// never re-read; `pick_best_child` also skips non-HeaderValid blocks, so
    /// the best valid alternative is chosen. Returns the new candidate top
    /// height, or the parent's height when no child survives.
    fn rebuild_candidate_from_parent(
        &self,
        invalid_hash: &BlockHash,
        invalid_height: Height,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Height, StoreError> {
        let parent_hash = self
            .get_share_header(invalid_hash)?
            .ok_or_else(|| {
                StoreError::NotFound(format!("No header for invalidated block {invalid_hash}"))
            })?
            .prev_share_blockhash;
        let parent_height = invalid_height - 1;
        let mut new_candidates: Chain = Vec::new();
        self.extend_candidates_with_children(
            parent_height,
            &parent_hash,
            &mut new_candidates,
            batch,
            Some(invalid_hash),
        )
    }

    /// Set the candidate top height after a rebuild, or delete it when the
    /// candidate chain is now empty (`final_top` is the confirmed tip, i.e.
    /// nothing survived above it).
    ///
    /// `extend_candidates_with_children` only raises the top when it appends,
    /// so the no-surviving-child and single-child cases are handled here.
    /// Record the rebuilt candidate top, or clear it when the candidate chain
    /// no longer reaches above the confirmed chain.
    ///
    /// `confirmed_top` is passed in rather than read: `mark_invalid` runs after
    /// `confirm_blocks` has queued a new confirmed top into the same batch, and
    /// a store read here would see the pre-batch value.
    fn set_or_clear_top_candidate_height(
        &self,
        final_top: Height,
        confirmed_top: Height,
        batch: &mut rocksdb::WriteBatch,
    ) {
        if final_top > confirmed_top {
            self.set_top_candidate_height(final_top, batch);
        } else {
            self.delete_top_candidate_height(batch);
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
            metadata.chain = ChainMembership::None;
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
            metadata.chain = ChainMembership::Candidate;
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
    /// only if at least one child was appended. `excluded` is forwarded to
    /// `pick_best_child` (see there) so a specific block is never selected.
    pub(super) fn extend_candidates_with_children(
        &self,
        current_top_height: Height,
        current_top_hash: &BlockHash,
        candidates: &mut Chain,
        batch: &mut rocksdb::WriteBatch,
        excluded: Option<&BlockHash>,
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
                self.pick_best_child(&children, &tip_hash, height + 1, excluded)?
            {
                let next_height = height + 1;
                self.put_candidate_entry(next_height, &best_hash, batch);
                best_metadata.chain = ChainMembership::Candidate;
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
    /// Filters for a valid header (`HeaderValid` or `BlockValid` -- both
    /// carry a valid PoW header and are eligible for the candidate chain;
    /// `BlockValid` is a candidate that has since passed chain-context
    /// validation), correct `expected_height`, and matching parent hash
    /// (to exclude uncle links in the block index). `excluded`, when set,
    /// skips a specific child by hash -- the invalidation reorg uses it so a
    /// block whose Invalid status is still uncommitted in the batch is never
    /// re-selected. Among qualifying children, returns the one with the
    /// highest `chain_work`.
    fn pick_best_child(
        &self,
        children: &[BlockHash],
        parent_hash: &BlockHash,
        expected_height: Height,
        excluded: Option<&BlockHash>,
    ) -> Result<Option<(BlockHash, BlockMetadata)>, StoreError> {
        let mut top_work_child: Option<(BlockHash, BlockMetadata)> = None;

        for child_hash in children {
            let all_children = self
                .get_block_metadata(child_hash)
                .ok()
                .filter(|_| excluded != Some(child_hash))
                .filter(|m| matches!(m.status, Status::HeaderValid | Status::BlockValid))
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

    // -- append_to_candidate tests -----------------------------------------

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

    // -- get_candidates / get_candidates_chain tests -------------------

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

    // -- is_candidate tests --------------------------------------------

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

    // -- extend_candidates_at unit tests ------------------------------

    #[test]
    fn test_extend_candidates_at_returns_share_expected_height_when_no_top_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let metadata = BlockMetadata {
            expected_height: Some(5),
            chain_work: share.header.get_work(),
            status: Status::Pending,
            chain: ChainMembership::None,
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
            chain: ChainMembership::None,
        };

        // height == top candidate height + 1 -> 6 == 5 + 1
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
            chain: ChainMembership::None,
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
            chain: ChainMembership::None,
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
            chain: ChainMembership::None,
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

    // -- should_reorg_candidate unit tests ------------------------------

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
            chain: ChainMembership::None,
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
            chain: ChainMembership::None,
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
            chain: ChainMembership::None,
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
            status: Status::HeaderValid,
            chain: ChainMembership::Candidate,
        };

        // Same blockhash as share -- should not reorg against itself
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
            chain: ChainMembership::None,
        };

        assert!(!store.should_reorg_candidate(&share.block_hash(), &metadata, None));
    }

    // -- pick_best_child unit tests ----------------------------------

    #[test]
    fn test_pick_best_child_returns_none_for_empty_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let result = store
            .pick_best_child(&[], &genesis.block_hash(), 1, None)
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
            .pick_best_child(&[fake_hash], &parent.block_hash(), 1, None)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pick_best_child_skips_invalid_status() {
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
        store.store_with_valid_metadata(&child);

        // pick_best_child only picks HeaderValid children, so an Invalid
        // child is skipped even though it exists at the right height.
        let mut metadata = store.get_block_metadata(&child.block_hash()).unwrap();
        metadata.status = Status::Invalid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let result = store
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 1, None)
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
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 5, None)
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
            .pick_best_child(&[child.block_hash()], &wrong_parent.block_hash(), 1, None)
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
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 1, None)
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
                None,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());

        // Order should not matter -- reverse the input
        let result = store
            .pick_best_child(
                &[heavy.block_hash(), light.block_hash()],
                &genesis.block_hash(),
                1,
                None,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());
    }

    #[test]
    fn test_pick_best_child_honours_exclusion() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Two valid children of genesis; the heavier one is excluded, so the
        // lighter one is chosen instead of being the overall best.
        let heavy = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .work(3)
            .build();
        store.store_with_valid_metadata(&heavy);
        let light = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695793)
            .work(1)
            .build();
        store.store_with_valid_metadata(&light);

        let result = store
            .pick_best_child(
                &[heavy.block_hash(), light.block_hash()],
                &genesis.block_hash(),
                1,
                Some(&heavy.block_hash()),
            )
            .unwrap();
        assert_eq!(result.unwrap().0, light.block_hash());
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

    /// When fork_height is below the confirmed height, blocks at
    /// that height should be included in the missing data result.
    ///
    /// Scenario: genesis -> share1(h:1, confirmed) -> share2(h:2, candidate).
    /// fork_block is a competing block at h:1 with Candidate status.
    /// Without fork_height, the scan starts at h:2 and misses
    /// fork_block. With fork_height=1, fork_block is found.
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

        // Without fork_height: fork_block at h:1 is skipped
        let missing = store.get_candidate_blocks_missing_data(None).unwrap();
        assert!(
            !missing.contains(&fork_block.block_hash()),
            "fork_block should NOT be returned without fork_height"
        );
        assert!(missing.contains(&share2.block_hash()));

        // With fork_height=1: fork_block at h:1 is found
        let missing = store.get_candidate_blocks_missing_data(Some(1)).unwrap();
        assert!(
            missing.contains(&fork_block.block_hash()),
            "fork_block should be returned with fork_height=1"
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

        // invalid_child: stored HeaderValid initially, then marked Invalid
        let invalid_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(3)
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&invalid_child);

        // Override status to Invalid (more work but ineligible for the chain)
        let mut metadata = store
            .get_block_metadata(&invalid_child.block_hash())
            .unwrap();
        metadata.status = Status::Invalid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&invalid_child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // invalid_child has more work but is Invalid -- should be skipped
        let result = store
            .pick_best_child(
                &[invalid_child.block_hash(), valid_child.block_hash()],
                &genesis.block_hash(),
                1,
                None,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, valid_child.block_hash());
    }

    /// A candidate that has passed chain-context validation is BlockValid
    /// while still on the candidate chain. pick_best_child must keep picking
    /// it so extend_candidates_with_children can rebuild the chain through an
    /// already-validated block (e.g. after a reorg).
    #[test]
    fn test_pick_best_child_selects_block_valid_child() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // header_valid_child: lower work, plain HeaderValid
        let header_valid_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(1)
            .nonce(0xe9695792)
            .build();
        store.store_with_valid_metadata(&header_valid_child);

        // block_valid_child: higher work, upgraded to BlockValid
        let block_valid_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(3)
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&block_valid_child);
        let mut metadata = store
            .get_block_metadata(&block_valid_child.block_hash())
            .unwrap();
        metadata.status = Status::BlockValid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&block_valid_child.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // block_valid_child has more work and is eligible -- it must win.
        let result = store
            .pick_best_child(
                &[
                    block_valid_child.block_hash(),
                    header_valid_child.block_hash(),
                ],
                &genesis.block_hash(),
                1,
                None,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, block_valid_child.block_hash());
    }

    #[test]
    fn test_missing_data_scan_start_clamps_to_prune_floor() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // confirmed tip at 0 (genesis), candidate tip above PRUNE_DEPTH
        // so prune_floor is meaningful.
        // next_confirmed_height = 0 + 1 = 1
        // prune_floor = candidate_tip - PRUNE_DEPTH = 1000
        let candidate_tip = PRUNE_DEPTH as u32 + 1000;
        let prune_floor = candidate_tip - PRUNE_DEPTH as u32;
        let mut batch = Store::get_write_batch();
        store
            .increment_top_candidate(candidate_tip, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // No fork_height: min_fork_and_confirmed_height = 1.
        // Result = max(1, prune_floor=1000) = 1000.
        let result = store.missing_data_scan_start(None).unwrap();
        assert_eq!(result, prune_floor);

        // fork_height below prune_floor: min(500, 1) = 1.
        // Result = max(1, 1000) = 1000.
        let result = store.missing_data_scan_start(Some(500)).unwrap();
        assert_eq!(result, prune_floor);

        // fork_height above prune_floor: min(2000, 1) = 1.
        // Result = max(1, 1000) = 1000.
        let result = store.missing_data_scan_start(Some(2000)).unwrap();
        assert_eq!(result, prune_floor);
    }

    #[test]
    fn test_missing_data_scan_start_no_clamp_on_short_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // candidate tip below PRUNE_DEPTH: prune_floor = 0.
        // next_confirmed_height = 0 + 1 = 1.
        // Result = max(1, 0) = 1.
        let mut batch = Store::get_write_batch();
        store.increment_top_candidate(100, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let result = store.missing_data_scan_start(None).unwrap();
        assert_eq!(result, 1);
    }

    // -- invalidation reorg tests -----------------------------------------

    /// Invalidating a mid-candidate block removes it and its descendants from
    /// the candidate chain and rebuilds the best surviving branch from the
    /// invalid block's parent.
    #[test]
    fn test_mark_invalid_reorgs_mid_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain: genesis -> c1 -> c2 -> c3.
        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();
        let c2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695793)
            .work(3)
            .build();
        store.push_to_candidate_chain(&c2).unwrap();
        let c3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c2.block_hash().to_string())
            .nonce(0xe9695794)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c3).unwrap();

        // c2b: a lower-work sibling of c2 (also a child of c1), off-chain.
        let c2b = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695795)
            .work(2)
            .build();
        store.store_with_valid_metadata(&c2b);

        assert_eq!(store.get_top_candidate_height().unwrap(), 3);

        // Invalidate c2 (mid-candidate).
        let mut batch = Store::get_write_batch();
        store
            .mark_invalid(&c2.block_hash(), None, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // c2 is Invalid and off the chain; c3 left the chain too.
        let c2_meta = store.get_block_metadata(&c2.block_hash()).unwrap();
        assert_eq!(c2_meta.status, Status::Invalid);
        assert_eq!(c2_meta.chain, ChainMembership::None);
        assert_eq!(
            store.get_block_metadata(&c3.block_hash()).unwrap().chain,
            ChainMembership::None
        );

        // The candidate chain was rebuilt onto the surviving sibling c2b.
        assert_eq!(store.get_top_candidate_height().unwrap(), 2);
        assert_eq!(store.get_candidate_at_height(1).unwrap(), c1.block_hash());
        assert_eq!(store.get_candidate_at_height(2).unwrap(), c2b.block_hash());
        assert!(store.get_candidate_at_height(3).is_err());
        assert_eq!(
            store.get_block_metadata(&c2b.block_hash()).unwrap().chain,
            ChainMembership::Candidate
        );
    }

    /// Invalidating the only candidate above the confirmed tip, with no
    /// surviving sibling, empties the candidate chain.
    #[test]
    fn test_mark_invalid_empties_candidate_chain_when_no_sibling() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();
        assert_eq!(store.get_top_candidate_height().unwrap(), 1);

        let mut batch = Store::get_write_batch();
        store
            .mark_invalid(&c1.block_hash(), None, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let c1_meta = store.get_block_metadata(&c1.block_hash()).unwrap();
        assert_eq!(c1_meta.status, Status::Invalid);
        assert_eq!(c1_meta.chain, ChainMembership::None);
        // No candidate remains above the confirmed tip.
        assert!(store.get_top_candidate_height().is_err());
        assert!(store.get_candidate_at_height(1).is_err());
    }

    // -- invalidation reorg helper unit tests -----------------------------

    /// detach_candidate_branch removes the branch from `from_height` up,
    /// and clears chain membership for every removed block except the invalid
    /// one, whose metadata the caller owns.
    #[test]
    fn test_detach_candidate_branch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();
        let c2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&c2).unwrap();
        let c3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_candidate_chain(&c3).unwrap();

        // Detach from height 2 treating c2 as the invalid block.
        let mut batch = Store::get_write_batch();
        store
            .detach_candidate_branch(&c2.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Index entries for the detached heights are gone; c1 stays.
        assert!(store.get_candidate_at_height(2).is_err());
        assert!(store.get_candidate_at_height(3).is_err());
        assert_eq!(store.get_candidate_at_height(1).unwrap(), c1.block_hash());
        // c3 (not the invalid block) left the candidate chain.
        assert_eq!(
            store.get_block_metadata(&c3.block_hash()).unwrap().chain,
            ChainMembership::None
        );
        // c2's metadata is untouched by detach (the caller owns it).
        assert_eq!(
            store.get_block_metadata(&c2.block_hash()).unwrap().chain,
            ChainMembership::Candidate
        );
    }

    /// rebuild_candidate_from_parent picks the best surviving child of the
    /// branch point (excluding the invalid block) and returns the new top.
    #[test]
    fn test_rebuild_candidate_from_parent() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();

        // Two children of c1: the invalid one and a surviving sibling.
        let invalid = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695793)
            .work(1)
            .build();
        store.store_with_valid_metadata(&invalid);
        let surviving = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695794)
            .work(2)
            .build();
        store.store_with_valid_metadata(&surviving);

        let mut batch = Store::get_write_batch();
        let final_top = store
            .rebuild_candidate_from_parent(&invalid.block_hash(), 2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(final_top, 2);
        assert_eq!(
            store.get_candidate_at_height(2).unwrap(),
            surviving.block_hash()
        );
        assert_eq!(
            store
                .get_block_metadata(&surviving.block_hash())
                .unwrap()
                .chain,
            ChainMembership::Candidate
        );
    }

    /// `mark_invalid` runs after `confirm_blocks` has queued a *lower* confirmed
    /// top into the same batch, which is what a reorg to a shorter validated
    /// prefix does. Reading the confirmed top from the store here would see the
    /// pre-batch value, decide the rebuilt candidate top no longer reaches
    /// above it, and erase TOP_CANDIDATE_KEY while candidate entries exist --
    /// leaving `get_top_candidate_height` permanently NotFound.
    #[test]
    fn test_mark_invalid_keeps_candidate_top_against_pending_confirmed_top() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain c1 -> c2 -> c3, with a surviving sibling of c2 so the
        // rebuild produces a candidate top above the invalidated height.
        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695802)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();
        let c2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695803)
            .work(3)
            .build();
        store.push_to_candidate_chain(&c2).unwrap();
        let c3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c2.block_hash().to_string())
            .nonce(0xe9695804)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c3).unwrap();

        let c2b = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695805)
            .work(2)
            .build();
        store.store_with_valid_metadata(&c2b);

        // Committed confirmed top is deliberately high: 5, above the candidate
        // heights, standing in for the branch a reorg is rewinding away.
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(5, &mut batch);
        store.commit_batch(batch).unwrap();

        // The batch has queued confirmed top 1, as confirm_blocks would when
        // the validated prefix ends at c1.
        let mut batch = Store::get_write_batch();
        store
            .mark_invalid(&c2.block_hash(), Some(1), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // The rebuild put c2b at height 2, which is above the batch's confirmed
        // top of 1, so the candidate top must survive.
        assert_eq!(store.get_candidate_at_height(2).unwrap(), c2b.block_hash());
        assert_eq!(
            store.get_top_candidate_height().unwrap(),
            2,
            "candidate top erased against the pre-batch confirmed top"
        );
    }

    /// When the rebuild finds no surviving child, the candidate top falls back
    /// to the invalidated block's parent. That parent is itself a candidate
    /// here, so candidate entries still exist and the top must be set to it,
    /// not cleared.
    #[test]
    fn test_mark_invalid_sets_candidate_top_to_parent_when_no_sibling_survives() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695812)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c1).unwrap();
        let c2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(0xe9695813)
            .work(1)
            .build();
        store.push_to_candidate_chain(&c2).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .mark_invalid(&c2.block_hash(), None, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_candidate_at_height(1).unwrap(), c1.block_hash());
        assert_eq!(store.get_top_candidate_height().unwrap(), 1);
    }

    /// set_or_clear_top_candidate_height sets the top above the confirmed tip
    /// and deletes it when the candidate chain is empty.
    #[test]
    fn test_set_or_clear_top_candidate_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Confirmed tip is genesis (height 0). A top above it is set.
        let mut batch = Store::get_write_batch();
        store.set_or_clear_top_candidate_height(5, 0, &mut batch);
        store.commit_batch(batch).unwrap();
        assert_eq!(store.get_top_candidate_height().unwrap(), 5);

        // A top at the confirmed tip means the candidate chain is empty.
        let mut batch = Store::get_write_batch();
        store.set_or_clear_top_candidate_height(0, 0, &mut batch);
        store.commit_batch(batch).unwrap();
        assert!(store.get_top_candidate_height().is_err());
    }

    #[test]
    fn test_reorg_branch_has_invalid_false_when_all_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate branch point at h1.
        let share_p = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share_p).unwrap();

        // share_a (h2) -> share_b (h3): HeaderValid, detached (chain = None).
        let share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_p.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&share_a);
        let share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&share_b);

        assert!(
            !store
                .reorg_branch_has_invalid(&share_b.block_hash())
                .unwrap()
        );
    }

    /// Returns true when an Invalid block lies between the target and the branch
    /// point (the case that would otherwise re-admit it via write_branch_as_candidates).
    #[test]
    fn test_reorg_branch_has_invalid_true_for_invalid_ancestor() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share_p = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share_p).unwrap();

        // share_a is Invalid and detached; share_b (HeaderValid) descends from it.
        let share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_p.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&share_a);
        let mut a_metadata = store.get_block_metadata(&share_a.block_hash()).unwrap();
        a_metadata.status = Status::Invalid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&share_a.block_hash(), &a_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&share_b);

        assert!(
            store
                .reorg_branch_has_invalid(&share_b.block_hash())
                .unwrap()
        );
    }

    /// Returns true when the target block itself is Invalid.
    #[test]
    fn test_reorg_branch_has_invalid_true_when_target_invalid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share_p = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share_p).unwrap();

        let share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_p.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&share_a);
        let mut a_metadata = store.get_block_metadata(&share_a.block_hash()).unwrap();
        a_metadata.status = Status::Invalid;
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(&share_a.block_hash(), &a_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(
            store
                .reorg_branch_has_invalid(&share_a.block_hash())
                .unwrap()
        );
    }

    /// Returns false when the branch does not reach the candidate/confirmed
    /// chain (get_branch_to_chain yields None because a parent header is missing).
    #[test]
    fn test_reorg_branch_has_invalid_false_when_branch_unresolved() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Orphan whose parent header is not stored, so the walk cannot reach the
        // candidate/confirmed chain.
        let orphan = TestShareBlockBuilder::new().nonce(0xe9695795).build();
        let mut batch = Store::get_write_batch();
        store.add_share_header(&orphan.header, &mut batch).unwrap();
        store
            .update_block_metadata(
                &orphan.block_hash(),
                &BlockMetadata {
                    expected_height: Some(1),
                    chain_work: orphan.header.get_work(),
                    status: Status::HeaderValid,
                    chain: ChainMembership::None,
                },
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(
            !store
                .reorg_branch_has_invalid(&orphan.block_hash())
                .unwrap()
        );
    }
}
