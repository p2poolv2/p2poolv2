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

use crate::{
    shares::share_block::ShareBlock,
    store::{block_tx_metadata::BlockMetadata, writer::StoreError},
};
use tracing::debug;

use super::{Chain, Height, Store, TopResult};
use bitcoin::BlockHash;

impl Store {
    /// Organise a share by updating candidate and confirmed indexes.
    ///
    /// Appends to candidate chain if the share extends either the top
    /// candidate or top confirmed chain (checked in that order).
    ///
    /// All writes go into the provided `WriteBatch` so the caller can
    /// commit them atomically.
    ///
    /// This atomicity is the only reason organise_share is in
    /// Store. We could provide a way to expose WriteBatch, but we'd
    /// still need to find a way to send all updates in a single event
    /// through StoreWriter, which will make things slightly more
    /// complicated to "organise" - pun intended.
    pub(crate) fn organise_share(
        &self,
        share: ShareBlock,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let blockhash = share.block_hash();
        tracing::debug!("organise_share called for {blockhash}");

        let mut metadata = self.get_block_metadata(&blockhash)?;
        let top_candidate = self.get_top_candidate().ok();
        let Some(top_confirmed) = self.get_top_confirmed().ok() else {
            return Err(StoreError::Database(
                "Organise share called without a genesis block".into(),
            ));
        };

        debug!("top candidate {:?}", top_candidate);
        debug!("top confirmed {:?}", top_confirmed);

        let effective_candidates = self.update_candidate_chain(
            &share,
            &blockhash,
            &mut metadata,
            top_candidate.as_ref(),
            &top_confirmed,
            batch,
        )?;

        // Promote candidates to confirmed if they extend the confirmed chain.
        match effective_candidates {
            Some((nc_height, candidates)) => {
                if self.should_extend_confirmed(
                    &candidates,
                    top_confirmed.height,
                    top_confirmed.hash,
                )? {
                    self.extend_confirmed(nc_height, candidates, batch)
                } else {
                    Ok(Some(top_confirmed.height)) // TODO: reorg confirmed chain
                }
            }
            None => Ok(Some(top_confirmed.height)),
        }
    }

    /// Update the candidate chain (append or reorg) and return the
    /// effective candidate chain built locally.
    ///
    /// Batch writes are not visible to DB reads within the same batch,
    /// so this method reads committed state and patches in the new entries.
    fn update_candidate_chain(
        &self,
        share: &ShareBlock,
        blockhash: &BlockHash,
        metadata: &mut BlockMetadata,
        top_candidate: Option<&TopResult>,
        top_confirmed: &TopResult,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<(Height, Chain)>, StoreError> {
        if let Some(extended_height) =
            self.should_extend_candidates(share, metadata, top_candidate)?
        {
            debug!("Should extend candidate");
            self.append_to_candidates(blockhash, extended_height, metadata, batch)?;

            // Committed candidates above confirmed are unaffected by the
            // append; read them, then add the newly written entry.
            let old_top = top_candidate
                .map(|t| t.height)
                .unwrap_or(top_confirmed.height);
            let mut candidates = self.get_candidates(top_confirmed.height + 1, old_top)?;
            candidates.push((extended_height, *blockhash));

            let final_height = self.extend_candidates_with_children(
                extended_height,
                blockhash,
                &mut candidates,
                batch,
            )?;
            debug!("new candidate height after extending candidates {final_height}");
            return Ok(Some((final_height, candidates)));
        }

        if self.should_reorg_candidate(blockhash, metadata, top_candidate) {
            let (new_height, reorg_chain) =
                self.reorg_candidate(blockhash, top_candidate, batch)?;
            debug!("new candidate height after reorging candidates {new_height}");

            // Include committed candidates below the reorg branch point
            let branch_start = reorg_chain.first().map(|(h, _)| *h).unwrap_or(0);
            let mut full_chain = if branch_start > top_confirmed.height + 1 {
                self.get_candidates(top_confirmed.height + 1, branch_start - 1)?
            } else {
                Vec::new()
            };
            full_chain.extend(reorg_chain);

            // reorg_candidate always returns a non-empty chain
            let reorg_tip_hash = full_chain.last().expect("reorg chain is non-empty").1;
            let final_height = self.extend_candidates_with_children(
                new_height,
                &reorg_tip_hash,
                &mut full_chain,
                batch,
            )?;
            debug!("new candidate height after reorg + forward walk {final_height}");
            return Ok(Some((final_height, full_chain)));
        }

        Ok(None)
    }

    /// Check if the confirmed chain can be extended by the local candidate chain.
    ///
    /// Accepts the effective candidate chain built locally (avoiding stale
    /// reads from the DB within the same WriteBatch).
    /// Returns true if the first candidate is a child of the top confirmed.
    fn should_extend_confirmed(
        &self,
        candidates: &Chain,
        top_confirmed_height: Height,
        top_confirmed_hash: BlockHash,
    ) -> Result<bool, StoreError> {
        debug!(
            "top confirmed height {}, top confirmed hash {}",
            top_confirmed_height, top_confirmed_hash
        );

        if candidates.is_empty() {
            debug!("No candidates found");
            return Ok(false);
        }

        let Some(first_candidate_header) = self.get_share_header(&candidates[0].1)? else {
            return Err(StoreError::NotFound(
                "No candidate header found in extending confirmed".into(),
            ));
        };

        debug!("First candidate header {:?}", first_candidate_header);

        // First candidate must be a child of top confirmed
        Ok(
            first_candidate_header.prev_share_blockhash == top_confirmed_hash
                && top_confirmed_height + 1 == candidates[0].0,
        )
    }

    /// Promote candidates to confirmed and clear the candidate chain.
    ///
    /// Moves each candidate entry to the confirmed index, updates metadata
    /// to Confirmed status, and removes the top candidate height marker.
    fn extend_confirmed(
        &self,
        to: Height,
        candidates: Vec<(Height, BlockHash)>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        for (candidate_height, candidate_hash) in candidates {
            self.put_confirmed_entry(candidate_height, &candidate_hash, batch);
            self.delete_candidate_entry(candidate_height, batch);
            let mut metadata = self.get_block_metadata(&candidate_hash)?;
            metadata.status = crate::store::block_tx_metadata::Status::Confirmed;
            self.update_block_metadata(&candidate_hash, &metadata, batch)?;
        }
        self.delete_top_candidate_height(batch);
        self.set_top_confirmed_height(to, batch);
        Ok(Some(to))
    }

    /// Returns true if the share being organised has more cumulative
    /// work than the top candidate. This identifies the case where
    /// share is not building on the current top_candidate, but is a
    /// different branch that needs to be reorged in.
    fn should_reorg_candidate(
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
    /// Returns the new top candidate height and the new candidate chain
    /// as `(height, blockhash)` pairs. The caller uses this local chain
    /// to check confirmed extension without re-reading from the DB.
    ///
    /// Directly manipulates candidate index entries and sets the final
    /// top height in a single pass, avoiding stale reads from the DB
    /// within the same WriteBatch. Reorged-out shares have their
    /// metadata status set to Valid so `is_candidate()` stays correct.
    fn reorg_candidate(
        &self,
        blockhash: &BlockHash,
        top_candidate: Option<&TopResult>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(Height, Chain), StoreError> {
        let branch = self.get_branch_to_candidates(blockhash)?.ok_or_else(|| {
            StoreError::NotFound("Branch point to reorg candidate chain not found.".into())
        })?;
        let branch_point = branch.front().ok_or_else(|| {
            StoreError::NotFound("Empty branch returned from get_branch_to_candidates.".into())
        })?;
        let reorged_out_chain = self.get_candidates_chain(branch_point, top_candidate)?;

        // Collect new branch blockhashes for quick lookup when deciding
        // whether to set reorged-out metadata to Valid
        let branch_set: std::collections::HashSet<&BlockHash> = branch.iter().collect();

        // Delete old candidate index entries and set reorged-out shares to Valid
        for (height, uncandidate) in &reorged_out_chain {
            self.delete_candidate_entry(*height, batch);
            if !branch_set.contains(uncandidate) {
                let mut metadata = self.get_block_metadata(uncandidate)?;
                metadata.status = crate::store::block_tx_metadata::Status::Valid;
                self.update_block_metadata(uncandidate, &metadata, batch)?;
            }
        }

        // Write new branch entries, collect the chain, and update metadata
        let mut new_top_height = 0u32;
        let mut new_chain = Vec::with_capacity(branch.len());
        for candidate in &branch {
            let mut metadata = self.get_block_metadata(candidate)?;
            let height = metadata.expected_height.ok_or_else(|| {
                StoreError::NotFound("Block metadata missing expected_height for candidate".into())
            })?;
            self.put_candidate_entry(height, candidate, batch);

            if metadata.status != crate::store::block_tx_metadata::Status::Candidate {
                metadata.status = crate::store::block_tx_metadata::Status::Candidate;
                self.update_block_metadata(candidate, &metadata, batch)?;
            }

            new_chain.push((height, *candidate));
            new_top_height = height;
        }

        // Set the final top candidate height directly
        self.set_top_candidate_height(new_top_height, batch);
        Ok((new_top_height, new_chain))
    }

    /// Walk forward from the current candidate tip, discovering children
    /// already stored with `Valid` status and appending them to the
    /// candidate chain in the same WriteBatch.
    ///
    /// Among multiple children at the same height, selects the one with
    /// the highest `chain_work`. Verifies parent hash to exclude uncle
    /// relationships from the block index. Overwrites `top_candidate_height`
    /// only if at least one child was appended.
    fn extend_candidates_with_children(
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
                best_metadata.status = crate::store::block_tx_metadata::Status::Candidate;
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
                .filter(|m| m.status == crate::store::block_tx_metadata::Status::Valid)
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
    fn should_extend_candidates(
        &self,
        share: &ShareBlock,
        metadata: &BlockMetadata,
        top_at_chain: Option<&TopResult>,
    ) -> Result<Option<Height>, StoreError> {
        match top_at_chain {
            None => Ok(metadata.expected_height),
            Some(top) => {
                let expected_height = metadata.expected_height.unwrap_or_default();
                if top.hash == share.header.prev_share_blockhash
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::Status;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::Work;
    use tempfile::tempdir;

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

        let result = store.should_extend_candidates(&share, &metadata, None);
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

        let result = store.should_extend_candidates(&share, &metadata, top_candidate.as_ref());
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

        let result = store.should_extend_candidates(&share, &metadata, top_candidate.as_ref());
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

        let result = store.should_extend_candidates(&share, &metadata, top_candidate.as_ref());
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

        let result = store.should_extend_candidates(&share, &metadata, top_candidate.as_ref());
        assert_eq!(result.unwrap(), None);
    }

    // ── organise_share integration tests ─────────────────────────────

    #[test]
    fn test_organise_share_promotes_first_candidate_to_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add a child share so its metadata is available
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // setup_genesis does not call append_to_candidate, so no top candidate
        assert!(store.get_top_candidate().is_err());

        let mut batch = Store::get_write_batch();
        store.organise_share(share.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate was promoted to confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);
    }

    #[test]
    fn test_organise_share_extends_candidate_when_conditions_match() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share1 (child of genesis) at height 1 and make it a candidate
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share1.block_hash(),
                height: 1,
                work: share1.header.get_work()
            })
        );

        // create share_to_organise with prev_share_blockhash = share1 at expected_height 2.
        // extend_candidates_at checks: hash, height and work conditions match
        let share_to_organise = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &share_to_organise,
                2,
                share_to_organise.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .organise_share(share_to_organise.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Both candidates promoted to confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share_to_organise.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
    }

    #[test]
    fn test_organise_share_noop_when_height_condition_not_met() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Make genesis a candidate at height 0
        let mut batch = Store::get_write_batch();
        let mut genesis_metadata = store.get_block_metadata(&genesis.block_hash()).unwrap();
        store
            .append_to_candidates(&genesis.block_hash(), 0, &mut genesis_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: genesis.block_hash(),
                height: 0,
                work: genesis.header.get_work()
            })
        );

        // Add share (child of genesis) at height 1.
        // extend_candidates_at checks: hash matches but height does'nt
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_share(share.clone(), &mut batch).unwrap();

        // No candidate at height 1
        assert!(store.get_candidate_at_height(1).is_err());
        // Top candidate unchanged
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: genesis.block_hash(),
                height: 0,
                work: genesis.header.get_work()
            })
        );
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
            status: Status::Valid,
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
            status: Status::Valid,
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
            status: Status::Valid,
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
            status: Status::Valid,
        };

        assert!(!store.should_reorg_candidate(&share.block_hash(), &metadata, None));
    }

    // ── reorg_candidate integration tests ──────────────────────────────

    /// Test reorg replacing the top candidate with a sibling fork.
    ///
    /// Before:  share1(h:1) → share2(h:2)  [top at h:2]
    /// Fork:    share1(h:1) → fork_share(h:2, more work)
    /// After:   share1(h:1) → fork_share(h:2)  [top at h:2]
    #[test]
    fn test_organise_share_reorgs_when_fork_has_more_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis (confirmed at h:0)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: child of genesis, candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: child of share1, candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share2.block_hash(),
                height: 2,
                work: share2.header.get_work()
            })
        );

        // fork_share: child of share1, at h:2, with MORE cumulative work
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &fork_share,
                2,
                fork_share.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_share should trigger reorg: replace share2 with fork_share
        let mut batch = Store::get_write_batch();
        store
            .organise_share(fork_share.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // After reorg + confirmed promotion: all on confirmed chain
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            fork_share.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);

        // share2 is reorged out and has Valid status
        let share2_metadata = store.get_block_metadata(&share2.block_hash()).unwrap();
        assert_eq!(share2_metadata.status, Status::Valid);
    }

    /// Test deeper reorg replacing multiple candidates with a competing branch.
    ///
    /// Before:  share1(h:1) → share2(h:2) → share3(h:3)  [top at h:3]
    /// Fork:    share1(h:1) → fork2(h:2) → fork3(h:3, more work)
    /// After:   all promoted to confirmed
    #[test]
    fn test_organise_share_reorgs_deeper_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build candidate chain: share1(h:1) → share2(h:2) → share3(h:3)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m3 = store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share3.block_hash(), 3, &mut m3, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share3.block_hash(),
                height: 3,
                work: share3.header.get_work()
            })
        );

        // Build fork: share1 → fork2(h:2) → fork3(h:3, more work)
        let fork2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695795)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&fork2, 2, fork2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let fork3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork2.block_hash().to_string())
            .work(2)
            .nonce(0xe9695796)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&fork3, 3, fork3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_share(fork3) should trigger reorg
        let mut batch = Store::get_write_batch();
        store.organise_share(fork3.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // After reorg + confirmed promotion: all on confirmed chain
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            fork2.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(3).unwrap(),
            fork3.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 3);

        // Reorged-out shares have Valid status
        let share2_meta = store.get_block_metadata(&share2.block_hash()).unwrap();
        assert_eq!(share2_meta.status, Status::Valid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::Valid);
    }

    /// Test reorg to a shorter fork (fork has fewer blocks but more work).
    ///
    /// Before:  share1(h:1) → share2(h:2) → share3(h:3)  [top at h:3]
    /// Fork:    share1(h:1) → fork_share(h:2, much more work)
    /// After:   all promoted to confirmed
    #[test]
    fn test_organise_share_reorgs_to_shorter_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build candidate chain: share1(h:1) → share2(h:2) → share3(h:3)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m3 = store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share3.block_hash(), 3, &mut m3, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_top_candidate_height().ok(), Some(3));

        // fork_share: child of share1, h:2, much more cumulative work
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695795)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &fork_share,
                2,
                fork_share.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_share should reorg to the shorter but heavier chain
        let mut batch = Store::get_write_batch();
        store
            .organise_share(fork_share.clone(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // After reorg + confirmed promotion: shorter chain on confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            fork_share.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);

        // Reorged-out shares have Valid status
        let share2_meta = store.get_block_metadata(&share2.block_hash()).unwrap();
        assert_eq!(share2_meta.status, Status::Valid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::Valid);
    }

    #[test_log::test]
    fn test_organise_share_extends_confirmed_and_removes_candidates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share1 (child of genesis) at height 1 and make it a candidate
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let _metadata1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_share(share1.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1 was promoted to confirmed immediately
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);

        // create share2 with prev_share_blockhash = share1 at expected_height 2.
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_share(share2.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // candidate chain should be empty as it is extended on to the confirmed chain
        assert!(store.get_top_candidate().is_err());
    }

    // ── forward walk (extend_candidates_with_children) tests ─────────

    /// share2 arrives filling the gap; forward walk discovers share3.
    ///
    /// Before: genesis(confirmed h:0) → share1(candidate h:1)
    ///         share3(Valid, parent=share2) already in store
    /// Action: add share2(parent=share1) and organise
    /// After:  all promoted to confirmed through h:3
    #[test]
    fn test_forward_walk_single_child() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: child of share1, NOT yet organised (will arrive later)
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share3: child of share2, stored as Valid (arrived out of order)
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .work(3)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2: extends candidate to h:2, forward walk picks up share3
        let mut batch = Store::get_write_batch();
        store.organise_share(share2.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // All promoted to confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(3).unwrap(),
            share3.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 3);
    }

    /// share2 fills gap; forward walk discovers share3 AND share4.
    ///
    /// Before: genesis(confirmed h:0) → share1(candidate h:1)
    ///         share3, share4 stored as Valid
    /// Action: add share2 and organise
    /// After:  all promoted to confirmed through h:4
    #[test]
    fn test_forward_walk_chain_of_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: gap filler (arrives last)
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        // share3: child of share2
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .work(3)
            .nonce(0xe9695794)
            .build();
        // share4: child of share3
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .work(4)
            .nonce(0xe9695795)
            .build();

        // Store share3 and share4 first (out of order), then share2
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_share(&share4, 4, share4.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2: extends to h:2, forward walk fills h:3 and h:4
        let mut batch = Store::get_write_batch();
        store.organise_share(share2.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // All promoted to confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(3).unwrap(),
            share3.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(4).unwrap(),
            share4.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 4);
    }

    /// Reorg replaces candidate chain, then forward walk picks up a
    /// child of the new branch tip.
    ///
    /// Before: genesis → share1(h:1) → share2(h:2)  [candidates]
    ///         fork(h:2, more work, parent=share1) and
    ///         fork_child(h:3, parent=fork) both stored as Valid
    /// Action: organise fork
    /// After:  reorg to share1→fork, forward walk adds fork_child,
    ///         all promoted to confirmed through h:3
    #[test]
    fn test_forward_walk_after_reorg() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // fork: child of share1, h:2, more work
        let fork = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&fork, 2, fork.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // fork_child: child of fork, h:3, stored as Valid
        let fork_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork.block_hash().to_string())
            .work(3)
            .nonce(0xe9695795)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &fork_child,
                3,
                fork_child.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise fork: reorg replaces share2, forward walk picks up fork_child
        let mut batch = Store::get_write_batch();
        store.organise_share(fork.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // All promoted to confirmed
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(store.get_confirmed_at_height(2).unwrap(), fork.block_hash());
        assert_eq!(
            store.get_confirmed_at_height(3).unwrap(),
            fork_child.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 3);

        // Reorged-out share2 has Valid status
        let share2_meta = store.get_block_metadata(&share2.block_hash()).unwrap();
        assert_eq!(share2_meta.status, Status::Valid);
    }

    /// Two children at the same height — forward walk picks the one
    /// with more cumulative work.
    ///
    /// Before: genesis(confirmed h:0), no candidates
    ///         share1(Valid, h:1), share2a(Valid, h:2, low work),
    ///         share2b(Valid, h:2, high work) all stored
    /// Action: organise share1 (becomes candidate, forward walk from h:1)
    /// After:  share2b selected, all promoted to confirmed
    #[test]
    fn test_forward_walk_picks_heaviest_child() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: child of genesis
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2a: child of share1, low work
        let share2a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2a, 2, share2a.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2b: child of share1, high work
        let share2b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(3)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2b, 2, share2b.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share1: becomes candidate at h:1, forward walk finds
        // share2a and share2b — should pick share2b (higher work)
        let mut batch = Store::get_write_batch();
        store.organise_share(share1.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Both promoted to confirmed, share2b selected
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2b.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);

        // share2a stays Valid (not selected)
        let share2a_meta = store.get_block_metadata(&share2a.block_hash()).unwrap();
        assert_eq!(share2a_meta.status, Status::Valid);
    }

    /// Forward walk stops when no qualifying children exist.
    ///
    /// Before: genesis(confirmed h:0) → share1(candidate h:1)
    ///         share2 stored but no share3
    /// Action: organise share2
    /// After:  chain extends to h:2 only, all promoted to confirmed
    #[test]
    fn test_forward_walk_stops_when_no_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: child of share1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2: extends to h:2, no children → stops
        let mut batch = Store::get_write_batch();
        store.organise_share(share2.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // All promoted to confirmed, stops at h:2
        assert!(store.get_top_candidate().is_err());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert!(store.get_confirmed_at_height(3).is_err());
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
        let mut batch = Store::get_write_batch();
        let mut m = store
            .add_share(&child, 1, child.header.get_work(), true, &mut batch)
            .unwrap();
        // Mark as Candidate — should be skipped by pick_best_child
        store
            .append_to_candidates(&child.block_hash(), 1, &mut m, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

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
        let mut batch = Store::get_write_batch();
        store
            .add_share(&child, 1, child.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Ask for height 5 — child is at height 1
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
        let mut batch = Store::get_write_batch();
        store
            .add_share(&child, 1, child.header.get_work(), true, &mut batch)
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
        let mut batch = Store::get_write_batch();
        store
            .add_share(&child, 1, child.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let result = store
            .pick_best_child(&[child.block_hash()], &genesis.block_hash(), 1)
            .unwrap();
        assert!(result.is_some());
        let (hash, metadata) = result.unwrap();
        assert_eq!(hash, child.block_hash());
        assert_eq!(metadata.expected_height, Some(1));
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

        let mut batch = Store::get_write_batch();
        store
            .add_share(&light, 1, light.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_share(&heavy, 1, heavy.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Both are valid children at height 1 — heavy has more work
        let result = store
            .pick_best_child(
                &[light.block_hash(), heavy.block_hash()],
                &genesis.block_hash(),
                1,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());

        // Order shouldn't matter — reverse the input
        let result = store
            .pick_best_child(
                &[heavy.block_hash(), light.block_hash()],
                &genesis.block_hash(),
                1,
            )
            .unwrap();
        assert_eq!(result.unwrap().0, heavy.block_hash());
    }

    #[test]
    fn test_pick_best_child_skips_invalid_among_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // valid_child: Status::Valid (default from add_share)
        let valid_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(1)
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                &valid_child,
                1,
                valid_child.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // candidate_child: marked Candidate (more work but ineligible)
        let candidate_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .work(3)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut m = store
            .add_share(
                &candidate_child,
                1,
                candidate_child.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store
            .append_to_candidates(&candidate_child.block_hash(), 1, &mut m, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // candidate_child has more work but is Candidate status — should be skipped
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
