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

use super::{Chain, Height, Store, TopResult};
use crate::accounting::payout::sharechain_pplns::pplns_window::PRUNE_DEPTH;
use crate::node::request_response_handler::block_fetcher::FETCH_BATCH_SIZE;
use crate::store::writer::StoreError;
use tracing::debug;

impl Store {
    /// Promote candidates to confirmed if conditions are met.
    ///
    /// Strictly follows the candidate chain order: finds the
    /// contiguous prefix of candidates (from confirmed tip + 1) that
    /// have block and uncle data available, then extends or reorgs
    /// the confirmed chain accordingly.
    ///
    /// When no candidate blocks can be promoted (e.g. the candidate
    /// chain is on a fork whose block data is missing), falls back to
    /// confirming any block at confirmed_height + 1 that is a child
    /// of the confirmed tip and has all block and uncle data
    /// available. This allows locally mined blocks to advance the
    /// confirmed chain even when the candidate chain is stuck.
    ///
    /// Returns the new confirmed height if it changed, or None if
    /// unchanged.
    pub(crate) fn organise_block(
        &self,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let top_confirmed = self.get_top_confirmed().map_err(|_| {
            StoreError::Database("organise_block called without a genesis block".into())
        })?;

        let candidate_tip_height = match self.get_top_candidate_height() {
            Ok(height) => height,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let prune_height = candidate_tip_height.saturating_sub(PRUNE_DEPTH as u32);

        let candidates =
            self.find_promotable_candidates(&top_confirmed, candidate_tip_height, prune_height)?;

        if !candidates.is_empty() {
            let promotable_height = candidates.last().unwrap().0;

            if self.should_extend_confirmed(
                &candidates,
                top_confirmed.height,
                top_confirmed.hash,
                prune_height,
            )? {
                return self.extend_confirmed(promotable_height, &candidates, batch);
            }

            if self.should_reorg_confirmed(&top_confirmed, &candidates) {
                return self.reorg_confirmed(&top_confirmed, &candidates, prune_height, batch);
            }
        }

        self.try_fallback_confirmation(&top_confirmed, prune_height, batch)
    }

    /// Fallback: when no candidate chain blocks can be promoted, look
    /// for any block at the next height that is a child of the
    /// confirmed tip with all block and uncle data available.
    fn try_fallback_confirmation(
        &self,
        top_confirmed: &TopResult,
        prune_height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let next_height = top_confirmed.height + 1;
        let height_entries = self.get_blockhashes_for_height_range(next_height, next_height);

        for (_, blockhashes) in &height_entries {
            for blockhash in blockhashes {
                let Some(header) = self.get_share_header(blockhash)? else {
                    continue;
                };
                if header.prev_share_blockhash != top_confirmed.hash {
                    continue;
                }
                if !self.all_block_and_uncle_data_available(&[*blockhash], prune_height)? {
                    continue;
                }
                debug!(
                    "Fallback confirmation: block {blockhash} at height {next_height} \
                     extends confirmed tip"
                );
                let candidates = vec![(next_height, *blockhash)];
                return self.extend_confirmed(next_height, &candidates, batch);
            }
        }

        Ok(None)
    }

    /// Find the contiguous prefix of candidates that are eligible for
    /// promotion to confirmed.
    ///
    /// Blocks below the prune boundary (candidate_tip - PRUNE_DEPTH) do
    /// not require block body data -- they are promoted header-only.
    /// Blocks at or above the boundary require full block data.
    ///
    /// Returns an empty vec when no candidate chain exists or when the
    /// first block above the prune boundary lacks block data.
    fn find_promotable_candidates(
        &self,
        top_confirmed: &TopResult,
        candidate_tip_height: u32,
        prune_height: u32,
    ) -> Result<Chain, StoreError> {
        debug!(
            "Finding promotable candidates: top_confirmed {:?}, candidate_tip_height {}",
            top_confirmed, candidate_tip_height
        );

        let scan_limit = top_confirmed.height + 1 + FETCH_BATCH_SIZE as u32;
        let scan_end = std::cmp::min(scan_limit, candidate_tip_height);
        let all_candidates = self.get_candidates(top_confirmed.height + 1, scan_end)?;
        Ok(self.contiguous_candidates_with_block_data(&all_candidates, prune_height))
    }

    /// Return the contiguous prefix of candidates eligible for promotion.
    ///
    /// Blocks below `prune_height` are allowed without body data (their
    /// PoW was validated at header time). Blocks at or above the boundary
    /// must have full block data stored. Stops at the first block above
    /// the boundary that lacks data.
    fn contiguous_candidates_with_block_data(
        &self,
        candidates: &Chain,
        prune_height: u32,
    ) -> Chain {
        let mut result = Vec::with_capacity(candidates.len());
        for (height, blockhash) in candidates {
            if *height >= prune_height && !self.share_block_exists(blockhash) {
                debug!(
                    "Candidate at height {} ({}) missing block data, stopping promotion",
                    height, blockhash
                );
                return result;
            }
            result.push((*height, *blockhash));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::Status;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    // -- organise_block integration tests --

    #[test]
    fn test_organise_block_returns_none_when_confirmed_caught_up() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Promote a child share so confirmed advances to height 1
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let result = store.push_to_confirmed_chain(&share).unwrap();
        assert_eq!(result, Some(1));
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);

        // Now confirmed == candidate tip. Calling organise_block again
        // must return None since there is nothing new to promote.
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        assert_eq!(
            result, None,
            "organise_block should return None when confirmed has caught up to candidates"
        );
    }

    /// When no candidate chain exists, organise_block must return
    /// None as no new blocks got organised.
    #[test]
    fn test_organise_block_returns_none_when_no_candidates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // No candidate chain exists after genesis setup
        assert!(store.get_top_candidate().is_err());

        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        assert_eq!(
            result, None,
            "organise_block should return None when no candidate chain exists"
        );
    }

    #[test]
    fn test_organise_block_promotes_first_candidate_to_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add a child share and push it through candidate and confirmed chains
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        // setup_genesis does not call append_to_candidate, so no top candidate
        assert!(store.get_top_candidate().is_err());

        store.push_to_confirmed_chain(&share).unwrap();

        // Candidate coexists with confirmed
        assert!(store.get_top_candidate().is_ok());
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);
    }

    #[test]
    fn test_organise_block_extends_candidate_when_conditions_match() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share1 (child of genesis) at height 1 and make it a candidate.
        // Store the block first so chain walks can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // Work in TopResult is cumulative: genesis_work + share1_work
        let genesis_work = genesis.header.get_work();
        let share1_cumulative_work = genesis_work + share1.header.get_work();
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share1.block_hash(),
                height: 1,
                work: share1_cumulative_work,
            })
        );

        // create share_to_organise with prev_share_blockhash = share1 at expected_height 2.
        let share_to_organise = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        store.push_to_confirmed_chain(&share_to_organise).unwrap();

        // Candidates coexist with confirmed
        assert!(store.get_top_candidate().is_ok());
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

    /// Pushing a share that neither extends nor reorgs the candidate
    /// chain leaves the chain unchanged.
    ///
    /// Scenario: genesis -> share1(h:1) -> share2(h:2) as candidates.
    /// Then push orphan_share (unknown parent, h:1, low work) which
    /// cannot extend (parent is not top candidate) and cannot reorg
    /// (cumulative work is less than the top candidate).
    #[test]
    fn test_organise_block_noop_when_height_condition_not_met() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build candidate chain: share1(h:1) -> share2(h:2)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let top_before = store.get_top_candidate().unwrap();
        assert_eq!(top_before.hash, share2.block_hash());
        assert_eq!(top_before.height, 2);

        // orphan_share has an unknown parent so organise_header
        // returns an error for missing parent.
        let orphan_share = TestShareBlockBuilder::new().nonce(0xe9695794).build();
        let result = store.push_to_candidate_chain(&orphan_share);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        let top_after = store.get_top_candidate().unwrap();
        assert_eq!(top_after.hash, share2.block_hash());
        assert_eq!(top_after.height, 2);
    }

    // -- reorg_candidate integration tests --

    /// Test reorg replacing the top candidate with a sibling fork.
    ///
    /// Before:  share1(h:1) -> share2(h:2)  [top at h:2]
    /// Fork:    share1(h:1) -> fork_share(h:2, more work)
    /// After:   share1(h:1) -> fork_share(h:2)  [top at h:2]
    #[test]
    fn test_organise_block_reorgs_when_fork_has_more_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis (confirmed at h:0)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: child of genesis, candidate at h:1.
        // Store block first so reorg chain walks can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: child of share1, candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        // Work in TopResult is cumulative: genesis + share1 + share2
        let genesis_work = genesis.header.get_work();
        let share2_cumulative_work =
            genesis_work + share1.header.get_work() + share2.header.get_work();
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share2.block_hash(),
                height: 2,
                work: share2_cumulative_work,
            })
        );

        // fork_share: child of share1, at h:2, with MORE cumulative work.
        // Store block and create Valid metadata so reorg_candidate can
        // read the metadata from committed DB state (the WriteBatch
        // inside organise_header is not yet committed when reorg runs).
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&fork_share);

        // push_to_confirmed_chain reorgs candidate chain and promotes to confirmed
        store.push_to_confirmed_chain(&fork_share).unwrap();

        // After reorg + confirmed promotion: candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
        assert_eq!(share2_metadata.status, Status::HeaderValid);
    }

    /// Test deeper reorg replacing multiple candidates with a competing branch.
    ///
    /// Before:  share1(h:1) -> share2(h:2) -> share3(h:3)  [top at h:3]
    /// Fork:    share1(h:1) -> fork2(h:2) -> fork3(h:3, more work)
    /// After:   all promoted to confirmed
    #[test]
    fn test_organise_block_reorgs_deeper_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build candidate chain: share1(h:1) -> share2(h:2) -> share3(h:3).
        // Store share1 block so reorg chain walks can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_candidate_chain(&share3).unwrap();

        // Work in TopResult is cumulative: genesis + share1 + share2 + share3
        let genesis_work = genesis.header.get_work();
        let share3_cumulative_work = genesis_work
            + share1.header.get_work()
            + share2.header.get_work()
            + share3.header.get_work();
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share3.block_hash(),
                height: 3,
                work: share3_cumulative_work,
            })
        );

        // Build fork: share1 -> fork2(h:2) -> fork3(h:3, more work).
        // Store both with Valid metadata so reorg_candidate can read
        // their metadata from committed DB state.
        let fork2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695795)
            .build();
        store.store_with_valid_metadata(&fork2);

        let fork3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork2.block_hash().to_string())
            .work(2)
            .nonce(0xe9695796)
            .build();
        store.store_with_valid_metadata(&fork3);

        // push_to_confirmed_chain reorgs candidate chain and promotes to confirmed
        store.push_to_confirmed_chain(&fork3).unwrap();

        // After reorg + confirmed promotion: candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
        assert_eq!(share2_meta.status, Status::HeaderValid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::HeaderValid);
    }

    /// Test reorg to a shorter fork (fork has fewer blocks but more work).
    ///
    /// Before:  share1(h:1) -> share2(h:2) -> share3(h:3)  [top at h:3]
    /// Fork:    share1(h:1) -> fork_share(h:2, much more work)
    /// After:   all promoted to confirmed
    #[test]
    fn test_organise_block_reorgs_to_shorter_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup genesis
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build candidate chain: share1(h:1) -> share2(h:2) -> share3(h:3).
        // Store share1 block so reorg chain walks can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_candidate_chain(&share3).unwrap();

        assert_eq!(store.get_top_candidate_height().ok(), Some(3));

        // fork_share: child of share1, h:2, much more cumulative work.
        // Store block and create Valid metadata so reorg_candidate can
        // read the metadata from committed DB state.
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695795)
            .build();
        store.store_with_valid_metadata(&fork_share);

        // push_to_confirmed_chain reorgs candidate chain and promotes to confirmed
        store.push_to_confirmed_chain(&fork_share).unwrap();

        // After reorg + confirmed promotion: candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
        assert_eq!(share2_meta.status, Status::HeaderValid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::HeaderValid);
    }

    #[test_log::test]
    fn test_organise_block_extends_confirmed_and_keeps_candidates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add share1 (child of genesis) at height 1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // share1 promoted to confirmed, candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
        store.push_to_confirmed_chain(&share2).unwrap();

        // candidate chain coexists with confirmed chain
        assert!(store.get_top_candidate().is_ok());
    }

    // -- forward walk (extend_candidates_with_children) tests --

    /// share2 arrives filling the gap; forward walk discovers share3.
    ///
    /// Before: genesis(confirmed h:0) -> share1(candidate h:1)
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

        // share1: candidate at h:1.
        // Store block first so confirmed extension can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: child of share1, NOT yet organised (will arrive later).
        // Create metadata only so share3 can compute its cumulative
        // height and work from share2.
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        store.create_valid_metadata_only(&share2);

        // share3: child of share2, stored as Valid with metadata (arrived out of order)
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .work(3)
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&share3);

        // Push share2 to confirmed chain: extends candidate to h:2, forward walk picks up share3
        store.push_to_confirmed_chain(&share2).unwrap();

        // All promoted to confirmed, candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
    /// Before: genesis(confirmed h:0) -> share1(candidate h:1)
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

        // share1: candidate at h:1.
        // Store block first so confirmed extension can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: gap filler (arrives last).
        // Create metadata only so share3 can compute its cumulative
        // height and work from share2.
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        store.create_valid_metadata_only(&share2);

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

        // Store share3 and share4 first (out of order) with Valid metadata
        store.store_with_valid_metadata(&share3);
        store.store_with_valid_metadata(&share4);

        // Push share2 to confirmed chain: extends to h:2, forward walk fills h:3 and h:4
        store.push_to_confirmed_chain(&share2).unwrap();

        // All promoted to confirmed, candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
    /// Before: genesis -> share1(h:1) -> share2(h:2)  [candidates]
    ///         fork(h:2, more work, parent=share1) and
    ///         fork_child(h:3, parent=fork) both stored as Valid
    /// Action: organise fork
    /// After:  reorg to share1->fork, forward walk adds fork_child,
    ///         all promoted to confirmed through h:3
    #[test]
    fn test_forward_walk_after_reorg() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1.
        // Store block first so reorg chain walks and confirmed extension can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        // fork: child of share1, h:2, more work.
        // Store block first so reorg chain walk can find its header.
        let fork = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&fork, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // fork_child: child of fork, h:3, stored as Valid with metadata.
        // fork's metadata must exist for fork_child to compute correct
        // cumulative height and work. Create fork's metadata only.
        store.create_valid_metadata_only(&fork);

        let fork_child = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork.block_hash().to_string())
            .work(3)
            .nonce(0xe9695795)
            .build();
        store.store_with_valid_metadata(&fork_child);

        // Push fork to confirmed chain: reorg replaces share2, forward walk picks up fork_child
        store.push_to_confirmed_chain(&fork).unwrap();

        // All promoted to confirmed, candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
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
        assert_eq!(share2_meta.status, Status::HeaderValid);
    }

    /// Two children at the same height -- forward walk picks the one
    /// with more cumulative work.
    ///
    /// Setup: genesis(confirmed h:0)
    ///        share1(stored with Valid metadata at h:1)
    ///        share2a(Valid, h:2, low work) and share2b(Valid, h:2, high work)
    ///        all stored with metadata before organising.
    /// Action: push share1 to confirmed chain -- organise_header makes
    ///         share1 candidate, forward walk discovers share2a and share2b,
    ///         picks share2b (heaviest). Then organise_block promotes all
    ///         to confirmed.
    /// After:  share2b selected at h:2, all promoted to confirmed
    #[test]
    fn test_forward_walk_picks_heaviest_child() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: child of genesis. Store with Valid metadata so
        // share2a/share2b can compute their cumulative work from it.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.store_with_valid_metadata(&share1);

        // share2a: child of share1, low work (stored as Valid with metadata)
        let share2a = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        store.store_with_valid_metadata(&share2a);

        // share2b: child of share1, high work (stored as Valid with metadata)
        let share2b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(3)
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&share2b);

        // Push share1 to confirmed chain. organise_header makes share1
        // candidate at h:1, forward walk discovers share2a and share2b
        // and picks share2b (higher cumulative work). Then organise_block
        // promotes candidates to confirmed.
        store.push_to_confirmed_chain(&share1).unwrap();

        // share2b promoted to confirmed, candidate chain coexists
        assert!(store.get_top_candidate().is_ok());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2b.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);

        // share2a stays Valid (not selected)
        let share2a_meta = store.get_block_metadata(&share2a.block_hash()).unwrap();
        assert_eq!(share2a_meta.status, Status::HeaderValid);
    }

    /// When the first candidate lacks block data, organise_block must
    /// return None and not promote anything.
    #[test]
    fn test_organise_block_skips_candidate_without_block_data() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Push two candidates via push_to_candidate_chain (header only, no block body)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        // Candidates exist but lack block data
        assert_eq!(store.get_top_candidate_height().ok(), Some(2));
        assert!(!store.share_block_exists(&share1.block_hash()));

        // organise_block should not promote since first candidate has no block data
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        assert_eq!(
            result, None,
            "organise_block should not promote candidates without block data"
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 0);
    }

    /// When the first two candidates have block data but the third does not,
    /// organise_block promotes only the first two.
    #[test]
    fn test_organise_block_promotes_contiguous_prefix_with_block_data() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: store full block data then push to candidate chain
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: store full block data then push to candidate chain
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share2).unwrap();

        // share3: header only, no block data
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_candidate_chain(&share3).unwrap();

        assert_eq!(store.get_top_candidate_height().ok(), Some(3));
        assert!(store.share_block_exists(&share1.block_hash()));
        assert!(store.share_block_exists(&share2.block_hash()));
        assert!(!store.share_block_exists(&share3.block_hash()));

        // organise_block should promote only share1 and share2
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(result, Some(2));
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        // share3 not promoted
        assert!(store.get_confirmed_at_height(3).is_err());
    }

    /// Forward walk stops when no qualifying children exist.
    ///
    /// Before: genesis(confirmed h:0) -> share1(candidate h:1)
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

        // share1: candidate at h:1.
        // Store block first so confirmed extension can find its header.
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: child of share1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();

        // Push share2 to confirmed chain: extends to h:2, no children -> stops
        store.push_to_confirmed_chain(&share2).unwrap();

        // All promoted to confirmed, candidate chain coexists, stops at h:2
        assert!(store.get_top_candidate().is_ok());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert!(store.get_confirmed_at_height(3).is_err());
    }

    /// Candidate chain reorg allows confirmation when the old
    /// candidate fork lacks block data.
    ///
    /// Scenario:
    /// - genesis -> share1(h:1) confirmed
    /// - Candidate chain on a fork (header-only, no block data)
    /// - Local block at h:2 with parent = share1, with block data
    /// - organise_header reorgs candidate chain to include local block
    /// - organise_block confirms from the new candidate chain
    #[test]
    fn test_candidate_reorg_allows_confirmation_after_stuck_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: confirmed at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);

        // fork_share: different child of genesis, candidate at h:1 on a
        // different fork. Push header only (no block data).
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.push_to_candidate_chain(&fork_share).unwrap();

        // Candidate tip is on the fork at h:1 with no block data
        assert!(!store.share_block_exists(&fork_share.block_hash()));

        // organise_block returns None: candidate has no block data
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        assert_eq!(result, None, "Candidates stuck on fork with no data");

        // local_block: child of share1 (confirmed tip), WITH block data.
        let local_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695801)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&local_block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header reorgs candidate chain if local_block has
        // more cumulative work than the fork. After this, the candidate
        // chain includes local_block.
        let mut batch = Store::get_write_batch();
        store
            .organise_header(&local_block.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Now organise_block confirms from the candidate chain
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(result, Some(2));
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            local_block.block_hash()
        );
    }

    /// Fallback confirmation when candidate chain is stuck on a fork
    /// whose block data is missing and the local block cannot reorg
    /// the candidate chain (equal cumulative work).
    ///
    /// Scenario:
    /// - genesis -> share1(h:1) confirmed
    /// - Candidate chain on a fork at h:1 (header only, no block data)
    ///   with a second fork block at h:2 (header only) keeping the
    ///   candidate tip ahead
    /// - Local block at h:2, parent = share1, WITH block data
    /// - Local block has equal cumulative work so cannot reorg candidates
    /// - organise_block falls back to confirming the local block
    #[test]
    fn test_fallback_confirms_block_when_candidate_chain_stuck() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: confirmed at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);

        // fork_share: different child of genesis on a competing fork.
        // Header only, no block data.
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.push_to_candidate_chain(&fork_share).unwrap();

        // fork_share2: extends fork to h:2 (header only, no block data).
        // This keeps the candidate tip ahead of confirmed.
        let fork_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork_share.block_hash().to_string())
            .nonce(0xe9695800)
            .build();
        store.push_to_candidate_chain(&fork_share2).unwrap();
        assert_eq!(store.get_top_candidate_height().ok(), Some(2));

        // local_block: child of share1 (confirmed tip), WITH block data.
        // It has equal cumulative work to fork_share at the same height,
        // so organise_header cannot reorg the candidate chain.
        let local_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695801)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&local_block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let mut batch = Store::get_write_batch();
        store
            .organise_header(&local_block.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain still on the fork (local block could not reorg)
        assert!(!store.share_block_exists(&fork_share.block_hash()));

        // organise_block: candidate chain has no block data at h:1,
        // so find_promotable_candidates returns empty. Fallback finds
        // local_block at h:2 with parent = confirmed tip and confirms it.
        let mut batch = Store::get_write_batch();
        let result = store.organise_block(&mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(result, Some(2));
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            local_block.block_hash()
        );
    }

    /// contiguous_candidates_with_block_data allows blocks below
    /// prune_height without body data. Test by calling it directly with
    /// an artificial prune_height.
    #[test]
    fn test_contiguous_candidates_allows_prune_zone_blocks_without_body() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build 3 candidates: header-only (no body)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_candidate_chain(&share3).unwrap();

        let candidates: Chain = vec![
            (1, share1.block_hash()),
            (2, share2.block_hash()),
            (3, share3.block_hash()),
        ];

        // prune_height = 4: all blocks (1,2,3) below boundary, no body needed
        let result = store.contiguous_candidates_with_block_data(&candidates, 4);
        assert_eq!(result.len(), 3, "All 3 should pass when below prune_height");

        // prune_height = 2: block at height 1 is below (OK), height 2 needs body
        let result = store.contiguous_candidates_with_block_data(&candidates, 2);
        assert_eq!(
            result.len(),
            1,
            "Only block at height 1 should pass (below 2), height 2 needs body"
        );

        // prune_height = 0: all blocks need body, none have it
        let result = store.contiguous_candidates_with_block_data(&candidates, 0);
        assert_eq!(
            result.len(),
            0,
            "No blocks should pass when all need body data"
        );
    }

    /// contiguous_candidates_with_block_data stops at the first block
    /// above prune_height that lacks body, even if later blocks have it.
    #[test]
    fn test_contiguous_candidates_stops_at_first_gap_above_prune_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: header only (no body)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: header only (no body)
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_candidate_chain(&share2).unwrap();

        // share3: has full body
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.store_with_valid_metadata(&share3);

        let candidates: Chain = vec![
            (1, share1.block_hash()),
            (2, share2.block_hash()),
            (3, share3.block_hash()),
        ];

        // prune_height = 2: height 1 is below (OK without body),
        // height 2 is at boundary (needs body, missing) -> stops
        // share3 at height 3 has body but is never reached
        let result = store.contiguous_candidates_with_block_data(&candidates, 2);
        assert_eq!(
            result.len(),
            1,
            "Should stop at height 2 (missing body at boundary)"
        );
    }
}
