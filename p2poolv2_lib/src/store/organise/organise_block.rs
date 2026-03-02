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

use crate::store::writer::StoreError;

use super::{Height, Store};

impl Store {
    /// Promote candidates to confirmed if conditions are met.
    ///
    /// Reads the candidate and confirmed chain state from committed RocksDB
    /// state and checks whether the candidate chain should extend or reorg
    /// the confirmed chain. Does not touch the candidate chain.
    ///
    /// Returns the new confirmed height if it changed, or None if unchanged.
    pub(crate) fn organise_block(
        &self,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let top_confirmed = self.get_top_confirmed().map_err(|_| {
            StoreError::Database("organise_block called without a genesis block".into())
        })?;

        let Ok(top_candidate) = self.get_top_candidate() else {
            return Ok(Some(top_confirmed.height));
        };

        let candidates = self.get_candidates(top_confirmed.height + 1, top_candidate.height)?;

        if candidates.is_empty() {
            return Ok(Some(top_confirmed.height));
        }

        if self.should_extend_confirmed(&candidates, top_confirmed.height, top_confirmed.hash)? {
            return self.extend_confirmed(top_candidate.height, &candidates, batch);
        }

        if self.should_reorg_confirmed(&top_confirmed, &candidates) {
            return self.reorg_confirmed(&top_confirmed, &candidates, batch);
        }

        Ok(None)
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

        store.push_to_confirmed_chain(&share, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store
            .push_to_confirmed_chain(&share_to_organise, true)
            .unwrap();

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

        // orphan_share has an unknown parent so organise_header computes
        // height 1 with only its own work. That work is less than the
        // top candidate cumulative work, so neither extend nor reorg fires.
        let orphan_share = TestShareBlockBuilder::new().nonce(0xe9695794).build();
        let result = store.push_to_candidate_chain(&orphan_share).unwrap();

        // Candidate chain unchanged
        assert!(result.is_none());
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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&fork_share, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&fork3, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&fork_share, true).unwrap();

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
        store.push_to_confirmed_chain(&share1, true).unwrap();

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
        store.push_to_confirmed_chain(&share2, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&share2, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&share2, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
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
        store.add_share_block(&fork, true, &mut batch).unwrap();
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
        store.push_to_confirmed_chain(&fork, true).unwrap();

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
        store.push_to_confirmed_chain(&share1, true).unwrap();

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
        store.add_share_block(&share1, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        store.push_to_candidate_chain(&share1).unwrap();

        // share2: child of share1
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();

        // Push share2 to confirmed chain: extends to h:2, no children -> stops
        store.push_to_confirmed_chain(&share2, true).unwrap();

        // All promoted to confirmed, candidate chain coexists, stops at h:2
        assert!(store.get_top_candidate().is_ok());
        assert_eq!(
            store.get_confirmed_at_height(2).unwrap(),
            share2.block_hash()
        );
        assert_eq!(store.get_top_confirmed_height().unwrap(), 2);
        assert!(store.get_confirmed_at_height(3).is_err());
    }
}
