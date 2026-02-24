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

    /// Helper: organise a header into the candidate chain and commit.
    fn organise_header_and_commit(store: &Store, header: &crate::shares::share_block::ShareHeader) {
        let mut batch = Store::get_write_batch();
        store.organise_header(header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
    }

    /// Helper: promote candidates to confirmed and commit.
    fn organise_block_and_commit(store: &Store) {
        let mut batch = Store::get_write_batch();
        store.organise_block(&mut batch).unwrap();
        store.commit_batch(batch).unwrap();
    }

    // -- organise_block integration tests --

    #[test]
    fn test_organise_block_promotes_first_candidate_to_confirmed() {
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
            .add_share_block(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // setup_genesis does not call append_to_candidate, so no top candidate
        assert!(store.get_top_candidate().is_err());

        organise_header_and_commit(&store, &share.header);
        organise_block_and_commit(&store);

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

        // Add share1 (child of genesis) at height 1 and make it a candidate
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
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
        let share_to_organise = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(
                &share_to_organise,
                2,
                share_to_organise.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        organise_header_and_commit(&store, &share_to_organise.header);
        organise_block_and_commit(&store);

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

    #[test]
    fn test_organise_block_noop_when_height_condition_not_met() {
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
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header does not extend (conditions not met)
        organise_header_and_commit(&store, &share.header);

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

        // share1: child of genesis, candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: child of share1, candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch)
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
            .add_share_block(
                &fork_share,
                2,
                fork_share.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header reorgs candidate chain, organise_block promotes
        organise_header_and_commit(&store, &fork_share.header);
        organise_block_and_commit(&store);

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
        assert_eq!(share2_metadata.status, Status::Valid);
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

        // Build candidate chain: share1(h:1) -> share2(h:2) -> share3(h:3)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata3 = store
            .add_share_block(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share3.block_hash(), 3, &mut metadata3, &mut batch)
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

        // Build fork: share1 -> fork2(h:2) -> fork3(h:3, more work)
        let fork2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695795)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&fork2, 2, fork2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let fork3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork2.block_hash().to_string())
            .work(2)
            .nonce(0xe9695796)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&fork3, 3, fork3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header reorgs candidate chain, organise_block promotes
        organise_header_and_commit(&store, &fork3.header);
        organise_block_and_commit(&store);

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
        assert_eq!(share2_meta.status, Status::Valid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::Valid);
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

        // Build candidate chain: share1(h:1) -> share2(h:2) -> share3(h:3)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata3 = store
            .add_share_block(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share3.block_hash(), 3, &mut metadata3, &mut batch)
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
            .add_share_block(
                &fork_share,
                2,
                fork_share.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header reorgs candidate chain, organise_block promotes
        organise_header_and_commit(&store, &fork_share.header);
        organise_block_and_commit(&store);

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
        assert_eq!(share2_meta.status, Status::Valid);
        let share3_meta = store.get_block_metadata(&share3.block_hash()).unwrap();
        assert_eq!(share3_meta.status, Status::Valid);
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
        let mut batch = Store::get_write_batch();
        let _metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        organise_header_and_commit(&store, &share1.header);
        organise_block_and_commit(&store);

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
        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        organise_header_and_commit(&store, &share2.header);
        organise_block_and_commit(&store);

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

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
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
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
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
            .add_share_block(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2 header: extends candidate to h:2, forward walk picks up share3
        organise_header_and_commit(&store, &share2.header);
        organise_block_and_commit(&store);

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

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
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
            .add_share_block(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&share4, 4, share4.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2 header: extends to h:2, forward walk fills h:3 and h:4
        organise_header_and_commit(&store, &share2.header);
        organise_block_and_commit(&store);

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

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2: candidate at h:2
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch)
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
            .add_share_block(&fork, 2, fork.header.get_work(), true, &mut batch)
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
            .add_share_block(
                &fork_child,
                3,
                fork_child.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise fork header: reorg replaces share2, forward walk picks up fork_child
        organise_header_and_commit(&store, &fork.header);
        organise_block_and_commit(&store);

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
        assert_eq!(share2_meta.status, Status::Valid);
    }

    /// Two children at the same height -- forward walk picks the one
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
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
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
            .add_share_block(&share2a, 2, share2a.header.get_work(), true, &mut batch)
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
            .add_share_block(&share2b, 2, share2b.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share1 header: becomes candidate at h:1, forward walk finds
        // share2a and share2b -- should pick share2b (higher work)
        organise_header_and_commit(&store, &share1.header);
        organise_block_and_commit(&store);

        // Both promoted to confirmed, candidate chain coexists, share2b selected
        assert!(store.get_top_candidate().is_ok());
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

        // share1: candidate at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share_block(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut metadata1, &mut batch)
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
            .add_share_block(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Organise share2 header: extends to h:2, no children -> stops
        organise_header_and_commit(&store, &share2.header);
        organise_block_and_commit(&store);

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
