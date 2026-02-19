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
            Some((new_candidate_height, candidates)) => self.update_confirmed_chain(
                &top_confirmed,
                new_candidate_height,
                candidates.as_ref(),
                batch,
            ),
            None => Ok(Some(top_confirmed.height)), // candidate chain is unchanged, nothing to do for confirmed
        }
    }

    /// Update confirmed chain by either extending it or reorging confirmed chain.
    /// Returns the top confirmed height if it changes, else None.
    fn update_confirmed_chain(
        &self,
        top_confirmed: &TopResult,
        new_candidate_height: Height,
        candidates: &Chain,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        if self.should_extend_confirmed(candidates, top_confirmed.height, top_confirmed.hash)? {
            return self.extend_confirmed(new_candidate_height, candidates, batch);
        }

        if self.should_reorg_confirmed(top_confirmed, candidates) {
            return self.reorg_confirmed(top_confirmed, candidates, batch);
        }

        Ok(None)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::Status;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

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
}
