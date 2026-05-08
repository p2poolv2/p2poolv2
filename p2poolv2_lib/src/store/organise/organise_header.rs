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

use crate::store::block_tx_metadata::Status;
use crate::{
    shares::share_block::ShareHeader,
    store::{block_tx_metadata::BlockMetadata, writer::StoreError},
};
use bitcoin::BlockHash;
use tracing::debug;

use super::{Height, Store, TopResult};

impl Store {
    /// Organise a share header into the candidate chain.
    ///
    /// Reads block metadata, top candidate, and top confirmed from the store,
    /// then extends or reorgs the candidate chain as needed. Also marks any
    /// uncles referenced by the header in the uncles index so that
    /// find_uncles will not select them again.
    ///
    /// Returns the new candidate height and chain if the candidate chain
    /// changed, or None if unchanged.
    pub(crate) fn organise_header(
        &self,
        header: &ShareHeader,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let blockhash = header.block_hash();
        debug!(
            "organise_header called for {blockhash} with prev blockhash {}",
            header.prev_share_blockhash
        );

        let mut metadata = match self.get_block_metadata(&blockhash) {
            Ok(existing) => {
                debug!("Block {blockhash} already has metadata, skipping header setup");
                self.repair_height_index_if_needed(header, &blockhash, &existing, batch)?;
                existing
            }
            Err(_) => {
                let metadata = self.initialise_new_header(header, &blockhash, batch)?;
                // Commit the header and metadata now so that subsequent
                // reads in reorg_candidate -> get_branch_to_chain can
                // find this header in the database. Without this commit
                // the header only exists in the uncommitted WriteBatch
                // and the reorg walk fails with "branch point not found".
                self.commit_batch(std::mem::take(batch))
                    .map_err(|error| StoreError::Database(error.to_string()))?;
                *batch = Store::get_write_batch();
                metadata
            }
        };

        let top_candidate = self.get_top_candidate().ok();
        let Some(top_confirmed) = self.get_top_confirmed().ok() else {
            return Err(StoreError::Database(
                "organise_header called without a genesis block".into(),
            ));
        };

        debug!("top candidate {:?}", top_candidate);
        debug!("top confirmed {:?}", top_confirmed);

        if let Some(extended_height) =
            self.should_extend_candidates(header, &metadata, top_candidate.as_ref())?
        {
            return self.extend_candidate_chain(&blockhash, extended_height, &mut metadata, batch);
        }

        if self.should_reorg_candidate(&blockhash, &metadata, top_candidate.as_ref()) {
            return self.reorg_candidate_chain(&blockhash, top_candidate.as_ref(), batch);
        }

        Ok(None)
    }

    /// Extend the candidate chain with a new block and walk forward
    /// to include any children that were waiting for this block.
    fn extend_candidate_chain(
        &self,
        blockhash: &BlockHash,
        extended_height: Height,
        metadata: &mut BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        debug!("Extending candidate");
        self.append_to_candidates(blockhash, extended_height, metadata, batch)?;

        let mut new_entries = vec![(extended_height, *blockhash)];
        let final_height = self.extend_candidates_with_children(
            extended_height,
            blockhash,
            &mut new_entries,
            batch,
        )?;
        debug!("new candidate height after extending candidates {final_height}");
        Ok(Some(final_height))
    }

    /// Reorg the candidate chain to a fork with more work, then walk
    /// forward to include any children beyond the new tip.
    fn reorg_candidate_chain(
        &self,
        blockhash: &BlockHash,
        top_candidate: Option<&TopResult>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Option<Height>, StoreError> {
        let (new_height, reorg_chain) = self.reorg_candidate(blockhash, top_candidate, batch)?;
        debug!("new candidate height after reorging candidates {new_height}");

        let reorg_tip_hash = reorg_chain.last().expect("reorg chain is non-empty").1;
        let mut new_entries = Vec::new();
        let final_height = self.extend_candidates_with_children(
            new_height,
            &reorg_tip_hash,
            &mut new_entries,
            batch,
        )?;
        debug!("new candidate height after reorg + forward walk {final_height}");
        Ok(Some(final_height))
    }

    /// Ensure the height-to-blockhash index contains this block.
    ///
    /// When a block's metadata already exists (e.g. from a previous
    /// gossip or partial sync), `initialise_new_header` is skipped.
    /// This means `set_height_to_blockhash` was never called for this
    /// height, leaving the block invisible to height-based scans such
    /// as `get_candidate_blocks_missing_data`. This function checks
    /// whether the block appears in the height index at its expected
    /// height and adds it if missing.
    fn repair_height_index_if_needed(
        &self,
        header: &ShareHeader,
        blockhash: &BlockHash,
        metadata: &BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let expected_height = match metadata.expected_height {
            Some(height) => height,
            None => return Ok(()),
        };

        let existing_hashes = self.get_blockhashes_for_height(expected_height);
        if existing_hashes.contains(blockhash) {
            return Ok(());
        }

        debug!("Repairing missing height index entry for {blockhash} at height {expected_height}");
        self.add_share_header(header, batch)?;
        self.set_height_to_blockhash(blockhash, expected_height, batch)?;
        Ok(())
    }

    /// Persist a new header and initialise its metadata.
    ///
    /// Stores the header, computes height and chain work from the
    /// parent, records uncle references in the block and uncles
    /// indexes, and writes initial metadata with HeaderValid status.
    fn initialise_new_header(
        &self,
        header: &ShareHeader,
        blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<BlockMetadata, StoreError> {
        self.add_share_header(header, batch)?;

        let share_work = header.get_work();

        let prev_metadata = self
            .get_block_metadata(&header.prev_share_blockhash)
            .map_err(|_| {
                StoreError::NotFound(format!(
                    "Parent {} not found for block {}",
                    header.prev_share_blockhash, blockhash
                ))
            })?;
        let prev_height = prev_metadata.expected_height.ok_or_else(|| {
            StoreError::Database(format!(
                "Parent {} has no expected height for block {}",
                header.prev_share_blockhash, blockhash
            ))
        })?;
        let new_height = prev_height + 1;
        let new_chain_work = prev_metadata.chain_work + share_work;

        for uncle_blockhash in &header.uncles {
            self.update_block_index(uncle_blockhash, blockhash, batch)?;
            self.add_to_uncles_index(uncle_blockhash, blockhash, batch)?;
        }

        self.set_height_to_blockhash(blockhash, new_height, batch)?;
        let metadata = BlockMetadata {
            expected_height: Some(new_height),
            chain_work: new_chain_work,
            status: Status::HeaderValid,
        };
        self.update_block_metadata(blockhash, &metadata, batch)?;

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::organise::TopResult;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    #[test]
    fn test_organise_header_extends_first_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add a child share so its block data is stored
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // No top candidate before organising
        assert!(store.get_top_candidate().is_err());

        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&share.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain should be updated
        assert!(result.is_some());
        let height = result.unwrap();
        assert_eq!(height, 1);

        // Top candidate work is cumulative: genesis_work + share_work
        let cumulative_work = genesis.header.get_work() + share.header.get_work();
        assert_eq!(
            store.get_top_candidate().ok(),
            Some(TopResult {
                hash: share.block_hash(),
                height: 1,
                work: cumulative_work,
            })
        );
    }

    /// Pushing a share that neither extends nor reorgs the candidate
    /// chain leaves the chain unchanged.
    ///
    /// Scenario: genesis -> share1(h:1) -> share2(h:2) as candidates.
    /// Then organise orphan_share (unknown parent, h:1, low work) which
    /// cannot extend (parent is not top candidate) and cannot reorg
    /// (cumulative work is less than the top candidate).
    #[test]
    fn test_organise_header_noop_when_conditions_not_met() {
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
        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&orphan_share.header, &mut batch);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
        let top_after = store.get_top_candidate().unwrap();
        assert_eq!(top_after.hash, share2.block_hash());
        assert_eq!(top_after.height, 2);
    }

    #[test]
    fn test_organise_header_reorgs_when_fork_has_more_work() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: candidate at h:1.
        // Store block first so reorg chain walks can find its header.
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

        // fork_share: child of share1, h:2, MORE cumulative work.
        // Store block and create Valid metadata so reorg_candidate can
        // read the metadata from committed DB state (the WriteBatch
        // inside organise_header is not yet committed when reorg runs).
        let fork_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695794)
            .build();
        {
            let blockhash = fork_share.block_hash();
            let share_work = fork_share.header.get_work();
            let parent_metadata = store
                .get_block_metadata(&fork_share.header.prev_share_blockhash)
                .unwrap();
            let parent_height = parent_metadata.expected_height.unwrap_or_default();
            let height = parent_height + 1;
            let chain_work = parent_metadata.chain_work + share_work;
            let mut batch = Store::get_write_batch();
            store.add_share_block(&fork_share, &mut batch).unwrap();
            store
                .set_height_to_blockhash(&blockhash, height, &mut batch)
                .unwrap();
            let metadata = BlockMetadata {
                expected_height: Some(height),
                chain_work,
                status: Status::HeaderValid,
            };
            store
                .update_block_metadata(&blockhash, &metadata, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // Organise candidate with fork_share header
        let mut batch = Store::get_write_batch();
        let result = store
            .organise_header(&fork_share.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain should be reorged
        assert!(result.is_some());

        // Top candidate should be fork_share
        let top = store.get_top_candidate().unwrap();
        assert_eq!(top.hash, fork_share.block_hash());
    }

    /// Organising a header that references uncles should mark those
    /// uncles in the uncles index so find_uncles excludes them later.
    ///
    /// Scenario: genesis -> share1(h:1, confirmed) with uncle_block as
    /// a fork at h:1. share2(h:2) includes uncle_block as an uncle.
    /// After organising share2, uncle_block should be marked as already
    /// used in the uncles index.
    #[test]
    fn test_organise_header_marks_uncles_in_uncles_index() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1: child of genesis, will be confirmed at h:1
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // uncle_block: fork child of genesis (sibling of share1)
        let uncle_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.store_with_valid_metadata(&uncle_block);

        // uncle_block should not be marked as uncle yet
        assert!(!store.is_already_uncle(&uncle_block.block_hash()));

        // share2: child of share1, includes uncle_block as uncle
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle_block.block_hash()])
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_header(&share2.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // uncle_block should now be marked in the uncles index
        assert!(store.is_already_uncle(&uncle_block.block_hash()));

        // The nephew recorded for uncle_block should be share2
        let nephews = store.get_nephews(&uncle_block.block_hash()).unwrap();
        assert_eq!(nephews.len(), 1);
        assert_eq!(nephews[0], share2.block_hash());
    }

    /// Organising a header with multiple uncles should mark all of them
    /// in the uncles index.
    #[test]
    fn test_organise_header_marks_multiple_uncles() {
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
        store.push_to_confirmed_chain(&share1).unwrap();

        // Two fork blocks at h:1
        let uncle_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695801)
            .build();
        let uncle_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695802)
            .build();
        store.store_with_valid_metadata(&uncle_a);
        store.store_with_valid_metadata(&uncle_b);

        assert!(!store.is_already_uncle(&uncle_a.block_hash()));
        assert!(!store.is_already_uncle(&uncle_b.block_hash()));

        // share2 includes both uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle_a.block_hash(), uncle_b.block_hash()])
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&share2, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.organise_header(&share2.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Both uncles should be marked
        assert!(store.is_already_uncle(&uncle_a.block_hash()));
        assert!(store.is_already_uncle(&uncle_b.block_hash()));
    }

    /// After organising a header with uncles, find_uncles should no
    /// longer return those uncles.
    #[test]
    fn test_organise_header_uncles_excluded_from_find_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Build: genesis -> share1(h:1) -> share2(h:2) -> share3(h:3)
        // with uncle_block as fork child of share1 (at h:2)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        // uncle_block: fork child of genesis at h:1 (sibling of share1)
        let uncle_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695799)
            .build();
        store.store_with_valid_metadata(&uncle_block);

        // share2 includes uncle_block; push through organise_header
        // so the uncles index is updated
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle_block.block_hash()])
            .nonce(0xe9695793)
            .build();
        store.push_to_confirmed_chain(&share2).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        store.push_to_confirmed_chain(&share3).unwrap();

        // find_uncles should not return uncle_block since share2
        // already included it and organise_header marked it
        let uncles = store.find_uncles().unwrap();
        assert!(
            !uncles.contains(&uncle_block.block_hash()),
            "uncle_block should be excluded after being included by share2"
        );
    }

    /// Reorg candidate when the branch point is on the confirmed chain
    /// and no candidates exist above confirmed.
    ///
    /// Scenario: genesis -> share1(h:1) -> share2(h:2), all confirmed.
    /// top_candidate == top_confirmed == share2 at h:2.
    /// Then fork_share1 (child of genesis, h:1) is organised -- it has
    /// less work than top, so it becomes HeaderValid only.
    /// Then fork_share2 (child of fork_share1, h:2, higher work) is
    /// organised -- it should reorg the candidate chain. The walk back
    /// must pass through fork_share1 (HeaderValid) and reach genesis
    /// (Confirmed) as the branch point.
    #[test]
    fn test_organise_header_reorgs_when_branch_point_is_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Build confirmed chain: genesis -> share1(h:1) -> share2(h:2)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.push_to_confirmed_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_confirmed_chain(&share2).unwrap();

        // Verify top_candidate == top_confirmed == share2 at h:2
        let top_confirmed = store.get_top_confirmed().unwrap();
        assert_eq!(top_confirmed.hash, share2.block_hash());
        assert_eq!(top_confirmed.height, 2);

        // fork_share1: child of genesis, h:1. Less cumulative work than
        // top, so organise_header leaves it as HeaderValid.
        let fork_share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&fork_share1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        let result = store
            .organise_header(&fork_share1.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        assert!(
            result.is_none(),
            "fork_share1 should not extend or reorg (less work)"
        );

        // fork_share2: child of fork_share1, h:2, with extra work so
        // its cumulative chain_work exceeds the top candidate.
        // Pre-store block and metadata so reorg_candidate can read
        // from committed DB state (the WriteBatch inside
        // organise_header is not yet committed when reorg runs).
        let fork_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork_share1.block_hash().to_string())
            .work(2)
            .nonce(0xe9695795)
            .build();
        {
            let blockhash = fork_share2.block_hash();
            let share_work = fork_share2.header.get_work();
            let parent_metadata = store
                .get_block_metadata(&fork_share2.header.prev_share_blockhash)
                .unwrap();
            let parent_height = parent_metadata.expected_height.unwrap_or_default();
            let height = parent_height + 1;
            let chain_work = parent_metadata.chain_work + share_work;
            let mut batch = Store::get_write_batch();
            store.add_share_block(&fork_share2, &mut batch).unwrap();
            store
                .set_height_to_blockhash(&blockhash, height, &mut batch)
                .unwrap();
            let metadata = BlockMetadata {
                expected_height: Some(height),
                chain_work,
                status: Status::HeaderValid,
            };
            store
                .update_block_metadata(&blockhash, &metadata, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();
        }

        // This should reorg candidates, walking back through
        // fork_share1 (HeaderValid) to genesis (Confirmed).
        let mut batch = Store::get_write_batch();
        let result = store
            .organise_header(&fork_share2.header, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(
            result.is_some(),
            "fork_share2 should trigger candidate reorg"
        );
        let height = result.unwrap();
        assert_eq!(height, 2);

        // Top candidate should be fork_share2
        let top = store.get_top_candidate().unwrap();
        assert_eq!(top.hash, fork_share2.block_hash());

        // Genesis should still be confirmed, not demoted
        assert!(store.is_confirmed(&genesis.block_hash()));
    }

    /// Re-organising a header that is already confirmed must not
    /// overwrite its Confirmed status.
    ///
    /// Scenario: genesis -> share1(h:1, confirmed). Then call
    /// organise_header for share1 again (as happens when synced
    /// headers from a peer include a block we already confirmed).
    /// share1 must remain Confirmed.
    #[test]
    fn test_organise_header_preserves_confirmed_status() {
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
        store.push_to_confirmed_chain(&share1).unwrap();

        assert!(store.is_confirmed(&share1.block_hash()));
        let metadata_before = store.get_block_metadata(&share1.block_hash()).unwrap();
        assert_eq!(metadata_before.status, Status::Confirmed);

        // Re-organise the already-confirmed header, simulating what
        // happens when synced headers from a peer include share1.
        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&share1.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Candidate chain must not change
        assert!(result.is_none());

        // share1 must still be Confirmed, not downgraded
        let metadata_after = store.get_block_metadata(&share1.block_hash()).unwrap();
        assert_eq!(
            metadata_after.status,
            Status::Confirmed,
            "organise_header must not overwrite Confirmed status"
        );
        assert!(store.is_confirmed(&share1.block_hash()));
    }

    /// Re-organising a confirmed block must not make it selectable
    /// as an uncle by find_uncles.
    ///
    /// Scenario: genesis -> share1(h:1) -> share2(h:2), both confirmed.
    /// Re-organise share1 (simulating sync). Then find_uncles must not
    /// return share1.
    #[test]
    fn test_organise_header_confirmed_block_not_selected_as_uncle() {
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
        store.push_to_confirmed_chain(&share1).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        store.push_to_confirmed_chain(&share2).unwrap();

        assert!(store.is_confirmed(&share1.block_hash()));
        assert!(store.is_confirmed(&share2.block_hash()));

        // Re-organise share1 as if received during sync
        let mut batch = Store::get_write_batch();
        store.organise_header(&share1.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1 must still be confirmed
        assert!(
            store.is_confirmed(&share1.block_hash()),
            "share1 must remain confirmed after re-organise"
        );

        // find_uncles must not return share1
        let uncles = store.find_uncles().unwrap();
        assert!(
            !uncles.contains(&share1.block_hash()),
            "confirmed share1 must not appear as uncle after re-organise"
        );
    }

    /// When a block has metadata but no height index entry,
    /// organise_header should repair the height index so that
    /// get_candidate_blocks_missing_data can find it.
    #[test]
    fn test_organise_header_repairs_missing_height_index() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        // Simulate a previous partial sync: create metadata and header
        // but do NOT call set_height_to_blockhash, so the height index
        // is missing.
        let share_work = share.header.get_work();
        let genesis_metadata = store.get_block_metadata(&genesis.block_hash()).unwrap();
        let chain_work = genesis_metadata.chain_work + share_work;
        let metadata = BlockMetadata {
            expected_height: Some(1),
            chain_work,
            status: Status::HeaderValid,
        };
        let mut batch = Store::get_write_batch();
        store.add_share_header(&share.header, &mut batch).unwrap();
        store
            .update_block_metadata(&share.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Height index should be empty at height 1 for this block
        let hashes_before = store.get_blockhashes_for_height(1);
        assert!(
            !hashes_before.contains(&share.block_hash()),
            "height index should not contain the share before repair"
        );

        // organise_header should repair the missing height index entry
        let mut batch = Store::get_write_batch();
        store.organise_header(&share.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Height index should now contain the share at height 1
        let hashes_after = store.get_blockhashes_for_height(1);
        assert!(
            hashes_after.contains(&share.block_hash()),
            "height index should contain the share after repair"
        );
    }

    /// When a block already has metadata AND a height index entry,
    /// organise_header should not duplicate the entry.
    #[test]
    fn test_organise_header_does_not_duplicate_height_index() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        // First organise creates metadata and height index
        let mut batch = Store::get_write_batch();
        store.organise_header(&share.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let hashes_after_first = store.get_blockhashes_for_height(1);
        let count_before = hashes_after_first
            .iter()
            .filter(|h| **h == share.block_hash())
            .count();
        assert_eq!(count_before, 1);

        // Second organise should not add a duplicate height entry
        let mut batch = Store::get_write_batch();
        store.organise_header(&share.header, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let hashes_after_second = store.get_blockhashes_for_height(1);
        let count_after = hashes_after_second
            .iter()
            .filter(|h| **h == share.block_hash())
            .count();
        assert_eq!(
            count_after, 1,
            "height index should contain exactly one entry, not duplicated"
        );
    }

    /// When a block has metadata with expected_height=None,
    /// repair_height_index_if_needed should be a no-op.
    #[test]
    fn test_organise_header_skips_repair_when_height_is_none() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();

        // Create metadata with expected_height=None
        let metadata = BlockMetadata {
            expected_height: None,
            chain_work: share.header.get_work(),
            status: Status::HeaderValid,
        };
        let mut batch = Store::get_write_batch();
        store.add_share_header(&share.header, &mut batch).unwrap();
        store
            .update_block_metadata(&share.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // organise_header should not panic or error
        let mut batch = Store::get_write_batch();
        let result = store.organise_header(&share.header, &mut batch);
        store.commit_batch(batch).unwrap();
        assert!(result.is_ok());
    }
}
