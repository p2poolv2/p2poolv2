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

use super::{
    ColumnFamily, Store,
    block_tx_metadata::{BlockMetadata, Status},
    writer::StoreError,
};
use bitcoin::{
    BlockHash, Work,
    consensus::{self, encode},
};
pub mod organise_share;

const CANDIDATE_SUFFIX: &str = ":c";
const CONFIRMED_SUFFIX: &str = ":f";
const TOP_CANDIDATE_KEY: &str = "meta:top_candidate_height";
const TOP_CONFIRMED_KEY: &str = "meta:top_confirmed_height";
const BRANCH_INITIAL_CAPACITY: usize = 16;

/// Returns key for height with provided suffix
fn height_to_key_with_suffix(height: u32, suffix: &str) -> Vec<u8> {
    [&height.to_be_bytes(), suffix.as_bytes()].concat()
}

impl Store {
    /// Increment top candidate key if height is one more than current height
    ///
    /// Only updates top if it is more than one higher.
    fn increment_top_candidate(
        &self,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<u32, StoreError> {
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

    /// Set top confirmed height
    /// The required height checks are already made in make_confirmed
    pub(crate) fn set_top_confirmed_height(&self, height: u32, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let serialized_height = consensus::serialize(&height);
        batch.put_cf(
            &block_height_cf,
            TOP_CONFIRMED_KEY.as_bytes().as_ref(),
            serialized_height,
        );
    }

    /// Get top candidate height from candidates index
    pub(crate) fn get_top_candidate_height(&self) -> Result<u32, StoreError> {
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

    /// Get top confirmed height from confirmed index
    pub(crate) fn get_top_confirmed_height(&self) -> Result<u32, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        match self
            .db
            .get_cf(&block_height_cf, TOP_CONFIRMED_KEY.as_bytes().as_ref())
        {
            Ok(Some(height_bytes)) => Ok(encode::deserialize(&height_bytes)?),
            Ok(None) => Err(StoreError::NotFound("No confirmed found at top".into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Get top candidate after looking up top candidate height
    /// Return both the blockhash and the height
    pub(crate) fn get_top_candidate(&self) -> Result<(BlockHash, u32, Work), StoreError> {
        let height = self.get_top_candidate_height()?;
        let hash = self.get_candidate_at_height(height)?;
        let metadata = self.get_block_metadata(&hash)?;
        Ok((hash, height, metadata.chain_work))
    }

    /// Get top confirmed after looking up top confirmed height
    pub(crate) fn get_top_confirmed(&self) -> Result<(BlockHash, u32, Work), StoreError> {
        let height = self.get_top_confirmed_height()?;
        let hash = self.get_confirmed_at_height(height)?;
        let metadata = self.get_block_metadata(&hash)?;
        Ok((hash, height, metadata.chain_work))
    }

    /// Add blockhash as a candidate at provided height.
    ///
    /// Also Updates the metadata status to Candidate.
    pub(crate) fn append_to_candidates(
        &self,
        blockhash: &BlockHash,
        height: u32,
        metadata: &mut BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);

        let serialized_blockhash = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized_blockhash);

        self.increment_top_candidate(height, batch)?;

        metadata.status = Status::Candidate;
        self.update_block_metadata(blockhash, metadata, batch)?;
        Ok(())
    }

    /// Get list of blockhashes from given blockhash up to top candidate
    /// If blockhash is None, returns empry vector
    pub(crate) fn get_candidates_chain(
        &self,
        blockhash: &BlockHash,
        top_candidate: Option<(BlockHash, u32, Work)>,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let Ok(metadata) = self.get_block_metadata(&blockhash) else {
            return Err(StoreError::NotFound(
                "Block metadata not found for branch point".into(),
            ));
        };
        let Some(height) = metadata.expected_height else {
            return Err(StoreError::NotFound(
                "Block metadata doesn't have an expected height".into(),
            ));
        };
        let Some((_, top_candidate_height, _)) = top_candidate else {
            return Err(StoreError::NotFound(
                "No top candidate height found when reorging candidate chain".into(),
            ));
        };
        self.get_candidates(height, top_candidate_height)
    }

    /// Fetch a list of blockhashes on the candidates chain between
    /// the given heights, inclusive.
    pub(crate) fn get_candidates(&self, from: u32, to: u32) -> Result<Vec<BlockHash>, StoreError> {
        if from > to {
            return Ok(Vec::new());
        }

        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();

        let lower_key = height_to_key_with_suffix(from, CANDIDATE_SUFFIX);
        // Upper bound is exclusive, so use to+1
        let upper_key = height_to_key_with_suffix(to + 1, CANDIDATE_SUFFIX);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower_key.clone());
        read_opts.set_iterate_upper_bound(upper_key);

        let iter = self.db.iterator_cf_opt(
            &block_height_cf,
            read_opts,
            rocksdb::IteratorMode::From(&lower_key, rocksdb::Direction::Forward),
        );

        let capacity = (to - from + 1) as usize;
        let mut candidates = Vec::with_capacity(capacity);
        for item in iter.flatten() {
            let (_key, value) = item;
            candidates.push(encode::deserialize(&value)?);
        }
        Ok(candidates)
    }

    /// Get list of blockhashes from given blockhash up to top confirmed.
    pub(crate) fn get_confirmed_chain(
        &self,
        blockhash: &BlockHash,
        top_confirmed: Option<(BlockHash, u32, Work)>,
    ) -> Result<Vec<BlockHash>, StoreError> {
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
        let Some((_, top_confirmed_height, _)) = top_confirmed else {
            return Err(StoreError::NotFound(
                "No top confirmed height found when fetching confirmed chain".into(),
            ));
        };
        self.get_confirmed(height, top_confirmed_height)
    }

    /// Fetch a list of blockhashes on the confirmed chain between
    /// the given heights, inclusive.
    pub(crate) fn get_confirmed(&self, from: u32, to: u32) -> Result<Vec<BlockHash>, StoreError> {
        if from > to {
            return Ok(Vec::new());
        }

        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();

        let lower_key = height_to_key_with_suffix(from, CONFIRMED_SUFFIX);
        // Upper bound is exclusive, so use to+1
        let upper_key = height_to_key_with_suffix(to + 1, CONFIRMED_SUFFIX);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower_key.clone());
        read_opts.set_iterate_upper_bound(upper_key);

        let iter = self.db.iterator_cf_opt(
            &block_height_cf,
            read_opts,
            rocksdb::IteratorMode::From(&lower_key, rocksdb::Direction::Forward),
        );

        let capacity = (to - from + 1) as usize;
        let mut confirmed = Vec::with_capacity(capacity);
        for item in iter.flatten() {
            let (_key, value) = item;
            confirmed.push(encode::deserialize(&value)?);
        }
        Ok(confirmed)
    }

    /// Add blockhash as a confirmed at provided height.
    ///
    /// Only adds to the confirmed index if the height is one more than the
    /// current top confirmed height (or if there is no top yet).
    ///
    /// Also updates the metadata status to Confirmed.
    ///
    /// Returns error if height check fails.
    pub(crate) fn append_to_confirmed(
        &self,
        blockhash: &BlockHash,
        height: u32,
        metadata: &mut BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let current_top = match self.get_top_confirmed_height() {
            Ok(top) => top,
            Err(StoreError::NotFound(_)) => 0,
            Err(e) => return Err(e),
        };

        // Only add if this is the first entry or height is exactly one more than current top
        // Or if it is the first confirmation
        if height.saturating_sub(current_top) != 1 && !(height == 0 && current_top == 0) {
            return Err(StoreError::Database("Incorrect confirmation".into()));
        }

        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);

        let serialized_blockhash = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized_blockhash);

        self.set_top_confirmed_height(height, batch);

        metadata.status = Status::Confirmed;
        self.update_block_metadata(blockhash, metadata, batch)?;
        Ok(())
    }

    /// Get the candidate blockhash at a specific height
    pub fn get_candidate_at_height(&self, height: u32) -> Result<BlockHash, StoreError> {
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

    /// Get the confirmed blockhash at a specific height
    pub fn get_confirmed_at_height(&self, height: u32) -> Result<BlockHash, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);

        match self.db.get_cf::<&[u8]>(&block_height_cf, key.as_ref()) {
            Ok(Some(blockhash_bytes)) => Ok(encode::deserialize(&blockhash_bytes)?),
            Ok(None) => Err(StoreError::NotFound(format!(
                "No confirmed found at height {height}"
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Check if a blockhash has Confirmed status in its metadata.
    pub fn is_confirmed(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.status == Status::Confirmed)
            .unwrap_or(false)
    }

    /// Check if a blockhash has Candidate status in its metadata.
    pub fn is_candidate(&self, blockhash: &BlockHash) -> bool {
        self.get_block_metadata(blockhash)
            .map(|m| m.status == Status::Candidate)
            .unwrap_or(false)
    }

    /// Get branch from a blockhash back to the first ancestor in the candidate chain.
    ///
    /// Walks backwards through the chain collecting blockhashes until finding
    /// one that's already a candidate. Returns the branch excluding the candidate
    /// ancestor (since it's already in the chain).
    ///
    /// Returns empty vec if the starting blockhash is already a candidate.
    pub fn get_branch_to_candidates(&self, blockhash: &BlockHash) -> Vec<BlockHash> {
        let mut branch = Vec::with_capacity(BRANCH_INITIAL_CAPACITY);

        let mut current = *blockhash;
        loop {
            if self.is_candidate(&current) {
                // Found ancestor in candidate chain, stop here
                return branch;
            }

            // Get the share to find its parent
            let Some(share) = self.get_share(&current) else {
                // Share not found, return what we have
                return branch;
            };

            branch.push(current);
            current = share.header.prev_share_blockhash;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    // ── increment_top_candidate tests ────────────────────────────────

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

        let share1 = TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .work(1)
            .build();
        let share2 = TestShareBlockBuilder::new()
            .nonce(0xe9695792)
            .work(2)
            .build();

        // Make share1 candidate at height 0
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share(&share1, 1, share1.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 0, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify we can retrieve it
        let candidate = store.get_candidate_at_height(0).unwrap();
        assert_eq!(candidate, share1.block_hash());

        // Make share2 candidate at height 1
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share(&share2, 2, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 1, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both heights
        assert_eq!(
            store.get_candidate_at_height(0).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_candidate_at_height(1).unwrap(),
            share2.block_hash()
        );

        // Non-existent height should return None
        assert!(store.get_candidate_at_height(999).is_err());

        // Top candidate height is changed
        assert_eq!(store.get_top_candidate_height().unwrap(), 1);

        // Top candidate is changed
        assert_eq!(
            store.get_top_candidate().unwrap(),
            (share2.block_hash(), 1, share2.header.get_work())
        );
    }

    #[test]
    fn test_make_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share(&share1, 0, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share1.block_hash(), 0, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify we can retrieve it
        let confirmed = store.get_confirmed_at_height(0).unwrap();
        assert_eq!(confirmed, share1.block_hash());

        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share(&share2, 1, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share2.block_hash(), 1, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both heights
        assert_eq!(
            store.get_confirmed_at_height(0).unwrap(),
            share1.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            share2.block_hash()
        );

        // Non-existent height should return None
        assert!(store.get_confirmed_at_height(999).is_err());

        // Top confirmed height is changed
        assert_eq!(store.get_top_confirmed_height().unwrap(), 1);

        // Top confirmed is changed
        let top_confirmed = store.get_top_confirmed().unwrap();
        assert_eq!(top_confirmed.0, (share2.block_hash()));
        assert_eq!(top_confirmed.1, 1);
        assert_eq!(top_confirmed.2, share2.header.get_work());
    }

    #[test]
    fn test_append_to_candidate_on_overwrite_previous_should_error() {
        // Each height should only have one candidate - new candidates replace old ones
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Add shares first
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share(&share1, 0, share1.header.get_work(), false, &mut batch)
            .unwrap();
        let mut metadata2 = store
            .add_share(&share2, 0, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 0, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_candidate_at_height(0).unwrap(),
            share1.block_hash()
        );

        // Make share2 candidate at same height - should error (height mismatch)
        let mut batch = Store::get_write_batch();
        let result =
            store.append_to_candidates(&share2.block_hash(), 0, &mut metadata2, &mut batch);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_confirmed_ignores_same_height() {
        // Confirming at the same height as current top is ignored
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let share3 = TestShareBlockBuilder::new().nonce(0xe9695793).build();

        // Add all shares first
        let mut batch = Store::get_write_batch();
        let mut metadata1 = store
            .add_share(&share1, 0, share1.header.get_work(), false, &mut batch)
            .unwrap();
        let mut metadata2 = store
            .add_share(&share2, 1, share2.header.get_work(), false, &mut batch)
            .unwrap();
        let mut metadata3 = store
            .add_share(&share3, 1, share3.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share1.block_hash(), 0, &mut metadata1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store.get_confirmed_at_height(0).unwrap(),
            share1.block_hash()
        );

        // Confirm share2
        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(&share2.block_hash(), 1, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Confirm share3 at same height as share2, should error.
        let mut batch = Store::get_write_batch();
        assert!(
            store
                .append_to_confirmed(&share3.block_hash(), 1, &mut metadata3, &mut batch)
                .is_err()
        );
    }

    #[test]
    fn test_candidate_and_confirmed_are_independent() {
        // Candidate and confirmed should be stored separately at the same height
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let candidate_share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let confirmed_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Add shares first
        let mut batch = Store::get_write_batch();
        let mut candidate_metadata = store
            .add_share(
                &candidate_share,
                0,
                candidate_share.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        let mut confirmed_metadata = store
            .add_share(
                &confirmed_share,
                0,
                confirmed_share.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store
            .append_to_candidates(
                &candidate_share.block_hash(),
                0,
                &mut candidate_metadata,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(
                &confirmed_share.block_hash(),
                0,
                &mut confirmed_metadata,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Both should be retrievable independently
        assert_eq!(
            store.get_candidate_at_height(0).unwrap(),
            candidate_share.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(0).unwrap(),
            confirmed_share.block_hash()
        );
    }

    #[test]
    fn test_is_confirmed_returns_true_when_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create and add a share to the store (this sets up block metadata)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Add a child share and mark it confirmed
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share1.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // is_confirmed should return true
        assert!(store.is_confirmed(&share1.block_hash()));
    }

    #[test]
    fn test_is_confirmed_returns_true_for_genesis_after_setup() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create and add a share to the store (this sets up block metadata)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Genesis is marked confirmed at setup
        assert!(store.is_confirmed(&genesis.block_hash()));
    }

    #[test]
    fn test_is_confirmed_returns_false_when_not_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create and add a share to the store (this sets up block metadata)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create another share
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 1, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Don't mark it as confirmed - is_confirmed should return false
        assert!(!store.is_confirmed(&share2.block_hash()));
    }

    #[test]
    fn test_is_confirmed_returns_false_when_different_block_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create genesis and add to store
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Create another share at the same height
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        let mut metadata2 = store
            .add_share(&share2, 1, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Create a third share at the same height as share2
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share3, 1, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Mark share2 as confirmed at height 1
        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(&share2.block_hash(), 1, &mut metadata2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share2 should be confirmed, share3 should not
        assert!(store.is_confirmed(&share2.block_hash()));
        assert!(!store.is_confirmed(&share3.block_hash()));
    }

    #[test]
    fn test_is_confirmed_returns_false_when_no_metadata() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a blockhash that doesn't exist in the store
        let fake_blockhash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .parse::<BlockHash>()
            .unwrap();

        // is_confirmed should return false because there's no metadata
        assert!(!store.is_confirmed(&fake_blockhash));
    }

    #[test]
    fn test_append_to_candidate_does_not_update_top_when_height_skips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share0 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Add shares first
        let mut batch = Store::get_write_batch();
        let mut metadata0 = store
            .add_share(&share0, 0, share0.header.get_work(), false, &mut batch)
            .unwrap();
        let mut metadata2 = store
            .add_share(&share2, 2, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share0.block_hash(), 0, &mut metadata0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify top candidate height is 0
        assert_eq!(store.get_top_candidate_height().unwrap(), 0);

        // Make share2 candidate at height 2 (skipping height 1)
        let mut batch = Store::get_write_batch();
        let result =
            store.append_to_candidates(&share2.block_hash(), 2, &mut metadata2, &mut batch);
        assert!(result.is_err());

        // Top candidate height should still be 0 (not updated because we skipped height 1)
        assert_eq!(store.get_top_candidate_height().unwrap(), 0);

        // The candidate at height 2 is not there
        assert!(store.get_candidate_at_height(2).is_err());
    }

    #[test]
    fn test_make_confirmed_does_not_update_top_when_height_skips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share0 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Add shares first
        let mut batch = Store::get_write_batch();
        let mut metadata0 = store
            .add_share(&share0, 0, share0.header.get_work(), false, &mut batch)
            .unwrap();
        let mut metadata2 = store
            .add_share(&share2, 2, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share0.block_hash(), 0, &mut metadata0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify top confirmed height is 0
        assert_eq!(store.get_top_confirmed_height().unwrap(), 0);

        // Make share2 confirmed at height 2 (skipping height 1) should error
        let mut batch = Store::get_write_batch();
        assert!(
            store
                .append_to_confirmed(&share2.block_hash(), 2, &mut metadata2, &mut batch)
                .is_err()
        );
    }

    // ── get_candidates / get_candidates_chain tests ───────────────────

    #[test]
    fn test_get_candidates_returns_blockhashes_in_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share0 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share1 = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695793).build();

        let mut batch = Store::get_write_batch();
        let mut m0 = store
            .add_share(&share0, 0, share0.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share0.block_hash(), 0, &mut m0, &mut batch)
            .unwrap();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Full range
        let result = store.get_candidates(0, 2).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], share0.block_hash());
        assert_eq!(result[1], share1.block_hash());
        assert_eq!(result[2], share2.block_hash());

        // Sub-range
        let result = store.get_candidates(1, 2).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], share1.block_hash());
        assert_eq!(result[1], share2.block_hash());

        // Single height
        let result = store.get_candidates(1, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], share1.block_hash());
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

        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let top = store.get_top_candidate().ok();
        let result = store
            .get_candidates_chain(&share1.block_hash(), top)
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], share1.block_hash());
        assert_eq!(result[1], share2.block_hash());
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

    // ── get_confirmed / get_confirmed_chain tests ───────────────────

    #[test]
    fn test_get_confirmed_returns_blockhashes_in_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share0 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share1 = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695793).build();

        // append_to_confirmed checks top height against DB, so commit between each
        let mut batch = Store::get_write_batch();
        let mut m0 = store
            .add_share(&share0, 0, share0.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share0.block_hash(), 0, &mut m0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), false, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Full range
        let result = store.get_confirmed(0, 2).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], share0.block_hash());
        assert_eq!(result[1], share1.block_hash());
        assert_eq!(result[2], share2.block_hash());

        // Sub-range
        let result = store.get_confirmed(1, 2).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], share1.block_hash());
        assert_eq!(result[1], share2.block_hash());

        // Single height
        let result = store.get_confirmed(1, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], share1.block_hash());
    }

    #[test]
    fn test_get_confirmed_returns_empty_when_from_greater_than_to() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let result = store.get_confirmed(5, 3).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_confirmed_chain_returns_confirmed_from_blockhash_to_top() {
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

        // append_to_confirmed checks top height against DB, so commit between each
        let mut batch = Store::get_write_batch();
        let mut m1 = store
            .add_share(&share1, 1, share1.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share1.block_hash(), 1, &mut m1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        let mut m2 = store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_confirmed(&share2.block_hash(), 2, &mut m2, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let top = store.get_top_confirmed().ok();
        let result = store
            .get_confirmed_chain(&share1.block_hash(), top)
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], share1.block_hash());
        assert_eq!(result[1], share2.block_hash());
    }

    #[test]
    fn test_get_confirmed_chain_errors_when_no_top_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let result = store.get_confirmed_chain(&genesis.block_hash(), None);
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
        let mut batch = Store::get_write_batch();
        let mut metadata = store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

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

        // Add share but don't make it a candidate
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(!store.is_candidate(&share.block_hash()));
    }

    // ── get_branch_to_candidates tests ────────────────────────────────

    #[test]
    fn test_get_branch_to_candidates_returns_empty_when_already_candidate() {
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
        let mut batch = Store::get_write_batch();
        let mut metadata = store
            .add_share(&share, 1, share.header.get_work(), true, &mut batch)
            .unwrap();
        store
            .append_to_candidates(&share.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Branch should be empty since share is already a candidate
        let branch = store.get_branch_to_candidates(&share.block_hash());
        assert!(branch.is_empty());
    }

    #[test]
    fn test_get_branch_to_candidates_returns_branch_to_candidate_ancestor() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup: genesis -> share1 (candidate) -> share2 -> share3
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // share1 is a candidate at height 1
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

        // share2 extends share1 but is NOT on candidate chain
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // share3 extends share2 and is NOT on candidate chain
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share3, 3, share3.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Branch from share3 should be [share3, share2] (excludes share1 which is candidate)
        let branch = store.get_branch_to_candidates(&share3.block_hash());
        assert_eq!(branch.len(), 2);
        assert_eq!(branch[0], share3.block_hash());
        assert_eq!(branch[1], share2.block_hash());
    }

    #[test]
    fn test_get_branch_to_candidates_returns_single_share_branch() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Setup: genesis -> share1 (candidate) -> share2 (not on candidate chain)
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

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

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(&share2, 2, share2.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Branch from share2 should be just [share2]
        let branch = store.get_branch_to_candidates(&share2.block_hash());
        assert_eq!(branch.len(), 1);
        assert_eq!(branch[0], share2.block_hash());
    }
}
