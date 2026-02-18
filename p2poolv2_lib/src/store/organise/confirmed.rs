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

use crate::store::{
    ColumnFamily, Store,
    block_tx_metadata::{BlockMetadata, Status},
    writer::StoreError,
};
use bitcoin::{
    BlockHash,
    consensus::{self, encode},
};
use tracing::debug;

use super::{Chain, Height, TopResult, height_to_key_with_suffix};

const CONFIRMED_SUFFIX: &str = ":f";
const TOP_CONFIRMED_KEY: &str = "meta:top_confirmed_height";

impl Store {
    /// Write a confirmed index entry directly into the batch.
    pub(super) fn put_confirmed_entry(
        &self,
        height: Height,
        blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);
        let serialized = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized);
    }

    /// Delete a confirmed index entry from the batch.
    fn delete_confirmed_entry(&self, height: Height, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);
        batch.delete_cf(&block_height_cf, key);
    }

    /// Set top confirmed height.
    /// The required height checks are already made in make_confirmed.
    pub(crate) fn set_top_confirmed_height(&self, height: Height, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let serialized_height = consensus::serialize(&height);
        batch.put_cf(
            &block_height_cf,
            TOP_CONFIRMED_KEY.as_bytes().as_ref(),
            serialized_height,
        );
    }

    /// Get top confirmed height from confirmed index
    pub(crate) fn get_top_confirmed_height(&self) -> Result<Height, StoreError> {
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

    /// Get top confirmed after looking up top confirmed height
    pub(crate) fn get_top_confirmed(&self) -> Result<TopResult, StoreError> {
        let height = self.get_top_confirmed_height()?;
        let hash = self.get_confirmed_at_height(height)?;
        let metadata = self.get_block_metadata(&hash)?;
        Ok(TopResult {
            hash,
            height,
            work: metadata.chain_work,
        })
    }

    /// Get list of (height, blockhash) pairs from given blockhash up to top confirmed.
    /// The blockhash is known to be on the confirmed chain.
    pub(crate) fn get_confirmed_chain(
        &self,
        blockhash: &BlockHash,
        top_confirmed: Option<&TopResult>,
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
        let Some(top) = top_confirmed else {
            return Err(StoreError::NotFound(
                "No top confirmed height found when fetching confirmed chain".into(),
            ));
        };
        self.get_confirmed(height, top.height)
    }

    /// Fetch a list of (height, blockhash) pairs on the confirmed chain between
    /// the given heights, inclusive.
    pub(crate) fn get_confirmed(&self, from: Height, to: Height) -> Result<Chain, StoreError> {
        self.get_chain_range(from, to, CONFIRMED_SUFFIX)
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
        height: Height,
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

    /// Get the confirmed blockhash at a specific height
    pub fn get_confirmed_at_height(&self, height: Height) -> Result<BlockHash, StoreError> {
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

    /// Check if the confirmed chain can be extended by the local candidate chain.
    ///
    /// Accepts the effective candidate chain built locally (avoiding stale
    /// reads from the DB within the same WriteBatch).
    /// Returns true if the first candidate is a child of the top confirmed.
    pub(super) fn should_extend_confirmed(
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
    pub(super) fn extend_confirmed(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    // ── append_to_confirmed tests ─────────────────────────────────────────

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
        assert_eq!(top_confirmed.hash, share2.block_hash());
        assert_eq!(top_confirmed.height, 1);
        assert_eq!(top_confirmed.work, share2.header.get_work());
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

    // ── candidate_and_confirmed_are_independent ──────────────────────

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

    // ── is_confirmed tests ────────────────────────────────────────────

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
        assert_eq!(result[0], (0, share0.block_hash()));
        assert_eq!(result[1], (1, share1.block_hash()));
        assert_eq!(result[2], (2, share2.block_hash()));

        // Sub-range
        let result = store.get_confirmed(1, 2).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (1, share1.block_hash()));
        assert_eq!(result[1], (2, share2.block_hash()));

        // Single height
        let result = store.get_confirmed(1, 1).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (1, share1.block_hash()));
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
            .get_confirmed_chain(&share1.block_hash(), top.as_ref())
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], (1, share1.block_hash()));
        assert_eq!(result[1], (2, share2.block_hash()));
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
}
