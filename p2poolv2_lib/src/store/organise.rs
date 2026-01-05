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

use super::{ColumnFamily, Store};
use bitcoin::{
    BlockHash,
    consensus::{self, encode},
};
use std::error::Error;

const CANDIDATE_SUFFIX: &str = ":c";
const CONFIRMED_SUFFIX: &str = ":f";
const TOP_CANDIDATE_KEY: &str = "meta:top_candidate_height";
const TOP_CONFIRMED_KEY: &str = "meta:top_confirmed_height";

/// Returns key for height with provided suffix
fn height_to_key_with_suffix(height: u32, suffix: &str) -> Vec<u8> {
    [&height.to_be_bytes(), suffix.as_bytes()].concat()
}

impl Store {
    /// Incremement top candidate key if height is one more than current height
    ///
    /// If it is more than one higher, return an error. This forces
    /// candidates to be added only at the top of the candidates list.
    fn increment_top_candidate(
        &self,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();

        let current_top = self.get_top_candidate_height();
        if current_top.is_none() || height.saturating_sub(current_top.unwrap()) == 1 {
            let serialized_height = consensus::serialize(&height);
            batch.put_cf(
                &block_height_cf,
                TOP_CANDIDATE_KEY.as_bytes().as_ref(),
                serialized_height,
            );
        }
        Ok(())
    }

    /// Incremement top confirmed key if height is one more than current height
    ///
    /// If it is more than one higher, return an error. This forces
    /// confirmed to be added only at the top of the confirmed list.
    fn increment_top_confirmed(
        &self,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();

        let current_top = self.get_top_confirmed_height();

        if current_top.is_none() || height.saturating_sub(current_top.unwrap()) == 1 {
            let serialized_height = consensus::serialize(&height);
            batch.put_cf(
                &block_height_cf,
                TOP_CONFIRMED_KEY.as_bytes().as_ref(),
                serialized_height,
            );
        }
        Ok(())
    }

    /// Get top candidate height from candidates index
    pub(crate) fn get_top_candidate_height(&self) -> Option<u32> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        match self
            .db
            .get_cf(&block_height_cf, TOP_CANDIDATE_KEY.as_bytes().as_ref())
        {
            Ok(Some(height_bytes)) => encode::deserialize(&height_bytes).ok(),
            Ok(None) | Err(_) => None,
        }
    }

    /// Get top confirmed height from confirmed index
    pub(crate) fn get_top_confirmed_height(&self) -> Option<u32> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        match self
            .db
            .get_cf(&block_height_cf, TOP_CONFIRMED_KEY.as_bytes().as_ref())
        {
            Ok(Some(height_bytes)) => encode::deserialize(&height_bytes).ok(),
            Ok(None) | Err(_) => None,
        }
    }

    /// Get top candidate after looking up top candidate height
    pub(crate) fn get_top_candidate(&self) -> Option<BlockHash> {
        match self.get_top_candidate_height() {
            Some(height) => self.get_candidate_at_height(height),
            None => None,
        }
    }

    /// Get top confirmed after looking up top confirmed height
    pub(crate) fn get_top_confirmed(&self) -> Option<BlockHash> {
        match self.get_top_confirmed_height() {
            Some(height) => self.get_confirmed_at_height(height),
            None => None,
        }
    }

    /// Add blockhash as a candidate at provided height
    pub(crate) fn make_candidate(
        &self,
        blockhash: &BlockHash,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);

        let serialized_blockhash = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized_blockhash);

        self.increment_top_candidate(height, batch)?;
        Ok(())
    }

    /// Add blockhash as a confirmed at provided height
    pub(crate) fn make_confirmed(
        &self,
        blockhash: &BlockHash,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);

        let serialized_blockhash = consensus::serialize(blockhash);
        batch.put_cf(&block_height_cf, key, serialized_blockhash);

        self.increment_top_confirmed(height, batch)?;
        Ok(())
    }

    /// Get the candidate blockhash at a specific height
    pub fn get_candidate_at_height(&self, height: u32) -> Option<BlockHash> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CANDIDATE_SUFFIX);

        match self.db.get_cf::<&[u8]>(&block_height_cf, key.as_ref()) {
            Ok(Some(blockhash_bytes)) => encode::deserialize(&blockhash_bytes).ok(),
            Ok(None) | Err(_) => None,
        }
    }

    /// Get the confirmed blockhash at a specific height
    pub fn get_confirmed_at_height(&self, height: u32) -> Option<BlockHash> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let key = height_to_key_with_suffix(height, CONFIRMED_SUFFIX);

        match self.db.get_cf::<&[u8]>(&block_height_cf, key.as_ref()) {
            Ok(Some(blockhash_bytes)) => encode::deserialize(&blockhash_bytes).ok(),
            Ok(None) | Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    #[test]
    fn test_make_candidate() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Make share1 candidate at height 0
        let mut batch = Store::get_write_batch();
        store
            .make_candidate(&share1.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify we can retrieve it
        let candidate = store.get_candidate_at_height(0);
        assert_eq!(candidate, Some(share1.block_hash()));

        // Make share2 candidate at height 1
        let mut batch = Store::get_write_batch();
        store
            .make_candidate(&share2.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both heights
        assert_eq!(store.get_candidate_at_height(0), Some(share1.block_hash()));
        assert_eq!(store.get_candidate_at_height(1), Some(share2.block_hash()));

        // Non-existent height should return None
        assert_eq!(store.get_candidate_at_height(999), None);

        // Top candidate height is changed
        assert_eq!(store.get_top_candidate_height(), Some(1));

        // Top candidate is changed
        assert_eq!(store.get_top_candidate(), Some(share2.block_hash()));
    }

    #[test]
    fn test_make_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Make share1 confirmed at height 0
        let mut batch = Store::get_write_batch();
        store
            .make_confirmed(&share1.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify we can retrieve it
        let confirmed = store.get_confirmed_at_height(0);
        assert_eq!(confirmed, Some(share1.block_hash()));

        // Make share2 confirmed at height 1
        let mut batch = Store::get_write_batch();
        store
            .make_confirmed(&share2.block_hash(), 1, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both heights
        assert_eq!(store.get_confirmed_at_height(0), Some(share1.block_hash()));
        assert_eq!(store.get_confirmed_at_height(1), Some(share2.block_hash()));

        // Non-existent height should return None
        assert_eq!(store.get_confirmed_at_height(999), None);

        // Top confirmed height is changed
        assert_eq!(store.get_top_confirmed_height(), Some(1));

        // Top confirmed is changed
        assert_eq!(store.get_top_confirmed(), Some(share2.block_hash()));
    }

    #[test]
    fn test_make_candidate_overwrites_previous() {
        // Each height should only have one candidate - new candidates replace old ones
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Make share1 candidate at height 0
        let mut batch = Store::get_write_batch();
        store
            .make_candidate(&share1.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_candidate_at_height(0), Some(share1.block_hash()));

        // Make share2 candidate at same height - should overwrite
        let mut batch = Store::get_write_batch();
        store
            .make_candidate(&share2.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Should now return share2, not share1
        assert_eq!(store.get_candidate_at_height(0), Some(share2.block_hash()));
    }

    #[test]
    fn test_make_confirmed_overwrites_previous() {
        // Each height should only have one confirmed - new confirmations replace old ones
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Make share1 confirmed at height 0
        let mut batch = Store::get_write_batch();
        store
            .make_confirmed(&share1.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.get_confirmed_at_height(0), Some(share1.block_hash()));

        // Make share2 confirmed at same height - should overwrite
        let mut batch = Store::get_write_batch();
        store
            .make_confirmed(&share2.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Should now return share2, not share1
        assert_eq!(store.get_confirmed_at_height(0), Some(share2.block_hash()));
    }

    #[test]
    fn test_candidate_and_confirmed_are_independent() {
        // Candidate and confirmed should be stored separately at the same height
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let candidate_share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let confirmed_share = TestShareBlockBuilder::new().nonce(0xe9695792).build();

        // Make different shares candidate and confirmed at same height
        let mut batch = Store::get_write_batch();
        store
            .make_candidate(&candidate_share.block_hash(), 0, &mut batch)
            .unwrap();
        store
            .make_confirmed(&confirmed_share.block_hash(), 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Both should be retrievable independently
        assert_eq!(
            store.get_candidate_at_height(0),
            Some(candidate_share.block_hash())
        );
        assert_eq!(
            store.get_confirmed_at_height(0),
            Some(confirmed_share.block_hash())
        );
    }
}
