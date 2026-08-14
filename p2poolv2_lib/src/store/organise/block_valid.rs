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

//! Highest-work `BlockValid` pointer.
//!
//! Tracks the block with the most cumulative work that has passed
//! chain-context validation (`Status::BlockValid`), independent of chain
//! membership -- a `BlockValid` block can be an off-chain fork, so the
//! pointer stores the hash and work directly rather than a height into a
//! chain index.
//!
//! Transitivity of `BlockValid` (a block is only marked `BlockValid` when
//! its parent is `BlockValid` or on the confirmed chain) guarantees this
//! block has a fully-validated ancestry, so it is a safe base to mine on and
//! to anchor payouts against.
//!
//! Ties on equal work are broken by the lexicographically smallest block
//! hash so every node converges on the same pointer.

use super::Store;
use crate::store::{ColumnFamily, writer::StoreError};
use bitcoin::{
    BlockHash, Work,
    consensus::{self, encode},
};

const HIGHEST_BLOCK_VALID_KEY: &str = "meta:highest_block_valid";

/// Serialized pointer length: 32-byte block hash followed by 32-byte work.
const POINTER_LEN: usize = 64;

impl Store {
    /// Update the highest-work `BlockValid` pointer if `blockhash` outranks
    /// the current pointer.
    ///
    /// Ranking is by cumulative `work`, with ties broken by the
    /// lexicographically smallest block hash. A no-op if the current pointer
    /// already outranks the candidate.
    pub(crate) fn update_highest_block_valid_if_new_high_work(
        &self,
        blockhash: &BlockHash,
        work: Work,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let outranks_current = match self.get_highest_block_valid()? {
            Some((current_hash, current_work)) => {
                work > current_work || (work == current_work && *blockhash < current_hash)
            }
            None => true,
        };
        if outranks_current {
            self.set_highest_block_valid(blockhash, work, batch);
        }
        Ok(())
    }

    /// Overwrite the highest-work `BlockValid` pointer unconditionally.
    pub(crate) fn set_highest_block_valid(
        &self,
        blockhash: &BlockHash,
        work: Work,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let mut value = consensus::serialize(blockhash);
        value.extend_from_slice(&work.to_le_bytes());
        batch.put_cf(
            &block_height_cf,
            HIGHEST_BLOCK_VALID_KEY.as_bytes().as_ref(),
            value,
        );
    }

    /// Clear the highest-work `BlockValid` pointer.
    ///
    /// Used by the invalidation reorg when the pointer referenced a block on
    /// the removed branch; it rebuilds as the reorged candidate chain is
    /// re-validated.
    pub(crate) fn delete_highest_block_valid(&self, batch: &mut rocksdb::WriteBatch) {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        batch.delete_cf(
            &block_height_cf,
            HIGHEST_BLOCK_VALID_KEY.as_bytes().as_ref(),
        );
    }

    /// Read the highest-work `BlockValid` pointer, or `None` if unset (no
    /// block has been marked `BlockValid` yet).
    pub(crate) fn get_highest_block_valid(&self) -> Result<Option<(BlockHash, Work)>, StoreError> {
        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        match self.db.get_cf(
            &block_height_cf,
            HIGHEST_BLOCK_VALID_KEY.as_bytes().as_ref(),
        ) {
            Ok(Some(bytes)) => {
                if bytes.len() != POINTER_LEN {
                    return Err(StoreError::Database(
                        "Invalid highest_block_valid pointer length".into(),
                    ));
                }
                let hash: BlockHash = encode::deserialize(&bytes[..32])?;
                let work_bytes: [u8; 32] = bytes[32..].try_into().map_err(|_| {
                    StoreError::Database("Invalid highest_block_valid work length".into())
                })?;
                Ok(Some((hash, Work::from_le_bytes(work_bytes))))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    fn test_store() -> (Store, tempfile::TempDir) {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        (store, temp_dir)
    }

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn work(byte: u8) -> Work {
        Work::from_le_bytes([byte; 32])
    }

    fn update(store: &Store, blockhash: &BlockHash, work: Work) {
        let mut batch = Store::get_write_batch();
        store
            .update_highest_block_valid_if_new_high_work(blockhash, work, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
    }

    #[test]
    fn test_pointer_unset_by_default() {
        let (store, _temp_dir) = test_store();
        assert_eq!(store.get_highest_block_valid().unwrap(), None);
    }

    #[test]
    fn test_first_update_sets_pointer() {
        let (store, _temp_dir) = test_store();
        update(&store, &hash(5), work(10));
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((hash(5), work(10)))
        );
    }

    #[test]
    fn test_higher_work_replaces_lower() {
        let (store, _temp_dir) = test_store();
        update(&store, &hash(5), work(10));
        update(&store, &hash(6), work(20));
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((hash(6), work(20)))
        );
    }

    #[test]
    fn test_lower_work_does_not_replace() {
        let (store, _temp_dir) = test_store();
        update(&store, &hash(6), work(20));
        update(&store, &hash(5), work(10));
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((hash(6), work(20)))
        );
    }

    #[test]
    fn test_equal_work_breaks_tie_on_smaller_hash() {
        let (store, _temp_dir) = test_store();
        let (smaller, larger) = if hash(1) < hash(2) {
            (hash(1), hash(2))
        } else {
            (hash(2), hash(1))
        };

        // Start on the larger hash, then the smaller hash at equal work wins.
        update(&store, &larger, work(10));
        update(&store, &smaller, work(10));
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((smaller, work(10)))
        );

        // The larger hash at equal work must not displace the smaller one.
        update(&store, &larger, work(10));
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((smaller, work(10)))
        );
    }

    #[test]
    fn test_mark_block_valid_advances_pointer() {
        let (store, _temp_dir) = test_store();
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        store.store_with_valid_metadata(&share);

        assert_eq!(store.get_highest_block_valid().unwrap(), None);

        let mut batch = Store::get_write_batch();
        store
            .mark_block_valid(&share.block_hash(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let chain_work = store
            .get_block_metadata(&share.block_hash())
            .unwrap()
            .chain_work;
        assert_eq!(
            store.get_highest_block_valid().unwrap(),
            Some((share.block_hash(), chain_work))
        );
    }
}
