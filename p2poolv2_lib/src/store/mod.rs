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

use crate::shares::share_block::ShareBlock;
use crate::store::block_tx_metadata::BlockMetadata;
use crate::store::column_families::ColumnFamily;
use bitcoin::consensus::{Encodable, encode};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Work};
use rocksdb::{ColumnFamilyDescriptor, DB, Options as RocksDbOptions};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::sync::{Arc, RwLock};
use tracing::debug;

pub mod background_tasks;
mod block_tx_metadata;
pub mod column_families;
pub mod dag_store;
pub mod job_store;
mod pplns_shares;
pub mod share_store;
pub mod stored_user;
pub mod transaction_store;
pub mod user;

/// A store for share blocks.
/// RocksDB as is used as the underlying database.
/// We use column families to store different types of data, so that compactions are independent for each type.
/// Key Value stores in column families:
/// - block: share blocks
/// - block_txids: txids for a block, to get transactions for a block. A tx can appear in multiple blocks.
/// - inputs: inputs for a transaction, to get inputs for a tx.
/// - outputs: outputs for a transaction, to get outputs for a tx. These can be marked as spent. So these are updated.
#[allow(dead_code)]
pub struct Store {
    path: String,
    db: DB,
    // Thread-safe chain state for use by ChainStore
    genesis_block_hash: Arc<RwLock<Option<BlockHash>>>,
    chain_tip: Arc<RwLock<BlockHash>>,
    tips: Arc<RwLock<HashSet<BlockHash>>>,
}

/// Merge operator for appending BlockHashes to a Vec<BlockHash>
/// This allows atomic append operations without read-modify-write cycles
fn blockhash_list_merge(
    _key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &rocksdb::MergeOperands,
) -> Option<Vec<u8>> {
    // Deserialize existing vector or start with empty
    let mut blockhashes: Vec<BlockHash> = existing_val
        .and_then(|bytes| encode::deserialize(bytes).ok())
        .unwrap_or_default();

    // Process each merge operand (each is a single BlockHash to append)
    for op in operands {
        if let Ok(new_hash) = encode::deserialize::<BlockHash>(op) {
            // Only add if not already present
            if !blockhashes.contains(&new_hash) {
                blockhashes.push(new_hash);
            }
        }
    }

    // Serialize the result
    let mut result = Vec::new();
    blockhashes.consensus_encode(&mut result).ok()?;
    Some(result)
}

/// A rocksdb based store for share blocks.
/// We use column families to store different types of data, so that compactions are independent for each type.
#[allow(dead_code)]
impl Store {
    /// Create a new share store
    pub fn new(path: String, read_only: bool) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // for now we use default options for all column families, we can tweak this later based on performance testing
        let block_cf = ColumnFamilyDescriptor::new(ColumnFamily::Block, RocksDbOptions::default());
        let block_txids_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockTxids, RocksDbOptions::default());
        let txids_blocks_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::TxidsBlocks, RocksDbOptions::default());
        let inputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Inputs, RocksDbOptions::default());
        let outputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Outputs, RocksDbOptions::default());
        let tx_cf = ColumnFamilyDescriptor::new(ColumnFamily::Tx, RocksDbOptions::default());

        // Configure BlockIndex column family with merge operator for efficient appends
        let mut block_index_opts = RocksDbOptions::default();
        block_index_opts
            .set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let block_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockIndex, block_index_opts);

        // Configure BlockHeight column family with merge operator for efficient appends
        let mut block_height_opts = RocksDbOptions::default();
        block_height_opts
            .set_merge_operator_associative("blockhash_list_merge", blockhash_list_merge);
        let block_height_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockHeight, block_height_opts);

        let bitcoin_txids_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BitcoinTxids, RocksDbOptions::default());

        let job_cf = ColumnFamilyDescriptor::new(ColumnFamily::Job, RocksDbOptions::default());
        let share_cf = ColumnFamilyDescriptor::new(ColumnFamily::Share, RocksDbOptions::default());
        let user_cf = ColumnFamilyDescriptor::new(ColumnFamily::User, RocksDbOptions::default());
        let user_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::UserIndex, RocksDbOptions::default());
        let metadata_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Metadata, RocksDbOptions::default());

        let spends_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::SpendsIndex, RocksDbOptions::default());

        let cfs = vec![
            block_cf,
            block_txids_cf,
            txids_blocks_cf,
            inputs_cf,
            outputs_cf,
            tx_cf,
            block_index_cf,
            block_height_cf,
            bitcoin_txids_cf,
            job_cf,
            share_cf,
            user_cf,
            user_index_cf,
            metadata_cf,
            spends_index_cf,
        ];

        // for the db too, we use default options for now
        let mut db_options = RocksDbOptions::default();
        db_options.create_missing_column_families(true);
        db_options.create_if_missing(true);
        let db = if read_only {
            DB::open_cf_descriptors_read_only(&db_options, path.clone(), cfs, false)?
        } else {
            DB::open_cf_descriptors(&db_options, path.clone(), cfs)?
        };
        let store = Self {
            path,
            db,
            // Initialize chain state fields
            genesis_block_hash: Arc::new(RwLock::new(None)),
            chain_tip: Arc::new(RwLock::new(BlockHash::all_zeros())),
            tips: Arc::new(RwLock::new(HashSet::new())),
        };
        Ok(store)
    }

    /// Get a rocksb write batch
    /// An associated function as batch is not obtained from db
    pub fn get_write_batch() -> rocksdb::WriteBatch {
        rocksdb::WriteBatch::default()
    }

    /// Commit a write batch earlier obtained using get batch
    pub fn commit_batch(&self, batch: rocksdb::WriteBatch) -> Result<(), rocksdb::Error> {
        self.db.write(batch)
    }

    /// Get all descendant blockhashes of a given blockhash
    fn get_descendant_blockhashes(
        &self,
        blockhash: &BlockHash,
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let mut blockhashes = Vec::with_capacity(limit);
        let mut next_children = VecDeque::new();
        next_children.push_back(*blockhash);

        while !next_children.is_empty() && blockhashes.len() < limit {
            match next_children.pop_front() {
                Some(current) => {
                    if current == *stop_blockhash {
                        break;
                    }
                    if let Some(children) = self.get_children_blockhashes(&current)? {
                        for child in children {
                            if blockhashes.len() < limit {
                                blockhashes.push(child);
                                next_children.push_back(child);
                            }
                        }
                    }
                }
                None => break, // no more in next_children
            }
        }
        Ok(blockhashes)
    }

    /// Get the genesis blockhash, as the first blockhash in the chain
    /// Assume there is no uncle at height 0
    pub fn get_genesis_blockhash(&self) -> BlockHash {
        self.get_blockhashes_for_height(0)[0]
    }

    /// Get genesis block hash from chain state
    pub fn get_genesis_block_hash(&self) -> Option<BlockHash> {
        *self.genesis_block_hash.read().unwrap()
    }

    /// Set genesis block hash in chain state
    pub fn set_genesis_block_hash(&self, hash: BlockHash) {
        *self.genesis_block_hash.write().unwrap() = Some(hash);
    }

    /// Get chain tip from chain state
    pub fn get_chain_tip(&self) -> BlockHash {
        *self.chain_tip.read().unwrap()
    }

    /// Set chain tip in chain state
    pub fn set_chain_tip(&self, hash: BlockHash) {
        *self.chain_tip.write().unwrap() = hash;
    }

    /// Get tips from chain state (returns clone of the set)
    pub fn get_tips(&self) -> HashSet<BlockHash> {
        self.tips.read().unwrap().clone()
    }

    /// Update tips in chain state
    pub fn update_tips(&self, new_tips: HashSet<BlockHash>) {
        *self.tips.write().unwrap() = new_tips;
    }

    /// Add a tip to the chain state
    pub fn add_tip(&self, hash: BlockHash) {
        self.tips.write().unwrap().insert(hash);
    }

    /// Remove a tip from the chain state
    pub fn remove_tip(&self, hash: &BlockHash) -> bool {
        self.tips.write().unwrap().remove(hash)
    }

    /// Get total work from chain state
    pub fn get_total_work(&self) -> Result<Work, Box<dyn Error + Send + Sync>> {
        let tip = self.get_block_metadata(&self.chain_tip.read().unwrap())?;
        Ok(tip.chain_work)
    }

    /// Setup genesis block for the store
    /// Returns an error, if store already has even a single block
    pub fn setup_genesis(
        &self,
        genesis: ShareBlock,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blockhash = genesis.block_hash();
        let genesis_work = genesis.header.get_work();
        self.add_share(genesis, 0, genesis_work, true, batch)?;
        *self.genesis_block_hash.write().unwrap() = Some(blockhash);
        self.add_tip(blockhash);
        self.set_chain_tip(blockhash);
        Ok(())
    }

    /// Initialize chain state from existing data in the store
    /// This should be called after opening an existing store to load cached state
    pub fn init_chain_state_from_store(
        &self,
        genesis_hash: BlockHash,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Set genesis block hash
        self.set_genesis_block_hash(genesis_hash);

        // Load main chain and total work
        let (chain, tips) = self.load_chain(genesis_hash)?;
        if !chain.is_empty() {
            let metadatas: Vec<BlockMetadata> = tips
                .iter()
                .map(|tip| self.get_block_metadata(tip))
                .collect::<Result<Vec<_>, _>>()?;

            // Find tip with maximum chain work
            let chain_tip = tips
                .iter()
                .zip(metadatas.iter())
                .max_by_key(|(_, metadata)| metadata.chain_work)
                .map(|(hash, _)| *hash)
                .expect("No tips found in a non-empty chain");

            self.set_chain_tip(chain_tip);
            self.update_tips(tips);
        }
        debug!(
            "Initialized chain state: tip={:?}, work={}, tips_count={}",
            self.get_chain_tip(),
            self.get_total_work()?,
            self.get_tips().len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use crate::test_utils::multiplied_compact_target_as_work;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test_log::test]
    fn test_chain_state_management() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test shares
        let share1 = TestShareBlockBuilder::new().build();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .work(2)
            .build();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .work(3)
            .build();

        let mut batch = rocksdb::WriteBatch::default();

        // Store shares in linear chain 0 -> 1 -> 2
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store
            .add_share(
                share3.clone(),
                2,
                share1.header.get_work() + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();

        store.commit_batch(batch).unwrap();

        let genesis_hash = share1.block_hash();

        // Test manual chain state operations
        store.set_genesis_block_hash(genesis_hash);
        assert_eq!(store.get_genesis_block_hash(), Some(genesis_hash));

        store.set_chain_tip(share3.block_hash());
        assert_eq!(store.get_chain_tip(), share3.block_hash());

        let mut tips = HashSet::new();
        tips.insert(share3.block_hash());
        store.update_tips(tips.clone());
        assert_eq!(store.get_tips(), tips);

        store.add_tip(share2.block_hash());
        assert!(store.get_tips().contains(&share2.block_hash()));

        store.remove_tip(&share2.block_hash());
        assert!(!store.get_tips().contains(&share2.block_hash()));

        // Test initialization from store
        store.init_chain_state_from_store(genesis_hash).unwrap();

        // After initialization, tip should be set to last block in main chain
        assert_eq!(store.get_chain_tip(), share3.block_hash());

        assert_eq!(store.get_genesis_block_hash(), Some(genesis_hash));

        // Tips should include only blocks at highest height (height 2)
        let tips_after_init = store.get_tips();
        assert_eq!(tips_after_init.len(), 1);
        assert!(tips_after_init.contains(&share3.block_hash()));

        // Total work should reflect sum of work from main chain
        assert_eq!(
            store.get_total_work().unwrap(),
            multiplied_compact_target_as_work(0x01e0377ae, 1)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 3)
        ); // 1 + 2 + 3 = 6
    }

    #[test]
    fn test_merge_operator_for_block_height() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let height = 100u32;

        // Create three different blockhashes
        let hash1 = BlockHash::from_byte_array([1u8; 32]);
        let hash2 = BlockHash::from_byte_array([2u8; 32]);
        let hash3 = BlockHash::from_byte_array([3u8; 32]);

        // Add hash1 at height 100
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify hash1 is stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&hash1));

        // Add hash2 at the same height using merge operator
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash2, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify both hash1 and hash2 are stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));

        // Add hash3 at the same height
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash3, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify all three hashes are stored
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));

        // Test deduplication - add hash1 again
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Should still have only 3 hashes (no duplicate)
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));
    }

    #[test]
    fn test_merge_operator_multiple_batches() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let height = 200u32;

        let hash1 = BlockHash::from_byte_array([10u8; 32]);
        let hash2 = BlockHash::from_byte_array([20u8; 32]);
        let hash3 = BlockHash::from_byte_array([30u8; 32]);

        // Add multiple hashes in a single batch
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, height, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash2, height, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash3, height, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify all hashes are stored correctly
        let hashes = store.get_blockhashes_for_height(height);
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
        assert!(hashes.contains(&hash3));
    }

    #[test]
    fn test_merge_operator_different_heights() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let hash1 = BlockHash::from_byte_array([100u8; 32]);
        let hash2 = BlockHash::from_byte_array([200u8; 32]);

        // Add hash1 at height 100 and hash2 at height 200
        let mut batch = Store::get_write_batch();
        store
            .set_height_to_blockhash(&hash1, 100, &mut batch)
            .unwrap();
        store
            .set_height_to_blockhash(&hash2, 200, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify hashes are stored at correct heights
        let hashes_100 = store.get_blockhashes_for_height(100);
        assert_eq!(hashes_100.len(), 1);
        assert!(hashes_100.contains(&hash1));

        let hashes_200 = store.get_blockhashes_for_height(200);
        assert_eq!(hashes_200.len(), 1);
        assert!(hashes_200.contains(&hash2));
    }
}
