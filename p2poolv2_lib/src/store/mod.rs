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

        let unspent_outputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::UnspentOutputs, RocksDbOptions::default());

        let cfs = vec![
            block_cf,
            block_txids_cf,
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
            unspent_outputs_cf,
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
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::shares::share_block::Txids;
    use crate::test_utils::TestShareBlockBuilder;
    use crate::test_utils::multiplied_compact_target_as_work;
    use bitcoin::Transaction;
    use bitcoin::Txid;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    #[test_log::test]
    fn test_setup_genesis() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();

        let mut batch = rocksdb::WriteBatch::default();

        let result = store.setup_genesis(share1.clone(), &mut batch);

        assert!(result.is_ok());

        store.db.write(batch).unwrap();

        let tip = store.get_chain_tip();
        assert_eq!(tip, share1.block_hash());

        let metadata = store.get_block_metadata(&tip).unwrap();

        assert_eq!(metadata.height, Some(0));
    }

    #[test_log::test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let genesis_work = genesis.header.get_work();

        let mut batch = rocksdb::WriteBatch::default();
        // Add all shares to store
        store
            .add_share(genesis.clone(), 0, genesis_work, true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let blocks_at_height_0 = store.get_blockhashes_for_height(0);
        assert_eq!(blocks_at_height_0, vec![genesis.block_hash()]);
    }

    #[test]
    fn test_transaction_store_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a simple test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Store the transaction
        let txid = tx.compute_txid();
        let mut batch = rocksdb::WriteBatch::default();
        let txs_metadata = store
            .add_sharechain_txs(&[tx.clone()], true, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        assert_eq!(txs_metadata.len(), 1);
        assert_eq!(txs_metadata[0].txid, txid);

        // Retrieve the transaction
        let retrieved_tx = store.get_tx(&txid).unwrap();
        assert_eq!(retrieved_tx.input.len(), 0);
        assert_eq!(retrieved_tx.output.len(), 0);
        assert_eq!(retrieved_tx.version, tx.version);
        assert_eq!(retrieved_tx.lock_time, tx.lock_time);
    }

    #[test]
    fn test_transaction_store_for_nonexistent_transaction_should_fail() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Try getting non-existent transaction
        let fake_txid = "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
            .parse()
            .unwrap();
        assert!(store.get_tx(&fake_txid).is_err());
    }

    #[test]
    fn test_store_retrieve_txids_by_blockhash_index() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test transactions
        let tx1 = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let tx2 = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid1 = tx1.compute_txid();
        let txid2 = tx2.compute_txid();

        // Create a test share block with transactions
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(tx1.clone())
            .add_transaction(tx2.clone())
            .build();

        let blockhash = share.block_hash();

        // Store the txids for the blockhash
        let txids = Txids(vec![txid1, txid2]);
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_txids_to_block_index(
                &blockhash,
                &txids,
                &mut batch,
                b"_txids",
                ColumnFamily::BlockTxids,
            )
            .unwrap();
        store.db.write(batch).unwrap();

        // Get txids for the blockhash
        let retrieved_txids = store
            .get_txids_for_blockhash(&blockhash, ColumnFamily::BlockTxids)
            .0;

        // Verify we got back the same txids in the same order
        assert_eq!(retrieved_txids.len(), 2);
        assert_eq!(retrieved_txids[0], txid1);
        assert_eq!(retrieved_txids[1], txid2);

        // Test getting txids for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse::<BlockHash>()
                .unwrap();
        let empty_txids =
            store.get_txids_for_blockhash(&non_existent_blockhash, ColumnFamily::BlockTxids);
        assert!(empty_txids.0.is_empty());
    }

    #[test]
    fn test_store_share_block_with_transactions_should_retreive_txs() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test transactions
        let tx1 = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let tx2 = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Create a test share block with transactions
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".to_string(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(tx1.clone())
            .add_transaction(tx2.clone())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        // Store the share block
        store
            .add_share(share.clone(), 0, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(share.transactions.len(), 3);

        // Retrieve transactions for the block hash
        let retrieved_txs =
            store.get_txs_for_blockhash(&share.block_hash(), ColumnFamily::BlockTxids);

        // Verify transactions were stored and can be retrieved
        assert_eq!(retrieved_txs.len(), 3);
        assert!(retrieved_txs[0].is_coinbase());
        assert_eq!(retrieved_txs[1], tx1);
        assert_eq!(retrieved_txs[2], tx2);

        // Verify individual transactions can be retrieved by txid
        let tx1_id = tx1.compute_txid();
        let tx2_id = tx2.compute_txid();

        assert_eq!(store.get_tx(&tx1_id).unwrap(), tx1);
        assert_eq!(store.get_tx(&tx2_id).unwrap(), tx2);
    }

    #[test]
    fn test_add_tx_metadata_with_no_inputs_or_outputs_should_succeed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid = tx.compute_txid();
        let mut batch = rocksdb::WriteBatch::default();
        let res = store.add_tx_metadata(txid, &tx, false, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        assert_eq!(res.txid, txid);
        let tx_metadata = store.get_tx_metadata(&txid).unwrap();
        assert_eq!(tx_metadata.txid, txid);
        assert_eq!(tx_metadata.version, tx.version);
        assert_eq!(tx_metadata.lock_time, tx.lock_time);
        assert_eq!(tx_metadata.input_count, 0);
        assert_eq!(tx_metadata.output_count, 0);
        assert!(!tx_metadata.validated);
    }

    #[test]
    fn test_add_txs_with_inputs_or_outputs_should_succeed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let script_true = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    "0101010101010101010101010101010101010101010101010101010101010101"
                        .parse()
                        .unwrap(),
                    0,
                ),
                sequence: bitcoin::Sequence::default(),
                witness: bitcoin::Witness::default(),
                script_sig: script_true.clone(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1000000),
                script_pubkey: script_true.clone(),
            }],
        };

        let txid = tx.compute_txid();
        let mut batch = rocksdb::WriteBatch::default();
        let res = store
            .add_sharechain_txs(&[tx.clone()], true, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        assert_eq!(res[0].txid, txid);

        let tx = store.get_tx(&txid).unwrap();
        assert_eq!(tx.version, tx.version);
        assert_eq!(tx.lock_time, tx.lock_time);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            tx.input[0].previous_output,
            bitcoin::OutPoint::new(
                "0101010101010101010101010101010101010101010101010101010101010101"
                    .parse()
                    .unwrap(),
                0,
            )
        );
        assert_eq!(tx.input[0].script_sig, script_true);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, bitcoin::Amount::from_sat(1000000));
        assert_eq!(tx.output[0].script_pubkey, script_true);
    }

    #[test]
    fn test_add_txs_should_succeed() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test transactions
        let tx1 = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let tx2 = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let transactions = vec![tx1.clone(), tx2.clone()];

        // Add transactions to store
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_sharechain_txs(&transactions, true, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify transactions were stored correctly by retrieving them by txid
        let tx1_id = tx1.compute_txid();
        let tx2_id = tx2.compute_txid();

        assert_eq!(store.get_tx(&tx1_id).unwrap(), tx1);
        assert_eq!(store.get_tx(&tx2_id).unwrap(), tx2);
    }

    #[test]
    fn test_get_share_header() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test share block
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        // Add share to store
        store
            .add_share(share.clone(), 0, share.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Get share header from store
        let read_share = store.get_share(&share.block_hash()).unwrap();

        // Verify header matches original
        assert_eq!(read_share.block_hash(), share.block_hash());
        assert_eq!(
            read_share.header.prev_share_blockhash,
            share.header.prev_share_blockhash
        );
        assert_eq!(read_share.header.uncles, share.header.uncles);
        assert_eq!(read_share.header.miner_pubkey, share.header.miner_pubkey);

        assert_eq!(
            read_share.header.bitcoin_header.nonce,
            share.header.bitcoin_header.nonce
        );
        assert_eq!(
            read_share.header.bitcoin_header.work(),
            share.header.bitcoin_header.work()
        );
        assert_eq!(
            read_share.header.bitcoin_header.time,
            share.header.bitcoin_header.time
        );
    }

    #[test]
    fn test_get_share_header_nonexistent() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Try to get share header for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse::<BlockHash>()
                .unwrap();
        let result = store.get_share(&non_existent_blockhash);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_children() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
            .build();

        // Create share3
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        // Add all shares to store
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle1_share2.clone(),
                1,
                share1.header.get_work() + uncle1_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle2_share2.clone(),
                1,
                share1.header.get_work() + uncle2_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
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

        // Verify children of share1
        let children_share1 = store
            .get_children_blockhashes(&share1.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.block_hash()));
        assert!(children_share1.contains(&uncle1_share2.block_hash()));
        assert!(children_share1.contains(&uncle2_share2.block_hash()));

        // Verify children of share2
        let children_share2 = store
            .get_children_blockhashes(&share2.block_hash())
            .unwrap()
            .unwrap();
        assert_eq!(children_share2.len(), 1);
        assert!(children_share2.contains(&share3.block_hash()));

        // Verify children of share3
        let children_share3 = store
            .get_children_blockhashes(&share3.block_hash())
            .unwrap();
        assert!(children_share3.is_none());

        // Verify children of uncle1_share2
        let children_uncle1_share2 = store
            .get_children_blockhashes(&uncle1_share2.block_hash())
            .unwrap()
            .unwrap();
        assert!(children_uncle1_share2.contains(&share2.block_hash()));

        // Verify children of uncle2_share2
        let children_uncle2_share2 = store
            .get_children_blockhashes(&uncle2_share2.block_hash())
            .unwrap()
            .unwrap();
        assert!(children_uncle2_share2.contains(&share2.block_hash()));
    }

    #[test]
    fn test_get_descendants() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
            .build();

        // Create share3
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let genesis_work = share1.header.get_work();

        let mut batch = rocksdb::WriteBatch::default();
        // Add all shares to store
        store
            .add_share(share1.clone(), 0, genesis_work, true, &mut batch)
            .unwrap();
        store
            .add_share(
                uncle1_share2.clone(),
                1,
                genesis_work + uncle1_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle2_share2.clone(),
                1,
                genesis_work + uncle2_share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                genesis_work + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share3.clone(),
                2,
                genesis_work + share2.header.get_work() + share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();

        store.commit_batch(batch).unwrap();

        // Verify descendants of share1
        let descendants_share1 = store
            .get_descendants(share1.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_share1.len(), 4);
        assert!(descendants_share1.contains(&share2.header));
        assert!(descendants_share1.contains(&share3.header));
        assert!(descendants_share1.contains(&uncle1_share2.header));
        assert!(descendants_share1.contains(&uncle2_share2.header));

        // Verify descendants of share2
        let descendants_share2 = store
            .get_descendants(share2.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_share2.len(), 1);
        assert_eq!(descendants_share2[0], share3.header);

        // Verify no descendants for share3
        let descendants_share3 = store
            .get_descendants(share3.block_hash(), &share3.block_hash(), 10)
            .unwrap();
        assert!(descendants_share3.is_empty());

        // Verify descendants with limit
        let descendants_with_limit = store
            .get_descendants(share1.block_hash(), &share3.block_hash(), 1)
            .unwrap();
        assert_eq!(descendants_with_limit.len(), 1);
        assert_eq!(descendants_with_limit[0], uncle1_share2.header);

        // Verify descendants with stop blockhash
        let descendants_with_limit = store
            .get_descendants(share1.block_hash(), &share2.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants_with_limit.len(), 3);
        assert!(descendants_with_limit.contains(&share2.header));
        assert!(descendants_with_limit.contains(&uncle1_share2.header));
        assert!(descendants_with_limit.contains(&uncle2_share2.header));
    }

    #[test_log::test]
    fn test_get_headers_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let num_blockhashes = 5;
        let mut hashes: Vec<BlockHash> = vec![];
        let mut prev_blockhash = BlockHash::all_zeros();

        for height in 0..num_blockhashes {
            let mut batch = rocksdb::WriteBatch::default();
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            store
                .add_share(
                    block.clone(),
                    height,
                    block.header.get_work(),
                    true,
                    &mut batch,
                )
                .unwrap();
            store.commit_batch(batch).unwrap();

            prev_blockhash = block.block_hash();
            hashes.push(prev_blockhash);
        }

        let stop_block = store.get_blockhashes_for_height(2)[0];
        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store
            .get_headers_for_locator(locator.as_slice(), &stop_block, 10)
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].block_hash(), hashes[1]);
        assert_eq!(result[1].block_hash(), hashes[2]);
    }

    #[test]
    fn test_get_headers_for_block_locator_stop_block_not_found() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut blocks = Vec::new();
        let mut locator = vec![];

        let num_blockhashes = 3;
        let mut hashes: Vec<BlockHash> = vec![];

        let mut prev_blockhash = BlockHash::all_zeros();

        for height in 0..num_blockhashes {
            let mut batch = rocksdb::WriteBatch::default();
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            blocks.push(block.clone());
            store
                .add_share(
                    block.clone(),
                    height as u32,
                    block.header.get_work(),
                    true,
                    &mut batch,
                )
                .unwrap();
            prev_blockhash = block.block_hash();
            hashes.push(prev_blockhash);
            store.commit_batch(batch).unwrap();
        }

        locator.push(blocks[0].block_hash()); // locator = tip

        // Use a stop block hash that doesn't exist in our chain
        let non_existent_stop_block =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse::<BlockHash>()
                .unwrap();

        // Call get_headers_for_block_locator with non-existent stop block
        let result = store
            .get_headers_for_locator(&locator, &non_existent_stop_block, 10)
            .unwrap();
        assert_eq!(result.len(), 2);
        // start block not in response
        assert_eq!(result[0], blocks[1].header);
        assert_eq!(result[1], blocks[2].header);
    }

    #[test]
    fn test_get_blockhashes_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut block_hashes = Vec::new();

        let num_blockhashes = 5;

        let mut prev_blockhash = BlockHash::all_zeros();

        let mut batch = rocksdb::WriteBatch::default();

        for height in 0..num_blockhashes {
            let builder =
                TestShareBlockBuilder::new().prev_share_blockhash(prev_blockhash.to_string());
            let block = builder.build();
            let blockhash = block.block_hash();
            block_hashes.push(blockhash);
            let work = block.header.get_work();
            store
                .add_share(block, height as u32, work, true, &mut batch)
                .unwrap();
            prev_blockhash = blockhash;
        }

        store.commit_batch(batch).unwrap();

        let stop_block = store.get_blockhashes_for_height(2)[0];

        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store
            .get_blockhashes_for_locator(locator.as_slice(), &stop_block, 10)
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], block_hashes[1]);
        assert_eq!(result[1], block_hashes[2]);
    }

    #[test]
    fn test_block_status_for_nonexistent_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a blockhash that doesn't exist in the store
        let nonexistent_blockhash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse::<BlockHash>()
                .unwrap();

        // Status checks should return false for non-existent blocks
        let metadata = store.get_block_metadata(&nonexistent_blockhash);
        assert!(metadata.is_err());
    }

    #[test]
    fn test_add_pplns_share() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_id = store
            .add_user("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string())
            .unwrap();

        // Create a PPLNS share
        let pplns_share = SimplePplnsShare::new(
            user_id,
            1,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            "".to_string(),
            1000,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );

        // Add the PPLNS share to the store
        let result = store.add_pplns_share(pplns_share.clone());
        assert!(
            result.is_ok(),
            "Failed to add PPLNS share: {:?}",
            result.err()
        );

        let stored_data = store.get_pplns_shares();
        assert!(
            !stored_data.is_empty(),
            "PPLNS share data not found in database"
        );
    }

    #[test]
    fn test_store_and_get_user() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();

        // Store a new user
        let user_id = store.add_user(btcaddress.clone()).unwrap();

        // Get user by ID
        let stored_user = store.get_user_by_id(user_id).unwrap().unwrap();
        assert_eq!(stored_user.user_id, user_id);
        assert_eq!(stored_user.btcaddress, btcaddress);
        assert!(stored_user.created_at > 0);

        // Get user by btcaddress
        let user_by_address = store.get_user_by_btcaddress(&btcaddress).unwrap().unwrap();
        assert_eq!(user_by_address.user_id, user_id);
        assert_eq!(user_by_address.btcaddress, btcaddress);

        // Store same user again - should return same ID
        let same_user_id = store.add_user(btcaddress.clone()).unwrap();
        assert_eq!(same_user_id, user_id);

        // Store different user - should get new ID
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let _user_id2 = store.add_user(btcaddress2.clone()).unwrap();

        // Verify both users exist
        let user1 = store.get_user_by_btcaddress(&btcaddress).unwrap().unwrap();
        let user2 = store.get_user_by_btcaddress(&btcaddress2).unwrap().unwrap();
        assert_ne!(user1.user_id, user2.user_id);
    }

    #[test]
    fn test_get_nonexistent_user() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Test getting non-existent user by ID
        let user = store.get_user_by_id(999).unwrap();
        assert!(user.is_none());

        // Test getting non-existent user by btcaddress
        let user = store.get_user_by_btcaddress("nonexistent_address").unwrap();
        assert!(user.is_none());
    }

    #[test]
    fn test_user_serialization() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();

        // Store user
        let user_id = store.add_user(btcaddress.clone()).unwrap();

        // Retrieve and verify data integrity
        let stored_user = store.get_user_by_id(user_id).unwrap().unwrap();

        // Verify all fields are correctly serialized/deserialized
        assert_eq!(stored_user.user_id, user_id);
        assert_eq!(stored_user.btcaddress, btcaddress);
        assert!(stored_user.created_at > 0);

        // Verify timestamps are reasonable (within last minute)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(stored_user.created_at <= now);
        assert!(stored_user.created_at > now - 60);
    }

    #[test]
    fn test_get_btcaddresses_for_user_ids() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Store multiple users
        let btcaddress1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let btcaddress3 = "1QGTJkBFhCjPHqbnwK6z7JfEHefq6Yj2jJ".to_string();

        let user_id1 = store.add_user(btcaddress1.clone()).unwrap();
        let user_id2 = store.add_user(btcaddress2.clone()).unwrap();
        let user_id3 = store.add_user(btcaddress3.clone()).unwrap();

        // Test getting btcaddresses for existing user IDs
        let user_ids = &[user_id1, user_id2, user_id3];
        let results = store.get_btcaddresses_for_user_ids(user_ids).unwrap();

        assert_eq!(results.len(), 3);

        // Convert to HashMap for easier lookup
        let result_map: std::collections::HashMap<u64, String> = results.into_iter().collect();

        assert_eq!(result_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(result_map.get(&user_id2), Some(&btcaddress2));
        assert_eq!(result_map.get(&user_id3), Some(&btcaddress3));

        // Test with subset of user IDs
        let subset_ids = &[user_id1, user_id3];
        let subset_results = store.get_btcaddresses_for_user_ids(subset_ids).unwrap();

        assert_eq!(subset_results.len(), 2);
        let subset_map: std::collections::HashMap<u64, String> =
            subset_results.into_iter().collect();

        assert_eq!(subset_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(subset_map.get(&user_id3), Some(&btcaddress3));
        assert!(!subset_map.contains_key(&user_id2));

        // Test with non-existent user IDs
        let nonexistent_ids = &[9999, 8888];
        let empty_results = store
            .get_btcaddresses_for_user_ids(nonexistent_ids)
            .unwrap();

        assert_eq!(empty_results.len(), 0);

        // Test with mixed existing and non-existent IDs
        let mixed_ids = &[user_id1, 9999, user_id2];
        let mixed_results = store.get_btcaddresses_for_user_ids(mixed_ids).unwrap();

        assert_eq!(mixed_results.len(), 2);
        let mixed_map: std::collections::HashMap<u64, String> = mixed_results.into_iter().collect();

        assert_eq!(mixed_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(mixed_map.get(&user_id2), Some(&btcaddress2));
        assert!(!mixed_map.contains_key(&9999));
    }

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
    fn test_add_job() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add a job with timestamp
        let timestamp = 1000000u64;
        let job_data = "test_job_data".to_string();

        let result = store.add_job(timestamp, job_data.clone());
        assert!(result.is_ok());

        // Verify job was stored by reading it back
        let jobs = store.get_jobs(None, Some(timestamp + 1000), 10).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, timestamp);
        assert_eq!(jobs[0].1, job_data);
    }

    #[test]
    fn test_get_jobs_with_no_jobs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let jobs = store.get_jobs(None, None, 10).unwrap();
        assert_eq!(jobs.len(), 0);
    }

    #[test]
    fn test_get_jobs_ordered_by_timestamp() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs with different timestamps
        let job1_time = 1000000u64;
        let job2_time = 2000000u64;
        let job3_time = 3000000u64;

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();

        // Get all jobs - should be ordered newest first
        let jobs = store.get_jobs(None, Some(job3_time + 1000), 10).unwrap();
        assert_eq!(jobs.len(), 3);

        // Verify newest first ordering
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[0].1, "job3");
        assert_eq!(jobs[1].0, job2_time);
        assert_eq!(jobs[1].1, "job2");
        assert_eq!(jobs[2].0, job1_time);
        assert_eq!(jobs[2].1, "job1");
    }

    #[test]
    fn test_get_jobs_with_limit() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add 5 jobs
        for i in 1..=5 {
            store.add_job(i * 1000000, format!("job{i}")).unwrap();
        }

        // Request only 3 jobs
        let jobs = store.get_jobs(None, Some(6000000), 3).unwrap();
        assert_eq!(jobs.len(), 3);

        // Should get the 3 newest
        assert_eq!(jobs[0].1, "job5");
        assert_eq!(jobs[1].1, "job4");
        assert_eq!(jobs[2].1, "job3");
    }

    #[test]
    fn test_get_jobs_with_time_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs with different timestamps
        let job1_time = 1000000u64;
        let job2_time = 2000000u64;
        let job3_time = 3000000u64;
        let job4_time = 4000000u64;

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();
        store.add_job(job4_time, "job4".to_string()).unwrap();

        // Get jobs between start_time=1.5M and end_time=3.5M
        // Should return job3 and job2 (newest first)
        let jobs = store.get_jobs(Some(1500000), Some(3500000), 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[0].1, "job3");
        assert_eq!(jobs[1].0, job2_time);
        assert_eq!(jobs[1].1, "job2");
    }

    #[test]
    fn test_get_jobs_with_end_time_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs
        store.add_job(1000000, "job1".to_string()).unwrap();
        store.add_job(2000000, "job2".to_string()).unwrap();
        store.add_job(3000000, "job3".to_string()).unwrap();

        // Get all jobs up to 2.5M
        let jobs = store.get_jobs(None, Some(2500000), 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].1, "job2");
        assert_eq!(jobs[1].1, "job1");
    }

    #[test]
    fn test_get_jobs_with_start_time_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Get current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        // Add jobs in the past
        let job1_time = now - 3000000; // ~3 seconds ago
        let job2_time = now - 2000000; // ~2 seconds ago
        let job3_time = now - 1000000; // ~1 second ago

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();

        // Get jobs from 2.5 seconds ago to now (should return job3 and job2)
        let jobs = store.get_jobs(Some(now - 2500000), None, 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[1].0, job2_time);
    }

    #[test]
    fn test_add_to_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid = Txid::from_byte_array([1u8; 32]);
        let index = 0;

        // Add to unspent outputs
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify it was added
        assert!(store.is_in_unspent_outputs(txid, index as u32).unwrap());
    }

    #[test]
    fn test_remove_from_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid = Txid::from_byte_array([2u8; 32]);
        let index = 1u32;

        // Add to unspent outputs
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify it was added
        assert!(store.is_in_unspent_outputs(txid, index).unwrap());

        // Remove from unspent outputs
        let mut batch = rocksdb::WriteBatch::default();
        store
            .remove_from_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify it was removed
        assert!(!store.is_in_unspent_outputs(txid, index).unwrap());
    }

    #[test]
    fn test_is_in_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid1 = Txid::from_byte_array([3u8; 32]);
        let txid2 = Txid::from_byte_array([4u8; 32]);
        let index1 = 0u32;
        let index2 = 1u32;

        // Add txid1:index1
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_unspent_outputs(&txid1, index1, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Check presence
        assert!(store.is_in_unspent_outputs(txid1, index1).unwrap());
        assert!(!store.is_in_unspent_outputs(txid1, index2).unwrap());
        assert!(!store.is_in_unspent_outputs(txid2, index1).unwrap());
        assert!(!store.is_in_unspent_outputs(txid2, index2).unwrap());

        // Add txid2:index2
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_to_unspent_outputs(&txid2, index2, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Check presence again
        assert!(store.is_in_unspent_outputs(txid1, index1).unwrap());
        assert!(!store.is_in_unspent_outputs(txid1, index2).unwrap());
        assert!(!store.is_in_unspent_outputs(txid2, index1).unwrap());
        assert!(store.is_in_unspent_outputs(txid2, index2).unwrap());
    }

    #[test]
    fn test_mark_transaction_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid = tx.compute_txid();

        // Add transaction metadata with validated = false
        let mut batch = rocksdb::WriteBatch::default();
        let metadata = store.add_tx_metadata(txid, &tx, false, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        // Verify initially not validated
        assert!(!metadata.validated);
        let stored_metadata = store.get_tx_metadata(&txid).unwrap();
        assert!(!stored_metadata.validated);

        // Mark transaction as valid
        let mut batch = rocksdb::WriteBatch::default();
        let updated_metadata = store.mark_transaction_valid(&txid, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        // Verify it's now validated
        assert!(updated_metadata.validated);
        let stored_metadata = store.get_tx_metadata(&txid).unwrap();
        assert!(stored_metadata.validated);
    }

    #[test]
    fn test_confirm_transaction() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a previous transaction with outputs
        let prev_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1000000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(2000000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };

        let prev_txid = prev_tx.compute_txid();

        // Add the previous transaction and its outputs to unspent set
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_tx_metadata(prev_txid, &prev_tx, false, &mut batch)
            .unwrap();
        store
            .add_to_unspent_outputs(&prev_txid, 0, &mut batch)
            .unwrap();
        store
            .add_to_unspent_outputs(&prev_txid, 1, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify outputs are in unspent set
        assert!(store.is_in_unspent_outputs(prev_txid, 0).unwrap());
        assert!(store.is_in_unspent_outputs(prev_txid, 1).unwrap());

        // Create a new transaction that spends the previous outputs
        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(prev_txid, 0),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(prev_txid, 1),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(2900000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Confirm the transaction (should remove inputs from unspent set)
        let mut batch = rocksdb::WriteBatch::default();
        store.confirm_transaction(&tx, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        // Verify the previous outputs are no longer in unspent set
        assert!(!store.is_in_unspent_outputs(prev_txid, 0).unwrap());
        assert!(!store.is_in_unspent_outputs(prev_txid, 1).unwrap());
    }

    #[test]
    fn test_unconfirm_transaction() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a previous transaction
        let prev_txid = Txid::from_byte_array([5u8; 32]);

        // Create a transaction that spends outputs
        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(prev_txid, 0),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(prev_txid, 1),
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(2900000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        // Verify outputs are not in unspent set initially
        assert!(!store.is_in_unspent_outputs(prev_txid, 0).unwrap());
        assert!(!store.is_in_unspent_outputs(prev_txid, 1).unwrap());

        // Unconfirm the transaction (should add inputs back to unspent set)
        let mut batch = rocksdb::WriteBatch::default();
        store.unconfirm_transaction(&tx, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        // Verify the previous outputs are now in unspent set
        assert!(store.is_in_unspent_outputs(prev_txid, 0).unwrap());
        assert!(store.is_in_unspent_outputs(prev_txid, 1).unwrap());
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create linear chain: share1 -> share2 -> share3
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
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

        // Set share3 as the tip
        store.add_tip(share3.block_hash());

        // Get chain from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all three shares
        assert_eq!(chain.len(), 3);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
    }

    #[test_log::test]
    fn test_get_shares_from_tip_to_blockhash_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestShareBlockBuilder::new().build();

        // Create uncles for share2
        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Create share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1.block_hash(), uncle2.block_hash()])
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle1.clone(),
                1,
                share1.header.get_work() + uncle1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle2.clone(),
                1,
                share1.header.get_work() + uncle2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Set share2 as the tip
        store.add_tip(share2.block_hash());

        // Get chain from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain share2, share1, and both uncles
        assert_eq!(chain.len(), 4);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&uncle1.block_hash()));
        assert!(chain_hashes.contains(&uncle2.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_multiple_tips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a chain that splits into two tips
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();

        // Two competing tips at height 2
        let tip1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(100)
            .build();

        let tip2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(200)
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                tip1.clone(),
                2,
                share1.header.get_work() + share2.header.get_work() + tip1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                tip2.clone(),
                2,
                share1.header.get_work() + share2.header.get_work() + tip2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Set both as tips
        store.add_tip(tip1.block_hash());
        store.add_tip(tip2.block_hash());

        // Get chain from tips to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all shares from both tips down to share1
        assert_eq!(chain.len(), 4);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&tip1.block_hash()));
        assert!(chain_hashes.contains(&tip2.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = rocksdb::WriteBatch::default();

        let share1 = TestShareBlockBuilder::new().build();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.add_tip(share1.block_hash());

        // Try to get chain to a non-existent blockhash
        let nonexistent_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .parse::<BlockHash>()
            .unwrap();

        let result = store.get_shares_from_tip_to_blockhash(&nonexistent_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_stops_at_target() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create chain: share1 -> share2 -> share3 -> share4
        let share1 = TestShareBlockBuilder::new().build();
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();
        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
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

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share4.clone(),
                3,
                share1.header.get_work()
                    + share2.header.get_work()
                    + share3.header.get_work()
                    + share4.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        store.add_tip(share4.block_hash());

        // Get chain from tip to share2 (should stop at share2)
        let chain = store
            .get_shares_from_tip_to_blockhash(&share2.block_hash())
            .unwrap();

        // Should contain share4, share3, and share2, but not share1
        assert_eq!(chain.len(), 3);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
        assert!(chain_hashes.contains(&share4.block_hash()));
        assert!(!chain_hashes.contains(&share1.block_hash()));
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_no_tips() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut batch = rocksdb::WriteBatch::default();

        let share1 = TestShareBlockBuilder::new().build();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Don't set any tips - should return empty vector
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn test_get_shares_from_tip_to_blockhash_complex_uncle_tree() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a more complex tree with multiple levels of uncles
        let share1 = TestShareBlockBuilder::new().build();

        // Level 1 uncles
        let uncle1_1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(100)
            .build();

        let uncle1_2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(200)
            .build();

        // Share2 with uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_1.block_hash(), uncle1_2.block_hash()])
            .build();

        // Level 2 uncles
        let uncle2_1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .build();

        // Share3 with uncle
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle2_1.block_hash()])
            .build();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share1.clone(),
                0,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle1_1.clone(),
                1,
                share1.header.get_work() + uncle1_1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle1_2.clone(),
                1,
                share1.header.get_work() + uncle1_2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share2.clone(),
                1,
                share1.header.get_work() + share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                uncle2_1.clone(),
                2,
                share1.header.get_work() + share2.header.get_work() + uncle2_1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = rocksdb::WriteBatch::default();
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

        store.add_tip(share3.block_hash());

        // Get all shares from tip to share1
        let chain = store
            .get_shares_from_tip_to_blockhash(&share1.block_hash())
            .unwrap();

        // Should contain all 6 shares
        assert_eq!(chain.len(), 6);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|s| s.block_hash()).collect();
        assert!(chain_hashes.contains(&share1.block_hash()));
        assert!(chain_hashes.contains(&share2.block_hash()));
        assert!(chain_hashes.contains(&share3.block_hash()));
        assert!(chain_hashes.contains(&uncle1_1.block_hash()));
        assert!(chain_hashes.contains(&uncle1_2.block_hash()));
        assert!(chain_hashes.contains(&uncle2_1.block_hash()));
    }

    #[test]
    fn test_get_descendant_blockhashes_with_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create four shares: a -> b -> c and b -> d (fork at b)
        let share_a = TestShareBlockBuilder::new().build();
        let share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .build();
        let share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .nonce(100)
            .build();
        let share_d = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .nonce(200)
            .build();

        // Add share a
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share_a.clone(),
                0,
                share_a.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share b
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share_b.clone(),
                1,
                share_a.header.get_work() + share_b.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share c
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share_c.clone(),
                2,
                share_a.header.get_work() + share_b.header.get_work() + share_c.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Add share d (fork from b)
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_share(
                share_d.clone(),
                2,
                share_a.header.get_work() + share_b.header.get_work() + share_d.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test getting all descendants from a (should get b, c, d)
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &BlockHash::all_zeros(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 3);
        assert!(descendants.contains(&share_b.block_hash()));
        assert!(descendants.contains(&share_c.block_hash()));
        assert!(descendants.contains(&share_d.block_hash()));

        // Test getting descendants from b (should get c and d)
        let descendants = store
            .get_descendant_blockhashes(&share_b.block_hash(), &BlockHash::all_zeros(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 2);
        assert!(descendants.contains(&share_c.block_hash()));
        assert!(descendants.contains(&share_d.block_hash()));

        // Test with limit
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &BlockHash::all_zeros(), 2)
            .unwrap();
        assert_eq!(descendants.len(), 2);

        // Test with stop_blockhash - should return just share_b
        let descendants = store
            .get_descendant_blockhashes(&share_a.block_hash(), &share_b.block_hash(), 10)
            .unwrap();
        assert_eq!(descendants.len(), 1);
        assert!(descendants.contains(&share_b.block_hash()));
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

    #[test]
    fn test_find_chain_for_depth_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a linear chain of 10 blocks
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(genesis.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut prev_hash = genesis.block_hash();
        let mut blocks = vec![genesis.block_hash()];

        for i in 1..10 {
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .nonce(0xe9695791 + i)
                .build();

            let mut batch = Store::get_write_batch();
            store
                .add_share(share.clone(), i, share.header.get_work(), true, &mut batch)
                .unwrap();
            store.commit_batch(batch).unwrap();

            blocks.push(share.block_hash());
            prev_hash = share.block_hash();
        }

        // Test finding chain from tip with depth 5
        let chain = store.get_dag_for_depth(&blocks[9], 5).unwrap();

        // Should return blocks 9, 8, 7, 6, 5 (from newest to oldest)
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0], blocks[9]);
        assert_eq!(chain[1], blocks[8]);
        assert_eq!(chain[2], blocks[7]);
        assert_eq!(chain[3], blocks[6]);
        assert_eq!(chain[4], blocks[5]);

        // Test finding chain with depth greater than chain length
        let chain = store.get_dag_for_depth(&blocks[5], 10).unwrap();

        // Should return blocks 5, 4, 3, 2, 1, 0 (6 blocks total)
        assert_eq!(chain.len(), 6);
        assert_eq!(chain[0], blocks[5]);
        assert_eq!(chain[5], blocks[0]);

        // Test finding chain from genesis
        let chain = store.get_dag_for_depth(&blocks[0], 5).unwrap();

        // Should return only genesis (height 0, depth 0)
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], blocks[0]);
    }

    #[test]
    fn test_get_common_ancestor_linear_chain() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a linear chain: genesis -> share1 -> share2 -> share3
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(genesis.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share1.clone(),
                1,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share2.clone(),
                2,
                share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share3.clone(),
                3,
                share3.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of share3 and share2
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &share2.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share2.block_hash()));

        // Test common ancestor of share3 and share1
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));

        // Test common ancestor of share3 and genesis
        let ancestor = store
            .get_common_ancestor(&share3.block_hash(), &genesis.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share2 and share1
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));
    }

    #[test]
    fn test_get_common_ancestor_with_fork() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a chain with a fork:
        //        genesis
        //         /  \
        //    share1  uncle1
        //      |
        //    share2
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(genesis.clone(), &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share1.clone(),
                1,
                share1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let uncle1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                uncle1.clone(),
                1,
                uncle1.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .nonce(0xe9695794)
            .build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                share2.clone(),
                2,
                share2.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of share2 and uncle1 (should be genesis)
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &uncle1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share1 and uncle1 (should be genesis)
        let ancestor = store
            .get_common_ancestor(&share1.block_hash(), &uncle1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(genesis.block_hash()));

        // Test common ancestor of share2 and share1 (should be share1)
        let ancestor = store
            .get_common_ancestor(&share2.block_hash(), &share1.block_hash())
            .unwrap();
        assert_eq!(ancestor, Some(share1.block_hash()));
    }

    #[test]
    fn test_get_common_ancestor_no_common_within_depth() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create two separate chains (only for testing - wouldn't happen in real usage)
        let genesis1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                genesis1.clone(),
                0,
                genesis1.header.get_work(),
                true,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let genesis2 = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        let mut batch = Store::get_write_batch();
        store
            .add_share(
                genesis2.clone(),
                0,
                genesis2.header.get_work(),
                false,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Test common ancestor of two different genesis blocks (should be None)
        let ancestor = store
            .get_common_ancestor(&genesis1.block_hash(), &genesis2.block_hash())
            .unwrap();
        assert_eq!(ancestor, None);
    }
}
