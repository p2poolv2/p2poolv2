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

use crate::node::messages::Message;
use crate::shares::miner_message::{MinerWorkbase, UserWorkbase};
use crate::shares::{ShareBlock, ShareBlockHash, ShareHeader, StorageShareBlock};
use crate::store::column_families::ColumnFamily;
use crate::store::user_and_worker::{StoredUser, StoredWorker};
use crate::utils::snowflake_simplified::get_next_id;
use bitcoin::Transaction;
use p2poolv2_accounting::simple_pplns::SimplePplnsShare;
use rocksdb::{ColumnFamilyDescriptor, DB, Options as RocksDbOptions};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

pub mod column_families;
mod pplns_shares;
pub mod user_and_worker;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxMetadata {
    txid: bitcoin::Txid,
    version: bitcoin::transaction::Version,
    lock_time: bitcoin::absolute::LockTime,
    input_count: u32,
    output_count: u32,
    spent_by: Option<bitcoin::Txid>,
}

/// ShareBlock metadata capturing if a share is valid and confirmed
/// This is stored indexed by the blockhash, we can later optimise to internal key, if needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub height: Option<u32>,
    pub is_valid: bool,
    pub is_confirmed: bool,
}

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
}

/// A rocksdb based store for share blocks.
/// We use column families to store different types of data, so that compactions are independent for each type.
#[allow(dead_code)]
impl Store {
    /// Create a new share store
    pub fn new(path: String, read_only: bool) -> Result<Self, Box<dyn Error>> {
        // for now we use default options for all column families, we can tweak this later based on performance testing
        let block_cf = ColumnFamilyDescriptor::new(ColumnFamily::Block, RocksDbOptions::default());
        let block_txids_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockTxids, RocksDbOptions::default());
        let inputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Inputs, RocksDbOptions::default());
        let outputs_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Outputs, RocksDbOptions::default());
        let tx_cf = ColumnFamilyDescriptor::new(ColumnFamily::Tx, RocksDbOptions::default());
        let workbase_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Workbase, RocksDbOptions::default());
        let block_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockIndex, RocksDbOptions::default());
        let block_height_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockHeight, RocksDbOptions::default());
        let user_workbase_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::UserWorkbase, RocksDbOptions::default());

        let job_cf = ColumnFamilyDescriptor::new(ColumnFamily::Job, RocksDbOptions::default());
        let share_cf = ColumnFamilyDescriptor::new(ColumnFamily::Share, RocksDbOptions::default());
        let user_cf = ColumnFamilyDescriptor::new(ColumnFamily::User, RocksDbOptions::default());
        let worker_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Worker, RocksDbOptions::default());
        let user_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::UserIndex, RocksDbOptions::default());
        let worker_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::WorkerIndex, RocksDbOptions::default());
        let metadata_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::Metadata, RocksDbOptions::default());

        let cfs = vec![
            block_cf,
            block_txids_cf,
            inputs_cf,
            outputs_cf,
            tx_cf,
            workbase_cf,
            user_workbase_cf,
            block_index_cf,
            block_height_cf,
            job_cf,
            share_cf,
            user_cf,
            worker_cf,
            user_index_cf,
            worker_index_cf,
            metadata_cf,
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
        let store = Self { path, db };
        store.init_metadata_counters()?;
        Ok(store)
    }

    /// Initialize metadata counters for user and worker IDs
    /// Sets counters to 1 if they don't exist
    fn init_metadata_counters(&self) -> Result<(), Box<dyn Error>> {
        let metadata_cf = self.db.cf_handle(&ColumnFamily::Metadata).unwrap();

        // Initialize next_user_id if it doesn't exist
        if self.db.get_cf(metadata_cf, b"next_user_id")?.is_none() {
            self.db
                .put_cf(metadata_cf, b"next_user_id", 1u64.to_be_bytes())?;
        }

        // Initialize next_worker_id if it doesn't exist
        if self.db.get_cf(metadata_cf, b"next_worker_id")?.is_none() {
            self.db
                .put_cf(metadata_cf, b"next_worker_id", 1u64.to_be_bytes())?;
        }

        Ok(())
    }

    /// Store a user by btcaddress, returns the user ID
    pub fn store_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        // Check if user already exists via index
        if let Some(existing_id_bytes) = self.db.get_cf(user_index_cf, &btcaddress)? {
            let user_id = u64::from_be_bytes(
                existing_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid user ID format in index")?,
            );
            return Ok(user_id);
        }

        // Generate new user ID
        let user_id = get_next_id();
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create stored user
        let stored_user = StoredUser {
            user_id,
            btcaddress: btcaddress.clone(),
            created_at: current_timestamp,
        };

        // Create write batch for atomic operation
        let mut batch = rocksdb::WriteBatch::default();

        // Store user data (key: user_id, value: CBOR serialized StoredUser)
        let mut serialized_user = Vec::new();
        ciborium::ser::into_writer(&stored_user, &mut serialized_user)?;
        batch.put_cf(user_cf, user_id.to_be_bytes(), serialized_user);

        // Store index mapping (key: btcaddress, value: user_id)
        batch.put_cf(user_index_cf, btcaddress, user_id.to_be_bytes());

        // Write batch atomically
        self.db.write(batch)?;

        Ok(user_id)
    }

    /// Store a worker by workername and user_id, returns the worker ID
    pub fn store_worker(&self, user_id: u64, workername: String) -> Result<u64, Box<dyn Error>> {
        let worker_cf = self.db.cf_handle(&ColumnFamily::Worker).unwrap();
        let worker_index_cf = self.db.cf_handle(&ColumnFamily::WorkerIndex).unwrap();

        // Check if worker already exists via index
        if let Some(existing_id_bytes) = self.db.get_cf(worker_index_cf, &workername)? {
            let worker_id = u64::from_be_bytes(
                existing_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid worker ID format in index")?,
            );
            return Ok(worker_id);
        }

        // Generate new worker ID
        let worker_id = get_next_id();
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create stored worker
        let stored_worker = StoredWorker {
            worker_id,
            user_id,
            workername: workername.clone(),
            created_at: current_timestamp,
        };

        // Create write batch for atomic operation
        let mut batch = rocksdb::WriteBatch::default();

        // Store worker data (key: worker_id, value: CBOR serialized StoredWorker)
        let mut serialized_worker = Vec::new();
        ciborium::ser::into_writer(&stored_worker, &mut serialized_worker)?;
        batch.put_cf(worker_cf, worker_id.to_be_bytes(), serialized_worker);

        // Store index mapping (key: workername, value: worker_id)
        batch.put_cf(worker_index_cf, workername, worker_id.to_be_bytes());

        // Write batch atomically
        self.db.write(batch)?;

        Ok(worker_id)
    }

    /// Get user by user ID
    pub fn get_user_by_id(&self, user_id: u64) -> Result<Option<StoredUser>, Box<dyn Error>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();

        if let Some(serialized_user) = self.db.get_cf(user_cf, user_id.to_be_bytes())? {
            let stored_user: StoredUser = ciborium::de::from_reader(&serialized_user[..])?;
            Ok(Some(stored_user))
        } else {
            Ok(None)
        }
    }

    /// Get user by btcaddress
    pub fn get_user_by_btcaddress(
        &self,
        btcaddress: &str,
    ) -> Result<Option<StoredUser>, Box<dyn Error>> {
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        if let Some(user_id_bytes) = self.db.get_cf(user_index_cf, btcaddress)? {
            let user_id = u64::from_be_bytes(
                user_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid user ID format in index")?,
            );
            self.get_user_by_id(user_id)
        } else {
            Ok(None)
        }
    }

    /// Get bitcoin addresses for multiple user IDs
    /// Returns a vector of tuples (user_id, btcaddress) for users that exist
    pub fn get_btcaddresses_for_user_ids(
        &self,
        user_ids: &[u64],
    ) -> Result<Vec<(u64, String)>, Box<dyn Error>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();
        let mut results = Vec::new();

        for &user_id in user_ids {
            if let Some(serialized_user) = self.db.get_cf(user_cf, user_id.to_be_bytes())? {
                let stored_user: StoredUser = ciborium::de::from_reader(&serialized_user[..])?;
                results.push((user_id, stored_user.btcaddress));
            }
        }

        Ok(results)
    }

    /// Get worker by worker ID
    pub fn get_worker_by_id(&self, worker_id: u64) -> Result<Option<StoredWorker>, Box<dyn Error>> {
        let worker_cf = self.db.cf_handle(&ColumnFamily::Worker).unwrap();

        if let Some(serialized_worker) = self.db.get_cf(worker_cf, worker_id.to_be_bytes())? {
            let stored_worker: StoredWorker = ciborium::de::from_reader(&serialized_worker[..])?;
            Ok(Some(stored_worker))
        } else {
            Ok(None)
        }
    }

    /// Get worker by workername
    pub fn get_worker_by_workername(
        &self,
        workername: &str,
    ) -> Result<Option<StoredWorker>, Box<dyn Error>> {
        let worker_index_cf = self.db.cf_handle(&ColumnFamily::WorkerIndex).unwrap();

        if let Some(worker_id_bytes) = self.db.get_cf(worker_index_cf, workername)? {
            let worker_id = u64::from_be_bytes(
                worker_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid worker ID format in index")?,
            );
            self.get_worker_by_id(worker_id)
        } else {
            Ok(None)
        }
    }

    /// Add a share to the store
    /// We use StorageShareBlock to serialize the share so that we do not store transactions serialized with the block.
    /// Transactions are stored separately. All writes are done in a single atomic batch.
    pub fn add_share(&mut self, share: ShareBlock, height: u32) {
        debug!(
            "Adding share to store with {} txs: {:?}",
            share.transactions.len(),
            share.cached_blockhash
        );
        let blockhash = share.cached_blockhash.unwrap();

        // Create a new write batch
        let mut batch = rocksdb::WriteBatch::default();

        // Store transactions and get their metadata
        let txs_metadata = self.store_txs(&share.transactions, &mut batch);

        let txids = txs_metadata.iter().map(|t| t.txid).collect();
        // Store block -> txids index
        self.store_txids_to_block_index(&blockhash, &txids, &mut batch);

        if let Err(e) =
            self.update_block_index(&share.header.prev_share_blockhash, &blockhash, &mut batch)
        {
            tracing::error!("Failed to update block index: {:?}", e);
            return;
        }

        self.set_height_to_blockhash(&blockhash, height, &mut batch);
        self.set_block_height_in_metadata(&blockhash, Some(height), Some(&mut batch))
            .unwrap();

        // Add the share block itself
        let storage_share_block: StorageShareBlock = share.into();
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(
            block_cf,
            blockhash.as_ref(),
            storage_share_block.cbor_serialize().unwrap(),
        );

        // Write the entire batch atomically
        self.db.write(batch).unwrap();
    }

    /// Add PPLNS Share to pplns_share_cf
    /// The key is "timestamp:username:share_hash" where timestamp is microseconds since epoch
    pub fn add_pplns_share(
        &mut self,
        pplns_share: SimplePplnsShare,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let pplns_share_cf = self.db.cf_handle(&ColumnFamily::Share).unwrap();
        let (hash, serialized) = pplns_share.hash_and_serialize()?;
        let timestamp = pplns_share.timestamp as u128 * 1_000_000; // Convert seconds to microseconds
        let key = format!("{}:{}:{}", timestamp, pplns_share.btcaddress, hash);
        self.db.put_cf(pplns_share_cf, key, serialized)?;
        Ok(())
    }

    // Get PPLNS shares, no filter yet
    pub fn get_pplns_shares(
        &mut self,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>> {
        self.get_pplns_shares_filtered(usize::MAX, None, None)
    }

    /// Iterate over the store from provided start blockhash
    /// Gather all highest work blocks and return as main chain
    pub fn get_main_chain(&self, genesis: ShareBlockHash) -> (Vec<ShareBlockHash>, Decimal) {
        let mut current = Some(genesis);
        let mut main_chain = vec![];
        // hard code diff 1 for the genesis block
        let mut total_difficulty = Decimal::new(1, 0);
        while current.is_some() {
            main_chain.push(current.unwrap());
            let children = self.get_children_blockhashes(&current.unwrap());
            if children.is_empty() {
                break;
            }

            // Find the child with the highest difficulty
            let hash_and_difficulties = children.iter().filter_map(|child_hash| {
                if let Some(share) = self.get_share(child_hash) {
                    Some((child_hash, share.header.miner_share.diff))
                } else {
                    None
                }
            });

            let max_difficulty_child = hash_and_difficulties
                .clone()
                .max_by(|a, b| a.1.cmp(&b.1))
                .map(|(hash, diff)| (*hash, diff));

            total_difficulty += max_difficulty_child.map_or(Decimal::new(0, 0), |(_, diff)| diff);

            if let Some((next_blockhash, _diff)) = max_difficulty_child {
                current = Some(next_blockhash);
            } else {
                current = None;
            }
        }
        (main_chain, total_difficulty)
    }

    /// Load children BlockHashes for a blockhash from the block index
    /// These are tracked in a separate index in rocksdb as relations from
    /// blockhash -> next blockhashes
    fn get_children_blockhashes(&self, blockhash: &ShareBlockHash) -> Vec<ShareBlockHash> {
        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut blockhash_bytes = blockhash.as_ref().to_vec();
        blockhash_bytes.extend_from_slice(b"_bi");

        match self
            .db
            .get_cf::<&[u8]>(block_index_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(existing)) => {
                let existing_blockhashes: Vec<ShareBlockHash> =
                    ciborium::de::from_reader(existing.as_slice()).unwrap();
                existing_blockhashes.into_iter().collect()
            }
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    /// Update the block index so that we can easily find all the children of a block
    /// We store the next blockhashes for a block in a separate column family
    fn update_block_index(
        &self,
        prev_blockhash: &Option<ShareBlockHash>,
        next_blockhash: &ShareBlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error>> {
        if prev_blockhash.is_none() {
            return Ok(());
        }

        let prev_blockhash = prev_blockhash.unwrap();

        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut prev_blockhash_bytes = prev_blockhash.as_ref().to_vec();
        prev_blockhash_bytes.extend_from_slice(b"_bi");

        let mut existing_children = self.get_children_blockhashes(&prev_blockhash);

        // Add the new prev blockhash to the set
        existing_children.push(*next_blockhash);

        // Serialize the updated set
        let mut serialized_children = Vec::new();
        match ciborium::ser::into_writer(
            &existing_children.into_iter().collect::<Vec<_>>(),
            &mut serialized_children,
        ) {
            Ok(_) => (),
            Err(e) => return Err(Box::new(e)),
        };

        // Store the updated set
        batch.put_cf::<&[u8], Vec<u8>>(
            block_index_cf,
            prev_blockhash_bytes.as_ref(),
            serialized_children,
        );
        Ok(())
    }

    /// Store transactions in the store
    /// Store inputs and outputs for each transaction in separate column families
    /// Store txid -> transaction metadata in the tx column family
    /// The block -> txids store is done in store_txids_to_block_index. This function lets us store transactions outside of a block context
    fn store_txs(
        &self,
        transactions: &[Transaction],
        batch: &mut rocksdb::WriteBatch,
    ) -> Vec<TxMetadata> {
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut txs_metadata = Vec::new();
        for tx in transactions {
            let txid = tx.compute_txid();
            let metadata = self.store_tx_metadata(txid, tx, batch);
            txs_metadata.push(metadata);

            // Store each input for the transaction
            for (i, input) in tx.input.iter().enumerate() {
                let input_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                ciborium::ser::into_writer(&input, &mut serialized).unwrap();
                batch.put_cf::<&[u8], Vec<u8>>(inputs_cf, input_key.as_ref(), serialized);
            }

            // Store each output for the transaction
            for (i, output) in tx.output.iter().enumerate() {
                let output_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                ciborium::ser::into_writer(&output, &mut serialized).unwrap();
                batch.put_cf::<&[u8], Vec<u8>>(outputs_cf, output_key.as_ref(), serialized);
            }
        }
        txs_metadata
    }

    /// Store transaction metadata
    fn store_tx_metadata(
        &self,
        txid: bitcoin::Txid,
        tx: &Transaction,
        batch: &mut rocksdb::WriteBatch,
    ) -> TxMetadata {
        let tx_metadata = TxMetadata {
            txid,
            version: tx.version,
            lock_time: tx.lock_time,
            input_count: tx.input.len() as u32,
            output_count: tx.output.len() as u32,
            spent_by: None,
        };

        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let mut tx_metadata_serialized = Vec::new();
        ciborium::ser::into_writer(&tx_metadata, &mut tx_metadata_serialized).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(tx_cf, txid.as_ref(), tx_metadata_serialized);
        tx_metadata
    }

    /// Add the list of transaction IDs to the batch
    /// Transactions themselves are stored in store_txs, here we just store the association between block and txids
    fn store_txids_to_block_index(
        &self,
        blockhash: &ShareBlockHash,
        txids: &Vec<bitcoin::Txid>,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let mut blockhash_bytes = blockhash.as_ref().to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        let mut serialized_txids = Vec::new();
        ciborium::ser::into_writer(&txids, &mut serialized_txids).unwrap();
        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(block_txids_cf, blockhash_bytes.as_ref(), serialized_txids);
    }

    /// Get all transaction IDs for a given block hash
    /// Returns a vector of transaction IDs that were included in the block
    fn get_txids_for_blockhash(&self, blockhash: &ShareBlockHash) -> Vec<bitcoin::Txid> {
        let mut blockhash_bytes = blockhash.as_ref().to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        match self
            .db
            .get_cf::<&[u8]>(block_txids_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(serialized_txids)) => {
                let txids: Vec<bitcoin::Txid> =
                    ciborium::de::from_reader(&serialized_txids[..]).unwrap_or_default();
                txids
            }
            _ => Vec::new(),
        }
    }

    /// Add a workbase to the store
    pub fn add_workbase(&mut self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error>> {
        let workbase_key = format!("workbase:{}", workbase.workinfoid);
        debug!("Adding workbase to store: {:?}", workbase_key);
        let workbase_cf = self.db.cf_handle(&ColumnFamily::Workbase).unwrap();
        self.db
            .put_cf(
                workbase_cf,
                workbase_key.as_bytes(),
                Message::Workbase(workbase).cbor_serialize().unwrap(),
            )
            .unwrap();
        Ok(())
    }

    /// Add a user workbase to the store
    pub fn add_user_workbase(&mut self, user_workbase: UserWorkbase) -> Result<(), Box<dyn Error>> {
        let user_workbase_key = format!("user_workbase:{}", user_workbase.workinfoid);
        debug!("Adding user workbase to store: {:?}", user_workbase_key);
        let user_workbase_cf = self.db.cf_handle(&ColumnFamily::UserWorkbase).unwrap();
        self.db
            .put_cf(
                user_workbase_cf,
                user_workbase_key.as_bytes(),
                Message::UserWorkbase(user_workbase)
                    .cbor_serialize()
                    .unwrap(),
            )
            .unwrap();
        Ok(())
    }

    /// Update a transaction's validation and spent status in the tx metadata store
    /// The status is stored separately from the transaction using txid + "_status" as key
    /// We read the transaction from the store, update spent_by and write back to the store.
    pub fn update_transaction_spent_status(
        &mut self,
        txid: &bitcoin::Txid,
        spent_by: Option<bitcoin::Txid>,
    ) -> Result<(), Box<dyn Error>> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let tx_metadata = self.db.get_cf::<&[u8]>(tx_cf, txid.as_ref()).unwrap();
        if tx_metadata.is_none() {
            return Err("Transaction not found".into());
        }
        let tx_metadata = tx_metadata.unwrap();
        let mut tx_metadata: TxMetadata =
            ciborium::de::from_reader(tx_metadata.as_slice()).unwrap();
        tx_metadata.spent_by = spent_by;
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&tx_metadata, &mut serialized).unwrap();
        self.db
            .put_cf::<&[u8], Vec<u8>>(tx_cf, txid.as_ref(), serialized)
            .unwrap();
        Ok(())
    }

    /// Get the validation status of a transaction from the store
    pub fn get_tx_metadata(&self, txid: &bitcoin::Txid) -> Option<TxMetadata> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let tx_metadata = self.db.get_cf::<&[u8]>(tx_cf, txid.as_ref()).unwrap();
        if let Some(tx_metadata) = tx_metadata {
            let tx_metadata: TxMetadata =
                ciborium::de::from_reader(tx_metadata.as_slice()).unwrap();
            Some(tx_metadata)
        } else {
            None
        }
    }

    /// Get a workbase from the store
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        let workbase_key = format!("workbase:{workinfoid}");
        debug!("Getting workbase from store: {:?}", workbase_key);
        let workbase_cf = self.db.cf_handle(&ColumnFamily::Workbase).unwrap();
        let workbase = self
            .db
            .get_cf::<&[u8]>(workbase_cf, workbase_key.as_bytes())
            .unwrap();
        if let Some(workbase) = workbase {
            let workbase = Message::cbor_deserialize(&workbase).unwrap();
            let workbase = match workbase {
                Message::Workbase(workbase) => workbase,
                _ => {
                    tracing::error!("Invalid workbase key: {:?}", workbase_key);
                    return None;
                }
            };
            Some(workbase)
        } else {
            None
        }
    }

    /// Get multiple workbases from the store given a set of workinfoids
    pub fn get_workbases(&self, workinfoids: &[u64]) -> Vec<MinerWorkbase> {
        debug!("Getting multiple workbases from store: {:?}", workinfoids);
        let workbase_cf = self.db.cf_handle(&ColumnFamily::Workbase).unwrap();

        let keys: Vec<(_, Vec<u8>)> = workinfoids
            .iter()
            .map(|id| {
                let workbase_key = format!("workbase:{id}");
                (workbase_cf, workbase_key.into_bytes())
            })
            .collect();

        let workbases = self.db.multi_get_cf(keys);

        workbases
            .into_iter()
            .filter_map(|result| match result {
                Ok(Some(data)) => match Message::cbor_deserialize(&data) {
                    Ok(Message::Workbase(workbase)) => Some(workbase),
                    _ => {
                        tracing::error!("Invalid workbase data");
                        None
                    }
                },
                _ => None,
            })
            .collect()
    }

    /// Get a user workbase from the store
    pub fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase> {
        let user_workbase_key = format!("user_workbase:{workinfoid}");
        debug!("Getting user workbase from store: {:?}", user_workbase_key);
        let user_workbase_cf = self.db.cf_handle(&ColumnFamily::UserWorkbase).unwrap();
        let user_workbase = self
            .db
            .get_cf::<&[u8]>(user_workbase_cf, user_workbase_key.as_bytes())
            .unwrap()?;
        let user_workbase = Message::cbor_deserialize(&user_workbase).unwrap();
        let user_workbase = match user_workbase {
            Message::UserWorkbase(user_workbase) => user_workbase,
            _ => {
                tracing::error!("Invalid user workbase key: {:?}", user_workbase_key);
                return None;
            }
        };
        Some(user_workbase)
    }

    /// Get multiple user workbases from the store by their workinfoids
    pub fn get_user_workbases(&self, workinfoids: &[u64]) -> Vec<UserWorkbase> {
        debug!(
            "Getting user workbases from store for workinfoids: {:?}",
            workinfoids
        );
        let user_workbase_cf = self.db.cf_handle(&ColumnFamily::UserWorkbase).unwrap();

        let keys: Vec<(_, Vec<u8>)> = workinfoids
            .iter()
            .map(|id| {
                let user_workbase_key = format!("user_workbase:{id}");
                (user_workbase_cf, user_workbase_key.into_bytes())
            })
            .collect();

        let user_workbases = self.db.multi_get_cf(keys);

        user_workbases
            .into_iter()
            .filter_map(|result| match result {
                Ok(Some(data)) => match Message::cbor_deserialize(&data) {
                    Ok(Message::UserWorkbase(user_workbase)) => Some(user_workbase),
                    _ => {
                        tracing::error!("Invalid user workbase data");
                        None
                    }
                },
                _ => None,
            })
            .collect()
    }

    /// Save a job with the given timestamp key to the Job column family
    pub fn save_job(
        &self,
        timestamp: u64,
        serialized_notify: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Saving job to store with key: {:?}", timestamp);
        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();
        self.db.put_cf(
            job_cf,
            timestamp.to_be_bytes(),
            serialized_notify.as_bytes(),
        )?;
        Ok(())
    }

    /// Get jobs within a time range from the Job column family
    /// Returns jobs ordered by timestamp (newest first)
    pub fn get_jobs(
        &self,
        start_time: u64,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        debug!(
            "Getting jobs from store with start_time: {:?}, end_time: {:?}, limit: {}",
            start_time, end_time, limit
        );

        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();

        // If end_time is None, use current time
        let effective_end_time = end_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        });

        // Create a read options object to set iteration bounds
        let mut read_opts = rocksdb::ReadOptions::default();

        // Set the upper bound (end_time)
        read_opts.set_iterate_upper_bound(start_time.to_be_bytes().to_vec());

        // Start iterating from start_time in reverse order to get newest first
        let iter = self.db.iterator_cf_opt(
            job_cf,
            read_opts,
            rocksdb::IteratorMode::From(
                &effective_end_time.to_be_bytes(),
                rocksdb::Direction::Forward,
            ),
        );

        // Collect results
        let mut results = Vec::with_capacity(limit);

        for (i, item) in iter.enumerate() {
            if i >= limit {
                break;
            }

            let (key, value) = item?;

            // Convert key bytes to u64 timestamp
            let timestamp = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| "Invalid timestamp key")?,
            );

            // Convert value bytes to string
            let job_data =
                String::from_utf8(value.to_vec()).map_err(|e| format!("Invalid job data: {e}"))?;

            results.push((timestamp, job_data));
        }

        Ok(results)
    }

    /// Get a share from the store
    pub fn get_share(&self, blockhash: &ShareBlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let share = match self.db.get_cf::<&[u8]>(share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share = match StorageShareBlock::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let transactions = self.get_txs_for_block(blockhash);
        let share = share.into_share_block_with_transactions(transactions);
        Some(share)
    }

    /// Get a share headers matching the vector of blockhashes
    pub fn get_share_headers(&self, blockhashes: &[ShareBlockHash]) -> Vec<ShareHeader> {
        debug!("Getting share headers from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (share_cf, h.as_ref()))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        let share_headers = shares
            .into_iter()
            .map(|v| {
                if let Ok(Some(v)) = v {
                    if let Ok(storage_share) = StorageShareBlock::cbor_deserialize(&v) {
                        Some(storage_share.header)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        share_headers.into_iter().flatten().collect()
    }

    // Find the first blockhash that exists by checking key existence
    fn get_first_existing_blockhash(&self, locator: &[ShareBlockHash]) -> Option<ShareBlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        for blockhash in locator {
            if self.db.key_may_exist_cf(block_cf, blockhash.as_ref()) {
                return Some(*blockhash);
            }
        }
        None
    }

    /// Get all descendant blockhashes of a given blockhash
    fn get_descendant_blockhashes(
        &self,
        blockhash: &ShareBlockHash,
        stop_blockhash: &ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareBlockHash> {
        let mut blockhashes = Vec::with_capacity(limit);
        let mut next_children = vec![];
        let mut current_blockhash = *blockhash;

        while blockhashes.len() < limit && current_blockhash != *stop_blockhash {
            let children = self.get_children_blockhashes(&current_blockhash);
            for child in children {
                if blockhashes.len() < limit {
                    blockhashes.push(child);
                    next_children.push(child);
                }
            }

            if next_children.is_empty() {
                break;
            }
            current_blockhash = next_children.remove(0);
        }
        blockhashes
    }

    /// Get the genesis blockhash, as the first blockhash in the chain
    /// Assume there is no uncle at height 0
    pub fn get_genesis_blockhash(&self) -> ShareBlockHash {
        self.get_blockhashes_for_height(0)[0]
    }

    /// Get blockhashes to satisfy the locator query.
    /// Returns a list of blockhashes from the earliest block from the block hashes
    /// We assume the list of blocks in the locator is ordered by height, so we stop when we find the first block in the locator
    /// Find blockhashes up to the stop blockhash, or the limit provided
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[ShareBlockHash],
        stop_blockhash: &ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareBlockHash> {
        let start_blockhash = self.get_first_existing_blockhash(locator);
        // If no blockhash found, return vector with genesis block
        let start_blockhash = match start_blockhash {
            Some(hash) => hash,
            None => return vec![self.get_genesis_blockhash()],
        };

        self.get_descendant_blockhashes(&start_blockhash, stop_blockhash, limit)
    }

    /// Get headers to satisy the locator query.
    pub fn get_headers_for_locator(
        &self,
        locator: &[ShareBlockHash],
        stop_blockhash: &ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        let blockhashes = self.get_blockhashes_for_locator(locator, stop_blockhash, limit);
        self.get_share_headers(&blockhashes)
    }

    /// Get descendants headers of a share
    /// We stop looking after we have found limit number of descendants or have hit stop blockhash
    pub fn get_descendants(
        &self,
        share: ShareBlockHash,
        stop_blockhash: &ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        let mut descendants = Vec::with_capacity(limit);

        let mut next_children = vec![];
        let mut current_blockhash = share;
        while descendants.len() < limit && current_blockhash != *stop_blockhash {
            let children = self.get_children_blockhashes(&current_blockhash);
            for child in children {
                if descendants.len() < limit {
                    descendants.push(child);
                    next_children.push(child);
                }
            }
            current_blockhash = match next_children.pop() {
                Some(hash) => hash,
                None => break,
            };
        }
        self.get_share_headers(&descendants)
    }

    /// Get multiple shares from the store
    /// TODO: Refactor to use get_share
    pub fn get_shares(
        &self,
        blockhashes: &[ShareBlockHash],
    ) -> HashMap<ShareBlockHash, ShareBlock> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (share_cf, h.as_ref()))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        // iterate over the blockhashes and shares, filter out the ones that are not found or can't be deserialized
        // then convert the storage share to share block and return as a hashmap
        blockhashes
            .iter()
            .zip(shares)
            .filter_map(|(blockhash, result)| {
                if let Ok(Some(data)) = result {
                    if let Ok(storage_share) = StorageShareBlock::cbor_deserialize(&data) {
                        let txids = self.get_txids_for_blockhash(blockhash);
                        let transactions = txids
                            .iter()
                            .map(|txid| self.get_tx(txid).unwrap())
                            .collect::<Vec<_>>();
                        Some((
                            *blockhash,
                            storage_share.into_share_block_with_transactions(transactions),
                        ))
                    } else {
                        tracing::warn!(
                            "Could not deserialize share for blockhash: {:?}",
                            blockhash
                        );
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get transactions for a blockhash
    /// First look up the txids from the blockhash_txids index, then get the transactions from the txids
    pub fn get_txs_for_block(&self, blockhash: &ShareBlockHash) -> Vec<Transaction> {
        let txids = self.get_txids_for_blockhash(blockhash);
        txids
            .iter()
            .map(|txid| self.get_tx(txid).unwrap())
            .collect()
    }

    /// Get a transaction from the store using a provided txid
    /// - Load tx metadata
    /// - Load inputs
    /// - Load outputs
    /// - Deserialize inputs and outputs
    /// - Return transaction
    pub fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Transaction, Box<dyn Error>> {
        let tx_metadata = self
            .get_tx_metadata(txid)
            .ok_or_else(|| format!("Transaction metadata not found for txid: {txid}"))?;

        debug!("Transaction metadata: {:?}", tx_metadata);

        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        for i in 0..tx_metadata.input_count {
            let input_key = format!("{txid}:{i}");
            let input = self
                .db
                .get_cf::<&[u8]>(inputs_cf, input_key.as_ref())
                .unwrap()
                .unwrap();
            let input: bitcoin::TxIn = match ciborium::de::from_reader(input.as_slice()) {
                Ok(input) => input,
                Err(e) => {
                    tracing::error!("Error deserializing input: {e:?}");
                    return Err(e.into());
                }
            };
            inputs.push(input);
        }
        for i in 0..tx_metadata.output_count {
            let output_key = format!("{txid}:{i}");
            let output = self
                .db
                .get_cf::<&[u8]>(outputs_cf, output_key.as_ref())
                .unwrap()
                .unwrap();
            let output: bitcoin::TxOut = match ciborium::de::from_reader(output.as_slice()) {
                Ok(output) => output,
                Err(e) => {
                    tracing::error!("Error deserializing output: {e:?}");
                    return Err(e.into());
                }
            };
            outputs.push(output);
        }
        let transaction = Transaction {
            version: tx_metadata.version,
            lock_time: tx_metadata.lock_time,
            input: inputs,
            output: outputs,
        };
        Ok(transaction)
    }

    /// Get the parent of a share as a ShareBlock
    pub fn get_parent(&self, blockhash: &ShareBlockHash) -> Option<ShareBlock> {
        let share = self.get_share(blockhash)?;
        let parent_blockhash = share.header.prev_share_blockhash;
        self.get_share(&parent_blockhash.unwrap())
    }

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
    pub fn get_uncles(&self, blockhash: &ShareBlockHash) -> Vec<ShareBlock> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return vec![];
        }
        let share = share.unwrap();
        let uncle_blocks = self.get_shares(&share.header.uncles);
        uncle_blocks.into_values().collect()
    }

    /// Get entire chain from earliest known block to given blockhash, excluding the given blockhash
    /// When we prune the chain, the oldest share in the chain will be marked as root, by removing it's prev_share_blockhash
    /// We can't use get_shares as we need to get a share, then find it's prev_share_blockhash, then get the share again, etc.
    pub fn get_chain_upto(&self, blockhash: &ShareBlockHash) -> Vec<ShareBlock> {
        debug!("Getting chain upto: {:?}", blockhash);
        std::iter::successors(self.get_share(blockhash), |share| {
            if share.header.prev_share_blockhash.is_none() {
                None
            } else {
                let prev_blockhash = share.header.prev_share_blockhash.unwrap();
                self.get_share(&prev_blockhash)
            }
        })
        .collect()
    }

    /// Get common ancestor of two blockhashes
    pub fn get_common_ancestor(
        &self,
        blockhash1: &ShareBlockHash,
        blockhash2: &ShareBlockHash,
    ) -> Option<ShareBlockHash> {
        debug!(
            "Getting common ancestor of: {:?} and {:?}",
            blockhash1, blockhash2
        );
        let chain1 = self.get_chain_upto(blockhash1);
        let chain2 = self.get_chain_upto(blockhash2);
        chain1
            .iter()
            .rev()
            .find(|share| chain2.contains(share))
            .map(|blockhash| blockhash.cached_blockhash.unwrap())
    }

    /// Set the height for the blockhash, storing it in a vector of blockhashes for that height
    /// We are fine with Vector instead of HashSet as we are not going to have a lot of blockhashes at the same height
    pub fn set_height_to_blockhash(
        &mut self,
        blockhash: &ShareBlockHash,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        // Convert height to big-endian bytes - this is our key
        let height_bytes = height.to_be_bytes();

        // Get any existing blockhashes for this height
        let mut blockhashes: Vec<ShareBlockHash> = match self
            .db
            .get_cf::<&[u8]>(column_family, height_bytes.as_ref())
        {
            Ok(Some(existing)) => ciborium::de::from_reader(&existing[..]).unwrap_or_default(),
            Ok(None) | Err(_) => Vec::new(),
        };

        // Add the new blockhash if not already present
        if !blockhashes.contains(blockhash) {
            blockhashes.push(*blockhash);

            // Serialize the updated vector of blockhashes
            let mut serialized = Vec::new();
            ciborium::ser::into_writer(&blockhashes, &mut serialized).unwrap();

            // Store the updated vector
            batch.put_cf(column_family, height_bytes, serialized);
        }
    }

    /// Get the blockhashes for a specific height
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<ShareBlockHash> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let height_bytes = height.to_be_bytes();
        match self
            .db
            .get_cf::<&[u8]>(column_family, height_bytes.as_ref())
        {
            Ok(Some(blockhashes)) => {
                ciborium::de::from_reader(&blockhashes[..]).unwrap_or_default()
            }
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Get the shares for a specific height
    pub fn get_shares_at_height(&self, height: u32) -> HashMap<ShareBlockHash, ShareBlock> {
        let blockhashes = self.get_blockhashes_for_height(height);
        self.get_shares(&blockhashes)
    }

    /// Get the block metadata for a blockhash
    pub fn get_block_metadata(&self, blockhash: &ShareBlockHash) -> Option<BlockMetadata> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = blockhash.as_ref().to_vec();
        metadata_key.extend_from_slice(b"_md");

        match self.db.get_cf::<&[u8]>(block_metadata_cf, &metadata_key) {
            Ok(Some(metadata)) => {
                let metadata: BlockMetadata = match ciborium::de::from_reader(metadata.as_slice()) {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        tracing::error!("Error deserializing block metadata: {:?}", e);
                        return None;
                    }
                };
                Some(metadata)
            }
            Ok(None) | Err(_) => {
                debug!("No metadata found for blockhash: {:?}", blockhash);
                None
            }
        }
    }

    /// Check which blockhashes from the provided list are missing from the store
    /// Returns a vector of blockhashes that are not present in the store
    pub fn get_missing_blockhashes(&self, blockhashes: &[ShareBlockHash]) -> Vec<ShareBlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        blockhashes
            .iter()
            .filter(|&hash| !self.db.key_may_exist_cf(block_cf, hash.as_ref()))
            .cloned()
            .collect()
    }

    /// Set the block metadata for a blockhash
    fn set_block_metadata(
        &mut self,
        blockhash: &ShareBlockHash,
        metadata: &BlockMetadata,
        batch: Option<&mut rocksdb::WriteBatch>,
    ) -> Result<(), Box<dyn Error>> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = blockhash.as_ref().to_vec();
        metadata_key.extend_from_slice(b"_md");

        let mut serialized = Vec::new();
        ciborium::ser::into_writer(metadata, &mut serialized)?;

        if let Some(batch) = batch {
            batch.put_cf(block_metadata_cf, &metadata_key, serialized);
        } else {
            self.db
                .put_cf(block_metadata_cf, &metadata_key, serialized)?;
        }
        Ok(())
    }

    /// Mark a block as valid in the store
    pub fn set_block_valid(
        &mut self,
        blockhash: &ShareBlockHash,
        valid: bool,
        batch: Option<&mut rocksdb::WriteBatch>,
    ) -> Result<(), Box<dyn Error>> {
        let metadata = self.get_block_metadata(blockhash).unwrap_or(BlockMetadata {
            is_valid: false,
            is_confirmed: false,
            height: None,
        });

        let updated_metadata = BlockMetadata {
            is_valid: valid,
            is_confirmed: metadata.is_confirmed,
            height: metadata.height,
        };

        self.set_block_metadata(blockhash, &updated_metadata, batch)
    }

    /// Mark a block as confirmed in the store
    pub fn set_block_confirmed(
        &mut self,
        blockhash: &ShareBlockHash,
        confirmed: bool,
        batch: Option<&mut rocksdb::WriteBatch>,
    ) -> Result<(), Box<dyn Error>> {
        let metadata = self.get_block_metadata(blockhash).unwrap_or(BlockMetadata {
            is_valid: false,
            is_confirmed: false,
            height: None,
        });

        let updated_metadata = BlockMetadata {
            is_valid: metadata.is_valid,
            is_confirmed: confirmed,
            height: metadata.height,
        };

        self.set_block_metadata(blockhash, &updated_metadata, batch)
    }

    pub fn set_block_height_in_metadata(
        &mut self,
        blockhash: &ShareBlockHash,
        height: Option<u32>,
        batch: Option<&mut rocksdb::WriteBatch>,
    ) -> Result<(), Box<dyn Error>> {
        let metadata = self.get_block_metadata(blockhash).unwrap_or(BlockMetadata {
            is_valid: false,
            is_confirmed: false,
            height,
        });

        let updated_metadata = BlockMetadata {
            is_valid: metadata.is_valid,
            is_confirmed: metadata.is_confirmed,
            height,
        };
        debug!("Setting block metadata: {:?}", updated_metadata);
        self.set_block_metadata(blockhash, &updated_metadata, batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestBlockBuilder, TestMinerWorkbaseBuilder, TestUserWorkbaseBuilder};
    use rust_decimal_macros::dec;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create uncles for share3
        let uncle1_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3 with uncles
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share3.cached_blockhash.unwrap(),
                uncle2_share3.cached_blockhash.unwrap(),
            ])
            .workinfoid(7452731920372203525 + 6)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone(), 0);
        store.add_share(uncle1_share2.clone(), 1);
        store.add_share(uncle2_share2.clone(), 1);
        store.add_share(share2.clone(), 1);
        store.add_share(uncle1_share3.clone(), 2);
        store.add_share(uncle2_share3.clone(), 2);
        store.add_share(share3.clone(), 2);

        // Get chain up to share3
        let chain = store.get_chain_upto(&share3.cached_blockhash.unwrap());

        // Get common ancestor of share3 and share2
        let common_ancestor = store.get_common_ancestor(
            &share3.cached_blockhash.unwrap(),
            &share2.cached_blockhash.unwrap(),
        );
        assert_eq!(common_ancestor, Some(share1.cached_blockhash.unwrap()));

        // Get chain up to uncle1_share3 (share31)
        let chain_to_uncle = store.get_chain_upto(&uncle1_share3.cached_blockhash.unwrap());
        assert_eq!(chain_to_uncle.len(), 3);
        assert_eq!(
            chain_to_uncle[0].cached_blockhash.unwrap(),
            uncle1_share3.cached_blockhash.unwrap()
        );
        assert_eq!(
            chain_to_uncle[1].cached_blockhash.unwrap(),
            share2.cached_blockhash.unwrap()
        );
        assert_eq!(
            chain_to_uncle[2].cached_blockhash.unwrap(),
            share1.cached_blockhash.unwrap()
        );

        // Chain should contain share3, share2, share1 in reverse order
        assert_eq!(chain.len(), 3);
        assert_eq!(
            chain[0].cached_blockhash.unwrap(),
            share3.cached_blockhash.unwrap()
        );
        assert_eq!(
            chain[1].cached_blockhash.unwrap(),
            share2.cached_blockhash.unwrap()
        );
        assert_eq!(
            chain[2].cached_blockhash.unwrap(),
            share1.cached_blockhash.unwrap()
        );

        // Verify uncles of share2
        let uncles_share2 = store.get_uncles(&share2.cached_blockhash.unwrap());
        assert_eq!(uncles_share2.len(), 2);
        assert!(
            uncles_share2
                .iter()
                .any(|u| u.header.miner_share.hash == uncle1_share2.header.miner_share.hash)
        );
        assert!(
            uncles_share2
                .iter()
                .any(|u| u.header.miner_share.hash == uncle2_share2.header.miner_share.hash)
        );

        // Verify uncles of share3
        let uncles_share3 = store.get_uncles(&share3.cached_blockhash.unwrap());
        assert_eq!(uncles_share3.len(), 2);
        assert!(
            uncles_share3
                .iter()
                .any(|u| u.header.miner_share.hash == uncle1_share3.header.miner_share.hash)
        );
        assert!(
            uncles_share3
                .iter()
                .any(|u| u.header.miner_share.hash == uncle2_share3.header.miner_share.hash)
        );

        // Verify children of share1
        let children_share1 = store.get_children_blockhashes(&share1.cached_blockhash.unwrap());
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.cached_blockhash.unwrap()));
        assert!(children_share1.contains(&uncle1_share2.cached_blockhash.unwrap()));
        assert!(children_share1.contains(&uncle2_share2.cached_blockhash.unwrap()));

        // Verify children of share2
        let children_share2 = store.get_children_blockhashes(&share2.cached_blockhash.unwrap());
        assert_eq!(children_share2.len(), 3);
        assert!(children_share2.contains(&share3.cached_blockhash.unwrap()));
        assert!(children_share2.contains(&uncle1_share3.cached_blockhash.unwrap()));
        assert!(children_share2.contains(&uncle2_share3.cached_blockhash.unwrap()));

        // Verify children of share3
        let children_share3 = store.get_children_blockhashes(&share3.cached_blockhash.unwrap());
        assert!(children_share3.is_empty());

        // Verify children of uncle1_share2
        let children_uncle1_share2 =
            store.get_children_blockhashes(&uncle1_share2.cached_blockhash.unwrap());
        assert!(children_uncle1_share2.is_empty());

        // Verify children of uncle2_share2
        let children_uncle2_share2 =
            store.get_children_blockhashes(&uncle2_share2.cached_blockhash.unwrap());
        assert!(children_uncle2_share2.is_empty());

        // Verify children of uncle1_share3
        let children_uncle1_share3 =
            store.get_children_blockhashes(&uncle1_share3.cached_blockhash.unwrap());
        assert!(children_uncle1_share3.is_empty());

        // Verify children of uncle2_share3
        let children_uncle2_share3 =
            store.get_children_blockhashes(&uncle2_share3.cached_blockhash.unwrap());
        assert!(children_uncle2_share3.is_empty());

        let blocks_at_height_0 = store.get_blockhashes_for_height(0);
        assert_eq!(blocks_at_height_0, vec![share1.cached_blockhash.unwrap()]);
        let blocks_at_height_1 = store.get_blockhashes_for_height(1);
        assert_eq!(
            blocks_at_height_1,
            vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
                share2.cached_blockhash.unwrap()
            ]
        );
        let blocks_at_height_2 = store.get_blockhashes_for_height(2);
        assert_eq!(
            blocks_at_height_2,
            vec![
                uncle1_share3.cached_blockhash.unwrap(),
                uncle2_share3.cached_blockhash.unwrap(),
                share3.cached_blockhash.unwrap()
            ]
        );

        let shares_at_height_0 = store.get_shares_at_height(0);
        assert_eq!(shares_at_height_0.len(), 1);
        assert_eq!(
            shares_at_height_0[&share1.cached_blockhash.unwrap()],
            share1
        );
        let shares_at_height_1 = store.get_shares_at_height(1);
        assert_eq!(shares_at_height_1.len(), 3);
        assert_eq!(
            shares_at_height_1[&uncle1_share2.cached_blockhash.unwrap()],
            uncle1_share2
        );
        assert_eq!(
            shares_at_height_1[&uncle2_share2.cached_blockhash.unwrap()],
            uncle2_share2
        );
        assert_eq!(
            shares_at_height_1[&share2.cached_blockhash.unwrap()],
            share2
        );
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
        let txs_metadata = store.store_txs(&[tx.clone()], &mut batch);
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
    fn test_transaction_spent_by_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Store the transaction
        let txid = tx.compute_txid();
        let mut batch = rocksdb::WriteBatch::default();
        store.store_txs(&[tx.clone()], &mut batch);
        store.db.write(batch).unwrap();

        // Initially status should be None
        let initial_spent_by = store.get_tx_metadata(&txid).unwrap().spent_by;
        assert!(initial_spent_by.is_none());

        // Update status to validated but not spent
        let batch = rocksdb::WriteBatch::default();
        store.update_transaction_spent_status(&txid, None).unwrap();
        store.db.write(batch).unwrap();
        let status = store.get_tx_metadata(&txid).unwrap().spent_by;
        assert_eq!(status, None);

        // Create another transaction that spends this one
        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let spending_txid = spending_tx.compute_txid();

        // Update status to spent
        let batch = rocksdb::WriteBatch::default();
        store
            .update_transaction_spent_status(&txid, Some(spending_txid))
            .unwrap();
        store.db.write(batch).unwrap();
        let status = store.get_tx_metadata(&txid).unwrap().spent_by;
        assert_eq!(status, Some(spending_txid));

        // Update status back to unspent
        let batch = rocksdb::WriteBatch::default();
        store.update_transaction_spent_status(&txid, None).unwrap();
        store.db.write(batch).unwrap();
        let status = store.get_tx_metadata(&txid).unwrap().spent_by;
        assert_eq!(status, None);
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
        let share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".into(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .add_transaction(tx1.clone())
            .add_transaction(tx2.clone())
            .build();

        let blockhash = share.cached_blockhash.unwrap();

        // Store the txids for the blockhash
        let txids = vec![txid1, txid2];
        let mut batch = rocksdb::WriteBatch::default();
        store.store_txids_to_block_index(&blockhash, &txids, &mut batch);
        store.db.write(batch).unwrap();

        // Get txids for the blockhash
        let retrieved_txids = store.get_txids_for_blockhash(&blockhash);

        // Verify we got back the same txids in the same order
        assert_eq!(retrieved_txids.len(), 2);
        assert_eq!(retrieved_txids[0], txid1);
        assert_eq!(retrieved_txids[1], txid2);

        // Test getting txids for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6".into();
        let empty_txids = store.get_txids_for_blockhash(&non_existent_blockhash);
        assert!(empty_txids.is_empty());
    }

    #[test]
    fn test_store_share_block_with_transactions_should_retreive_txs() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

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
        let share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".into(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .add_transaction(tx1.clone())
            .add_transaction(tx2.clone())
            .build();

        // Store the share block
        store.add_share(share.clone(), 0);
        assert_eq!(share.transactions.len(), 3);

        // Retrieve transactions for the block hash
        let retrieved_txs = store.get_txs_for_block(&share.cached_blockhash.unwrap());

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
    fn test_store_tx_metadata_with_no_inputs_or_outputs_should_succeed() {
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
        let res = store.store_tx_metadata(txid, &tx, &mut batch);
        store.db.write(batch).unwrap();

        assert_eq!(res.txid, txid);
        let tx_metadata = store.get_tx_metadata(&txid).unwrap();
        assert_eq!(tx_metadata.txid, txid);
        assert_eq!(tx_metadata.version, tx.version);
        assert_eq!(tx_metadata.lock_time, tx.lock_time);
        assert_eq!(tx_metadata.input_count, 0);
        assert_eq!(tx_metadata.output_count, 0);
    }

    #[test]
    fn test_store_txs_with_inputs_or_outputs_should_succeed() {
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
        let res = store.store_txs(&[tx.clone()], &mut batch);
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
    fn test_store_txs_should_succeed() {
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
        store.store_txs(&transactions, &mut batch);
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
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test share block
        let share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add share to store
        store.add_share(share.clone(), 0);

        // Get share header from store
        let read_share = store.get_share(&share.cached_blockhash.unwrap()).unwrap();

        // Verify header matches original
        assert_eq!(read_share.cached_blockhash, share.cached_blockhash);
        assert_eq!(
            read_share.header.prev_share_blockhash,
            share.header.prev_share_blockhash
        );
        assert_eq!(read_share.header.uncles, share.header.uncles);
        assert_eq!(read_share.header.miner_pubkey, share.header.miner_pubkey);
        assert_eq!(read_share.header.merkle_root, share.header.merkle_root);

        // Verify miner share matches original
        assert_eq!(
            read_share.header.miner_share.workinfoid,
            share.header.miner_share.workinfoid
        );
        assert_eq!(
            read_share.header.miner_share.nonce,
            share.header.miner_share.nonce
        );
        assert_eq!(
            read_share.header.miner_share.diff,
            share.header.miner_share.diff
        );
        assert_eq!(
            read_share.header.miner_share.ntime,
            share.header.miner_share.ntime
        );
    }

    #[test]
    fn test_get_share_header_nonexistent() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Try to get share header for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6".into();
        let result = store.get_share(&non_existent_blockhash);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_children() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone(), 0);
        store.add_share(uncle1_share2.clone(), 1);
        store.add_share(uncle2_share2.clone(), 1);
        store.add_share(share2.clone(), 1);
        store.add_share(share3.clone(), 2);

        // Verify children of share1
        let children_share1 = store.get_children_blockhashes(&share1.cached_blockhash.unwrap());
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.cached_blockhash.unwrap()));
        assert!(children_share1.contains(&uncle1_share2.cached_blockhash.unwrap()));
        assert!(children_share1.contains(&uncle2_share2.cached_blockhash.unwrap()));

        // Verify children of share2
        let children_share2 = store.get_children_blockhashes(&share2.cached_blockhash.unwrap());
        assert_eq!(children_share2.len(), 1);
        assert!(children_share2.contains(&share3.cached_blockhash.unwrap()));

        // Verify children of share3
        let children_share3 = store.get_children_blockhashes(&share3.cached_blockhash.unwrap());
        assert!(children_share3.is_empty());

        // Verify children of uncle1_share2
        let children_uncle1_share2 =
            store.get_children_blockhashes(&uncle1_share2.cached_blockhash.unwrap());
        assert!(children_uncle1_share2.is_empty());

        // Verify children of uncle2_share2
        let children_uncle2_share2 =
            store.get_children_blockhashes(&uncle2_share2.cached_blockhash.unwrap());
        assert!(children_uncle2_share2.is_empty());
    }

    #[test]
    fn test_get_descendants() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone(), 0);
        store.add_share(uncle1_share2.clone(), 1);
        store.add_share(uncle2_share2.clone(), 1);
        store.add_share(share2.clone(), 1);
        store.add_share(share3.clone(), 2);

        // Verify descendants of share1
        let descendants_share1 = store.get_descendants(
            share1.cached_blockhash.unwrap(),
            &share3.cached_blockhash.unwrap(),
            10,
        );
        assert_eq!(descendants_share1.len(), 4);
        assert!(descendants_share1.contains(&share2.header));
        assert!(descendants_share1.contains(&share3.header));
        assert!(descendants_share1.contains(&uncle1_share2.header));
        assert!(descendants_share1.contains(&uncle2_share2.header));

        // Verify descendants of share2
        let descendants_share2 = store.get_descendants(
            share2.cached_blockhash.unwrap(),
            &share3.cached_blockhash.unwrap(),
            10,
        );
        assert_eq!(descendants_share2.len(), 1);
        assert_eq!(descendants_share2[0], share3.header);

        // Verify no descendants for share3
        let descendants_share3 = store.get_descendants(
            share3.cached_blockhash.unwrap(),
            &share3.cached_blockhash.unwrap(),
            10,
        );
        assert!(descendants_share3.is_empty());

        // Verify descendants with limit
        let descendants_with_limit = store.get_descendants(
            share1.cached_blockhash.unwrap(),
            &share3.cached_blockhash.unwrap(),
            1,
        );
        assert_eq!(descendants_with_limit.len(), 1);
        assert_eq!(descendants_with_limit[0], uncle1_share2.header);

        // Verify descendants with stop blockhash
        let descendants_with_limit = store.get_descendants(
            share1.cached_blockhash.unwrap(),
            &share2.cached_blockhash.unwrap(),
            10,
        );
        assert_eq!(descendants_with_limit.len(), 3);
        assert!(descendants_with_limit.contains(&share2.header));
        assert!(descendants_with_limit.contains(&uncle1_share2.header));
        assert!(descendants_with_limit.contains(&uncle2_share2.header));
    }

    #[test]
    fn test_get_headers_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let blockhashes = [
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485", // genesis
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", // stop block
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", // tip
        ];

        for (height, &blockhash) in blockhashes.iter().enumerate() {
            let mut builder = TestBlockBuilder::new().blockhash(blockhash);
            if height > 0 {
                builder = builder
                    .prev_share_blockhash(store.get_blockhashes_for_height(height as u32 - 1)[0]);
            }
            let block = builder.build();
            store.add_share(block, height as u32);
        }

        let stop_block = store.get_blockhashes_for_height(2)[0];

        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store.get_headers_for_locator(&locator, &stop_block, 10);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].miner_share.hash.to_string(),
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449"
        );
        assert_eq!(
            result[1].miner_share.hash.to_string(),
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
        );
    }

    #[test]
    fn test_get_headers_for_block_locator_stop_block_not_found() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut blocks = Vec::new();
        let mut locator = vec![];

        let blockhashes = [
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", // genesis
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", // tip
        ];

        for (height, &blockhash) in blockhashes.iter().enumerate() {
            let mut builder = TestBlockBuilder::new().blockhash(blockhash);
            if height > 0 {
                builder = builder
                    .prev_share_blockhash(store.get_blockhashes_for_height(height as u32 - 1)[0]);
            }
            let block = builder.build();
            blocks.push(block.clone());
            store.add_share(block, height as u32);
        }

        locator.push(blocks[0].cached_blockhash.unwrap()); // locator = tip

        // Use a stop block hash that doesn't exist in our chain
        let non_existent_stop_block =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();

        // Call get_headers_for_block_locator with non-existent stop block
        let result = store.get_headers_for_locator(&locator, &non_existent_stop_block, 10);
        assert_eq!(result.len(), 2);
        // start block not in response
        assert_eq!(result[0], blocks[1].header);
        assert_eq!(result[1], blocks[2].header);
    }

    #[test]
    fn test_get_blockhashes_for_block_locator_should_find_matching_blocks() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mut blocks = Vec::new();

        let blockhashes = [
            "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485", // genesis
            "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
            "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd", // stop block
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", // tip
        ];

        for (height, &blockhash) in blockhashes.iter().enumerate() {
            let mut builder = TestBlockBuilder::new().blockhash(blockhash);
            if height > 0 {
                builder = builder
                    .prev_share_blockhash(store.get_blockhashes_for_height(height as u32 - 1)[0]);
            }
            let block = builder.build();
            blocks.push(block.clone());
            store.add_share(block, height as u32);
        }

        let stop_block = store.get_blockhashes_for_height(2)[0];

        let locator = store.get_blockhashes_for_height(0);

        // Call handle_getblocks
        let result = store.get_blockhashes_for_locator(&locator, &stop_block, 10);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], blocks[1].cached_blockhash.unwrap());
        assert_eq!(result[1], blocks[2].cached_blockhash.unwrap());
    }

    #[test]
    fn test_block_status_operations() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test block
        let share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add share to store
        store.add_share(share.clone(), 0);
        let blockhash = share.cached_blockhash.unwrap();

        // Initially, block should not be valid or confirmed
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(!metadata.is_confirmed);
        assert_eq!(metadata.height, Some(0));

        // Set block as valid
        store.set_block_valid(&blockhash, true, None).unwrap();
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(metadata.is_valid);
        assert!(!metadata.is_confirmed);

        // Set block as confirmed
        store.set_block_confirmed(&blockhash, true, None).unwrap();
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(metadata.is_valid);
        assert!(metadata.is_confirmed);

        // Reset block's valid status
        store.set_block_valid(&blockhash, false, None).unwrap();
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(metadata.is_confirmed);

        // Reset block's confirmed status
        store.set_block_confirmed(&blockhash, false, None).unwrap();
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(!metadata.is_confirmed);
    }

    #[test]
    fn test_block_status_for_nonexistent_block() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a blockhash that doesn't exist in the store
        let nonexistent_blockhash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();

        // Status checks should return false for non-existent blocks
        let metadata = store.get_block_metadata(&nonexistent_blockhash);
        assert!(metadata.is_none());
    }

    #[test]
    fn test_multiple_block_status_updates() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create multiple test blocks
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add shares to store
        store.add_share(share1.clone(), 0);
        store.add_share(share2.clone(), 1);

        let blockhash1 = share1.cached_blockhash.unwrap();
        let blockhash2 = share2.cached_blockhash.unwrap();

        // Set status
        assert!(store.set_block_valid(&blockhash1, true, None).is_ok());
        assert!(store.set_block_confirmed(&blockhash2, true, None).is_ok());

        // Verify each block has the correct status
        let metadata1 = store.get_block_metadata(&blockhash1).unwrap();
        let metadata2 = store.get_block_metadata(&blockhash2).unwrap();
        assert!(metadata1.is_valid);
        assert!(!metadata1.is_confirmed);
        assert!(!metadata2.is_valid);
        assert!(metadata2.is_confirmed);

        // Update statuses
        store.set_block_valid(&blockhash1, false, None).unwrap();
        store.set_block_confirmed(&blockhash2, false, None).unwrap();

        let updated_metadata1 = store.get_block_metadata(&blockhash1).unwrap();
        let updated_metadata2 = store.get_block_metadata(&blockhash2).unwrap();

        // Verify updated statuses
        assert!(!updated_metadata1.is_valid);
        assert!(!updated_metadata2.is_confirmed);
    }

    #[test]
    fn test_set_and_get_block_height_in_metadata() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a test block
        let share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let blockhash = share.cached_blockhash.unwrap();

        // Add share to store without setting height in metadata
        store.add_share(share.clone(), 0);

        // Height should be set during add_share
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(metadata.height, Some(0));

        // Update the height to a different value
        store
            .set_block_height_in_metadata(&blockhash, Some(42), None)
            .unwrap();

        // Verify height is updated correctly
        let updated_metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(updated_metadata.height, Some(42));

        // Remove height by setting to None
        store
            .set_block_height_in_metadata(&blockhash, None, None)
            .unwrap();

        // Verify height is removed
        let metadata_without_height = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(metadata_without_height.height, None);

        // Test with batch operation
        let mut batch = rocksdb::WriteBatch::default();
        store
            .set_block_height_in_metadata(&blockhash, Some(100), Some(&mut batch))
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify batch operation worked
        let batch_updated_metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(batch_updated_metadata.height, Some(100));
    }

    #[test]
    fn test_get_workbases() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let workbase1 = TestMinerWorkbaseBuilder::new().workinfoid(1000).build();
        let workbase2 = TestMinerWorkbaseBuilder::new().workinfoid(2000).build();
        let workbase3 = TestMinerWorkbaseBuilder::new().workinfoid(3000).build();

        // Add workbases to store
        store.add_workbase(workbase1.clone()).unwrap();
        store.add_workbase(workbase2.clone()).unwrap();
        store.add_workbase(workbase3.clone()).unwrap();

        // Test getting a single workbase
        let retrieved_workbase = store.get_workbase(1000);
        assert!(retrieved_workbase.is_some());
        assert_eq!(retrieved_workbase.unwrap().workinfoid, 1000);

        // Test getting multiple workbases
        let workinfoids = vec![1000, 2000, 3000];
        let retrieved_workbases = store.get_workbases(&workinfoids);

        assert_eq!(retrieved_workbases.len(), 3);

        // Verify workbases are retrieved correctly
        let workinfoid_set: HashSet<u64> =
            retrieved_workbases.iter().map(|wb| wb.workinfoid).collect();

        assert!(workinfoid_set.contains(&1000));
        assert!(workinfoid_set.contains(&2000));
        assert!(workinfoid_set.contains(&3000));

        // Test getting a subset of workbases
        let subset_ids = vec![1000, 3000];
        let subset_workbases = store.get_workbases(&subset_ids);

        assert_eq!(subset_workbases.len(), 2);

        let subset_workinfoid_set: HashSet<u64> =
            subset_workbases.iter().map(|wb| wb.workinfoid).collect();

        assert!(subset_workinfoid_set.contains(&1000));
        assert!(subset_workinfoid_set.contains(&3000));
        assert!(!subset_workinfoid_set.contains(&2000));

        // Test getting non-existent workbases
        let nonexistent_ids = vec![4000, 5000];
        let nonexistent_workbases = store.get_workbases(&nonexistent_ids);
        assert_eq!(nonexistent_workbases.len(), 0);

        // Test getting a mix of existent and non-existent workbases
        let mixed_ids = vec![1000, 4000, 3000];
        let mixed_workbases = store.get_workbases(&mixed_ids);

        assert_eq!(mixed_workbases.len(), 2);

        let mixed_workinfoid_set: HashSet<u64> =
            mixed_workbases.iter().map(|wb| wb.workinfoid).collect();

        assert!(mixed_workinfoid_set.contains(&1000));
        assert!(mixed_workinfoid_set.contains(&3000));
        assert!(!mixed_workinfoid_set.contains(&4000));
    }

    #[test]
    fn test_get_user_workbases() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_workbase1 = TestUserWorkbaseBuilder::new().workinfoid(1000).build();
        let user_workbase2 = TestUserWorkbaseBuilder::new().workinfoid(2000).build();
        let user_workbase3 = TestUserWorkbaseBuilder::new().workinfoid(3000).build();

        // Add user workbases to store
        store.add_user_workbase(user_workbase1.clone()).unwrap();
        store.add_user_workbase(user_workbase2.clone()).unwrap();
        store.add_user_workbase(user_workbase3.clone()).unwrap();

        // Test getting individual user workbases
        let retrieved_workbases = store.get_user_workbases(&[1000, 2000]);
        assert_eq!(retrieved_workbases.len(), 2);
        assert_eq!(retrieved_workbases[0].workinfoid, 1000);
        assert_eq!(retrieved_workbases[1].workinfoid, 2000);

        // Test getting a non-existent user workbase
        let nonexistent_workbase = store.get_user_workbases(&[4000, 5000]);
        assert_eq!(nonexistent_workbase.len(), 0);

        // Verify the content of retrieved workbases
        let workbase1 = &retrieved_workbases[0];
        assert_eq!(workbase1.params.id, "67b6f8fc00000003");
        assert_eq!(
            workbase1.params.prevhash,
            "6d600f568f665af26301fcafa53326454b9db355ff5d87f9863a956300000000"
        );
        assert_eq!(workbase1.workinfoid, 1000);

        let workbase2 = &retrieved_workbases[1];
        assert_eq!(workbase2.params.id, "67b6f8fc00000003");
        assert_eq!(
            workbase2.params.prevhash,
            "6d600f568f665af26301fcafa53326454b9db355ff5d87f9863a956300000000"
        );
        assert_eq!(workbase2.workinfoid, 2000);
    }

    #[test]
    fn test_add_pplns_share() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a PPLNS share
        let pplns_share = SimplePplnsShare::new(
            1,
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            "".to_string(),
            1000,
        );

        // Add the PPLNS share to the store
        let result = store.add_pplns_share(pplns_share.clone());
        assert!(
            result.is_ok(),
            "Failed to add PPLNS share: {:?}",
            result.err()
        );

        let stored_data = store.get_pplns_shares().unwrap();
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
        let user_id = store.store_user(btcaddress.clone()).unwrap();

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
        let same_user_id = store.store_user(btcaddress.clone()).unwrap();
        assert_eq!(same_user_id, user_id);

        // Store different user - should get new ID
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let user_id2 = store.store_user(btcaddress2.clone()).unwrap();

        // Verify both users exist
        let user1 = store.get_user_by_btcaddress(&btcaddress).unwrap().unwrap();
        let user2 = store.get_user_by_btcaddress(&btcaddress2).unwrap().unwrap();
        assert_ne!(user1.user_id, user2.user_id);
    }

    #[test]
    fn test_store_and_get_worker() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let workername = "worker1".to_string();

        // First create a user
        let user_id = store.store_user(btcaddress.clone()).unwrap();

        // Store a worker for this user
        let worker_id = store.store_worker(user_id, workername.clone()).unwrap();

        // Get worker by ID
        let stored_worker = store.get_worker_by_id(worker_id).unwrap().unwrap();
        assert_eq!(stored_worker.worker_id, worker_id);
        assert_eq!(stored_worker.user_id, user_id);
        assert_eq!(stored_worker.workername, workername);
        assert!(stored_worker.created_at > 0);

        // Get worker by workername
        let worker_by_name = store
            .get_worker_by_workername(&workername)
            .unwrap()
            .unwrap();
        assert_eq!(worker_by_name.worker_id, worker_id);
        assert_eq!(worker_by_name.user_id, user_id);
        assert_eq!(worker_by_name.workername, workername);

        // Store same worker again - should return same ID
        let same_worker_id = store.store_worker(user_id, workername.clone()).unwrap();
        assert_eq!(same_worker_id, worker_id);

        // Store different worker for same user
        let workername2 = "worker2".to_string();
        let worker_id2 = store.store_worker(user_id, workername2.clone()).unwrap();
        assert_ne!(worker_id2, worker_id);
    }

    #[test]
    fn test_worker_user_relationship() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create two users
        let user1_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let user2_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();

        let user1_id = store.store_user(user1_address).unwrap();
        let user2_id = store.store_user(user2_address).unwrap();

        // Create workers for each user
        let worker1_id = store
            .store_worker(user1_id, "user1_worker1".to_string())
            .unwrap();
        let worker2_id = store
            .store_worker(user1_id, "user1_worker2".to_string())
            .unwrap();
        let worker3_id = store
            .store_worker(user2_id, "user2_worker1".to_string())
            .unwrap();

        // Verify workers belong to correct users
        let worker1 = store.get_worker_by_id(worker1_id).unwrap().unwrap();
        let worker2 = store.get_worker_by_id(worker2_id).unwrap().unwrap();
        let worker3 = store.get_worker_by_id(worker3_id).unwrap().unwrap();

        assert_eq!(worker1.user_id, user1_id);
        assert_eq!(worker2.user_id, user1_id);
        assert_eq!(worker3.user_id, user2_id);
    }

    #[test]
    fn test_get_nonexistent_user_and_worker() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Test getting non-existent user by ID
        let user = store.get_user_by_id(999).unwrap();
        assert!(user.is_none());

        // Test getting non-existent user by btcaddress
        let user = store.get_user_by_btcaddress("nonexistent_address").unwrap();
        assert!(user.is_none());

        // Test getting non-existent worker by ID
        let worker = store.get_worker_by_id(999).unwrap();
        assert!(worker.is_none());

        // Test getting non-existent worker by workername
        let worker = store
            .get_worker_by_workername("nonexistent_worker")
            .unwrap();
        assert!(worker.is_none());
    }

    #[test]
    fn test_metadata_counters_persistence() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap().to_string();

        // Create store and add some users/workers
        {
            let store = Store::new(temp_path.clone(), false).unwrap();
            let user_id1 = store.store_user("user1".to_string()).unwrap();
            let user_id2 = store.store_user("user2".to_string()).unwrap();
            let _worker_id1 = store.store_worker(user_id1, "worker1".to_string()).unwrap();
            let _worker_id2 = store.store_worker(user_id2, "worker2".to_string()).unwrap();

            assert_ne!(user_id1, user_id2);
        }

        // Reopen store and verify counters continue from where they left off
        {
            let store = Store::new(temp_path, false).unwrap();
            let user_id3 = store.store_user("user3".to_string()).unwrap();
            let worker_id3 = store.store_worker(user_id3, "worker3".to_string()).unwrap();

            assert!(worker_id3 > user_id3);
        }
    }

    #[test]
    fn test_user_worker_cbor_serialization() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let workername = "test_worker".to_string();

        // Store user and worker
        let user_id = store.store_user(btcaddress.clone()).unwrap();
        let worker_id = store.store_worker(user_id, workername.clone()).unwrap();

        // Retrieve and verify data integrity
        let stored_user = store.get_user_by_id(user_id).unwrap().unwrap();
        let stored_worker = store.get_worker_by_id(worker_id).unwrap().unwrap();

        // Verify all fields are correctly serialized/deserialized
        assert_eq!(stored_user.user_id, user_id);
        assert_eq!(stored_user.btcaddress, btcaddress);
        assert!(stored_user.created_at > 0);

        assert_eq!(stored_worker.worker_id, worker_id);
        assert_eq!(stored_worker.user_id, user_id);
        assert_eq!(stored_worker.workername, workername);
        assert!(stored_worker.created_at > 0);

        // Verify timestamps are reasonable (within last minute)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(stored_user.created_at <= now);
        assert!(stored_user.created_at > now - 60);
        assert!(stored_worker.created_at <= now);
        assert!(stored_worker.created_at > now - 60);
    }

    #[test]
    fn test_get_btcaddresses_for_user_ids() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Store multiple users
        let btcaddress1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let btcaddress3 = "1QGTJkBFhCjPHqbnwK6z7JfEHefq6Yj2jJ".to_string();

        let user_id1 = store.store_user(btcaddress1.clone()).unwrap();
        let user_id2 = store.store_user(btcaddress2.clone()).unwrap();
        let user_id3 = store.store_user(btcaddress3.clone()).unwrap();

        // Test getting btcaddresses for existing user IDs
        let user_ids = vec![user_id1, user_id2, user_id3];
        let results = store.get_btcaddresses_for_user_ids(&user_ids).unwrap();

        assert_eq!(results.len(), 3);

        // Convert to HashMap for easier lookup
        let result_map: std::collections::HashMap<u64, String> = results.into_iter().collect();

        assert_eq!(result_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(result_map.get(&user_id2), Some(&btcaddress2));
        assert_eq!(result_map.get(&user_id3), Some(&btcaddress3));

        // Test with subset of user IDs
        let subset_ids = vec![user_id1, user_id3];
        let subset_results = store.get_btcaddresses_for_user_ids(&subset_ids).unwrap();

        assert_eq!(subset_results.len(), 2);
        let subset_map: std::collections::HashMap<u64, String> =
            subset_results.into_iter().collect();

        assert_eq!(subset_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(subset_map.get(&user_id3), Some(&btcaddress3));
        assert!(!subset_map.contains_key(&user_id2));

        // Test with non-existent user IDs
        let nonexistent_ids = vec![9999, 8888];
        let empty_results = store
            .get_btcaddresses_for_user_ids(&nonexistent_ids)
            .unwrap();

        assert_eq!(empty_results.len(), 0);

        // Test with mixed existing and non-existent IDs
        let mixed_ids = vec![user_id1, 9999, user_id2];
        let mixed_results = store.get_btcaddresses_for_user_ids(&mixed_ids).unwrap();

        assert_eq!(mixed_results.len(), 2);
        let mixed_map: std::collections::HashMap<u64, String> = mixed_results.into_iter().collect();

        assert_eq!(mixed_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(mixed_map.get(&user_id2), Some(&btcaddress2));
        assert!(!mixed_map.contains_key(&9999));
    }
}
