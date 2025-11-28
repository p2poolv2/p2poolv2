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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::shares::share_block::{ShareBlock, ShareHeader, StorageShareBlock, Txids};
use crate::store::block_tx_metadata::{BlockMetadata, TxMetadata};
use crate::store::column_families::ColumnFamily;
use crate::store::user::StoredUser;
use crate::utils::snowflake_simplified::get_next_id;
use bitcoin::consensus::{Encodable, encode};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Transaction, Txid, Work};
use rocksdb::{ColumnFamilyDescriptor, DB, Options as RocksDbOptions};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

pub mod background_tasks;
mod block_tx_metadata;
pub mod column_families;
mod pplns_shares;
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
        let block_index_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockIndex, RocksDbOptions::default());
        let block_height_cf =
            ColumnFamilyDescriptor::new(ColumnFamily::BlockHeight, RocksDbOptions::default());
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

    /// Store a user by btcaddress, returns the user ID
    pub fn add_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        // Check if user already exists via index
        if let Some(existing_id_bytes) = self.db.get_cf(&user_index_cf, &btcaddress)? {
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
        let mut batch = Self::get_write_batch();

        // Store user data (key: user_id, value: serialized StoredUser)
        let mut serialized_user = Vec::new();
        stored_user.consensus_encode(&mut serialized_user)?;
        batch.put_cf(&user_cf, user_id.to_be_bytes(), serialized_user);

        // Store index mapping (key: btcaddress, value: user_id)
        batch.put_cf(&user_index_cf, btcaddress, user_id.to_be_bytes());

        // Write batch atomically
        self.db.write(batch)?;

        Ok(user_id)
    }

    /// Get user by user ID
    pub fn get_user_by_id(
        &self,
        user_id: u64,
    ) -> Result<Option<StoredUser>, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();

        if let Some(serialized_user) = self.db.get_cf(&user_cf, user_id.to_be_bytes())? {
            if let Ok(stored_user) = encode::deserialize(&serialized_user) {
                Ok(Some(stored_user))
            } else {
                tracing::warn!("Error deserializing stored user. Database corrupted?");
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get user by btcaddress
    pub fn get_user_by_btcaddress(
        &self,
        btcaddress: &str,
    ) -> Result<Option<StoredUser>, Box<dyn Error + Send + Sync>> {
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        if let Some(user_id_bytes) = self.db.get_cf(&user_index_cf, btcaddress)? {
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
    /// Accepts any iterable of user IDs for flexibility (HashSet, Vec, slice, etc.)
    /// Uses RocksDB multi_get_cf for efficient batch querying
    pub fn get_btcaddresses_for_user_ids(
        &self,
        user_ids: &[u64],
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();

        // Build keys for multi_get_cf: (column_family, key_bytes)
        let keys: Vec<_> = user_ids
            .iter()
            .map(|user_id| (&user_cf, user_id.to_be_bytes()))
            .collect();

        // Batch fetch all users in a single multi_get_cf call
        let users = self.db.multi_get_cf(keys);

        // Zip user_ids with results, filter successful ones, and extract btcaddresses
        let results: Vec<(u64, String)> = user_ids
            .iter()
            .zip(users)
            .filter_map(|(user_id, result)| {
                if let Ok(Some(serialized_user)) = result {
                    if let Ok(stored_user) = encode::deserialize::<StoredUser>(&serialized_user) {
                        Some((*user_id, stored_user.btcaddress))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(results)
    }

    /// Add a share to the store
    /// We use StorageShareBlock to serialize the share so that we do not store transactions serialized with the block.
    /// Transactions are stored separately. All writes are done in a single atomic batch.
    pub fn add_share(
        &self,
        share: ShareBlock,
        height: u32,
        chain_work: Work,
        on_main_chain: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let blockhash = share.block_hash();
        debug!(
            "Adding share to store with {} txs: {:?} work: {:?}",
            share.transactions.len(),
            blockhash,
            share.header.get_work()
        );

        // Store transactions and get their metadata
        let txs_metadata = self.add_sharechain_txs(&share.transactions, on_main_chain, batch)?;

        let txids = Txids(txs_metadata.iter().map(|t| t.txid).collect());
        // Store block -> txids index
        self.add_txids_to_block_index(
            &blockhash,
            &txids,
            batch,
            b"_txids",
            ColumnFamily::BlockTxids,
        )?;

        let bitcoin_txids = Txids(
            share
                .bitcoin_transactions
                .iter()
                .map(|tx| tx.compute_txid())
                .collect(),
        );
        // Store block -> bitcoin txids index
        self.add_txids_to_block_index(
            &blockhash,
            &bitcoin_txids,
            batch,
            b"_bitcoin_txids",
            ColumnFamily::BitcoinTxids,
        )?;

        if let Err(e) =
            self.update_block_index(&share.header.prev_share_blockhash, &blockhash, batch)
        {
            tracing::error!("Failed to update block index: {:?}", e);
            return Err(e);
        }

        self.set_height_to_blockhash(&blockhash, height, batch)?;
        let block_metadata = BlockMetadata {
            height: Some(height),
            is_on_main_chain: false,
            is_valid: false,
            chain_work,
        };
        self.set_block_metadata(&blockhash, &block_metadata, batch)?;

        // Add the share block itself
        let storage_share_block: StorageShareBlock = share.into();
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let mut encoded_share_block = Vec::new();
        storage_share_block.consensus_encode(&mut encoded_share_block)?;
        batch.put_cf::<&[u8], Vec<u8>>(&block_cf, blockhash.as_ref(), encoded_share_block);

        Ok(())
    }

    /// Add PPLNS Share to pplns_share_cf
    /// btcaddress and workername are skipped during serialization (serde(skip)) to minimize storage
    ///
    /// Key is timestamp (8) + user_id (8) + share id (8) = 24 bytes
    pub fn add_pplns_share(
        &self,
        pplns_share: SimplePplnsShare,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let pplns_share_cf = self.db.cf_handle(&ColumnFamily::Share).unwrap();

        let mut serialized = Vec::new();
        pplns_share.consensus_encode(&mut serialized)?;

        let n_time = pplns_share.n_time * 1_000_000;
        let key = SimplePplnsShare::make_key(n_time, pplns_share.user_id, get_next_id());
        self.db.put_cf(&pplns_share_cf, key, serialized)?;
        Ok(())
    }

    // Get PPLNS shares, no filter yet
    pub fn get_pplns_shares(&self) -> Vec<SimplePplnsShare> {
        self.get_pplns_shares_filtered(None, None, None)
    }

    /// Iterate over the store from provided start blockhash
    /// Gather all shares along all branches from the genesis
    pub fn load_chain(&self, genesis: BlockHash) -> Vec<BlockHash> {
        let mut chain = vec![];

        let children = self.get_children_blockhashes(&genesis);
        for child in children.iter() {
            if *child != genesis {
                chain.push(*child);
            }
        }
        chain
    }

    /// Load children BlockHashes for a blockhash from the block index
    /// These are tracked in a separate index in rocksdb as relations from
    /// blockhash -> next blockhashes
    fn get_children_blockhashes(&self, blockhash: &BlockHash) -> Vec<BlockHash> {
        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut blockhash_bytes = bitcoin::consensus::serialize(blockhash);
        blockhash_bytes.extend_from_slice(b"_bi");

        match self
            .db
            .get_cf::<&[u8]>(&block_index_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(existing)) => {
                debug!("Found existing");
                if let Ok(existing_blockhashes) = encode::deserialize::<Vec<BlockHash>>(&existing) {
                    debug!("Found existing blockhashes {:?}", existing_blockhashes);
                    existing_blockhashes
                } else {
                    tracing::warn!("Failed to deseriliaze child blockhash");
                    Vec::new()
                }
            }
            Ok(None) | Err(_) => Vec::new(),
        }
    }

    /// Update the block index so that we can easily find all the children of a block
    /// We store the next blockhashes for a block in a separate column family
    fn update_block_index(
        &self,
        prev_blockhash: &BlockHash,
        next_blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!(
            "Updating block index {} to {}",
            prev_blockhash, next_blockhash
        );

        let block_index_cf = self.db.cf_handle(&ColumnFamily::BlockIndex).unwrap();
        let mut prev_blockhash_bytes = bitcoin::consensus::serialize(prev_blockhash);
        prev_blockhash_bytes.extend_from_slice(b"_bi");

        let mut existing_children = self.get_children_blockhashes(prev_blockhash);

        if !existing_children.contains(next_blockhash) {
            // Add the new prev blockhash
            existing_children.push(*next_blockhash);
        }

        debug!("New children {:?}", &existing_children);

        // Serialize the updated set
        let mut serialized_children = Vec::new();
        match existing_children.consensus_encode(&mut serialized_children) {
            Ok(_) => (),
            Err(e) => return Err(Box::new(e)),
        };

        // Store the updated set
        batch.put_cf::<&[u8], Vec<u8>>(
            &block_index_cf,
            prev_blockhash_bytes.as_ref(),
            serialized_children,
        );
        Ok(())
    }

    /// Store transactions in the store
    /// Store inputs and outputs for each transaction in separate column families
    /// Store txid -> transaction metadata in the tx column family
    /// The block -> txids store is done in add_txids_to_block_index. This function lets us store transactions outside of a block context
    fn add_sharechain_txs(
        &self,
        transactions: &[Transaction],
        confirmed: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Vec<TxMetadata>, Box<dyn Error + Send + Sync>> {
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut txs_metadata = Vec::new();
        for tx in transactions {
            let txid = tx.compute_txid();
            let metadata = self.add_tx_metadata(txid, tx, false, batch)?;
            txs_metadata.push(metadata);

            // Store each input for the transaction
            for (i, input) in tx.input.iter().enumerate() {
                let input_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                input.consensus_encode(&mut serialized)?;
                batch.put_cf::<&[u8], Vec<u8>>(&inputs_cf, input_key.as_ref(), serialized);

                if confirmed {
                    self.confirm_transaction(tx, batch)?;
                }
            }

            // Store each output for the transaction
            for (i, output) in tx.output.iter().enumerate() {
                let output_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                output.consensus_encode(&mut serialized)?;
                batch.put_cf::<&[u8], Vec<u8>>(&outputs_cf, output_key.as_ref(), serialized);

                // part of batch write, so we make individual calls
                self.add_to_unspent_outputs(&txid, i as u32, batch)?;
            }
        }
        Ok(txs_metadata)
    }

    /// Marks the transaction as successfully validated, this prevents us validating it again.
    /// We only validate what is dependent on the chain state. Once valid, the txid is never made invalid.
    fn mark_transaction_valid(
        &self,
        txid: &Txid,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<TxMetadata, Box<dyn Error + Send + Sync>> {
        // mark tx metadata as validated
        let mut tx_metadata = self.get_tx_metadata(txid)?;
        tx_metadata.validated = true;

        let mut serialized = Vec::new();
        tx_metadata.consensus_encode(&mut serialized)?;
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(&tx_cf, txid.as_ref(), serialized);

        Ok(tx_metadata)
    }

    /// Transaction confirmation means it has been validated and is part of a block in the main chain.
    /// Adds the outputs to unspent output set
    /// Validated status remains unchanged, the script is still valid etc
    fn confirm_transaction(
        &self,
        transaction: &Transaction,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Remove all input prevouts from unspent outputs
        for txin in transaction.input.iter() {
            self.remove_from_unspent_outputs(
                &txin.previous_output.txid,
                txin.previous_output.vout,
                batch,
            )?;
        }
        Ok(())
    }

    /// Marking transaction as unconfirmed means it has been removed from the main chain as a result of a reorg
    /// Removes the outputs to unspent output set
    /// Validated status remains unchanged, the script is still valid etc
    fn unconfirm_transaction(
        &self,
        transaction: &Transaction,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Add all input prevouts from unspent outputs
        for txin in transaction.input.iter() {
            self.add_to_unspent_outputs(
                &txin.previous_output.txid,
                txin.previous_output.vout,
                batch,
            )?;
        }
        Ok(())
    }

    /// An the txid, index as an unspent output
    fn add_to_unspent_outputs(
        &self,
        txid: &Txid,
        index: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let utxo_cf = self.db.cf_handle(&ColumnFamily::UnspentOutputs).unwrap();
        let key = format!("{txid}:{index}");
        batch.put_cf(&utxo_cf, key.as_str(), []);
        Ok(())
    }

    /// Remove txid, index from unspent outputs
    fn remove_from_unspent_outputs(
        &self,
        txid: &Txid,
        index: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let utxo_cf = self.db.cf_handle(&ColumnFamily::UnspentOutputs).unwrap();
        let key = format!("{txid}:{index}");
        batch.delete_cf(&utxo_cf, key.as_str());
        Ok(())
    }

    /// Check if txid, index is in unspent outputs
    fn is_in_unspent_outputs(
        &self,
        txid: Txid,
        index: u32,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let utxo_cf = self.db.cf_handle(&ColumnFamily::UnspentOutputs).unwrap();
        let key = format!("{txid}:{index}");
        // Most of the time OutPoint will NOT exist in unspent txs,
        // and key may exist will definitely return false in that case
        let mut exists = self.db.key_may_exist_cf(&utxo_cf, key.as_str());
        // Check if exists for sure, if we a false positive
        if exists {
            exists = self.db.get_pinned_cf(&utxo_cf, key.as_str())?.is_some();
        }
        Ok(exists)
    }

    /// Store transaction metadata
    fn add_tx_metadata(
        &self,
        txid: bitcoin::Txid,
        tx: &Transaction,
        validated: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<TxMetadata, Box<dyn Error + Send + Sync>> {
        debug!("Adding tx metdata for txid {txid}");
        let tx_metadata = TxMetadata {
            txid,
            version: tx.version,
            lock_time: tx.lock_time,
            input_count: tx.input.len() as u32,
            output_count: tx.output.len() as u32,
            validated,
        };

        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let mut tx_metadata_serialized = Vec::new();
        tx_metadata.consensus_encode(&mut tx_metadata_serialized)?;
        batch.put_cf::<&[u8], Vec<u8>>(&tx_cf, txid.as_ref(), tx_metadata_serialized);
        Ok(tx_metadata)
    }

    /// Add the list of transaction IDs to the batch
    /// Transactions themselves are stored in add_txs, here we just store the association between block and txids
    fn add_txids_to_block_index(
        &self,
        blockhash: &BlockHash,
        txids: &Txids,
        batch: &mut rocksdb::WriteBatch,
        bytes_suffix: &[u8],
        column_family: ColumnFamily,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut blockhash_bytes = bitcoin::consensus::serialize(blockhash);
        blockhash_bytes.extend_from_slice(bytes_suffix);

        let mut serialized_txids = Vec::new();
        txids.consensus_encode(&mut serialized_txids)?;
        let block_txids_cf = self.db.cf_handle(&column_family).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(&block_txids_cf, blockhash_bytes.as_ref(), serialized_txids);
        Ok(())
    }

    /// Get all transaction IDs for a given block hash
    /// Returns a vector of transaction IDs that were included in the block
    fn get_txids_for_blockhash(&self, blockhash: &BlockHash, column_family: ColumnFamily) -> Txids {
        let mut blockhash_bytes = bitcoin::consensus::serialize(blockhash);
        let suffix_bytes: &[u8] = if column_family == ColumnFamily::BlockTxids {
            b"_txids"
        } else {
            b"_bitcoin_txids"
        };
        blockhash_bytes.extend_from_slice(suffix_bytes);

        let block_txids_cf = self.db.cf_handle(&column_family).unwrap();
        match self
            .db
            .get_cf::<&[u8]>(&block_txids_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(serialized_txids)) => match encode::deserialize(&serialized_txids) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!("Error reading txids for blockhash");
                    Txids(Vec::new())
                }
            },
            _ => Txids(Vec::new()),
        }
    }

    /// Mark output as spent,
    pub fn remove_output_from_unspent(
        &self,
        output_point: OutPoint,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // TODO - implement
        Ok(())
    }

    /// Get the validation status of a transaction from the store
    pub fn get_tx_metadata(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<TxMetadata, Box<dyn Error + Send + Sync>> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        match self.db.get_cf::<&[u8]>(&tx_cf, txid.as_ref())? {
            Some(tx_metadata) => encode::deserialize(&tx_metadata)
                .map_err(|_| "Failed to seralize tx metadata".into()),
            None => Err(format!("Transaction metadata not found for txid: {txid}").into()),
        }
    }

    /// Save a job with the given timestamp key to the Job column family
    pub fn add_job(
        &self,
        timestamp: u64,
        serialized_notify: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Saving job to store with key: {:?}", timestamp);
        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();
        self.db.put_cf(
            &job_cf,
            timestamp.to_be_bytes(),
            serialized_notify.as_bytes(),
        )?;
        Ok(())
    }

    /// Get jobs within a time range from the Job column family
    /// Returns jobs ordered by timestamp (newest first)
    pub fn get_jobs(
        &self,
        start_time: Option<u64>,
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

        if let Some(start) = start_time {
            // Set the lower bound (start_time) for reverse iteration
            read_opts.set_iterate_lower_bound(start.to_be_bytes().to_vec());
        }

        // Start iterating from end_time in reverse order to get newest first
        let iter = self.db.iterator_cf_opt(
            &job_cf,
            read_opts,
            rocksdb::IteratorMode::From(
                &effective_end_time.to_be_bytes(),
                rocksdb::Direction::Reverse,
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
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let share = match self.db.get_cf::<&[u8]>(&share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share: StorageShareBlock = match encode::deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let transactions = self.get_txs_for_blockhash(blockhash, ColumnFamily::BlockTxids);
        let bitcoin_transactions =
            self.get_txs_for_blockhash(blockhash, ColumnFamily::BitcoinTxids);
        let share = ShareBlock {
            header: share.header,
            transactions,
            bitcoin_transactions,
        };
        Some(share)
    }

    /// Get a share headers matching the vector of blockhashes
    pub fn get_share_headers(&self, blockhashes: &[BlockHash]) -> Vec<ShareHeader> {
        debug!("Getting share headers from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (&share_cf, bitcoin::consensus::serialize(h)))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        let share_headers = shares
            .into_iter()
            .map(|v| {
                if let Ok(Some(v)) = v {
                    if let Ok(storage_share) = encode::deserialize::<StorageShareBlock>(&v) {
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
    fn get_first_existing_blockhash(&self, locator: &[BlockHash]) -> Option<BlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        for blockhash in locator {
            if self
                .db
                .key_may_exist_cf(&block_cf, bitcoin::consensus::serialize(blockhash))
            {
                return Some(*blockhash);
            }
        }
        None
    }

    /// Get all descendant blockhashes of a given blockhash
    fn get_descendant_blockhashes(
        &self,
        blockhash: &BlockHash,
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Vec<BlockHash> {
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
    pub fn get_genesis_blockhash(&self) -> BlockHash {
        self.get_blockhashes_for_height(0)[0]
    }

    /// Get blockhashes to satisfy the locator query.
    /// Returns a list of blockhashes from the earliest block from the block hashes
    /// We assume the list of blocks in the locator is ordered by height, so we stop when we find the first block in the locator
    /// Find blockhashes up to the stop blockhash, or the limit provided
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[BlockHash],
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Vec<BlockHash> {
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
        locator: &[BlockHash],
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        let blockhashes = self.get_blockhashes_for_locator(locator, stop_blockhash, limit);
        self.get_share_headers(&blockhashes)
    }

    /// Get descendants headers of a share
    /// We stop looking after we have found limit number of descendants or have hit stop blockhash
    pub fn get_descendants(
        &self,
        share: BlockHash,
        stop_blockhash: &BlockHash,
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
    pub fn get_shares(&self, blockhashes: &[BlockHash]) -> HashMap<BlockHash, ShareBlock> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (&share_cf, bitcoin::consensus::serialize(h)))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        // iterate over the blockhashes and shares, filter out the ones that are not found or can't be deserialized
        // then convert the storage share to share block and return as a hashmap
        blockhashes
            .iter()
            .zip(shares)
            .filter_map(|(blockhash, result)| {
                if let Ok(Some(data)) = result {
                    if let Ok(storage_share) = encode::deserialize::<StorageShareBlock>(&data) {
                        let transactions =
                            self.get_txs_for_blockhash(blockhash, ColumnFamily::BlockTxids);
                        let bitcoin_transactions =
                            self.get_txs_for_blockhash(blockhash, ColumnFamily::BitcoinTxids);
                        Some((
                            *blockhash,
                            ShareBlock {
                                header: storage_share.header,
                                transactions,
                                bitcoin_transactions,
                            },
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
    pub fn get_txs_for_blockhash(
        &self,
        blockhash: &BlockHash,
        column_family: ColumnFamily,
    ) -> Vec<Transaction> {
        let txids = self.get_txids_for_blockhash(blockhash, column_family);
        txids
            .0
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
    pub fn get_tx(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Transaction, Box<dyn Error + Send + Sync>> {
        let tx_metadata = self.get_tx_metadata(txid)?;

        debug!("Transaction metadata: {:?}", tx_metadata);

        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        for i in 0..tx_metadata.input_count {
            let input_key = format!("{txid}:{i}");
            let input = self
                .db
                .get_cf::<&[u8]>(&inputs_cf, input_key.as_ref())
                .unwrap()
                .unwrap();
            let input: bitcoin::TxIn = match encode::deserialize(&input) {
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
                .get_cf::<&[u8]>(&outputs_cf, output_key.as_ref())
                .unwrap()
                .unwrap();
            let output: bitcoin::TxOut = match encode::deserialize(&output) {
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
    pub fn get_parent(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        let share = self.get_share(blockhash)?;
        let parent_blockhash = share.header.prev_share_blockhash;
        self.get_share(&parent_blockhash)
    }

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
    pub fn get_uncles(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return vec![];
        }
        let share = share.unwrap();
        let uncle_blocks = self.get_shares(&share.header.uncles);
        uncle_blocks.into_values().collect()
    }

    /// Get entire chain from earliest known block to given blockhash,
    /// excluding the given blockhash
    ///
    /// We can't use get_shares as we need to get a share, then find
    /// it's prev_share_blockhash, then get the share again, etc.
    pub fn get_chain_upto(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        debug!("Getting chain upto: {:?}", blockhash);
        std::iter::successors(self.get_share(blockhash), |share| {
            self.get_share(&share.header.prev_share_blockhash)
        })
        .collect()
    }

    /// Get the main chain and the uncles from the tips to the provided blockhash
    /// All shares are collected in a single vector
    /// Returns an error if blockhash is not found
    pub fn get_shares_from_tip_to_blockhash(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<ShareBlock>, Box<dyn Error + Send + Sync>> {
        let share_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        if !self
            .db
            .key_may_exist_cf::<&[u8]>(&share_cf, blockhash.as_ref())
        {
            return Err(format!("Blockhash {blockhash} not found in chain").into());
        };

        let tips = self.get_tips();
        let mut all_shares = Vec::new();
        let mut visited = HashSet::new();
        let mut to_visit: VecDeque<BlockHash> = tips.into_iter().collect();

        while let Some(hash) = to_visit.pop_front() {
            if visited.contains(&hash) {
                continue;
            }

            if let Some(share) = self.get_share(&hash) {
                visited.insert(hash);
                all_shares.push(share.clone());

                if hash != *blockhash {
                    to_visit.push_back(share.header.prev_share_blockhash);
                    // Also traverse uncles
                    for uncle_hash in share.header.uncles.iter() {
                        to_visit.push_back(*uncle_hash);
                    }
                }
            }
        }

        Ok(all_shares)
    }

    /// Get common ancestor of two blockhashes
    pub fn get_common_ancestor(
        &self,
        blockhash1: &BlockHash,
        blockhash2: &BlockHash,
    ) -> Option<BlockHash> {
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
            .map(|block| block.block_hash())
    }

    /// Set the height for the blockhash, storing it in a vector of blockhashes for that height
    /// We are fine with Vector instead of HashSet as we are not going to have a lot of blockhashes at the same height
    pub fn set_height_to_blockhash(
        &self,
        blockhash: &BlockHash,
        height: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        // Convert height to big-endian bytes - this is our key
        let height_bytes = height.to_be_bytes();

        // Get any existing blockhashes for this height
        let mut blockhashes: Vec<BlockHash> = match self
            .db
            .get_cf::<&[u8]>(&column_family, height_bytes.as_ref())
        {
            Ok(Some(existing)) => encode::deserialize(&existing).unwrap_or_default(),
            Ok(None) | Err(_) => Vec::new(),
        };

        // Add the new blockhash if not already present
        if !blockhashes.contains(blockhash) {
            blockhashes.push(*blockhash);

            // Serialize the updated vector of blockhashes
            let mut serialized = Vec::new();
            blockhashes.consensus_encode(&mut serialized)?;

            // Store the updated vector
            batch.put_cf(&column_family, height_bytes, serialized);
        }
        Ok(())
    }

    /// Get the blockhashes for a specific height
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        let column_family = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let height_bytes = height.to_be_bytes();
        match self
            .db
            .get_cf::<&[u8]>(&column_family, height_bytes.as_ref())
        {
            Ok(Some(blockhashes)) => encode::deserialize(&blockhashes).unwrap_or_default(),
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Get the shares for a specific height
    pub fn get_shares_at_height(&self, height: u32) -> HashMap<BlockHash, ShareBlock> {
        let blockhashes = self.get_blockhashes_for_height(height);
        self.get_shares(&blockhashes)
    }

    /// Get the block metadata for a blockhash
    pub fn get_block_metadata(
        &self,
        blockhash: &BlockHash,
    ) -> Result<BlockMetadata, Box<dyn Error + Send + Sync>> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = bitcoin::consensus::serialize(blockhash);
        metadata_key.extend_from_slice(b"_md");

        match self.db.get_cf::<&[u8]>(&block_metadata_cf, &metadata_key) {
            Ok(Some(metadata_serialized)) => match encode::deserialize(&metadata_serialized) {
                Ok(metadata) => Ok(metadata),
                Err(e) => Err(format!("Error deserializing block metadata: {e}").into()),
            },
            Ok(None) | Err(_) => {
                Err(format!("No metadata found for blockhash: {blockhash}").into())
            }
        }
    }

    /// Check which blockhashes from the provided list are missing from the store
    /// Returns a vector of blockhashes that are not present in the store
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        let block_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();
        blockhashes
            .iter()
            .filter(|&hash| {
                !self
                    .db
                    .key_may_exist_cf(&block_cf, bitcoin::consensus::serialize(hash))
            })
            .cloned()
            .collect()
    }

    /// Set the block metadata for a blockhash
    fn set_block_metadata(
        &self,
        blockhash: &BlockHash,
        metadata: &BlockMetadata,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_metadata_cf = self.db.cf_handle(&ColumnFamily::Block).unwrap();

        let mut metadata_key = bitcoin::consensus::serialize(blockhash);
        metadata_key.extend_from_slice(b"_md");

        let mut serialized = Vec::new();
        metadata.consensus_encode(&mut serialized)?;

        batch.put_cf(&block_metadata_cf, &metadata_key, serialized);
        Ok(())
    }

    /// Mark a block as valid in the store
    pub fn set_block_valid(
        &self,
        blockhash: &BlockHash,
        valid: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let metadata = self.get_block_metadata(blockhash)?;

        let updated_metadata = BlockMetadata {
            is_valid: valid,
            is_on_main_chain: metadata.is_on_main_chain,
            height: metadata.height,
            chain_work: metadata.chain_work,
        };

        self.set_block_metadata(blockhash, &updated_metadata, batch)
    }

    /// Mark a block as confirmed in the store
    pub fn set_block_on_main_chain(
        &self,
        blockhash: &BlockHash,
        on_main_chain: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let metadata = self.get_block_metadata(blockhash)?;

        let updated_metadata = BlockMetadata {
            is_valid: metadata.is_valid,
            is_on_main_chain: on_main_chain,
            height: metadata.height,
            chain_work: metadata.chain_work,
        };

        self.set_block_metadata(blockhash, &updated_metadata, batch)
    }

    pub fn set_block_height_in_metadata(
        &self,
        blockhash: &BlockHash,
        height: Option<u32>,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let metadata = self.get_block_metadata(blockhash)?;

        let updated_metadata = BlockMetadata {
            is_valid: metadata.is_valid,
            is_on_main_chain: metadata.is_on_main_chain,
            height,
            chain_work: metadata.chain_work,
        };
        debug!("Setting block metadata: {:?}", updated_metadata);
        self.set_block_metadata(blockhash, &updated_metadata, batch)
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
        let chain = self.load_chain(genesis_hash);
        if !chain.is_empty() {
            // Set chain tip to last block in main chain
            self.set_chain_tip(*chain.last().unwrap());

            // Load tips from the highest height
            let height = chain.len() as u32 - 1;
            let tips_shares = self.get_shares_at_height(height);
            let tips: HashSet<BlockHash> = tips_shares.keys().cloned().collect();
            self.update_tips(tips);

            debug!(
                "Initialized chain state: tip={:?}, work={}, tips_count={}",
                self.get_chain_tip(),
                self.get_total_work()?,
                self.get_tips().len()
            );
        }

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

    // #[test_log::test]
    // fn test_chain_with_uncles() {
    //     let temp_dir = tempdir().unwrap();
    //     let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

    //     // Create initial share
    //     let share1 = TestShareBlockBuilder::new().nonce(0xe9695791).build();

    //     // Create uncles for share2
    //     let uncle1_share2 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share1.block_hash().to_string())
    //         .nonce(0xe9695792)
    //         .build();

    //     let uncle2_share2 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share1.block_hash().to_string())
    //         .nonce(0xe9695793)
    //         .build();

    //     // Create share2 with uncles
    //     let share2 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share1.block_hash().to_string())
    //         .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
    //         .nonce(0xe9695794)
    //         .build();

    //     // Create uncles for share3
    //     let uncle1_share3 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share2.block_hash().to_string())
    //         .nonce(0xe9695795)
    //         .build();

    //     let uncle2_share3 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share2.block_hash().to_string())
    //         .nonce(0xe9695796)
    //         .build();

    //     // Create share3 with uncles
    //     let share3 = TestShareBlockBuilder::new()
    //         .prev_share_blockhash(share2.block_hash().to_string())
    //         .uncles(vec![uncle1_share3.block_hash(), uncle2_share3.block_hash()])
    //         .nonce(0xe9695797)
    //         .build();

    //     let genesis_work = share1.header.get_work();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     // Add all shares to store
    //     store
    //         .add_share(share1.clone(), 0, genesis_work, true, &mut batch)
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             uncle1_share2.clone(),
    //             1,
    //             genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             uncle2_share2.clone(),
    //             1,
    //             genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             share2.clone(),
    //             1,
    //             genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             uncle1_share3.clone(),
    //             2,
    //             genesis_work + genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             uncle2_share3.clone(),
    //             2,
    //             genesis_work + genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();
    //     store.commit_batch(batch).unwrap();

    //     let mut batch = rocksdb::WriteBatch::default();
    //     store
    //         .add_share(
    //             share3.clone(),
    //             2,
    //             genesis_work + genesis_work + genesis_work,
    //             true,
    //             &mut batch,
    //         )
    //         .unwrap();

    //     store.commit_batch(batch).unwrap();

    //     let tips = store.get_tips();
    //     assert_eq!(tips.len(), 3);

    //     // Get chain up to share1 - the entire chain
    //     let chain = store.get_main_chain(share1.block_hash());

    //     // Chain should contain share3, share2, share1
    //     assert_eq!(chain.len(), 3);
    //     assert_eq!(chain[0], share1.block_hash());
    //     assert_eq!(chain[1], share2.block_hash());
    //     assert_eq!(chain[2], share3.block_hash());

    //     // Get common ancestor of share3 and share2
    //     let common_ancestor = store.get_common_ancestor(&share3.block_hash(), &share2.block_hash());
    //     assert_eq!(common_ancestor, Some(share1.block_hash()));

    //     // Get chain up to uncle1_share3 (share31)
    //     let chain_to_uncle = store
    //         .get_shares_from_tip_to_blockhash(&share1.block_hash())
    //         .unwrap();
    //     assert_eq!(chain_to_uncle.len(), 7);

    //     // Verify uncles of share2
    //     let uncles_share2 = store.get_uncles(&share2.block_hash());
    //     assert_eq!(uncles_share2.len(), 2);
    //     assert!(
    //         uncles_share2
    //             .iter()
    //             .any(|u| u.header.bitcoin_header.block_hash()
    //                 == uncle1_share2.header.bitcoin_header.block_hash())
    //     );
    //     assert!(
    //         uncles_share2
    //             .iter()
    //             .any(|u| u.header.bitcoin_header.block_hash()
    //                 == uncle2_share2.header.bitcoin_header.block_hash())
    //     );

    //     // Verify uncles of share3
    //     let uncles_share3 = store.get_uncles(&share3.block_hash());
    //     assert_eq!(uncles_share3.len(), 2);
    //     assert!(
    //         uncles_share3
    //             .iter()
    //             .any(|u| u.header.bitcoin_header.block_hash()
    //                 == uncle1_share3.header.bitcoin_header.block_hash())
    //     );
    //     assert!(
    //         uncles_share3
    //             .iter()
    //             .any(|u| u.header.bitcoin_header.block_hash()
    //                 == uncle2_share3.header.bitcoin_header.block_hash())
    //     );

    //     // Verify children of share1
    //     let children_share1 = store.get_children_blockhashes(&share1.block_hash());
    //     assert_eq!(children_share1.len(), 3);
    //     assert!(children_share1.contains(&share2.block_hash()));
    //     assert!(children_share1.contains(&uncle1_share2.block_hash()));
    //     assert!(children_share1.contains(&uncle2_share2.block_hash()));

    //     // Verify children of share2
    //     let children_share2 = store.get_children_blockhashes(&share2.block_hash());
    //     assert_eq!(children_share2.len(), 3);
    //     assert!(children_share2.contains(&share3.block_hash()));
    //     assert!(children_share2.contains(&uncle1_share3.block_hash()));
    //     assert!(children_share2.contains(&uncle2_share3.block_hash()));

    //     // Verify children of share3
    //     let children_share3 = store.get_children_blockhashes(&share3.block_hash());
    //     assert!(children_share3.is_empty());

    //     // Verify children of uncle1_share2
    //     let children_uncle1_share2 = store.get_children_blockhashes(&uncle1_share2.block_hash());
    //     assert!(children_uncle1_share2.is_empty());

    //     // Verify children of uncle2_share2
    //     let children_uncle2_share2 = store.get_children_blockhashes(&uncle2_share2.block_hash());
    //     assert!(children_uncle2_share2.is_empty());

    //     // Verify children of uncle1_share3
    //     let children_uncle1_share3 = store.get_children_blockhashes(&uncle1_share3.block_hash());
    //     assert!(children_uncle1_share3.is_empty());

    //     // Verify children of uncle2_share3
    //     let children_uncle2_share3 = store.get_children_blockhashes(&uncle2_share3.block_hash());
    //     assert!(children_uncle2_share3.is_empty());

    //     let blocks_at_height_0 = store.get_blockhashes_for_height(0);
    //     assert_eq!(blocks_at_height_0, vec![share1.block_hash()]);
    //     let blocks_at_height_1 = store.get_blockhashes_for_height(1);
    //     assert_eq!(
    //         blocks_at_height_1,
    //         vec![
    //             uncle1_share2.block_hash(),
    //             uncle2_share2.block_hash(),
    //             share2.block_hash()
    //         ]
    //     );
    //     let blocks_at_height_2 = store.get_blockhashes_for_height(2);
    //     assert_eq!(
    //         blocks_at_height_2,
    //         vec![
    //             uncle1_share3.block_hash(),
    //             uncle2_share3.block_hash(),
    //             share3.block_hash()
    //         ]
    //     );

    //     let shares_at_height_0 = store.get_shares_at_height(0);
    //     assert_eq!(shares_at_height_0.len(), 1);
    //     assert_eq!(shares_at_height_0[&share1.block_hash()], share1);
    //     let shares_at_height_1 = store.get_shares_at_height(1);
    //     assert_eq!(shares_at_height_1.len(), 3);
    //     assert_eq!(
    //         shares_at_height_1[&uncle1_share2.block_hash()],
    //         uncle1_share2
    //     );
    //     assert_eq!(
    //         shares_at_height_1[&uncle2_share2.block_hash()],
    //         uncle2_share2
    //     );
    //     assert_eq!(shares_at_height_1[&share2.block_hash()], share2);
    // }

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
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
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
        let children_share1 = store.get_children_blockhashes(&share1.block_hash());
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.block_hash()));
        assert!(children_share1.contains(&uncle1_share2.block_hash()));
        assert!(children_share1.contains(&uncle2_share2.block_hash()));

        // Verify children of share2
        let children_share2 = store.get_children_blockhashes(&share2.block_hash());
        assert_eq!(children_share2.len(), 1);
        assert!(children_share2.contains(&share3.block_hash()));

        // Verify children of share3
        let children_share3 = store.get_children_blockhashes(&share3.block_hash());
        assert!(children_share3.is_empty());

        // Verify children of uncle1_share2
        let children_uncle1_share2 = store.get_children_blockhashes(&uncle1_share2.block_hash());
        assert!(children_uncle1_share2.is_empty());

        // Verify children of uncle2_share2
        let children_uncle2_share2 = store.get_children_blockhashes(&uncle2_share2.block_hash());
        assert!(children_uncle2_share2.is_empty());
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
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
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
        let descendants_share1 =
            store.get_descendants(share1.block_hash(), &share3.block_hash(), 10);
        assert_eq!(descendants_share1.len(), 4);
        assert!(descendants_share1.contains(&share2.header));
        assert!(descendants_share1.contains(&share3.header));
        assert!(descendants_share1.contains(&uncle1_share2.header));
        assert!(descendants_share1.contains(&uncle2_share2.header));

        // Verify descendants of share2
        let descendants_share2 =
            store.get_descendants(share2.block_hash(), &share3.block_hash(), 10);
        assert_eq!(descendants_share2.len(), 1);
        assert_eq!(descendants_share2[0], share3.header);

        // Verify no descendants for share3
        let descendants_share3 =
            store.get_descendants(share3.block_hash(), &share3.block_hash(), 10);
        assert!(descendants_share3.is_empty());

        // Verify descendants with limit
        let descendants_with_limit =
            store.get_descendants(share1.block_hash(), &share3.block_hash(), 1);
        assert_eq!(descendants_with_limit.len(), 1);
        assert_eq!(descendants_with_limit[0], uncle1_share2.header);

        // Verify descendants with stop blockhash
        let descendants_with_limit =
            store.get_descendants(share1.block_hash(), &share2.block_hash(), 10);
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
        let result = store.get_headers_for_locator(locator.as_slice(), &stop_block, 10);

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
        let result = store.get_headers_for_locator(&locator, &non_existent_stop_block, 10);
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
        let result = store.get_blockhashes_for_locator(locator.as_slice(), &stop_block, 10);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0], block_hashes[1]);
        assert_eq!(result[1], block_hashes[2]);
    }

    #[test]
    fn test_block_status_operations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create test block
        let share = TestShareBlockBuilder::new().build();

        let mut batch = rocksdb::WriteBatch::default();

        // Add share to store
        store
            .add_share(share.clone(), 0, share.header.get_work(), true, &mut batch)
            .unwrap();

        store.commit_batch(batch).unwrap();

        let blockhash = share.block_hash();

        // Initially, block should not be valid or confirmed
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(!metadata.is_on_main_chain);
        assert_eq!(metadata.height, Some(0));

        let mut batch = rocksdb::WriteBatch::default();
        // Set block as valid
        store.set_block_valid(&blockhash, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(metadata.is_valid);
        assert!(!metadata.is_on_main_chain);

        let mut batch = rocksdb::WriteBatch::default();
        // Set block as confirmed
        store
            .set_block_on_main_chain(&blockhash, true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(metadata.is_valid);
        assert!(metadata.is_on_main_chain);

        let mut batch = rocksdb::WriteBatch::default();
        // Reset block's valid status
        store
            .set_block_valid(&blockhash, false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(metadata.is_on_main_chain);

        let mut batch = rocksdb::WriteBatch::default();
        // Reset block's confirmed status
        store
            .set_block_on_main_chain(&blockhash, false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert!(!metadata.is_valid);
        assert!(!metadata.is_on_main_chain);
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
    fn test_multiple_block_status_updates() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create multiple test blocks
        let share1 = TestShareBlockBuilder::new().build();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .build();

        let mut batch = rocksdb::WriteBatch::default();

        // Add shares to store
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

        store.commit_batch(batch).unwrap();

        let blockhash1 = share1.block_hash();
        let blockhash2 = share2.block_hash();

        let mut batch = rocksdb::WriteBatch::default();
        // Set status
        store
            .set_block_valid(&blockhash1, true, &mut batch)
            .unwrap();
        store
            .set_block_on_main_chain(&blockhash2, true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify each block has the correct status
        let metadata1 = store.get_block_metadata(&blockhash1).unwrap();
        let metadata2 = store.get_block_metadata(&blockhash2).unwrap();
        assert!(metadata1.is_valid);
        assert!(!metadata1.is_on_main_chain);
        assert!(!metadata2.is_valid);
        assert!(metadata2.is_on_main_chain);

        let mut batch = rocksdb::WriteBatch::default();
        // Update statuses
        store
            .set_block_valid(&blockhash1, false, &mut batch)
            .unwrap();
        store
            .set_block_on_main_chain(&blockhash2, false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let updated_metadata1 = store.get_block_metadata(&blockhash1).unwrap();
        let updated_metadata2 = store.get_block_metadata(&blockhash2).unwrap();

        // Verify updated statuses
        assert!(!updated_metadata1.is_valid);
        assert!(!updated_metadata2.is_on_main_chain);
    }

    #[test]
    fn test_set_and_get_block_height_in_metadata() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a test block
        let share = TestShareBlockBuilder::new().build();

        let blockhash = share.block_hash();

        let mut batch = rocksdb::WriteBatch::default();

        // Add share to store without setting height in metadata
        store
            .add_share(share.clone(), 0, share.header.get_work(), true, &mut batch)
            .unwrap();

        store.commit_batch(batch).unwrap();

        // Height should be set during add_share
        let metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(metadata.height, Some(0));

        let mut batch = rocksdb::WriteBatch::default();
        // Update the height to a different value
        store
            .set_block_height_in_metadata(&blockhash, Some(42), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify height is updated correctly
        let updated_metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(updated_metadata.height, Some(42));

        let mut batch = rocksdb::WriteBatch::default();
        // Remove height by setting to None
        store
            .set_block_height_in_metadata(&blockhash, None, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify height is removed
        let metadata_without_height = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(metadata_without_height.height, None);

        // Test with batch operation
        let mut batch = rocksdb::WriteBatch::default();
        store
            .set_block_height_in_metadata(&blockhash, Some(100), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Verify batch operation worked
        let batch_updated_metadata = store.get_block_metadata(&blockhash).unwrap();
        assert_eq!(batch_updated_metadata.height, Some(100));
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
            store.add_job(i * 1000000, format!("job{}", i)).unwrap();
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
}
