// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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
use crate::shares::{BlockHash, ShareBlock, ShareHeader, StorageShareBlock};
use bitcoin::Transaction;
use rocksdb::{ColumnFamilyDescriptor, Options as RocksDbOptions, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxMetadata {
    txid: bitcoin::Txid,
    version: bitcoin::transaction::Version,
    lock_time: bitcoin::absolute::LockTime,
    input_count: u32,
    output_count: u32,
    spent_by: Option<bitcoin::Txid>,
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
    pub fn new(path: String) -> Result<Self, Box<dyn Error>> {
        // for now we use default options for all column families, we can tweak this later based on performance testing
        let block_cf = ColumnFamilyDescriptor::new("block", RocksDbOptions::default());
        let block_txids_cf = ColumnFamilyDescriptor::new("block_txids", RocksDbOptions::default());
        let inputs_cf = ColumnFamilyDescriptor::new("inputs", RocksDbOptions::default());
        let outputs_cf = ColumnFamilyDescriptor::new("outputs", RocksDbOptions::default());
        let tx_cf = ColumnFamilyDescriptor::new("tx", RocksDbOptions::default());
        let workbase_cf = ColumnFamilyDescriptor::new("workbase", RocksDbOptions::default());
        let block_index_cf = ColumnFamilyDescriptor::new("block_index", RocksDbOptions::default());
        let user_workbase_cf =
            ColumnFamilyDescriptor::new("user_workbase", RocksDbOptions::default());

        // for the db too, we use default options for now
        let mut db_options = RocksDbOptions::default();
        db_options.create_missing_column_families(true);
        db_options.create_if_missing(true);
        let db = DB::open_cf_descriptors(
            &db_options,
            path.clone(),
            vec![
                block_cf,
                block_txids_cf,
                inputs_cf,
                outputs_cf,
                tx_cf,
                workbase_cf,
                user_workbase_cf,
                block_index_cf,
            ],
        )
        .unwrap();
        Ok(Self { path, db })
    }

    /// Add a share to the store
    /// We use StorageShareBlock to serialize the share so that we do not store transactions serialized with the block.
    /// Transactions are stored separately. All writes are done in a single atomic batch.
    pub fn add_share(&mut self, share: ShareBlock) {
        debug!(
            "Adding share to store with {} txs: {:?}",
            share.transactions.len(),
            share.header.blockhash
        );
        let blockhash = share.header.blockhash.clone();

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

        // Add the share block itself
        let storage_share_block: StorageShareBlock = share.into();
        let block_cf = self.db.cf_handle("block").unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(
            block_cf,
            bitcoin::BlockHash::as_ref(&blockhash),
            storage_share_block.cbor_serialize().unwrap(),
        );

        // Write the entire batch atomically
        self.db.write(batch).unwrap();
    }

    /// Load children BlockHashes for a blockhash from the block index
    /// These are tracked in a separate index in rocksdb as relations from
    /// blockhash -> next blockhashes
    fn get_children_blockhashes(&self, blockhash: &BlockHash) -> Vec<BlockHash> {
        let block_index_cf = self.db.cf_handle("block_index").unwrap();
        let mut blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(blockhash).to_vec();
        blockhash_bytes.extend_from_slice(b"_bi");

        match self
            .db
            .get_cf::<&[u8]>(block_index_cf, blockhash_bytes.as_ref())
        {
            Ok(Some(existing)) => {
                let existing_blockhashes: Vec<BlockHash> =
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
        prev_blockhash: &Option<BlockHash>,
        next_blockhash: &BlockHash,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error>> {
        if prev_blockhash.is_none() {
            return Ok(());
        }

        let prev_blockhash = prev_blockhash.unwrap();

        let block_index_cf = self.db.cf_handle("block_index").unwrap();
        let mut prev_blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(&prev_blockhash).to_vec();
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
        let inputs_cf = self.db.cf_handle("inputs").unwrap();
        let outputs_cf = self.db.cf_handle("outputs").unwrap();
        let mut txs_metadata = Vec::new();
        for tx in transactions {
            let txid = tx.compute_txid();
            let metadata = self.store_tx_metadata(txid, tx, batch);
            txs_metadata.push(metadata);

            // Store each input for the transaction
            for (i, input) in tx.input.iter().enumerate() {
                let input_key = format!("{}:{}", txid, i);
                let mut serialized = Vec::new();
                ciborium::ser::into_writer(&input, &mut serialized).unwrap();
                batch.put_cf::<&[u8], Vec<u8>>(inputs_cf, input_key.as_ref(), serialized);
            }

            // Store each output for the transaction
            for (i, output) in tx.output.iter().enumerate() {
                let output_key = format!("{}:{}", txid, i);
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

        let tx_cf = self.db.cf_handle("tx").unwrap();
        let mut tx_metadata_serialized = Vec::new();
        ciborium::ser::into_writer(&tx_metadata, &mut tx_metadata_serialized).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(tx_cf, txid.as_ref(), tx_metadata_serialized);
        tx_metadata
    }

    /// Add the list of transaction IDs to the batch
    /// Transactions themselves are stored in store_txs, here we just store the association between block and txids
    fn store_txids_to_block_index(
        &self,
        blockhash: &BlockHash,
        txids: &Vec<bitcoin::Txid>,
        batch: &mut rocksdb::WriteBatch,
    ) {
        let mut blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(blockhash).to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        let mut serialized_txids = Vec::new();
        ciborium::ser::into_writer(&txids, &mut serialized_txids).unwrap();
        let block_txids_cf = self.db.cf_handle("block_txids").unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(block_txids_cf, blockhash_bytes.as_ref(), serialized_txids);
    }

    /// Get all transaction IDs for a given block hash
    /// Returns a vector of transaction IDs that were included in the block
    fn get_txids_for_blockhash(&self, blockhash: &BlockHash) -> Vec<bitcoin::Txid> {
        let mut blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(blockhash).to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        let block_txids_cf = self.db.cf_handle("block_txids").unwrap();
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
        let workbase_cf = self.db.cf_handle("workbase").unwrap();
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
        let user_workbase_cf = self.db.cf_handle("user_workbase").unwrap();
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
        let tx_cf = self.db.cf_handle("tx").unwrap();
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
        let tx_cf = self.db.cf_handle("tx").unwrap();
        let tx_metadata = self.db.get_cf::<&[u8]>(tx_cf, txid.as_ref()).unwrap();
        if tx_metadata.is_none() {
            return None;
        }
        let tx_metadata = tx_metadata.unwrap();
        let tx_metadata: TxMetadata = ciborium::de::from_reader(tx_metadata.as_slice()).unwrap();
        Some(tx_metadata)
    }

    /// Get a workbase from the store
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        let workbase_key = format!("workbase:{}", workinfoid);
        debug!("Getting workbase from store: {:?}", workbase_key);
        let workbase_cf = self.db.cf_handle("workbase").unwrap();
        let workbase = self
            .db
            .get_cf::<&[u8]>(workbase_cf, workbase_key.as_bytes())
            .unwrap();
        if workbase.is_none() {
            return None;
        }
        let workbase = Message::cbor_deserialize(&workbase.unwrap()).unwrap();
        let workbase = match workbase {
            Message::Workbase(workbase) => workbase,
            _ => {
                tracing::error!("Invalid workbase key: {:?}", workbase_key);
                return None;
            }
        };
        Some(workbase)
    }

    /// Get a user workbase from the store
    pub fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase> {
        let user_workbase_key = format!("user_workbase:{}", workinfoid);
        debug!("Getting user workbase from store: {:?}", user_workbase_key);
        let user_workbase_cf = self.db.cf_handle("user_workbase").unwrap();
        let user_workbase = self
            .db
            .get_cf::<&[u8]>(user_workbase_cf, user_workbase_key.as_bytes())
            .unwrap();
        if user_workbase.is_none() {
            return None;
        }
        let user_workbase = Message::cbor_deserialize(&user_workbase.unwrap()).unwrap();
        let user_workbase = match user_workbase {
            Message::UserWorkbase(user_workbase) => user_workbase,
            _ => {
                tracing::error!("Invalid user workbase key: {:?}", user_workbase_key);
                return None;
            }
        };
        Some(user_workbase)
    }

    /// Get a share from the store
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle("block").unwrap();
        let share = match self.db.get_cf::<&[u8]>(share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share = match StorageShareBlock::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let transactions = self.get_txs_for_block(&share.header.blockhash);
        let share = share.into_share_block_with_transactions(transactions);
        Some(share)
    }

    /// Get a share headers matching the vector of blockhashes
    pub fn get_share_headers(
        &self,
        blockhashes: Vec<BlockHash>,
    ) -> HashMap<BlockHash, ShareHeader> {
        debug!("Getting share headers from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle("block").unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (share_cf, <bitcoin::BlockHash as AsRef<[u8]>>::as_ref(h)))
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
        share_headers
            .into_iter()
            .filter_map(|share| share.map(|s| (s.blockhash, s)))
            .collect::<HashMap<BlockHash, ShareHeader>>()
    }

    /// Get headers to satisy the locator query.
    /// Returns a list of headers from the earliest block from the block hashes
    /// We assume the list of blocks in the locator is ordered by height, so we stop when we find the first block in the locator
    /// Find headers up to the stop blockhash, or the limit provided
    pub fn get_headers_for_locator(
        &self,
        locator: &Vec<BlockHash>,
        stop_blockhash: &BlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        // Find the first share that exists from the block_hashes
        let mut start_share_block = None;
        for blockhash in locator {
            if let Some(share) = self.get_share(blockhash) {
                start_share_block = Some(share);
                break;
            }
        }

        // If no share found, return empty vector
        if start_share_block.is_none() {
            return Vec::new();
        }

        self.get_descendants(
            start_share_block.unwrap().header.blockhash,
            stop_blockhash,
            limit,
        )
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
                    descendants.push(child.clone());
                    next_children.push(child.clone());
                }
            }
            current_blockhash = match next_children.pop() {
                Some(hash) => hash,
                None => break,
            };
        }
        self.get_share_headers(descendants)
            .into_iter()
            .map(|(_, header)| header)
            .collect()
    }

    /// Get multiple shares from the store
    pub fn get_shares(&self, blockhashes: Vec<BlockHash>) -> HashMap<BlockHash, ShareBlock> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let share_cf = self.db.cf_handle("block").unwrap();
        let keys = blockhashes
            .iter()
            .map(|h| (share_cf, <bitcoin::BlockHash as AsRef<[u8]>>::as_ref(h)))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get_cf(keys);
        let shares = shares
            .into_iter()
            .map(|v| {
                if let Ok(Some(v)) = v {
                    if let Ok(storage_share) = StorageShareBlock::cbor_deserialize(&v) {
                        let txids = self.get_txids_for_blockhash(&storage_share.header.blockhash);
                        let transactions = txids
                            .iter()
                            .map(|txid| self.get_tx(txid).unwrap())
                            .collect::<Vec<_>>();
                        Some(storage_share.into_share_block_with_transactions(transactions))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        shares
            .into_iter()
            .filter_map(|share| share.map(|s| (s.header.blockhash, s)))
            .collect::<HashMap<BlockHash, ShareBlock>>()
    }

    /// Get a storage share, which is share header and miner share, from the store without loading transactions
    /// This is used when we want to get a share header and miner share without loading transactions
    pub fn get_storage_share(&self, blockhash: &BlockHash) -> Option<StorageShareBlock> {
        debug!("Getting share header from store: {:?}", blockhash);
        let share_cf = self.db.cf_handle("block").unwrap();
        let share = match self.db.get_cf::<&[u8]>(share_cf, blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let storage_share = match StorageShareBlock::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        Some(storage_share)
    }

    /// Get transactions for a blockhash
    /// First look up the txids from the blockhash_txids index, then get the transactions from the txids
    pub fn get_txs_for_block(&self, blockhash: &BlockHash) -> Vec<Transaction> {
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
            .ok_or_else(|| format!("Transaction metadata not found for txid: {}", txid))?;

        debug!("Transaction metadata: {:?}", tx_metadata);

        let inputs_cf = self.db.cf_handle("inputs").unwrap();
        let outputs_cf = self.db.cf_handle("outputs").unwrap();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();

        for i in 0..tx_metadata.input_count {
            let input_key = format!("{}:{}", txid, i);
            let input = self
                .db
                .get_cf::<&[u8]>(inputs_cf, input_key.as_ref())
                .unwrap()
                .unwrap();
            let input: bitcoin::TxIn = match ciborium::de::from_reader(input.as_slice()) {
                Ok(input) => input,
                Err(e) => {
                    tracing::error!("Error deserializing input: {:?}", e);
                    return Err(e.into());
                }
            };
            inputs.push(input);
        }
        for i in 0..tx_metadata.output_count {
            let output_key = format!("{}:{}", txid, i);
            let output = self
                .db
                .get_cf::<&[u8]>(outputs_cf, output_key.as_ref())
                .unwrap()
                .unwrap();
            let output: bitcoin::TxOut = match ciborium::de::from_reader(output.as_slice()) {
                Ok(output) => output,
                Err(e) => {
                    tracing::error!("Error deserializing output: {:?}", e);
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
        let parent_blockhash = share.header.prev_share_blockhash.clone();
        self.get_share(&parent_blockhash.unwrap())
    }

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
    pub fn get_uncles(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return vec![];
        }
        let share = share.unwrap();
        let uncle_blocks = self.get_shares(share.header.uncles);
        uncle_blocks.into_iter().map(|(_, share)| share).collect()
    }

    /// Get entire chain from earliest known block to given blockhash, excluding the given blockhash
    /// When we prune the chain, the oldest share in the chain will be marked as root, by removing it's prev_share_blockhash
    /// We can't use get_shares as we need to get a share, then find it's prev_share_blockhash, then get the share again, etc.
    pub fn get_chain_upto(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
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
        blockhash1: &BlockHash,
        blockhash2: &BlockHash,
    ) -> Option<BlockHash> {
        debug!(
            "Getting common ancestor of: {:?} and {:?}",
            blockhash1, blockhash2
        );
        let chain1 = self.get_chain_upto(blockhash1);
        let chain2 = self.get_chain_upto(blockhash2);
        if let Some(blockhash) = chain1.iter().rev().find(|share| chain2.contains(share)) {
            Some(blockhash.header.blockhash.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestBlockBuilder;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share2.header.blockhash,
                uncle2_share2.header.blockhash,
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create uncles for share3
        let uncle1_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3 with uncles
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share3.header.blockhash,
                uncle2_share3.header.blockhash,
            ])
            .workinfoid(7452731920372203525 + 6)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone());
        store.add_share(uncle1_share2.clone());
        store.add_share(uncle2_share2.clone());
        store.add_share(share2.clone());
        store.add_share(uncle1_share3.clone());
        store.add_share(uncle2_share3.clone());
        store.add_share(share3.clone());

        // Get chain up to share3
        let chain = store.get_chain_upto(&share3.header.blockhash);

        // Get common ancestor of share3 and share2
        let common_ancestor =
            store.get_common_ancestor(&share3.header.blockhash, &share2.header.blockhash);
        assert_eq!(common_ancestor, Some(share1.header.blockhash));

        // Get chain up to uncle1_share3 (share31)
        let chain_to_uncle = store.get_chain_upto(&uncle1_share3.header.blockhash);
        assert_eq!(chain_to_uncle.len(), 3);
        assert_eq!(
            chain_to_uncle[0].header.blockhash,
            uncle1_share3.header.blockhash
        );
        assert_eq!(chain_to_uncle[1].header.blockhash, share2.header.blockhash);
        assert_eq!(chain_to_uncle[2].header.blockhash, share1.header.blockhash);

        // Chain should contain share3, share2, share1 in reverse order
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].header.blockhash, share3.header.blockhash);
        assert_eq!(chain[1].header.blockhash, share2.header.blockhash);
        assert_eq!(chain[2].header.blockhash, share1.header.blockhash);

        // Verify uncles of share2
        let uncles_share2 = store.get_uncles(&share2.header.blockhash);
        assert_eq!(uncles_share2.len(), 2);
        assert!(uncles_share2
            .iter()
            .any(|u| u.header.blockhash == uncle1_share2.header.blockhash));
        assert!(uncles_share2
            .iter()
            .any(|u| u.header.blockhash == uncle2_share2.header.blockhash));

        // Verify uncles of share3
        let uncles_share3 = store.get_uncles(&share3.header.blockhash);
        assert_eq!(uncles_share3.len(), 2);
        assert!(uncles_share3
            .iter()
            .any(|u| u.header.blockhash == uncle1_share3.header.blockhash));
        assert!(uncles_share3
            .iter()
            .any(|u| u.header.blockhash == uncle2_share3.header.blockhash));

        // Verify children of share1
        let children_share1 = store.get_children_blockhashes(&share1.header.blockhash);
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.header.blockhash));
        assert!(children_share1.contains(&uncle1_share2.header.blockhash));
        assert!(children_share1.contains(&uncle2_share2.header.blockhash));

        // Verify children of share2
        let children_share2 = store.get_children_blockhashes(&share2.header.blockhash);
        assert_eq!(children_share2.len(), 3);
        assert!(children_share2.contains(&share3.header.blockhash));
        assert!(children_share2.contains(&uncle1_share3.header.blockhash));
        assert!(children_share2.contains(&uncle2_share3.header.blockhash));

        // Verify children of share3
        let children_share3 = store.get_children_blockhashes(&share3.header.blockhash);
        assert!(children_share3.is_empty());

        // Verify children of uncle1_share2
        let children_uncle1_share2 =
            store.get_children_blockhashes(&uncle1_share2.header.blockhash);
        assert!(children_uncle1_share2.is_empty());

        // Verify children of uncle2_share2
        let children_uncle2_share2 =
            store.get_children_blockhashes(&uncle2_share2.header.blockhash);
        assert!(children_uncle2_share2.is_empty());

        // Verify children of uncle1_share3
        let children_uncle1_share3 =
            store.get_children_blockhashes(&uncle1_share3.header.blockhash);
        assert!(children_uncle1_share3.is_empty());

        // Verify children of uncle2_share3
        let children_uncle2_share3 =
            store.get_children_blockhashes(&uncle2_share3.header.blockhash);
        assert!(children_uncle2_share3.is_empty());
    }

    #[test]
    fn test_transaction_store_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

        // Try getting non-existent transaction
        let fake_txid = "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
            .parse()
            .unwrap();
        assert!(store.get_tx(&fake_txid).is_err());
    }

    #[test]
    fn test_transaction_spent_by_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .add_transaction(tx1.clone())
            .add_transaction(tx2.clone())
            .build();

        let blockhash = share.header.blockhash;

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
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap();
        let empty_txids = store.get_txids_for_blockhash(&non_existent_blockhash);
        assert!(empty_txids.is_empty());
    }

    #[test]
    fn test_store_share_block_with_transactions_should_retreive_txs() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
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
        store.add_share(share.clone());
        assert_eq!(share.transactions.len(), 3);

        // Retrieve transactions for the block hash
        let retrieved_txs = store.get_txs_for_block(&share.header.blockhash);

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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
        store.add_share(share.clone());

        // Get share header from store
        let read_share = store.get_share(&share.header.blockhash).unwrap();

        // Verify header matches original
        assert_eq!(read_share.header.blockhash, share.header.blockhash);
        assert_eq!(
            read_share.header.prev_share_blockhash,
            share.header.prev_share_blockhash
        );
        assert_eq!(read_share.header.uncles, share.header.uncles);
        assert_eq!(read_share.header.miner_pubkey, share.header.miner_pubkey);
        assert_eq!(read_share.header.merkle_root, share.header.merkle_root);

        // Verify miner share matches original
        assert_eq!(
            read_share.miner_share.workinfoid,
            share.miner_share.workinfoid
        );
        assert_eq!(read_share.miner_share.nonce, share.miner_share.nonce);
        assert_eq!(read_share.miner_share.diff, share.miner_share.diff);
        assert_eq!(read_share.miner_share.ntime, share.miner_share.ntime);
    }

    #[test]
    fn test_get_share_header_nonexistent() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

        // Try to get share header for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap();
        let result = store.get_share(&non_existent_blockhash);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_children() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share2.header.blockhash,
                uncle2_share2.header.blockhash,
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone());
        store.add_share(uncle1_share2.clone());
        store.add_share(uncle2_share2.clone());
        store.add_share(share2.clone());
        store.add_share(share3.clone());

        // Verify children of share1
        let children_share1 = store.get_children_blockhashes(&share1.header.blockhash);
        assert_eq!(children_share1.len(), 3);
        assert!(children_share1.contains(&share2.header.blockhash));
        assert!(children_share1.contains(&uncle1_share2.header.blockhash));
        assert!(children_share1.contains(&uncle2_share2.header.blockhash));

        // Verify children of share2
        let children_share2 = store.get_children_blockhashes(&share2.header.blockhash);
        assert_eq!(children_share2.len(), 1);
        assert!(children_share2.contains(&share3.header.blockhash));

        // Verify children of share3
        let children_share3 = store.get_children_blockhashes(&share3.header.blockhash);
        assert!(children_share3.is_empty());

        // Verify children of uncle1_share2
        let children_uncle1_share2 =
            store.get_children_blockhashes(&uncle1_share2.header.blockhash);
        assert!(children_uncle1_share2.is_empty());

        // Verify children of uncle2_share2
        let children_uncle2_share2 =
            store.get_children_blockhashes(&uncle2_share2.header.blockhash);
        assert!(children_uncle2_share2.is_empty());
    }

    #[test]
    fn test_get_descendants() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();

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
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share2 with uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share2.header.blockhash,
                uncle2_share2.header.blockhash,
            ])
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Create share3
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add all shares to store
        store.add_share(share1.clone());
        store.add_share(uncle1_share2.clone());
        store.add_share(uncle2_share2.clone());
        store.add_share(share2.clone());
        store.add_share(share3.clone());

        // Verify descendants of share1
        let descendants_share1 =
            store.get_descendants(share1.header.blockhash, &share3.header.blockhash, 10);
        assert_eq!(descendants_share1.len(), 4);
        assert!(descendants_share1.contains(&share2.header));
        assert!(descendants_share1.contains(&share3.header));
        assert!(descendants_share1.contains(&uncle1_share2.header));
        assert!(descendants_share1.contains(&uncle2_share2.header));

        // Verify descendants of share2
        let descendants_share2 =
            store.get_descendants(share2.header.blockhash, &share3.header.blockhash, 10);
        assert_eq!(descendants_share2.len(), 1);
        assert_eq!(descendants_share2[0].blockhash, share3.header.blockhash);

        // Verify no descendants for share3
        let descendants_share3 =
            store.get_descendants(share3.header.blockhash, &share3.header.blockhash, 10);
        assert!(descendants_share3.is_empty());

        // Verify descendants with limit
        let descendants_with_limit =
            store.get_descendants(share1.header.blockhash, &share3.header.blockhash, 1);
        assert_eq!(descendants_with_limit.len(), 1);
        assert_eq!(
            descendants_with_limit[0].blockhash,
            uncle1_share2.header.blockhash
        );

        // Verify descendants with stop blockhash
        let descendants_with_limit =
            store.get_descendants(share1.header.blockhash, &share2.header.blockhash, 10);
        assert_eq!(descendants_with_limit.len(), 3);
        assert!(descendants_with_limit.contains(&share2.header));
        assert!(descendants_with_limit.contains(&uncle1_share2.header));
        assert!(descendants_with_limit.contains(&uncle2_share2.header));
    }
}
