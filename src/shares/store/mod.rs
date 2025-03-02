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
use crate::shares::miner_message::{MinerShare, MinerWorkbase, UserWorkbase};
use crate::shares::{BlockHash, ShareBlock, ShareHeader, StorageShareBlock};
use bitcoin::Transaction;
use rocksdb::DB;
use std::collections::HashMap;
use std::error::Error;
use tracing::debug;

/// A store for share blocks.
/// RocksDB as is used as the underlying database.
#[allow(dead_code)]
pub struct Store {
    path: String,
    db: DB,
}

#[allow(dead_code)]
impl Store {
    /// Create a new share store
    pub fn new(path: String) -> Self {
        let db = DB::open_default(path.clone()).unwrap();
        Self { path, db }
    }

    /// Add a share to the store
    /// We use StorageShareBlock to serialize the share so that we do not store transactions serialized with the block.
    /// Transactions are stored separately. All writes are done in a single atomic batch.
    pub fn add_share(&mut self, share: ShareBlock) {
        debug!("Adding share to store: {:?}", share.header.blockhash);
        let blockhash = share.header.blockhash.clone();

        // Create a new write batch
        let mut batch = rocksdb::WriteBatch::default();

        // Add transactions and get their txids
        let txids = self.store_transactions_batch(&share.transactions, &mut batch);

        // Store txids list for this block
        self.store_txids_to_block_index(&blockhash, &txids, &mut batch);

        // Add the share block itself
        let storage_share_block: StorageShareBlock = share.into();
        batch.put::<&[u8], Vec<u8>>(
            bitcoin::BlockHash::as_ref(&blockhash),
            storage_share_block.cbor_serialize().unwrap(),
        );

        // Write the entire batch atomically
        self.db.write(batch).unwrap();
    }

    /// Add the list of transaction IDs to the batch
    fn store_txids_to_block_index(
        &self,
        blockhash: &BlockHash,
        txids: &[bitcoin::Txid],
        batch: &mut rocksdb::WriteBatch,
    ) {
        let mut blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(blockhash).to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        let mut serialized_txids = Vec::new();
        ciborium::ser::into_writer(&txids, &mut serialized_txids).unwrap();
        batch.put::<&[u8], Vec<u8>>(blockhash_bytes.as_ref(), serialized_txids);
    }

    /// Get all transaction IDs for a given block hash
    /// Returns a vector of transaction IDs that were included in the block
    fn get_txids_for_blockhash(&self, blockhash: &BlockHash) -> Vec<bitcoin::Txid> {
        let mut blockhash_bytes = <BlockHash as AsRef<[u8]>>::as_ref(blockhash).to_vec();
        blockhash_bytes.extend_from_slice(b"_txids");

        match self.db.get::<&[u8]>(blockhash_bytes.as_ref()) {
            Ok(Some(serialized_txids)) => {
                let txids: Vec<bitcoin::Txid> =
                    ciborium::de::from_reader(&serialized_txids[..]).unwrap_or_default();
                txids
            }
            _ => Vec::new(),
        }
    }

    /// Store transactions in a batch and return their txids
    /// This is a helper function used by add_share and add_transactions
    fn store_transactions_batch(
        &self,
        transactions: &[Transaction],
        batch: &mut rocksdb::WriteBatch,
    ) -> Vec<bitcoin::Txid> {
        transactions
            .iter()
            .map(|tx| {
                let txid = tx.compute_txid();
                let mut serialized = Vec::new();
                ciborium::ser::into_writer(&tx, &mut serialized).unwrap();
                batch.put::<&[u8], Vec<u8>>(bitcoin::Txid::as_ref(&txid), serialized);
                txid
            })
            .collect()
    }

    /// Add a vector of transactions to the store outside of a block context
    /// The transactions are neither marked validated nor spent, that is done later
    /// Use rocksdb batch to add transactions atomically
    pub fn add_transactions(&mut self, transactions: Vec<Transaction>) {
        let mut batch = rocksdb::WriteBatch::default();
        self.store_transactions_batch(&transactions, &mut batch);
        self.db.write(batch).unwrap();
    }

    /// Add a workbase to the store
    pub fn add_workbase(&mut self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error>> {
        let workbase_key = format!("workbase:{}", workbase.workinfoid);
        debug!("Adding workbase to store: {:?}", workbase_key);
        self.db
            .put(
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
        self.db
            .put(
                user_workbase_key.as_bytes(),
                Message::UserWorkbase(user_workbase)
                    .cbor_serialize()
                    .unwrap(),
            )
            .unwrap();
        Ok(())
    }

    /// Add a transaction to the store
    /// The txid is computed and Transaction is serialized using cbor
    /// If blockhash is provided, it is used as a key to store txid, this will let us query are transactions in a block
    /// Note: A txid can be present in multiple blocks, we do not check for this. For example, different peers can include the same txid in different blocks,
    /// we store all that information.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), Box<dyn Error>> {
        let txid = tx.compute_txid();
        debug!("Adding transaction to store: {:?}", txid);
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&tx, &mut serialized).unwrap();
        // store txid -> transaction
        self.db
            .put::<&[u8], Vec<u8>>(txid.as_ref(), serialized)
            .unwrap();
        Ok(())
    }

    /// Update a transaction's validation and spent status in the store
    /// The status is stored separately from the transaction using txid + "_status" as key
    pub fn update_transaction(
        &mut self,
        txid: &bitcoin::Txid,
        validated: bool,
        spent_by: Option<bitcoin::Txid>,
    ) -> Result<(), Box<dyn Error>> {
        // Create status key by concatenating txid bytes and status suffix
        let mut status_key_bytes = <bitcoin::Txid as AsRef<[u8]>>::as_ref(&txid).to_vec();
        status_key_bytes.extend_from_slice(b"_status");

        let status = (validated, spent_by);
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&status, &mut serialized).unwrap();
        self.db.put(&status_key_bytes, serialized).unwrap();
        Ok(())
    }

    /// Get the validation status of a transaction from the store
    pub fn get_transaction_status(
        &self,
        txid: &bitcoin::Txid,
    ) -> Option<(bool, Option<bitcoin::Txid>)> {
        // Create status key by concatenating txid bytes and status suffix
        let mut status_key_bytes = <bitcoin::Txid as AsRef<[u8]>>::as_ref(&txid).to_vec();
        status_key_bytes.extend_from_slice(b"_status");

        let status = match self.db.get::<&[u8]>(&status_key_bytes) {
            Ok(Some(status)) => status,
            Ok(None) | Err(_) => return None,
        };

        let (validated, spent_by): (bool, Option<bitcoin::Txid>) =
            match ciborium::de::from_reader(status.as_slice()) {
                Ok(status) => status,
                Err(e) => {
                    tracing::error!("Error deserializing transaction status: {:?}", e);
                    return None;
                }
            };

        Some((validated, spent_by))
    }

    /// Get a workbase from the store
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        let workbase_key = format!("workbase:{}", workinfoid);
        debug!("Getting workbase from store: {:?}", workbase_key);
        let workbase = self.db.get(workbase_key.as_bytes()).unwrap();
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
        let user_workbase = self.db.get(user_workbase_key.as_bytes()).unwrap();
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
        let share = match self.db.get::<&[u8]>(blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share = match StorageShareBlock::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let transactions = self.get_transactions(&share.header.blockhash);
        let share = share.into_share_block_with_transactions(transactions);
        Some(share)
    }

    /// Get multiple shares from the store
    pub fn get_shares(&self, blockhashes: Vec<BlockHash>) -> HashMap<BlockHash, ShareBlock> {
        debug!("Getting shares from store: {:?}", blockhashes);
        let keys = blockhashes
            .iter()
            .map(|h| <bitcoin::BlockHash as AsRef<[u8]>>::as_ref(h))
            .collect::<Vec<_>>();
        let shares = self.db.multi_get::<&[u8], Vec<&[u8]>>(keys);
        let shares = shares
            .into_iter()
            .map(|v| {
                if let Ok(Some(v)) = v {
                    if let Ok(storage_share) = StorageShareBlock::cbor_deserialize(&v) {
                        let txids = self.get_txids_for_blockhash(&storage_share.header.blockhash);
                        let transactions = txids
                            .iter()
                            .map(|txid| self.get_transaction(txid).unwrap())
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

    /// Get a share header and miner share from the store without loading transactions
    pub fn get_share_header(&self, blockhash: &BlockHash) -> Option<(ShareHeader, MinerShare)> {
        debug!("Getting share header from store: {:?}", blockhash);
        let share = match self.db.get::<&[u8]>(blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let storage_share = match StorageShareBlock::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        Some((storage_share.header, storage_share.miner_share))
    }

    /// Get transactions for a blockhash
    /// First look up the txids from the blockhash_txids index, then get the transactions from the txids
    pub fn get_transactions(&self, blockhash: &BlockHash) -> Vec<Transaction> {
        let txids = self.get_txids_for_blockhash(blockhash);
        txids
            .iter()
            .map(|txid| self.get_transaction(txid).unwrap())
            .collect()
    }

    /// Get a transaction from the store using a provided txid
    /// The transaction is deserialized using cbor
    pub fn get_transaction(&self, txid: &bitcoin::Txid) -> Option<Transaction> {
        let tx = match self.db.get::<&[u8]>(txid.as_ref()) {
            Ok(Some(tx)) => tx,
            Ok(None) | Err(_) => return None,
        };
        let tx: Transaction = match ciborium::de::from_reader(tx.as_slice()) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Error deserializing transaction: {:?}", e);
                return None;
            }
        };
        Some(tx)
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
    use crate::test_utils::test_share_block;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create initial share
        let share1 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            None,
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        // Create uncles for share2
        let uncle1_share2 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"),
            Some(share1.header.blockhash.to_string().as_str()),
            vec![],
            None,
            Some(7452731920372203525 + 1),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        let uncle2_share2 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"),
            Some(share1.header.blockhash.to_string().as_str()),
            vec![],
            None,
            Some(7452731920372203525 + 2),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        // Create share2 with uncles
        let share2 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"),
            Some(share1.header.blockhash.to_string().as_str()),
            vec![
                uncle1_share2.header.blockhash,
                uncle2_share2.header.blockhash,
            ],
            None,
            Some(7452731920372203525 + 3),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        // Create uncles for share3
        let uncle1_share3 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9"),
            Some(share2.header.blockhash.to_string().as_str()),
            vec![],
            None,
            Some(7452731920372203525 + 4),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        let uncle2_share3 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba"),
            Some(share2.header.blockhash.to_string().as_str()),
            vec![],
            None,
            Some(7452731920372203525 + 5),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        // Create share3 with uncles
        let share3 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb"),
            Some(share2.header.blockhash.to_string().as_str()),
            vec![
                uncle1_share3.header.blockhash,
                uncle2_share3.header.blockhash,
            ],
            None,
            Some(7452731920372203525 + 6),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

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
    }

    #[test]
    fn test_transaction_store() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create a simple test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Store the transaction
        let txid = tx.compute_txid();
        store.add_transaction(tx.clone()).unwrap();

        // Retrieve the transaction
        let retrieved_tx = store.get_transaction(&txid);
        assert!(retrieved_tx.is_some());
        assert_eq!(retrieved_tx.unwrap(), tx);

        // Try getting non-existent transaction
        let fake_txid = "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
            .parse()
            .unwrap();
        assert!(store.get_transaction(&fake_txid).is_none());
    }

    #[test]
    fn test_transaction_status() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create a test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Store the transaction
        let txid = tx.compute_txid();
        store.add_transaction(tx.clone()).unwrap();

        // Initially status should be None
        let initial_status = store.get_transaction_status(&txid);
        assert!(initial_status.is_none());

        // Update status to validated but not spent
        store.update_transaction(&txid, true, None).unwrap();
        let status = store.get_transaction_status(&txid).unwrap();
        assert_eq!(status, (true, None));

        // Create another transaction that spends this one
        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let spending_txid = spending_tx.compute_txid();

        // Update status to spent
        store
            .update_transaction(&txid, true, Some(spending_txid))
            .unwrap();
        let status = store.get_transaction_status(&txid).unwrap();
        assert_eq!(status, (true, Some(spending_txid)));

        // Update status back to unspent
        store.update_transaction(&txid, true, None).unwrap();
        let status = store.get_transaction_status(&txid).unwrap();
        assert_eq!(status, (true, None));

        // Update status to invalidated
        store.update_transaction(&txid, false, None).unwrap();
        let status = store.get_transaction_status(&txid).unwrap();
        assert_eq!(status, (false, None));
    }

    #[test]
    fn test_store_retrieve_txids_by_blockhash_index() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());

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
        let share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4"),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![tx1.clone(), tx2.clone()],
        );

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
    fn test_share_block_with_transactions_storage() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

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
        let share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4"),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![tx1.clone(), tx2.clone()],
        );

        // Store the share block
        store.add_share(share.clone());

        // Retrieve transactions for the block hash
        let retrieved_txs = store.get_transactions(&share.header.blockhash);

        // Verify transactions were stored and can be retrieved
        assert_eq!(retrieved_txs.len(), 3);
        assert!(retrieved_txs[0].is_coinbase());
        assert_eq!(retrieved_txs[1], tx1);
        assert_eq!(retrieved_txs[2], tx2);

        // Verify individual transactions can be retrieved by txid
        let tx1_id = tx1.compute_txid();
        let tx2_id = tx2.compute_txid();

        assert_eq!(store.get_transaction(&tx1_id).unwrap(), tx1);
        assert_eq!(store.get_transaction(&tx2_id).unwrap(), tx2);
    }

    #[test]
    fn test_add_transactions_with_batch() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());

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

        // Create a write batch and store transactions
        let mut batch = rocksdb::WriteBatch::default();
        let txids = store.store_transactions_batch(&transactions, &mut batch);

        // Write the batch
        store.db.write(batch).unwrap();

        // Verify transactions were stored correctly
        assert_eq!(txids.len(), 2);
        assert_eq!(store.get_transaction(&txids[0]).unwrap(), tx1);
        assert_eq!(store.get_transaction(&txids[1]).unwrap(), tx2);
    }

    #[test]
    fn test_add_transactions() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

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
        store.add_transactions(transactions);

        // Verify transactions were stored correctly by retrieving them by txid
        let tx1_id = tx1.compute_txid();
        let tx2_id = tx2.compute_txid();

        assert_eq!(store.get_transaction(&tx1_id).unwrap(), tx1);
        assert_eq!(store.get_transaction(&tx2_id).unwrap(), tx2);
    }

    #[test]
    fn test_get_share_header() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create test share block
        let share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
            &mut vec![],
        );

        // Add share to store
        store.add_share(share.clone());

        // Get share header from store
        let (header, miner_share) = store.get_share_header(&share.header.blockhash).unwrap();

        // Verify header matches original
        assert_eq!(header.blockhash, share.header.blockhash);
        assert_eq!(
            header.prev_share_blockhash,
            share.header.prev_share_blockhash
        );
        assert_eq!(header.uncles, share.header.uncles);
        assert_eq!(header.miner_pubkey, share.header.miner_pubkey);
        assert_eq!(header.merkle_root, share.header.merkle_root);

        // Verify miner share matches original
        assert_eq!(miner_share.workinfoid, share.miner_share.workinfoid);
        assert_eq!(miner_share.nonce, share.miner_share.nonce);
        assert_eq!(miner_share.diff, share.miner_share.diff);
        assert_eq!(miner_share.ntime, share.miner_share.ntime);
    }

    #[test]
    fn test_get_share_header_nonexistent() {
        // Create a new store with a temporary path
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Try to get share header for non-existent blockhash
        let non_existent_blockhash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap();
        let result = store.get_share_header(&non_existent_blockhash);
        assert!(result.is_none());
    }
}
