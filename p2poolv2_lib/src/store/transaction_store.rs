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

use super::{ColumnFamily, Store, writer::StoreError};
use crate::shares::share_block::{ShareTransaction, Txids};
use crate::store::block_tx_metadata::TxMetadata;
use bitcoin::consensus::{self, Encodable, encode};
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use rocksdb::WriteBatch;
use tracing::debug;

/// Serialized outpoint size: 32B for Txid hash, 4B for index
const OUTPOINT_SIZE: usize = 36;

#[allow(dead_code)]
impl Store {
    /// Store share chain transactions in the store
    ///
    /// Store inputs and outputs for each transaction in separate column families
    ///
    /// Store txid -> transaction metadata in the tx column family
    ///
    /// The block -> txids store is done in
    /// add_txids_to_block_index. This function lets us store
    /// transactions outside of a block context
    ///
    /// Creates entries in spend index to track inputs spending
    /// outputs. These transactions are saved only for valid and
    /// candidate blocks, so the spends are valid. Their confirmation
    /// status depends on the block confirmation status they are
    /// included in.
    ///
    /// On chain reorgs this should be called again, so that any
    /// outputs spent by different txs in the new cofirmed chain are
    /// overwritten.
    pub(crate) fn add_sharechain_txs(
        &self,
        transactions: &[ShareTransaction],
        on_main_chain: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Vec<TxMetadata>, StoreError> {
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

                if on_main_chain {
                    // Add spends for transaction, confirmed or not.
                    self.add_spend(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                        &txid,
                        i as u32,
                        batch,
                    )?;
                }
            }

            // Store each output for the transaction
            for (i, output) in tx.output.iter().enumerate() {
                let output_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                output.consensus_encode(&mut serialized)?;
                batch.put_cf::<&[u8], Vec<u8>>(&outputs_cf, output_key.as_ref(), serialized);
            }
        }
        Ok(txs_metadata)
    }

    /// Marks the transaction as successfully validated, this prevents us validating it again.
    /// We only validate what is dependent on the chain state. Once valid, the txid is never made invalid.
    pub(crate) fn mark_transaction_valid(
        &self,
        txid: &Txid,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<TxMetadata, StoreError> {
        // mark tx metadata as validated
        let mut tx_metadata = self.get_tx_metadata(txid)?;
        tx_metadata.validated = true;

        let mut serialized = Vec::new();
        tx_metadata.consensus_encode(&mut serialized)?;
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(&tx_cf, txid.as_ref(), serialized);

        Ok(tx_metadata)
    }

    /// Add spend index entry from output -> input. This helps us
    /// track which outputs have been spent, and quickly check if an
    /// output is spent - by checking for presence in this index.
    ///
    /// Using this index instead of an UTXO set we can concurrently
    /// update this index.
    ///
    /// To check if a spend is a part of a confirmed block, we need to
    /// look at the spending txid and check if it is included in a
    /// confirmed block.
    ///
    /// We need to add a transaction id -> blockhash index
    pub(crate) fn add_spend(
        &self,
        input_txid: &Txid,
        input_vout: u32,
        spending_txid: &Txid,
        spending_index: u32,
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        let key = format!("{input_txid}:{input_vout}");
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        let mut serialized = Vec::with_capacity(OUTPOINT_SIZE);
        spending_txid.consensus_encode(&mut serialized)?;
        spending_index.consensus_encode(&mut serialized)?;
        batch.put_cf::<&[u8], Vec<u8>>(&spends_index_cf, key.as_ref(), serialized);
        Ok(())
    }

    /// Check if txid:vout outpoint is spent
    ///
    /// Checks if the outpoint is in the index and return the spending
    /// input txid:index as outpoint if present
    ///
    /// Caller should check if the spending outpoint is in a confirmed
    /// block or not, if they need to.
    pub(crate) fn is_spent(&self, txid: &Txid, vout: u32) -> Result<Option<OutPoint>, StoreError> {
        let key = format!("{txid}:{vout}");
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();

        match self.db.get_cf::<&[u8]>(&spends_index_cf, key.as_ref())? {
            Some(outpoint) => {
                let (txid, consumed) = encode::deserialize_partial(&outpoint)?;
                let (vout, _consumed) = encode::deserialize_partial(&outpoint[consumed..])?;
                Ok(Some(OutPoint { txid, vout }))
            }
            None => Ok(None),
        }
    }

    /// Store transaction metadata
    pub(crate) fn add_tx_metadata(
        &self,
        txid: bitcoin::Txid,
        tx: &Transaction,
        validated: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<TxMetadata, StoreError> {
        debug!("Adding tx metadata for txid {txid}");
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

    /// Add the given blockhash to the txids→blocks index for all txids.
    ///
    /// This index maps each txid to one or more blockhashes, allowing
    /// callers to look up which blocks contain a given transaction.
    /// Whether those blocks (and thus the transactions) are confirmed
    /// depends on the chain state and is determined by callers outside
    /// this function.
    ///
    /// Uses merge operator to append blockhashes, since a txid can be
    /// included in multiple blocks (e.g., competing miners extending
    /// different chain tips).
    pub(crate) fn add_txids_to_blocks_index(
        &self,
        blockhash: &BlockHash,
        txids: &Txids,
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();
        let serialized_blockhash = consensus::serialize(blockhash);

        for txid in &txids.0 {
            batch.merge_cf(
                &txids_blocks_cf,
                AsRef::<[u8]>::as_ref(txid),
                &serialized_blockhash,
            );
        }
        Ok(())
    }

    /// Get all blockhashes for a given txid from the txids_blocks index
    ///
    /// Returns a vector of blockhashes that contain this txid.
    /// A txid can be in multiple blocks when competing miners include
    /// the same transaction in different blocks.
    /// This is the reverse lookup of add_txids_to_blocks_index.
    pub(crate) fn get_blockhashes_for_txid(
        &self,
        txid: &Txid,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();

        match self.db.get_cf::<&[u8]>(&txids_blocks_cf, txid.as_ref())? {
            Some(blockhash_bytes) => {
                let blockhashes: Vec<BlockHash> =
                    encode::deserialize(&blockhash_bytes).map_err(|_| {
                        StoreError::Serialization(
                            "Failed to deserialize blockhashes from txids_blocks index".to_string(),
                        )
                    })?;
                Ok(blockhashes)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Add the list of transaction IDs to the batch
    /// Transactions themselves are stored in add_txs, here we just store the association between block and txids
    pub(crate) fn add_block_to_txids_index(
        &self,
        blockhash: &BlockHash,
        txids: &Txids,
        batch: &mut rocksdb::WriteBatch,
        bytes_suffix: &[u8],
        column_family: ColumnFamily,
    ) -> Result<(), StoreError> {
        let mut blockhash_bytes = consensus::serialize(blockhash);
        blockhash_bytes.extend_from_slice(bytes_suffix);

        let mut serialized_txids = Vec::new();
        txids.consensus_encode(&mut serialized_txids)?;
        let block_txids_cf = self.db.cf_handle(&column_family).unwrap();
        batch.put_cf::<&[u8], Vec<u8>>(&block_txids_cf, blockhash_bytes.as_ref(), serialized_txids);
        Ok(())
    }

    /// Get all transaction IDs for a given block hash
    /// Returns a vector of transaction IDs that were included in the block
    pub(crate) fn get_txids_for_blockhash(
        &self,
        blockhash: &BlockHash,
        column_family: ColumnFamily,
    ) -> Txids {
        let mut blockhash_bytes = consensus::serialize(blockhash);
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

    /// Get the validation status of a transaction from the store
    pub(crate) fn get_tx_metadata(&self, txid: &bitcoin::Txid) -> Result<TxMetadata, StoreError> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        match self.db.get_cf::<&[u8]>(&tx_cf, txid.as_ref())? {
            Some(tx_metadata) => encode::deserialize(&tx_metadata).map_err(|_| {
                StoreError::Serialization("Failed to deserialize tx metadata".to_string())
            }),
            None => Err(StoreError::NotFound(format!(
                "Transaction metadata not found for txid: {txid}"
            ))),
        }
    }

    /// Get transactions for a blockhash
    /// First look up the txids from the blockhash_txids index, then get the transactions from the txids
    pub fn get_txs_for_blockhash(
        &self,
        blockhash: &BlockHash,
        column_family: ColumnFamily,
    ) -> Vec<Transaction> {
        let txids = self.get_txids_for_blockhash(blockhash, column_family);
        txids.0.iter().flat_map(|txid| self.get_tx(txid)).collect()
    }

    /// Get a transaction from the store using a provided txid
    /// - Load tx metadata
    /// - Load inputs
    /// - Load outputs
    /// - Deserialize inputs and outputs
    /// - Return transaction
    pub fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Transaction, StoreError> {
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

    /// Get transactions by blockhash index for Bitcoin transactions
    pub(crate) fn get_bitcoin_txs_by_blockhash_index(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<Transaction>, StoreError> {
        let txids = self.get_txids_for_blockhash(blockhash, ColumnFamily::BitcoinTxids);
        let mut txs = Vec::new();
        for txid in txids.0 {
            txs.push(self.get_tx(&txid)?);
        }
        Ok(txs)
    }

    /// Get transactions by blockhash index for sharechain transactions
    pub(crate) fn get_sharechain_txs_by_blockhash_index(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<ShareTransaction>, StoreError> {
        let txids = self.get_txids_for_blockhash(blockhash, ColumnFamily::BlockTxids);
        let mut txs = Vec::with_capacity(txids.0.len());
        for txid in txids.0 {
            txs.push(ShareTransaction(self.get_tx(&txid)?));
        }
        Ok(txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test]
    fn test_transaction_store_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let block = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();

        let metadata = store
            .add_sharechain_txs(&block.transactions, false, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(metadata.len(), block.transactions.len());
        for tx_meta in &metadata {
            let tx = store.get_tx(&tx_meta.txid).unwrap();
            assert_eq!(tx.compute_txid(), tx_meta.txid);
        }
    }

    #[test]
    fn test_transaction_store_for_nonexistent_transaction_should_fail() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let nonexistent_txid = Txid::all_zeros();
        let result = store.get_tx(&nonexistent_txid);
        assert!(result.is_err());
    }

    #[test]
    fn test_store_retrieve_txids_by_blockhash_index() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify block -> txids index (forward lookup)
        let txids = store.get_txids_for_blockhash(&blockhash, ColumnFamily::BlockTxids);
        assert_eq!(txids.0.len(), block.transactions.len());

        // Verify txid -> block index (reverse lookup via add_txids_to_blocks_index)
        for tx in &block.transactions {
            let txid = tx.compute_txid();
            let retrieved_blockhashes = store.get_blockhashes_for_txid(&txid).unwrap();
            assert_eq!(retrieved_blockhashes.len(), 1);
            assert_eq!(
                retrieved_blockhashes[0], blockhash,
                "txid {} should map to blockhash {}",
                txid, blockhash
            );
        }

        // Verify a non-existent txid returns empty vector
        let nonexistent_txid = Txid::all_zeros();
        let result = store.get_blockhashes_for_txid(&nonexistent_txid).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_txid_to_blocks_index_supports_multiple_blockhashes() {
        // Test that a txid can be associated with multiple blockhashes,
        // simulating the scenario where competing miners include the same
        // transaction in different blocks.
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a transaction that will be included in multiple blocks
        let shared_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1000000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let shared_txid = shared_tx.compute_txid();

        // Create first block containing the shared transaction
        let block1 = TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .add_transaction(shared_tx.clone())
            .build();
        let blockhash1 = block1.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block1, true, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify the txid maps to the first blockhash
        let blockhashes = store.get_blockhashes_for_txid(&shared_txid).unwrap();
        assert_eq!(blockhashes.len(), 1);
        assert!(blockhashes.contains(&blockhash1));

        // Create second block (different nonce) containing the same transaction
        // This simulates a competing miner including the same tx
        let block2 = TestShareBlockBuilder::new()
            .nonce(0xe9695792)
            .add_transaction(shared_tx.clone())
            .build();
        let blockhash2 = block2.block_hash();
        assert_ne!(
            blockhash1, blockhash2,
            "blocks should have different hashes"
        );

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block2, false, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify the txid now maps to both blockhashes
        let blockhashes = store.get_blockhashes_for_txid(&shared_txid).unwrap();
        assert_eq!(blockhashes.len(), 2, "txid should map to 2 blockhashes");
        assert!(
            blockhashes.contains(&blockhash1),
            "should contain first blockhash"
        );
        assert!(
            blockhashes.contains(&blockhash2),
            "should contain second blockhash"
        );

        // Create third block with the same transaction
        let block3 = TestShareBlockBuilder::new()
            .nonce(0xe9695793)
            .add_transaction(shared_tx.clone())
            .build();
        let blockhash3 = block3.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block3, false, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify the txid now maps to all three blockhashes
        let blockhashes = store.get_blockhashes_for_txid(&shared_txid).unwrap();
        assert_eq!(blockhashes.len(), 3, "txid should map to 3 blockhashes");
        assert!(blockhashes.contains(&blockhash1));
        assert!(blockhashes.contains(&blockhash2));
        assert!(blockhashes.contains(&blockhash3));
    }

    #[test]
    fn test_txid_to_blocks_index_deduplicates_blockhashes() {
        // Test that adding the same blockhash for a txid multiple times
        // doesn't create duplicates (merge operator should handle this)
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let txid = tx.compute_txid();
        let txids = Txids(vec![txid]);

        let blockhash = BlockHash::from_byte_array([1u8; 32]);

        // Add the same blockhash for the txid multiple times
        let mut batch = Store::get_write_batch();
        store
            .add_txids_to_blocks_index(&blockhash, &txids, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_txids_to_blocks_index(&blockhash, &txids, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .add_txids_to_blocks_index(&blockhash, &txids, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Should still only have 1 blockhash (no duplicates)
        let blockhashes = store.get_blockhashes_for_txid(&txid).unwrap();
        assert_eq!(
            blockhashes.len(),
            1,
            "should have only 1 blockhash (deduplication)"
        );
        assert_eq!(blockhashes[0], blockhash);
    }

    #[test]
    fn test_add_tx_metadata_with_no_inputs_or_outputs_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut batch = Store::get_write_batch();
        let txid = tx.compute_txid();
        let result = store.add_tx_metadata(txid, &tx, false, &mut batch);
        store.commit_batch(batch).unwrap();

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.txid, txid);
        assert_eq!(metadata.input_count, 0);
        assert_eq!(metadata.output_count, 0);
        assert!(!metadata.validated);
    }

    #[test]
    fn test_mark_transaction_valid() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let txid = tx.compute_txid();

        // Add tx metadata first
        let mut batch = Store::get_write_batch();
        store.add_tx_metadata(txid, &tx, false, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify it's not validated
        let metadata = store.get_tx_metadata(&txid).unwrap();
        assert!(!metadata.validated);

        // Mark as valid
        let mut batch = Store::get_write_batch();
        store.mark_transaction_valid(&txid, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify it's now validated
        let metadata = store.get_tx_metadata(&txid).unwrap();
        assert!(metadata.validated);
    }

    #[test]
    fn test_add_txs_should_succeed() {
        // Create a new store with a temporary path
        let temp_dir = tempdir().unwrap();
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

        let transactions = vec![ShareTransaction(tx1.clone()), ShareTransaction(tx2.clone())];

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
    fn test_add_txs_with_inputs_or_outputs_should_succeed() {
        let temp_dir = tempdir().unwrap();
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
            .add_sharechain_txs(&[ShareTransaction(tx.clone())], true, &mut batch)
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

        // Add the previous transaction and update spends index
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_tx_metadata(prev_txid, &prev_tx, false, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify outputs are not yet spent
        assert!(store.is_spent(&prev_txid, 0).unwrap().is_none());
        assert!(store.is_spent(&prev_txid, 1).unwrap().is_none());

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

        let txid = tx.compute_txid();

        // Confirm the transaction (should add to spend index)
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_sharechain_txs(&[ShareTransaction(tx)], true, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        // Verify the previous outputs are now in spends index
        let stored = store.is_spent(&prev_txid, 0).unwrap();
        assert!(stored.is_some());
        assert_eq!(txid, stored.unwrap().txid);
        assert_eq!(0, stored.unwrap().vout);

        let stored_second = store.is_spent(&prev_txid, 1).unwrap();
        assert!(stored_second.is_some());
        assert_eq!(txid, stored_second.unwrap().txid);
        assert_eq!(1, stored_second.unwrap().vout);
    }
}
