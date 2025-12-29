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
use crate::shares::share_block::Txids;
use crate::store::block_tx_metadata::TxMetadata;
use bitcoin::consensus::{self, Encodable, encode};
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use std::error::Error;
use tracing::debug;

#[allow(dead_code)]
impl Store {
    /// Store transactions in the store
    /// Store inputs and outputs for each transaction in separate column families
    /// Store txid -> transaction metadata in the tx column family
    /// The block -> txids store is done in add_txids_to_block_index. This function lets us store transactions outside of a block context
    pub(crate) fn add_sharechain_txs(
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
    pub(crate) fn mark_transaction_valid(
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
    pub(crate) fn confirm_transaction(
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
    pub(crate) fn unconfirm_transaction(
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
    pub(crate) fn add_to_unspent_outputs(
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
    pub(crate) fn remove_from_unspent_outputs(
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
    pub(crate) fn is_in_unspent_outputs(
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
    pub(crate) fn add_tx_metadata(
        &self,
        txid: bitcoin::Txid,
        tx: &Transaction,
        validated: bool,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<TxMetadata, Box<dyn Error + Send + Sync>> {
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

    /// Add the list of transaction IDs to the batch
    /// Transactions themselves are stored in add_txs, here we just store the association between block and txids
    pub(crate) fn add_txids_to_block_index(
        &self,
        blockhash: &BlockHash,
        txids: &Txids,
        batch: &mut rocksdb::WriteBatch,
        bytes_suffix: &[u8],
        column_family: ColumnFamily,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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

    /// Mark output as spent,
    pub(crate) fn remove_output_from_unspent(
        &self,
        _output_point: OutPoint,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // TODO - implement
        Ok(())
    }

    /// Get the validation status of a transaction from the store
    pub(crate) fn get_tx_metadata(
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

    /// Get transactions by blockhash index for Bitcoin transactions
    pub(crate) fn get_bitcoin_txs_by_blockhash_index(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<Transaction>, Box<dyn Error + Send + Sync>> {
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
    ) -> Result<Vec<Transaction>, Box<dyn Error + Send + Sync>> {
        let txids = self.get_txids_for_blockhash(blockhash, ColumnFamily::BlockTxids);
        let mut txs = Vec::new();
        for txid in txids.0 {
            txs.push(self.get_tx(&txid)?);
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
        store
            .add_share(block.clone(), 0, block.header.get_work(), true, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let txids = store.get_txids_for_blockhash(&blockhash, ColumnFamily::BlockTxids);
        assert_eq!(txids.0.len(), block.transactions.len());
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
    fn test_add_to_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid = Txid::all_zeros();
        let index = 0;

        let mut batch = Store::get_write_batch();
        store
            .add_to_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.is_in_unspent_outputs(txid, index).unwrap());
    }

    #[test]
    fn test_remove_from_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid = Txid::all_zeros();
        let index = 0;

        // Add first
        let mut batch = Store::get_write_batch();
        store
            .add_to_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        assert!(store.is_in_unspent_outputs(txid, index).unwrap());

        // Remove
        let mut batch = Store::get_write_batch();
        store
            .remove_from_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        assert!(!store.is_in_unspent_outputs(txid, index).unwrap());
    }

    #[test]
    fn test_is_in_unspent_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid = Txid::all_zeros();
        let index = 0;

        // Should not exist initially
        assert!(!store.is_in_unspent_outputs(txid, index).unwrap());

        // Add and verify
        let mut batch = Store::get_write_batch();
        store
            .add_to_unspent_outputs(&txid, index, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        assert!(store.is_in_unspent_outputs(txid, index).unwrap());
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
}
