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
use crate::store::block_tx_metadata::{Status, TxMetadata};
use bitcoin::consensus::{self, Decodable, Encodable, encode};
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use rocksdb::WriteBatch;
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// Serialized outpoint size: 32B for Txid hash, 4B for index
const OUTPOINT_SIZE: usize = 36;

/// A TxOut stored in the Outputs CF together with a flag indicating
/// whether it belongs to a coinbase transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredTxOut {
    pub tx_out: bitcoin::TxOut,
    pub is_coinbase: bool,
}

impl Encodable for StoredTxOut {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut length = self.tx_out.consensus_encode(writer)?;
        length += self.is_coinbase.consensus_encode(writer)?;
        Ok(length)
    }
}

impl Decodable for StoredTxOut {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let tx_out = bitcoin::TxOut::consensus_decode(reader)?;
        let is_coinbase = bool::consensus_decode(reader)?;
        Ok(StoredTxOut {
            tx_out,
            is_coinbase,
        })
    }
}

#[allow(dead_code)]
impl Store {
    /// Retrieve all previous outputs being spent by a transaction's inputs.
    ///
    /// Uses a single batch query to fetch all spent outputs, avoiding
    /// N+1 lookups. Returns a vector of (input_index, TxOut) pairs in
    /// input order.
    pub(crate) fn get_all_prevouts(
        &self,
        transaction: &bitcoin::Transaction,
    ) -> Result<Vec<(usize, bitcoin::TxOut)>, StoreError> {
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let keys: Vec<(_, String)> = transaction
            .input
            .iter()
            .map(|input| {
                let key = format!(
                    "{}:{}",
                    input.previous_output.txid, input.previous_output.vout
                );
                (&outputs_cf, key)
            })
            .collect();

        let cf_keys: Vec<(_, &[u8])> = keys.iter().map(|(cf, key)| (*cf, key.as_bytes())).collect();

        // results are in the same order as keys
        let results = self.db.multi_get_cf(cf_keys);
        let mut prevouts = Vec::with_capacity(results.len());
        for (input_index, result) in results.into_iter().enumerate() {
            let data = result?.ok_or_else(|| {
                let outpoint = &transaction.input[input_index].previous_output;
                StoreError::NotFound(format!(
                    "Output not found for {}:{}",
                    outpoint.txid, outpoint.vout
                ))
            })?;
            let stored: StoredTxOut = encode::deserialize(&data).map_err(|_| {
                StoreError::Serialization("Failed to deserialize output".to_string())
            })?;
            prevouts.push((input_index, stored.tx_out));
        }
        Ok(prevouts)
    }

    /// Batch-read all outpoints from the Outputs CF in a single multi_get.
    ///
    /// Returns an error if any outpoint is missing. On success, returns
    /// the subset of outpoints that belong to coinbase transactions.
    pub(crate) fn check_prevouts_and_find_coinbase(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<OutPoint>, StoreError> {
        if outpoints.is_empty() {
            return Ok(Vec::new());
        }
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let keys: Vec<String> = outpoints
            .iter()
            .map(|outpoint| format!("{}:{}", outpoint.txid, outpoint.vout))
            .collect();
        let cf_keys: Vec<(_, &[u8])> = keys
            .iter()
            .map(|key| (&outputs_cf, key.as_bytes()))
            .collect();
        let mut coinbase_outpoints = Vec::new();
        for (index, result) in self.db.multi_get_cf(cf_keys).into_iter().enumerate() {
            let data = result?.ok_or_else(|| {
                StoreError::NotFound(format!(
                    "Output not found for {}:{}",
                    outpoints[index].txid, outpoints[index].vout
                ))
            })?;
            let stored: StoredTxOut = encode::deserialize(&data).map_err(|_| {
                StoreError::Serialization("Failed to deserialize output".to_string())
            })?;
            if stored.is_coinbase {
                coinbase_outpoints.push(outpoints[index]);
            }
        }
        Ok(coinbase_outpoints)
    }

    /// Batch check the SpendsIndex column family: returns true if any
    /// outpoint has a stored spend entry.
    ///
    /// `SpendsIndex` is written only from the confirmation path
    /// (`put_confirmed_entry`) and cleared on reorg-out, so presence in
    /// this column family means "spent by a transaction on the confirmed
    /// sharechain". No per-hit confirmation lookup is needed.
    pub(crate) fn is_any_prevout_spent(&self, outpoints: &[OutPoint]) -> Result<bool, StoreError> {
        if outpoints.is_empty() {
            return Ok(false);
        }
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        let keys: Vec<String> = outpoints
            .iter()
            .map(|outpoint| format!("{}:{}", outpoint.txid, outpoint.vout))
            .collect();
        let cf_keys: Vec<(_, &[u8])> = keys
            .iter()
            .map(|key| (&spends_index_cf, key.as_bytes()))
            .collect();
        for result in self.db.multi_get_cf(cf_keys) {
            if result?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Given coinbase outpoints (already known to be on the confirmed chain),
    /// return the first outpoint whose confirmed block is shallower than
    /// `min_depth`. Returns `Ok(None)` if all coinbase outpoints are mature.
    ///
    /// Each coinbase tx has exactly one output and appears in exactly one
    /// confirmed block, so txids are already unique and each has a single
    /// confirmed height.
    ///
    /// Uses two batch calls: `get_blockhashes_for_all_txids` for txid-to-block
    /// lookups, then `get_block_metadata_batch` for all referenced blockhashes.
    pub(crate) fn find_immature_coinbase_prevout(
        &self,
        coinbase_outpoints: &[OutPoint],
        min_depth: usize,
        tip_height: u32,
    ) -> Result<Option<OutPoint>, StoreError> {
        if coinbase_outpoints.is_empty() {
            return Ok(None);
        }

        let txids: Vec<Txid> = coinbase_outpoints
            .iter()
            .map(|outpoint| outpoint.txid)
            .collect();

        let per_txid_blockhashes = self.get_blockhashes_for_all_txids(&txids)?;

        let all_blockhashes: Vec<BlockHash> = per_txid_blockhashes
            .iter()
            .flat_map(|blockhashes| blockhashes.iter().copied())
            .collect();

        let blockhash_to_metadata = self.get_block_metadata_batch(&all_blockhashes);

        // Map blockhash -> confirmed height
        let confirmed_block_heights: HashMap<BlockHash, u32> = blockhash_to_metadata
            .into_iter()
            .filter(|(_, metadata)| metadata.status == Status::Confirmed)
            .filter_map(|(blockhash, metadata)| {
                metadata.expected_height.map(|height| (blockhash, height))
            })
            .collect();

        for (index, outpoint) in coinbase_outpoints.iter().enumerate() {
            let confirmed_height = per_txid_blockhashes[index]
                .iter()
                .find_map(|blockhash| confirmed_block_heights.get(blockhash).copied());
            match confirmed_height {
                Some(height) => {
                    if tip_height < height || (tip_height - height) < min_depth as u32 {
                        return Ok(Some(*outpoint));
                    }
                }
                None => {
                    return Ok(Some(*outpoint));
                }
            }
        }

        Ok(None)
    }

    /// Returns true if every provided txid is included in at least one
    /// block whose `BlockMetadata::status` is `Status::Confirmed`. Returns
    /// false on the first txid that has no confirmed blockhash.
    pub(crate) fn are_all_txids_confirmed(&self, txids: &[Txid]) -> Result<bool, StoreError> {
        let per_txid_blockhashes = self.get_blockhashes_for_all_txids(txids)?;

        let all_blockhashes: Vec<BlockHash> = per_txid_blockhashes
            .iter()
            .flat_map(|blockhashes| blockhashes.iter().copied())
            .collect();

        let metadata_pairs = self.get_block_metadata_batch(&all_blockhashes);
        let confirmed_set: HashSet<BlockHash> = metadata_pairs
            .into_iter()
            .filter(|(_, metadata)| metadata.status == Status::Confirmed)
            .map(|(blockhash, _)| blockhash)
            .collect();

        for blockhashes in &per_txid_blockhashes {
            let has_confirmed = blockhashes
                .iter()
                .any(|blockhash| confirmed_set.contains(blockhash));
            if !has_confirmed {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Retrieve a single transaction output by txid and output index.
    ///
    /// Looks up the output in the Outputs column family using the
    /// key format `{txid}:{vout}`.
    pub(crate) fn get_output(&self, txid: &Txid, vout: u32) -> Result<bitcoin::TxOut, StoreError> {
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let output_key = format!("{txid}:{vout}");
        match self.db.get_cf::<&[u8]>(&outputs_cf, output_key.as_ref())? {
            Some(data) => {
                let stored: StoredTxOut = encode::deserialize(&data).map_err(|_| {
                    StoreError::Serialization("Failed to deserialize output".to_string())
                })?;
                Ok(stored.tx_out)
            }
            None => Err(StoreError::NotFound(format!(
                "Output not found for {txid}:{vout}"
            ))),
        }
    }

    /// Store share chain transactions in the store.
    ///
    /// Writes transaction metadata, each input, and each output into
    /// their respective column families. This function is pure tx
    /// storage and does not touch the `SpendsIndex` — chain-state
    /// bookkeeping of spends is the responsibility of the confirmation
    /// path (`put_confirmed_entry` / `remove_spends_for_block`).
    ///
    /// The block -> txids association is stored separately via
    /// `add_txids_to_blocks_index`, allowing this function to persist
    /// transactions outside of a block context.
    pub(crate) fn add_sharechain_txs(
        &self,
        transactions: &[ShareTransaction],
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Vec<TxMetadata>, StoreError> {
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut txs_metadata = Vec::new();
        for tx in transactions {
            let txid = tx.compute_txid();
            let metadata = self.add_tx_metadata(txid, tx, false, batch)?;
            txs_metadata.push(metadata);

            for (i, input) in tx.input.iter().enumerate() {
                let input_key = format!("{txid}:{i}");
                let mut serialized = Vec::new();
                input.consensus_encode(&mut serialized)?;
                batch.put_cf::<&[u8], Vec<u8>>(&inputs_cf, input_key.as_ref(), serialized);
            }

            let is_coinbase = tx.0.is_coinbase();
            for (i, output) in tx.output.iter().enumerate() {
                let output_key = format!("{txid}:{i}");
                let stored = StoredTxOut {
                    tx_out: output.clone(),
                    is_coinbase,
                };
                let serialized = consensus::serialize(&stored);
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
        prevout_txid: &Txid,
        prevout_index: u32,
        spending_txid: &Txid,
        spending_index: u32,
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        let key = format!("{prevout_txid}:{prevout_index}");
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        let mut serialized = Vec::with_capacity(OUTPOINT_SIZE);
        spending_txid.consensus_encode(&mut serialized)?;
        spending_index.consensus_encode(&mut serialized)?;
        batch.put_cf::<&[u8], Vec<u8>>(&spends_index_cf, key.as_ref(), serialized);
        Ok(())
    }

    /// Delete a `SpendsIndex` entry for `(prevout_txid, prevout_index)`.
    ///
    /// Used by the reorg-out path when a block that previously recorded
    /// the spend is no longer on the confirmed sharechain. `delete_cf`
    /// leaves a RocksDB tombstone; this is acceptable at `SpendsIndex`
    /// cardinality (bounded by inputs in reorged blocks).
    pub(crate) fn remove_spend(
        &self,
        prevout_txid: &Txid,
        prevout_index: u32,
        batch: &mut WriteBatch,
    ) {
        let key = format!("{prevout_txid}:{prevout_index}");
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        batch.delete_cf::<&[u8]>(&spends_index_cf, key.as_ref());
    }

    /// Write `SpendsIndex` entries for every non-coinbase input of every
    /// transaction in `txs`. Intended to be called from the confirmation
    /// path so that `SpendsIndex` presence means "spent on the confirmed
    /// sharechain".
    pub(crate) fn add_spends_for_block(
        &self,
        txs: &[ShareTransaction],
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        for share_transaction in txs {
            let transaction = &share_transaction.0;
            if !transaction.is_coinbase() {
                let spending_txid = transaction.compute_txid();
                for (spending_index, input) in transaction.input.iter().enumerate() {
                    self.add_spend(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                        &spending_txid,
                        spending_index as u32,
                        batch,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Delete every `SpendsIndex` entry that `add_spends_for_block` would
    /// have written for `txs`. Used by the reorg-out path.
    pub(crate) fn remove_spends_for_block(&self, txs: &[ShareTransaction], batch: &mut WriteBatch) {
        for share_transaction in txs {
            let transaction = &share_transaction.0;
            if !transaction.is_coinbase() {
                for input in &transaction.input {
                    self.remove_spend(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                        batch,
                    );
                }
            }
        }
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

    /// Batch-fetch blockhashes for all provided txids in a single multi_get_cf call.
    ///
    /// Returns a Vec parallel to the input: each entry is the list of
    /// blockhashes that contain that txid (empty if none found).
    pub(crate) fn get_blockhashes_for_all_txids(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<Vec<BlockHash>>, StoreError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();
        let cf_keys: Vec<(_, &[u8])> = txids
            .iter()
            .map(|txid| (&txids_blocks_cf, txid.as_ref()))
            .collect();
        let results = self.db.multi_get_cf(cf_keys);
        let mut all_blockhashes: Vec<Vec<BlockHash>> = Vec::with_capacity(txids.len());
        for result in results {
            match result? {
                Some(blockhash_bytes) => {
                    let blockhashes: Vec<BlockHash> = encode::deserialize(&blockhash_bytes)
                        .map_err(|_| {
                            StoreError::Serialization(
                                "Failed to deserialize blockhashes from txids_blocks index"
                                    .to_string(),
                            )
                        })?;
                    all_blockhashes.push(blockhashes);
                }
                None => {
                    all_blockhashes.push(Vec::new());
                }
            }
        }
        Ok(all_blockhashes)
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

    /// Get all transaction IDs for a given block hash from the
    /// BlockTxids column family.
    pub fn get_txids_for_blockhash(&self, blockhash: &BlockHash) -> Txids {
        let mut blockhash_bytes = consensus::serialize(blockhash);
        blockhash_bytes.extend_from_slice(b"_txids");

        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
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

    /// Get transactions for a blockhash from the BlockTxids column
    /// family. Looks up the txids index, then reconstructs each
    /// transaction from the Tx/Inputs/Outputs CFs.
    pub fn get_txs_for_blockhash(&self, blockhash: &BlockHash) -> Vec<Transaction> {
        let txids = self.get_txids_for_blockhash(blockhash);
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
            let output = match encode::deserialize::<StoredTxOut>(&output) {
                Ok(stored) => stored.tx_out,
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

    /// Batch load `TxMetadata` for a list of txids via a single
    /// `multi_get_cf` on the `Tx` column family. Result order matches
    /// the input order. Errors on any missing txid.
    pub(crate) fn get_metadata_for_txids(
        &self,
        txids: &[Txid],
    ) -> Result<Vec<TxMetadata>, StoreError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let keys: Vec<(_, &[u8])> = txids.iter().map(|txid| (&tx_cf, txid.as_ref())).collect();
        let results = self.db.multi_get_cf(keys);
        let mut metadatas: Vec<TxMetadata> = Vec::with_capacity(txids.len());
        for (index, result) in results.into_iter().enumerate() {
            let bytes = result?.ok_or_else(|| {
                StoreError::NotFound(format!(
                    "Transaction metadata not found for txid: {}",
                    txids[index]
                ))
            })?;
            let metadata: TxMetadata = encode::deserialize(&bytes).map_err(|_| {
                StoreError::Serialization("Failed to deserialize tx metadata".to_string())
            })?;
            metadatas.push(metadata);
        }
        Ok(metadatas)
    }

    /// Batch load transaction inputs for every `(txid, metadata)` pair
    /// via a single `multi_get_cf` on the `Inputs` column family. Returns
    /// a per-tx `Vec<TxIn>` in the same order as `txids`. `txids` and
    /// `metadatas` must have the same length.
    pub(crate) fn get_inputs(
        &self,
        txids: &[Txid],
        metadatas: &[TxMetadata],
    ) -> Result<Vec<Vec<bitcoin::TxIn>>, StoreError> {
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let mut keys: Vec<String> = Vec::new();
        // Use offsets to track inputs for various txids to avoid using hashmap here
        let mut offsets: Vec<usize> = Vec::with_capacity(txids.len() + 1);
        offsets.push(0);
        for (index, metadata) in metadatas.iter().enumerate() {
            let txid = &txids[index];
            for input_index in 0..metadata.input_count {
                keys.push(format!("{txid}:{input_index}"));
            }
            offsets.push(keys.len());
        }

        let cf_keys: Vec<(_, &[u8])> = keys
            .iter()
            .map(|key| (&inputs_cf, key.as_bytes()))
            .collect();
        let results = self.db.multi_get_cf(cf_keys);
        let mut decoded: Vec<bitcoin::TxIn> = Vec::with_capacity(keys.len());
        for (index, result) in results.into_iter().enumerate() {
            let bytes = result?.ok_or_else(|| {
                StoreError::NotFound(format!("Input not found for {}", keys[index]))
            })?;
            decoded.push(encode::deserialize(&bytes).map_err(|_| {
                StoreError::Serialization("Failed to deserialize input".to_string())
            })?);
        }

        // group the offset based inputs for each txid
        let mut grouped: Vec<Vec<bitcoin::TxIn>> = Vec::with_capacity(txids.len());
        for index in 0..txids.len() {
            grouped.push(decoded[offsets[index]..offsets[index + 1]].to_vec());
        }
        Ok(grouped)
    }

    /// Batch load transaction outputs for every `(txid, metadata)` pair
    /// via a single `multi_get_cf` on the `Outputs` column family.
    /// Returns a per-tx `Vec<TxOut>` in the same order as `txids`.
    /// `txids` and `metadatas` must have the same length.
    pub(crate) fn get_outputs(
        &self,
        txids: &[Txid],
        metadatas: &[TxMetadata],
    ) -> Result<Vec<Vec<bitcoin::TxOut>>, StoreError> {
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut keys: Vec<String> = Vec::new();
        // Use offsets to track ouputs for various txids to avoid using hashmap here
        let mut offsets: Vec<usize> = Vec::with_capacity(txids.len() + 1);
        offsets.push(0);
        for (index, metadata) in metadatas.iter().enumerate() {
            let txid = &txids[index];
            for output_index in 0..metadata.output_count {
                keys.push(format!("{txid}:{output_index}"));
            }
            offsets.push(keys.len());
        }

        let cf_keys: Vec<(_, &[u8])> = keys
            .iter()
            .map(|key| (&outputs_cf, key.as_bytes()))
            .collect();
        let results = self.db.multi_get_cf(cf_keys);
        let mut decoded: Vec<bitcoin::TxOut> = Vec::with_capacity(keys.len());
        for (index, result) in results.into_iter().enumerate() {
            let bytes = result?.ok_or_else(|| {
                StoreError::NotFound(format!("Output not found for {}", keys[index]))
            })?;
            let stored: StoredTxOut = encode::deserialize(&bytes).map_err(|_| {
                StoreError::Serialization("Failed to deserialize output".to_string())
            })?;
            decoded.push(stored.tx_out);
        }

        // group the offset based outputs for each txid
        let mut grouped: Vec<Vec<bitcoin::TxOut>> = Vec::with_capacity(txids.len());
        for index in 0..txids.len() {
            grouped.push(decoded[offsets[index]..offsets[index + 1]].to_vec());
        }
        Ok(grouped)
    }

    /// Batch load transactions for a list of txids.
    ///
    /// Composes `get_metadata_for_txids`, `get_inputs`, and
    /// `get_outputs`: three `multi_get_cf` calls total, one per column
    /// family, independent of how many transactions are requested.
    pub(crate) fn get_txs(&self, txids: &[Txid]) -> Result<Vec<Transaction>, StoreError> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let metadatas = self.get_metadata_for_txids(txids)?;
        let inputs = self.get_inputs(txids, &metadatas)?;
        let outputs = self.get_outputs(txids, &metadatas)?;
        let mut txs = Vec::with_capacity(txids.len());
        for (metadata, (tx_inputs, tx_outputs)) in metadatas
            .into_iter()
            .zip(inputs.into_iter().zip(outputs.into_iter()))
        {
            txs.push(Transaction {
                version: metadata.version,
                lock_time: metadata.lock_time,
                input: tx_inputs,
                output: tx_outputs,
            });
        }
        Ok(txs)
    }

    /// Get transactions by blockhash index for sharechain transactions
    pub(crate) fn get_txs_by_blockhash_index(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Vec<ShareTransaction>, StoreError> {
        let txids = self.get_txids_for_blockhash(blockhash);
        let txs = self.get_txs(&txids.0)?;
        let mut share_txs = Vec::with_capacity(txs.len());
        for tx in txs {
            share_txs.push(ShareTransaction(tx));
        }
        Ok(share_txs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::hashes::Hash;
    use bitcoin::pow::Work;
    use tempfile::tempdir;

    #[test]
    fn test_transaction_store_should_succeed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let block = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();

        let metadata = store
            .add_sharechain_txs(&block.transactions, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(metadata.len(), block.transactions.len());
        for tx_meta in &metadata {
            let tx = store.get_tx(&tx_meta.txid).unwrap();
            assert_eq!(tx.compute_txid(), tx_meta.txid);
        }
    }

    #[test]
    fn test_get_txs_returns_empty_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert!(store.get_txs(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_get_txs_returns_every_requested_transaction() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx_a = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::hashes::sha256d::Hash::from_byte_array([0x01; 32]).into(),
                    0,
                ),
                ..Default::default()
            }],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(100),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(200),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };
        let tx_b = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0x02; 32]).into(),
                        5,
                    ),
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(
                        bitcoin::hashes::sha256d::Hash::from_byte_array([0x03; 32]).into(),
                        1,
                    ),
                    ..Default::default()
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(300),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let txid_a = tx_a.compute_txid();
        let txid_b = tx_b.compute_txid();

        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(
                &[
                    ShareTransaction(tx_a.clone()),
                    ShareTransaction(tx_b.clone()),
                ],
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let loaded = store.get_txs(&[txid_a, txid_b]).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], tx_a);
        assert_eq!(loaded[1], tx_b);

        // Order of the request drives the order of the result.
        let reversed = store.get_txs(&[txid_b, txid_a]).unwrap();
        assert_eq!(reversed[0], tx_b);
        assert_eq!(reversed[1], tx_a);
    }

    #[test]
    fn test_get_txs_errors_when_any_txid_unknown() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let unknown_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x99; 32]).into();
        let result = store.get_txs(&[unknown_txid]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_all_prevouts_succeeds_for_stored_outputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Create a funding transaction with two outputs
        let funding_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(2_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };
        let funding_txid = funding_tx.compute_txid();

        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(&[ShareTransaction(funding_tx)], &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Build a spending transaction that consumes both outputs
        let spending_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(funding_txid, 0),
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(funding_txid, 1),
                    ..Default::default()
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(2_900_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let prevouts = store.get_all_prevouts(&spending_tx).unwrap();
        assert_eq!(prevouts.len(), 2);
        assert_eq!(prevouts[0].0, 0);
        assert_eq!(prevouts[0].1.value, bitcoin::Amount::from_sat(1_000_000));
        assert_eq!(prevouts[1].0, 1);
        assert_eq!(prevouts[1].1.value, bitcoin::Amount::from_sat(2_000_000));
    }

    #[test]
    fn test_get_all_prevouts_fails_for_missing_output() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(Txid::all_zeros(), 0),
                ..Default::default()
            }],
            output: vec![],
        };

        let result = store.get_all_prevouts(&spending_tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_prevouts_and_find_coinbase_returns_empty_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let result = store.check_prevouts_and_find_coinbase(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_prevouts_and_find_coinbase_succeeds_when_all_present() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(2_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };
        let funding_txid = funding_tx.compute_txid();

        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(&[ShareTransaction(funding_tx)], &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let outpoints = vec![
            bitcoin::OutPoint::new(funding_txid, 0),
            bitcoin::OutPoint::new(funding_txid, 1),
        ];
        let coinbase_outpoints = store.check_prevouts_and_find_coinbase(&outpoints).unwrap();
        assert!(coinbase_outpoints.is_empty());
    }

    #[test]
    fn test_check_prevouts_and_find_coinbase_errors_when_one_missing() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let funding_txid = funding_tx.compute_txid();

        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(&[ShareTransaction(funding_tx)], &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let unknown_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([7u8; 32]).into();
        let outpoints = vec![
            bitcoin::OutPoint::new(funding_txid, 0),
            bitcoin::OutPoint::new(unknown_txid, 0),
        ];
        let result = store.check_prevouts_and_find_coinbase(&outpoints);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_prevouts_and_find_coinbase_returns_coinbase_outpoints() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), u32::MAX),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
                script_sig: bitcoin::ScriptBuf::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let coinbase_txid = coinbase_tx.compute_txid();

        let regular_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let regular_txid = regular_tx.compute_txid();

        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(
                &[ShareTransaction(coinbase_tx), ShareTransaction(regular_tx)],
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        let outpoints = vec![
            bitcoin::OutPoint::new(coinbase_txid, 0),
            bitcoin::OutPoint::new(regular_txid, 0),
        ];
        let coinbase_outpoints = store.check_prevouts_and_find_coinbase(&outpoints).unwrap();
        assert_eq!(coinbase_outpoints.len(), 1);
        assert_eq!(coinbase_outpoints[0].txid, coinbase_txid);
    }

    #[test]
    fn test_is_any_prevout_spent_returns_false_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert!(!store.is_any_prevout_spent(&[]).unwrap());
    }

    #[test]
    fn test_is_any_prevout_spent_reflects_spends_index_presence() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let funding_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([41u8; 32]).into();
        let spending_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([42u8; 32]).into();

        // No SpendsIndex entries yet.
        assert!(
            !store
                .is_any_prevout_spent(&[bitcoin::OutPoint::new(funding_txid, 0)])
                .unwrap()
        );

        // Record vout 0 as spent via the confirmation-path helper.
        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_spend(&funding_txid, 0, &spending_txid, 0, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(
            store
                .is_any_prevout_spent(&[bitcoin::OutPoint::new(funding_txid, 0)])
                .unwrap()
        );
        assert!(
            !store
                .is_any_prevout_spent(&[bitcoin::OutPoint::new(funding_txid, 1)])
                .unwrap()
        );
        // Mixed batch with one present should report true.
        assert!(
            store
                .is_any_prevout_spent(&[
                    bitcoin::OutPoint::new(funding_txid, 1),
                    bitcoin::OutPoint::new(funding_txid, 0),
                ])
                .unwrap()
        );
    }

    #[test]
    fn test_are_all_txids_confirmed_returns_true_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert!(store.are_all_txids_confirmed(&[]).unwrap());
    }

    #[test]
    fn test_are_all_txids_confirmed_true_when_all_confirmed() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid_a: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([1u8; 32]).into();
        let txid_b: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([2u8; 32]).into();

        let blockhash = TestShareBlockBuilder::new().build().block_hash();
        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(
                &blockhash,
                &BlockMetadata {
                    expected_height: Some(1),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(&blockhash, &Txids(vec![txid_a, txid_b]), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.are_all_txids_confirmed(&[txid_a, txid_b]).unwrap());
    }

    #[test]
    fn test_are_all_txids_confirmed_false_when_any_uncle_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let txid_confirmed: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([3u8; 32]).into();
        let txid_uncle_only: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([4u8; 32]).into();

        let confirmed_blockhash = TestShareBlockBuilder::new()
            .nonce(0xaaaa0001)
            .build()
            .block_hash();
        let uncle_blockhash = TestShareBlockBuilder::new()
            .nonce(0xaaaa0002)
            .build()
            .block_hash();

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(
                &confirmed_blockhash,
                &BlockMetadata {
                    expected_height: Some(1),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .update_block_metadata(
                &uncle_blockhash,
                &BlockMetadata {
                    expected_height: Some(1),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Candidate,
                },
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(
                &confirmed_blockhash,
                &Txids(vec![txid_confirmed]),
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(&uncle_blockhash, &Txids(vec![txid_uncle_only]), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.are_all_txids_confirmed(&[txid_confirmed]).unwrap());
        assert!(!store.are_all_txids_confirmed(&[txid_uncle_only]).unwrap());
        assert!(
            !store
                .are_all_txids_confirmed(&[txid_confirmed, txid_uncle_only])
                .unwrap()
        );
    }

    #[test]
    fn test_are_all_txids_confirmed_false_when_unknown() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let unknown_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([9u8; 32]).into();
        assert!(!store.are_all_txids_confirmed(&[unknown_txid]).unwrap());
    }

    #[test]
    fn test_get_output_succeeds_for_stored_output() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(2_000_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
        };

        let txid = tx.compute_txid();
        let mut batch = Store::get_write_batch();
        store
            .add_sharechain_txs(&[ShareTransaction(tx)], &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let output_0 = store.get_output(&txid, 0).unwrap();
        assert_eq!(output_0.value, bitcoin::Amount::from_sat(1_000_000));

        let output_1 = store.get_output(&txid, 1).unwrap();
        assert_eq!(output_1.value, bitcoin::Amount::from_sat(2_000_000));

        let missing = store.get_output(&txid, 99);
        assert!(missing.is_err());
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
        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        // Verify block -> txids index (forward lookup)
        let txids = store.get_txids_for_blockhash(&blockhash);
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
        store.add_share_block(&block1, &mut batch).unwrap();
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
        store.add_share_block(&block2, &mut batch).unwrap();
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
        store.add_share_block(&block3, &mut batch).unwrap();
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
        store.add_sharechain_txs(&transactions, &mut batch).unwrap();
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
            .add_sharechain_txs(&[ShareTransaction(tx.clone())], &mut batch)
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
    fn test_remove_spend_clears_spends_index_entry() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let prev_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([11u8; 32]).into();
        let spending_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([12u8; 32]).into();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_spend(&prev_txid, 0, &spending_txid, 0, &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();
        assert!(store.is_spent(&prev_txid, 0).unwrap().is_some());

        let mut batch = rocksdb::WriteBatch::default();
        store.remove_spend(&prev_txid, 0, &mut batch);
        store.db.write(batch).unwrap();
        assert!(store.is_spent(&prev_txid, 0).unwrap().is_none());
    }

    #[test]
    fn test_add_spends_for_block_populates_non_coinbase_inputs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let funding_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([21u8; 32]).into();
        let other_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([22u8; 32]).into();

        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5_000_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(funding_txid, 0),
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(other_txid, 3),
                    ..Default::default()
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(900_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let spending_txid = spending_tx.compute_txid();

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_spends_for_block(
                &[ShareTransaction(coinbase_tx), ShareTransaction(spending_tx)],
                &mut batch,
            )
            .unwrap();
        store.db.write(batch).unwrap();

        let spent_a = store.is_spent(&funding_txid, 0).unwrap().unwrap();
        assert_eq!(spent_a.txid, spending_txid);
        assert_eq!(spent_a.vout, 0);

        let spent_b = store.is_spent(&other_txid, 3).unwrap().unwrap();
        assert_eq!(spent_b.txid, spending_txid);
        assert_eq!(spent_b.vout, 1);

        // Coinbase input's null prevout must not have been written.
        assert!(
            store
                .is_spent(&bitcoin::Txid::all_zeros(), u32::MAX)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_remove_spends_for_block_clears_every_non_coinbase_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let funding_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([31u8; 32]).into();

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(funding_txid, 0),
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint::new(funding_txid, 1),
                    ..Default::default()
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(900_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let txs = vec![ShareTransaction(spending_tx)];

        let mut batch = rocksdb::WriteBatch::default();
        store.add_spends_for_block(&txs, &mut batch).unwrap();
        store.db.write(batch).unwrap();
        assert!(store.is_spent(&funding_txid, 0).unwrap().is_some());
        assert!(store.is_spent(&funding_txid, 1).unwrap().is_some());

        let mut batch = rocksdb::WriteBatch::default();
        store.remove_spends_for_block(&txs, &mut batch);
        store.db.write(batch).unwrap();
        assert!(store.is_spent(&funding_txid, 0).unwrap().is_none());
        assert!(store.is_spent(&funding_txid, 1).unwrap().is_none());
    }

    #[test]
    fn test_add_spends_for_block_is_noop_for_coinbase_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5_000_000_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };

        let mut batch = rocksdb::WriteBatch::default();
        store
            .add_spends_for_block(&[ShareTransaction(coinbase_tx)], &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        assert!(
            store
                .is_spent(&bitcoin::Txid::all_zeros(), u32::MAX)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_get_blockhashes_for_all_txids_returns_empty_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let result = store.get_blockhashes_for_all_txids(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_blockhashes_for_all_txids_returns_blockhashes_for_known_txids() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let txids: Vec<Txid> = block
            .transactions
            .iter()
            .map(|tx| tx.compute_txid())
            .collect();
        let result = store.get_blockhashes_for_all_txids(&txids).unwrap();

        assert_eq!(result.len(), txids.len());
        for blockhashes in &result {
            assert_eq!(blockhashes.len(), 1);
            assert_eq!(blockhashes[0], blockhash);
        }
    }

    #[test]
    fn test_get_blockhashes_for_all_txids_returns_empty_vec_for_unknown_txids() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let unknown_txid_a = Txid::all_zeros();
        let unknown_txid_b = Txid::from_byte_array([1u8; 32]);
        let result = store
            .get_blockhashes_for_all_txids(&[unknown_txid_a, unknown_txid_b])
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].is_empty());
        assert!(result[1].is_empty());
    }

    #[test]
    fn test_get_blockhashes_for_all_txids_mixed_known_and_unknown() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let block = TestShareBlockBuilder::new().build();
        let blockhash = block.block_hash();
        let known_txid = block.transactions[0].compute_txid();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let unknown_txid = Txid::from_byte_array([0xffu8; 32]);
        let result = store
            .get_blockhashes_for_all_txids(&[known_txid, unknown_txid])
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].len(), 1);
        assert_eq!(result[0][0], blockhash);
        assert!(result[1].is_empty());
    }

    #[test]
    fn test_get_blockhashes_for_all_txids_txid_in_multiple_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

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

        let block1 = TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .add_transaction(shared_tx.clone())
            .build();
        let blockhash1 = block1.block_hash();

        let block2 = TestShareBlockBuilder::new()
            .nonce(0xe9695792)
            .add_transaction(shared_tx.clone())
            .build();
        let blockhash2 = block2.block_hash();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block1, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store.add_share_block(&block2, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        let result = store.get_blockhashes_for_all_txids(&[shared_txid]).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len(), 2);
        assert!(result[0].contains(&blockhash1));
        assert!(result[0].contains(&blockhash2));
    }

    #[test]
    fn test_find_immature_coinbase_prevout_returns_none_for_empty_input() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let result = store
            .find_immature_coinbase_prevout(&[], 6048, 10000)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_find_immature_coinbase_prevout_returns_none_when_mature() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let coinbase_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([10u8; 32]).into();

        let blockhash = TestShareBlockBuilder::new()
            .nonce(0xbb000001)
            .build()
            .block_hash();

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(
                &blockhash,
                &BlockMetadata {
                    expected_height: Some(1000),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(&blockhash, &Txids(vec![coinbase_txid]), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let outpoint = bitcoin::OutPoint::new(coinbase_txid, 0);
        // tip_height=8000, block_height=1000, depth=7000 >= 6048
        let result = store
            .find_immature_coinbase_prevout(&[outpoint], 6048, 8000)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_find_immature_coinbase_prevout_returns_outpoint_when_immature() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let coinbase_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([11u8; 32]).into();

        let blockhash = TestShareBlockBuilder::new()
            .nonce(0xbb000002)
            .build()
            .block_hash();

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(
                &blockhash,
                &BlockMetadata {
                    expected_height: Some(5000),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(&blockhash, &Txids(vec![coinbase_txid]), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        let outpoint = bitcoin::OutPoint::new(coinbase_txid, 0);
        // tip_height=8000, block_height=5000, depth=3000 < 6048
        let result = store
            .find_immature_coinbase_prevout(&[outpoint], 6048, 8000)
            .unwrap();
        assert_eq!(result, Some(outpoint));
    }

    #[test]
    fn test_find_immature_coinbase_prevout_non_coinbase_unaffected() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let mature_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([12u8; 32]).into();
        let immature_txid: bitcoin::Txid =
            bitcoin::hashes::sha256d::Hash::from_byte_array([13u8; 32]).into();

        let block_old = TestShareBlockBuilder::new()
            .nonce(0xbb000003)
            .build()
            .block_hash();
        let block_new = TestShareBlockBuilder::new()
            .nonce(0xbb000004)
            .build()
            .block_hash();

        let mut batch = Store::get_write_batch();
        store
            .update_block_metadata(
                &block_old,
                &BlockMetadata {
                    expected_height: Some(100),
                    chain_work: Work::from_le_bytes([1u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .update_block_metadata(
                &block_new,
                &BlockMetadata {
                    expected_height: Some(9000),
                    chain_work: Work::from_le_bytes([2u8; 32]),
                    status: Status::Confirmed,
                },
                &mut batch,
            )
            .unwrap();
        store
            .add_txids_to_blocks_index(&block_old, &Txids(vec![mature_txid]), &mut batch)
            .unwrap();
        store
            .add_txids_to_blocks_index(&block_new, &Txids(vec![immature_txid]), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        // Only the immature one should be returned
        let outpoints = vec![
            bitcoin::OutPoint::new(mature_txid, 0),
            bitcoin::OutPoint::new(immature_txid, 0),
        ];
        // tip=10000: mature depth=9900 >= 6048, immature depth=1000 < 6048
        let result = store
            .find_immature_coinbase_prevout(&outpoints, 6048, 10000)
            .unwrap();
        assert_eq!(result, Some(bitcoin::OutPoint::new(immature_txid, 0)));
    }
}
