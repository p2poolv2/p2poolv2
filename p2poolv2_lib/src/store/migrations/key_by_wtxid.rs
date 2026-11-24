// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Migration to schema version 2: key share transaction metadata and inputs
//! by wtxid.
//!
//! Version 1 keyed the `Tx` and `Inputs` rows by txid, so two blocks holding
//! one txid with different witnesses shared one row. Version 2 keys them by
//! wtxid and stores each block's `(txid, wtxid)` pairs in `BlockTxids`.
//! `Outputs`, `SpendsIndex` and `TxidsBlocks` stay keyed by txid.
//!
//! For each block in `BlockTxids`, every transaction is rebuilt from its
//! version 1 rows to compute its wtxid. The `Tx` and `Inputs` values are the
//! same bytes in both versions, so they are copied unchanged under the new
//! keys. A transaction without witness data has wtxid == txid, so its rows
//! already sit under their version 2 keys and are left alone; only rows whose
//! key changes are rewritten and their old keys deleted.
//!
//! The rows are not checked against block headers or repaired: a block whose
//! row a copy with another witness had overwritten keeps the overwritten copy.

use crate::store::column_families::ColumnFamily;
use crate::store::writer::StoreError;
use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::{Decodable, serialize};
use bitcoin::{Transaction, TxIn, TxOut, Txid, Wtxid};
use rocksdb::{DB, IteratorMode, WriteBatch};
use std::collections::HashMap;
use tracing::info;

/// Suffix of a block's key in the `BlockTxids` CF, after its 32 byte
/// consensus-serialized blockhash. The same in versions 1 and 2.
///
/// Copied over in migration as migrations should not depend on
/// encoding rules from production modules that can change between
/// migrations.
const BLOCK_TXIDS_SUFFIX: &[u8] = b"_txids";

/// Length of a consensus-serialized hash: a blockhash, txid or wtxid.
const HASH_LENGTH: usize = 32;

/// Length of one version 2 `BlockTxids` entry: a txid, then its wtxid.
const TXID_WTXID_PAIR_LENGTH: usize = 2 * HASH_LENGTH;

/// Largest serialized `VarInt`: a marker byte, then a u64.
const MAX_VARINT_LENGTH: usize = 9;

/// Length of a `BlockTxids` key: the blockhash, then `BLOCK_TXIDS_SUFFIX`.
const BLOCK_TXIDS_KEY_LENGTH: usize = HASH_LENGTH + BLOCK_TXIDS_SUFFIX.len();

/// The fields of a version 1 `Tx` row this migration needs. The row is
/// `txid, version, lock_time, input_count, output_count, validated`, each
/// consensus encoded.
struct Version1TxMetadata {
    txid: Txid,
    version: bitcoin::transaction::Version,
    lock_time: bitcoin::absolute::LockTime,
    input_count: u32,
    output_count: u32,
}

/// A transaction rebuilt from its version 1 rows, with the raw `Inputs`
/// values that need to be copied to new keys.
struct Version1Transaction {
    metadata_bytes: Vec<u8>,
    input_bytes: Vec<Vec<u8>>,
    transaction: Transaction,
}

/// Counts of what the migration rewrote, for the log.
#[derive(Default)]
struct MigrationCounts {
    blocks: usize,
    transactions: usize,
    rekeyed: usize,
}

/// Rewrite every block's transactions from the version 1 layout to the
/// version 2 layout, into `batch`.
pub(super) fn run(db: &DB, batch: &mut WriteBatch) -> Result<(), StoreError> {
    let block_txids_cf = db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
    let mut wtxids: HashMap<Txid, Wtxid> = HashMap::new();
    let mut counts = MigrationCounts::default();

    for entry in db.iterator_cf(&block_txids_cf, IteratorMode::Start) {
        let (key, value) = entry?;
        check_block_txids_key_format(&key)?;
        let txids = decode_version_1_txids(&value)?;
        let mut pairs = Vec::with_capacity(txids.len());
        for txid in txids {
            let wtxid = match wtxids.get(&txid) {
                Some(wtxid) => *wtxid,
                None => {
                    let wtxid = migrate_transaction(db, &txid, batch, &mut counts)?;
                    wtxids.insert(txid, wtxid);
                    wtxid
                }
            };
            pairs.push((txid, wtxid));
        }
        batch.put_cf(&block_txids_cf, &key, encode_version_2_pairs(&pairs));
        counts.blocks += 1;
    }

    info!(
        "Rewrote transaction ids of {} blocks; {} transactions, {} rekeyed by wtxid",
        counts.blocks, counts.transactions, counts.rekeyed
    );
    Ok(())
}

/// Read transaction `txid` from its version 1 rows, compute its wtxid, and
/// when the wtxid differs from the txid put its `Tx` and `Inputs` rows under
/// the wtxid keys and delete the txid keys. Returns the wtxid.
fn migrate_transaction(
    db: &DB,
    txid: &Txid,
    batch: &mut WriteBatch,
    counts: &mut MigrationCounts,
) -> Result<Wtxid, StoreError> {
    let stored = read_version_1_transaction(db, txid)?;
    let rebuilt_txid = stored.transaction.compute_txid();
    if rebuilt_txid != *txid {
        return Err(StoreError::Serialization(format!(
            "rows stored under txid {txid} rebuild to txid {rebuilt_txid}"
        )));
    }
    let wtxid = stored.transaction.compute_wtxid();
    counts.transactions += 1;

    //* Rows of a transaction without witness data already have their version 2 keys
    if wtxid.to_raw_hash() != txid.to_raw_hash() {
        let tx_cf = db.cf_handle(&ColumnFamily::Tx).unwrap();
        let inputs_cf = db.cf_handle(&ColumnFamily::Inputs).unwrap();
        batch.put_cf(&tx_cf, wtxid.as_ref() as &[u8], &stored.metadata_bytes);
        batch.delete_cf(&tx_cf, txid.as_ref() as &[u8]);
        for (index, input_bytes) in stored.input_bytes.iter().enumerate() {
            batch.put_cf(&inputs_cf, format!("{wtxid}:{index}"), input_bytes);
            batch.delete_cf(&inputs_cf, format!("{txid}:{index}"));
        }
        counts.rekeyed += 1;
    }
    Ok(wtxid)
}

/// Rebuild transaction `txid` from its version 1 `Tx`, `Inputs` and
/// `Outputs` rows. `NotFound` if any row is missing.
fn read_version_1_transaction(db: &DB, txid: &Txid) -> Result<Version1Transaction, StoreError> {
    let tx_cf = db.cf_handle(&ColumnFamily::Tx).unwrap();
    let inputs_cf = db.cf_handle(&ColumnFamily::Inputs).unwrap();
    let outputs_cf = db.cf_handle(&ColumnFamily::Outputs).unwrap();

    let metadata_bytes = db
        .get_cf(&tx_cf, txid.as_ref() as &[u8])?
        .ok_or_else(|| StoreError::NotFound(format!("Tx row of {txid}")))?;
    let metadata = decode_version_1_tx_metadata(&metadata_bytes)?;

    let mut input_bytes = Vec::with_capacity(metadata.input_count as usize);
    let mut inputs = Vec::with_capacity(metadata.input_count as usize);
    for index in 0..metadata.input_count {
        let bytes = db
            .get_cf(&inputs_cf, format!("{txid}:{index}"))?
            .ok_or_else(|| StoreError::NotFound(format!("Inputs row {txid}:{index}")))?;
        inputs.push(decode_version_1_input(&bytes)?);
        input_bytes.push(bytes);
    }

    let mut outputs = Vec::with_capacity(metadata.output_count as usize);
    for index in 0..metadata.output_count {
        let bytes = db
            .get_cf(&outputs_cf, format!("{txid}:{index}"))?
            .ok_or_else(|| StoreError::NotFound(format!("Outputs row {txid}:{index}")))?;
        outputs.push(decode_version_1_output(&bytes)?);
    }

    if metadata.txid != *txid {
        return Err(StoreError::Serialization(format!(
            "Tx row under {txid} records txid {}",
            metadata.txid
        )));
    }
    Ok(Version1Transaction {
        metadata_bytes,
        input_bytes,
        transaction: Transaction {
            version: metadata.version,
            lock_time: metadata.lock_time,
            input: inputs,
            output: outputs,
        },
    })
}

/// Check that `key` is a `BlockTxids` key: a blockhash then
/// `BLOCK_TXIDS_SUFFIX`.
fn check_block_txids_key_format(key: &[u8]) -> Result<(), StoreError> {
    if key.len() == BLOCK_TXIDS_KEY_LENGTH && key.ends_with(BLOCK_TXIDS_SUFFIX) {
        Ok(())
    } else {
        Err(StoreError::Serialization(format!(
            "unexpected BlockTxids key of {} bytes",
            key.len()
        )))
    }
}

/// Decode a version 1 `BlockTxids` value: a VarInt count, then that many
/// txids.
fn decode_version_1_txids(bytes: &[u8]) -> Result<Vec<Txid>, StoreError> {
    let mut reader = bytes;
    let count = VarInt::consensus_decode(&mut reader)?.0;
    //* Cap the preallocation; a corrupt count runs out of data instead
    let mut txids = Vec::with_capacity(count.min((bytes.len() / HASH_LENGTH) as u64) as usize);
    for _ in 0..count {
        txids.push(Txid::consensus_decode(&mut reader)?);
    }
    expect_consumed(reader, "BlockTxids value")?;
    Ok(txids)
}

/// Encode a version 2 `BlockTxids` value: a VarInt count, then each txid
/// followed by its wtxid.
///
/// Encoding here without using production code as migrations should
/// never encode using production code.
fn encode_version_2_pairs(pairs: &[(Txid, Wtxid)]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_VARINT_LENGTH + pairs.len() * TXID_WTXID_PAIR_LENGTH);
    bytes.extend(serialize(&VarInt(pairs.len() as u64)));
    for (txid, wtxid) in pairs {
        bytes.extend(serialize(txid));
        bytes.extend(serialize(wtxid));
    }
    bytes
}

/// Encode a version 1 `BlockTxids` value, for tests that write a version 1
/// store.
///
/// Again, encode without using production code.
#[cfg(test)]
fn encode_version_1_txids(txids: &[Txid]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_VARINT_LENGTH + txids.len() * HASH_LENGTH);
    bytes.extend(serialize(&VarInt(txids.len() as u64)));
    for txid in txids {
        bytes.extend(serialize(txid));
    }
    bytes
}

/// The `BlockTxids` key of `block`, in versions 1 and 2, for tests that
/// write a version 1 store.
#[cfg(test)]
fn block_txids_key(block: &crate::shares::share_block::ShareBlock) -> Vec<u8> {
    let mut key = serialize(&block.block_hash());
    key.extend_from_slice(BLOCK_TXIDS_SUFFIX);
    key
}

/// Decode a version 1 `Tx` value.
fn decode_version_1_tx_metadata(bytes: &[u8]) -> Result<Version1TxMetadata, StoreError> {
    let mut reader = bytes;
    let txid = Txid::consensus_decode(&mut reader)?;
    let version = bitcoin::transaction::Version::consensus_decode(&mut reader)?;
    let lock_time = bitcoin::absolute::LockTime::consensus_decode(&mut reader)?;
    let input_count = u32::consensus_decode(&mut reader)?;
    let output_count = u32::consensus_decode(&mut reader)?;
    let _validated = bool::consensus_decode(&mut reader)?;
    expect_consumed(reader, "Tx value")?;
    Ok(Version1TxMetadata {
        txid,
        version,
        lock_time,
        input_count,
        output_count,
    })
}

/// Decode a version 1 `Inputs` value: the input, then its witness.
fn decode_version_1_input(bytes: &[u8]) -> Result<TxIn, StoreError> {
    let mut reader = bytes;
    let mut input = TxIn::consensus_decode(&mut reader)?;
    input.witness = bitcoin::Witness::consensus_decode(&mut reader)?;
    expect_consumed(reader, "Inputs value")?;
    Ok(input)
}

/// Decode the output of a version 1 `Outputs` value: the output, then the
/// coinbase flag and `coinbase_root_height`, which are not needed here.
fn decode_version_1_output(bytes: &[u8]) -> Result<TxOut, StoreError> {
    let mut reader = bytes;
    let output = TxOut::consensus_decode(&mut reader)?;
    let _is_coinbase = bool::consensus_decode(&mut reader)?;
    let _coinbase_root_height = u32::consensus_decode(&mut reader)?;
    expect_consumed(reader, "Outputs value")?;
    Ok(output)
}

/// Fail if `remaining` still holds bytes after decoding a value.
fn expect_consumed(remaining: &[u8], what: &str) -> Result<(), StoreError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(StoreError::Serialization(format!(
            "{what} has {} trailing bytes",
            remaining.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::migrations::{
        CURRENT_SCHEMA_VERSION, StoredSchemaVersion, column_family_contents, write_schema_version,
    };
    use crate::test_utils::{TestShareBlockBuilder, coinbase_outpoint, test_funding_transaction};
    use bitcoin::OutPoint;
    use tempfile::tempdir;

    /// A version 1 store, rewritten by the migration, holds exactly the
    /// `Tx`, `Inputs` and `BlockTxids` rows the current code writes for the
    /// same blocks, and every block rebuilds as it was stored.
    #[test]
    fn test_migration_rewrites_a_version_1_store_to_the_current_layout() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let source = TestShareBlockBuilder::new().nonce(1).build();
        let mut witness_spend = test_funding_transaction(coinbase_outpoint(&source), 1_000);
        witness_spend.input[0].witness.push([0x42u8; 4]);
        let plain_spend = test_funding_transaction(
            OutPoint {
                txid: witness_spend.compute_txid(),
                vout: 0,
            },
            500,
        );
        let block = TestShareBlockBuilder::new()
            .nonce(2)
            .add_transaction(witness_spend.clone())
            .add_transaction(plain_spend.clone())
            .build();
        let source_coinbase = source.transactions[0].0.clone();
        let block_coinbase = block.transactions[0].0.clone();
        assert_ne!(
            source_coinbase.compute_wtxid().to_raw_hash(),
            source_coinbase.compute_txid().to_raw_hash()
        );
        assert_ne!(
            witness_spend.compute_wtxid().to_raw_hash(),
            witness_spend.compute_txid().to_raw_hash()
        );
        assert_eq!(
            plain_spend.compute_wtxid().to_raw_hash(),
            plain_spend.compute_txid().to_raw_hash()
        );

        //* Store both blocks with the current code and record the rows it writes
        let store = Store::new(path.clone(), false).unwrap();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&source, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let current_tx_rows = column_family_contents(&store.db, ColumnFamily::Tx);
        let current_input_rows = column_family_contents(&store.db, ColumnFamily::Inputs);
        let current_block_txids_rows = column_family_contents(&store.db, ColumnFamily::BlockTxids);

        //* Rewrite those rows into the version 1 layout: txid keys, txid lists
        {
            let tx_cf = store.db.cf_handle(&ColumnFamily::Tx).unwrap();
            let inputs_cf = store.db.cf_handle(&ColumnFamily::Inputs).unwrap();
            let block_txids_cf = store.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
            let mut batch = WriteBatch::default();
            //* Only rows of transactions with witness data change key
            batch.delete_cf(&tx_cf, source_coinbase.compute_wtxid().as_ref() as &[u8]);
            batch.delete_cf(&inputs_cf, format!("{}:0", source_coinbase.compute_wtxid()));
            batch.put_cf(
                &tx_cf,
                source_coinbase.compute_txid().as_ref() as &[u8],
                store
                    .db
                    .get_cf(&tx_cf, source_coinbase.compute_wtxid().as_ref() as &[u8])
                    .unwrap()
                    .unwrap(),
            );
            batch.put_cf(
                &inputs_cf,
                format!("{}:0", source_coinbase.compute_txid()),
                store
                    .db
                    .get_cf(&inputs_cf, format!("{}:0", source_coinbase.compute_wtxid()))
                    .unwrap()
                    .unwrap(),
            );
            batch.delete_cf(&tx_cf, block_coinbase.compute_wtxid().as_ref() as &[u8]);
            batch.delete_cf(&inputs_cf, format!("{}:0", block_coinbase.compute_wtxid()));
            batch.put_cf(
                &tx_cf,
                block_coinbase.compute_txid().as_ref() as &[u8],
                store
                    .db
                    .get_cf(&tx_cf, block_coinbase.compute_wtxid().as_ref() as &[u8])
                    .unwrap()
                    .unwrap(),
            );
            batch.put_cf(
                &inputs_cf,
                format!("{}:0", block_coinbase.compute_txid()),
                store
                    .db
                    .get_cf(&inputs_cf, format!("{}:0", block_coinbase.compute_wtxid()))
                    .unwrap()
                    .unwrap(),
            );
            batch.delete_cf(&tx_cf, witness_spend.compute_wtxid().as_ref() as &[u8]);
            batch.delete_cf(&inputs_cf, format!("{}:0", witness_spend.compute_wtxid()));
            batch.put_cf(
                &tx_cf,
                witness_spend.compute_txid().as_ref() as &[u8],
                store
                    .db
                    .get_cf(&tx_cf, witness_spend.compute_wtxid().as_ref() as &[u8])
                    .unwrap()
                    .unwrap(),
            );
            batch.put_cf(
                &inputs_cf,
                format!("{}:0", witness_spend.compute_txid()),
                store
                    .db
                    .get_cf(&inputs_cf, format!("{}:0", witness_spend.compute_wtxid()))
                    .unwrap()
                    .unwrap(),
            );
            batch.put_cf(
                &block_txids_cf,
                block_txids_key(&source),
                encode_version_1_txids(&[source_coinbase.compute_txid()]),
            );
            batch.put_cf(
                &block_txids_cf,
                block_txids_key(&block),
                encode_version_1_txids(&[
                    block_coinbase.compute_txid(),
                    witness_spend.compute_txid(),
                    plain_spend.compute_txid(),
                ]),
            );
            store.db.write(batch).unwrap();
        }
        write_schema_version(&store.db, 1).unwrap();
        drop(store);

        let migrated = Store::new(path, false).unwrap();

        assert_eq!(
            migrated.schema_version().unwrap(),
            StoredSchemaVersion::Version(CURRENT_SCHEMA_VERSION)
        );
        assert_eq!(
            column_family_contents(&migrated.db, ColumnFamily::Tx),
            current_tx_rows
        );
        assert_eq!(
            column_family_contents(&migrated.db, ColumnFamily::Inputs),
            current_input_rows
        );
        assert_eq!(
            column_family_contents(&migrated.db, ColumnFamily::BlockTxids),
            current_block_txids_rows
        );
        assert_eq!(migrated.get_share(&source.block_hash()), Some(source));
        assert_eq!(migrated.get_share(&block.block_hash()), Some(block));
    }

    /// A transaction listed by a block but missing its `Tx` row fails the
    /// migration, which commits nothing: the store stays at version 1.
    #[test]
    fn test_migration_with_a_missing_tx_row_leaves_store_at_version_1() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let block = TestShareBlockBuilder::new().build();
        let store = Store::new(path.clone(), false).unwrap();
        {
            let block_txids_cf = store.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
            store
                .db
                .put_cf(
                    &block_txids_cf,
                    block_txids_key(&block),
                    encode_version_1_txids(&[block.transactions[0].compute_txid()]),
                )
                .unwrap();
        }
        write_schema_version(&store.db, 1).unwrap();
        drop(store);

        let error = Store::new(path.clone(), false).err().unwrap();

        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert!(error.to_string().contains("Tx row of"), "{error}");
        let read_only_error = Store::new(path, true).err().unwrap();
        assert!(
            read_only_error.to_string().contains("schema version 1"),
            "{read_only_error}"
        );
    }
}
