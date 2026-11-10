// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confirmed share chain history per script, for wallet history queries.
//!
//! A transaction touches a script when one of its outputs pays it, or one of
//! its inputs spends an output that paid it. `OP_RETURN` outputs are left
//! out: they are provably unspendable, so no wallet owns them, and the share
//! coinbase witness commitment would otherwise give one script a row at
//! every height.
//!
//! Rows live in `ScriptHistory`, keyed `scripthash || height || position`
//! with the txid as value. Heights and positions are big endian, so a
//! prefix scan returns a script's history in height then position order;
//! the position is the transaction's index in its block.
//!
//! The history window is spendable depth: the heights whose outputs the
//! next block on the candidate tip may still spend, starting at
//! `Store::history_start`. Only blocks confirmed inside the window get
//! rows. Those blocks were fully validated, so their prevouts are held by
//! every current node, and every node writes and serves the same rows.
//! Reads never go below the window.
//!
//! Rows are written in the batch that confirms their block and deleted in
//! the batch that reorgs it out, recomputed from the block. Rows that fall
//! below the window are never deleted explicitly: a compaction filter drops
//! them once they are below `history_gc_threshold_for_tip(confirmed tip)`,
//! which stays `PRUNE_INTERVAL` below the window so a small tip drop never
//! exposes a dropped row. Correctness rests on the read bound; the filter
//! only reclaims space.

use super::transaction_store::{StoredTxOut, outpoint_key};
use super::{ColumnFamily, Store, writer::StoreError};
use crate::accounting::payout::sharechain_pplns::pplns_window::{PAYOUT_DEPTH, PRUNE_INTERVAL};
use crate::shares::share_block::ShareTransaction;
use bitcoin::consensus::encode;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Script, ScriptBuf, Transaction, Txid};
use rocksdb::compaction_filter::Decision;
use rocksdb::{Direction, IteratorMode, Options as RocksDbOptions, ReadOptions, WriteBatch};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::warn;

/// `sha256(script_pubkey)` in internal byte order. Electrum shows it
/// reversed.
pub type ScriptHash = [u8; 32];

/// One `ScriptHistory` row as RocksDB iteration yields it: key and value.
type HistoryRow = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

const SCRIPT_HASH_LENGTH: usize = 32;
const HEIGHT_LENGTH: usize = 4;
const POSITION_LENGTH: usize = 4;
const SCRIPT_HISTORY_KEY_LENGTH: usize = SCRIPT_HASH_LENGTH + HEIGHT_LENGTH + POSITION_LENGTH;

/// Every `ScriptHistory` file is compacted, and so filtered, at least this
/// often, bounding how long rows below the threshold stay on disk.
const SCRIPT_HISTORY_PERIODIC_COMPACTION_SECONDS: u64 = 24 * 60 * 60;

/// One confirmed transaction that touches a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptHistoryEntry {
    pub height: u32,
    pub txid: Txid,
}

/// A page of a script's history, in height order. `more` is true when rows
/// remain after the last entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHistoryPage {
    pub entries: Vec<ScriptHistoryEntry>,
    pub has_more: bool,
}

/// The scripthash of `script`.
pub fn script_hash(script: &Script) -> ScriptHash {
    sha256::Hash::hash(script.as_bytes()).to_byte_array()
}

/// The first height of the history window for a tip: the lowest
/// height whose outputs the next block may still spend
/// (`coinbase_root_height >= height - PAYOUT_DEPTH`). Saturates to genesis
/// on a young chain.
pub fn history_start_for_tip(tip_height: u32) -> u32 {
    tip_height
        .saturating_add(1)
        .saturating_sub(PAYOUT_DEPTH as u32)
}

/// The height below which the compaction filter drops script history rows,
/// for a confirmed tip. `PRUNE_INTERVAL` below the window, so the window
/// would have to drop by more than that before it reached a dropped row.
pub fn gc_threshold_for_tip(confirmed_tip_height: u32) -> u32 {
    confirmed_tip_height.saturating_sub((PAYOUT_DEPTH + PRUNE_INTERVAL) as u32)
}

/// Options for the `ScriptHistory` column family. It is range-scanned, so
/// it gets no bloom filter. Its compaction filter drops rows below
/// `gc_threshold`, and periodic compaction makes sure every file is
/// filtered.
pub(super) fn script_history_cf_options(gc_threshold: Arc<AtomicU32>) -> RocksDbOptions {
    let mut options = RocksDbOptions::default();
    options.set_compaction_filter(
        "script_history_gc",
        move |_level: u32, key: &[u8], _value: &[u8]| {
            script_history_gc_decision(key, gc_threshold.load(Ordering::Relaxed))
        },
    );
    options.set_periodic_compaction_seconds(SCRIPT_HISTORY_PERIODIC_COMPACTION_SECONDS);
    options
}

/// Remove a row only when its key is a well-formed `ScriptHistory` key at a
/// height below `threshold`; keep anything else, so a row is never dropped
/// on doubt.
fn script_history_gc_decision(key: &[u8], threshold: u32) -> Decision {
    match history_key_height(key) {
        Some(height) if height < threshold => Decision::Remove,
        _ => Decision::Keep,
    }
}

/// `ScriptHistory` key: `scripthash || height || position`.
fn history_key(scripthash: &ScriptHash, height: u32, position: u32) -> Vec<u8> {
    [
        scripthash.as_slice(),
        &height.to_be_bytes(),
        &position.to_be_bytes(),
    ]
    .concat()
}

/// The height in a `ScriptHistory` key, or `None` when the key does not
/// have the `ScriptHistory` key length.
fn history_key_height(key: &[u8]) -> Option<u32> {
    if key.len() != SCRIPT_HISTORY_KEY_LENGTH {
        return None;
    }
    key.get(SCRIPT_HASH_LENGTH..SCRIPT_HASH_LENGTH + HEIGHT_LENGTH)
        .and_then(|height_bytes| height_bytes.try_into().ok())
        .map(u32::from_be_bytes)
}

/// The txid stored as a `ScriptHistory` value.
fn decode_history_txid(value: &[u8]) -> Result<Txid, StoreError> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| {
        StoreError::Serialization(format!("Invalid script history txid: {value:?}"))
    })?;
    Ok(Txid::from_byte_array(bytes))
}

impl Store {
    /// The first height of the history window for the current candidate
    /// tip. Genesis when there is no candidate tip yet. Store read errors are
    /// propagated.
    pub fn history_start(&self) -> Result<u32, StoreError> {
        match self.get_top_candidate_height() {
            Ok(tip_height) => Ok(history_start_for_tip(tip_height)),
            Err(StoreError::NotFound(_)) => Ok(0),
            Err(error) => Err(error),
        }
    }

    /// Write the script history rows of the block confirmed at `height`
    /// into `batch`, when `height` is inside the history window. Blocks
    /// below the window get no rows: they would never be served.
    ///
    /// Prevouts are read from the committed store, so the bodies of the
    /// block and of the transactions it spends must already be committed.
    pub(crate) fn add_script_history_for_block(
        &self,
        height: u32,
        txs: &[ShareTransaction],
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        if height >= self.history_start()? {
            let history_cf = self.db.cf_handle(&ColumnFamily::ScriptHistory).unwrap();
            for (key, txid) in self.script_history_keys(height, txs)? {
                batch.put_cf(&history_cf, key, txid.to_byte_array());
            }
        }
        Ok(())
    }

    /// Delete the script history rows of the block reorged out at `height`
    /// into `batch`, recomputing their keys as the write did. There is no
    /// window check: deleting a key that was never written is a no-op, and
    /// skipping the delete could leave a row that a later, lower window
    /// would serve.
    pub(crate) fn remove_script_history_for_block(
        &self,
        height: u32,
        txs: &[ShareTransaction],
        batch: &mut WriteBatch,
    ) -> Result<(), StoreError> {
        let history_cf = self.db.cf_handle(&ColumnFamily::ScriptHistory).unwrap();
        for (key, _txid) in self.script_history_keys(height, txs)? {
            batch.delete_cf(&history_cf, key);
        }
        Ok(())
    }

    /// The `ScriptHistory` keys of the block at `height` holding `txs`, each
    /// with the txid its row stores: one per distinct script each
    /// transaction touches.
    fn script_history_keys(
        &self,
        height: u32,
        txs: &[ShareTransaction],
    ) -> Result<Vec<(Vec<u8>, Txid)>, StoreError> {
        let capacity = txs
            .iter()
            .map(|share_transaction| {
                share_transaction.0.output.len() + share_transaction.0.input.len()
            })
            .sum();
        let mut keys = Vec::with_capacity(capacity);
        for (index, share_transaction) in txs.iter().enumerate() {
            let transaction = &share_transaction.0;
            let position = u32::try_from(index).map_err(|_| {
                StoreError::Serialization(format!("Transaction position {index} exceeds u32"))
            })?;
            let txid = transaction.compute_txid();
            keys.extend(
                self.touched_script_hashes(transaction)?
                    .into_iter()
                    .map(|scripthash| (history_key(&scripthash, height, position), txid)),
            );
        }
        Ok(keys)
    }

    /// The distinct scripthashes `transaction` touches: its non-`OP_RETURN`
    /// outputs and, unless it is a coinbase, the outputs its inputs spend.
    fn touched_script_hashes(
        &self,
        transaction: &Transaction,
    ) -> Result<HashSet<ScriptHash>, StoreError> {
        let mut scripthashes =
            HashSet::with_capacity(transaction.output.len() + transaction.input.len());
        scripthashes.extend(
            transaction
                .output
                .iter()
                .filter(|output| !output.script_pubkey.is_op_return())
                .map(|output| script_hash(&output.script_pubkey)),
        );
        if !transaction.is_coinbase() {
            scripthashes.extend(
                self.prevout_scripts(transaction)?
                    .iter()
                    .map(|script| script_hash(script)),
            );
        }
        Ok(scripthashes)
    }

    /// The scripts of the outputs `transaction` spends, read with one
    /// `multi_get_cf`.
    ///
    /// A missing prevout is skipped with a warning rather than failing: the
    /// index must never stall confirmation, and inside the history window a
    /// prevout can only be missing through corruption, so skipping can make
    /// history incomplete but never wrong. Read and decode errors propagate.
    fn prevout_scripts(&self, transaction: &Transaction) -> Result<Vec<ScriptBuf>, StoreError> {
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let keys: Vec<String> = transaction
            .input
            .iter()
            .map(|input| outpoint_key(&input.previous_output.txid, input.previous_output.vout))
            .collect();
        let results = self
            .db
            .multi_get_cf(keys.iter().map(|key| (&outputs_cf, key.as_bytes())));
        let mut scripts = Vec::with_capacity(keys.len());
        for (key, result) in keys.iter().zip(results) {
            match result? {
                Some(bytes) => {
                    let stored: StoredTxOut = encode::deserialize(&bytes).map_err(|error| {
                        StoreError::Serialization(format!(
                            "Failed to deserialize output {key}: {error}"
                        ))
                    })?;
                    scripts.push(stored.tx_out.script_pubkey);
                }
                None => warn!(
                    "Script history skips missing prevout {key} of transaction {}",
                    transaction.compute_txid()
                ),
            }
        }
        Ok(scripts)
    }

    /// Set the compaction filter threshold from the confirmed tip. Leaves it
    /// unchanged when there is no confirmed tip yet. Callers update it only
    /// while the node is current, so a syncing node never drops rows.
    pub fn update_script_history_gc_threshold(&self) -> Result<(), StoreError> {
        match self.get_top_confirmed_height() {
            Ok(confirmed_tip_height) => {
                self.script_history_gc_threshold.store(
                    gc_threshold_for_tip(confirmed_tip_height),
                    Ordering::Relaxed,
                );
                Ok(())
            }
            Err(StoreError::NotFound(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read one page of the confirmed history of `scripthash`, starting at
    /// `start_height` but never below the history window, in height then
    /// position order.
    ///
    /// A page ends only at a height boundary, with at least `max_rows`
    /// entries unless the history runs out first (see
    /// `collect_history_page`). `more` tells whether any row is left after
    /// the page.
    pub fn get_script_history(
        &self,
        scripthash: &ScriptHash,
        start_height: u32,
        max_rows: usize,
    ) -> Result<ScriptHistoryPage, StoreError> {
        let history_cf = self.db.cf_handle(&ColumnFamily::ScriptHistory).unwrap();
        let from_height = start_height.max(self.history_start()?);
        let (lower_key, upper_key) = history_scan_bounds(scripthash, from_height);
        let mut read_options = ReadOptions::default();
        read_options.set_iterate_lower_bound(lower_key.clone());
        read_options.set_iterate_upper_bound(upper_key);
        let rows = self.db.iterator_cf_opt(
            &history_cf,
            read_options,
            IteratorMode::From(&lower_key, Direction::Forward),
        );
        collect_history_page(rows, max_rows)
    }
}

/// The `ScriptHistory` key range of `scripthash` from `from_height` on: an
/// inclusive lower bound and an exclusive upper bound. The upper bound is one
/// byte longer than every key of this scripthash, so it sorts after the last
/// of them and before the next scripthash.
fn history_scan_bounds(scripthash: &ScriptHash, from_height: u32) -> (Vec<u8>, Vec<u8>) {
    let lower_key = history_key(scripthash, from_height, 0);
    let mut upper_key = history_key(scripthash, u32::MAX, u32::MAX);
    upper_key.push(0);
    (lower_key, upper_key)
}

/// Collect `ScriptHistory` rows, in key order, into one page: rows are taken
/// until there are at least `max_rows` and the next row is at a new height,
/// so all rows of one height are always in the same page. `more` tells
/// whether a row was left. The page is not sized to `max_rows` up front,
/// since most histories are far shorter.
fn collect_history_page<Rows>(
    mut rows: Rows,
    max_rows: usize,
) -> Result<ScriptHistoryPage, StoreError>
where
    Rows: Iterator<Item = HistoryRow>,
{
    let mut entries: Vec<ScriptHistoryEntry> = Vec::new();
    let mut more = false;
    let mut scanning = true;
    while scanning {
        match rows.next() {
            None => scanning = false,
            Some(row) => {
                let (key, value) = row?;
                let height = history_key_height(&key).ok_or_else(|| {
                    StoreError::Serialization(format!("Invalid script history key: {key:?}"))
                })?;
                let page_full = entries.len() >= max_rows
                    && entries.last().is_none_or(|last| last.height != height);
                if page_full {
                    more = true;
                    scanning = false;
                } else {
                    entries.push(ScriptHistoryEntry {
                        height,
                        txid: decode_history_txid(&value)?,
                    });
                }
            }
        }
    }
    Ok(ScriptHistoryPage {
        entries,
        has_more: more,
    })
}

#[cfg(test)]
impl Store {
    /// The current compaction filter threshold.
    pub(crate) fn script_history_gc_threshold(&self) -> u32 {
        self.script_history_gc_threshold.load(Ordering::Relaxed)
    }

    /// Set the compaction filter threshold directly.
    pub(crate) fn set_script_history_gc_threshold(&self, threshold: u32) {
        self.script_history_gc_threshold
            .store(threshold, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership, Status};
    use crate::test_utils::{
        PUBKEY_2G, TestShareBlockBuilder, build_confirmed_test_chain, confirm_test_block,
        genesis_for_tests, make_test_share_program, setup_test_chain_store_handle,
        test_funding_transaction,
    };
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use bitcoin::{absolute::LockTime, transaction::Version};
    use tempfile::tempdir;

    /// Three rows at one height and a page size of one: the page still
    /// holds all three, because a page only ends at a height boundary.
    #[test]
    fn page_keeps_every_row_of_a_height_past_max_rows() {
        let scripthash = script_hash(&ScriptBuf::new_witness_program(&make_test_share_program(1)));
        let txids = [
            test_funding_transaction(1).compute_txid(),
            test_funding_transaction(2).compute_txid(),
            test_funding_transaction(3).compute_txid(),
        ];
        let rows: Vec<HistoryRow> = vec![
            Ok((
                history_key(&scripthash, 5, 0).into_boxed_slice(),
                Box::from(txids[0].to_byte_array()),
            )),
            Ok((
                history_key(&scripthash, 5, 1).into_boxed_slice(),
                Box::from(txids[1].to_byte_array()),
            )),
            Ok((
                history_key(&scripthash, 5, 2).into_boxed_slice(),
                Box::from(txids[2].to_byte_array()),
            )),
        ];

        let page = collect_history_page(rows.into_iter(), 1).unwrap();

        assert_eq!(
            page,
            ScriptHistoryPage {
                entries: vec![
                    ScriptHistoryEntry {
                        height: 5,
                        txid: txids[0],
                    },
                    ScriptHistoryEntry {
                        height: 5,
                        txid: txids[1],
                    },
                    ScriptHistoryEntry {
                        height: 5,
                        txid: txids[2],
                    },
                ],
                has_more: false,
            }
        );
    }

    #[test]
    fn page_of_zero_rows_is_empty_and_reports_more() {
        let scripthash = script_hash(&ScriptBuf::new_witness_program(&make_test_share_program(1)));
        let rows: Vec<HistoryRow> = vec![Ok((
            history_key(&scripthash, 5, 0).into_boxed_slice(),
            Box::from(test_funding_transaction(1).compute_txid().to_byte_array()),
        ))];

        let page = collect_history_page(rows.into_iter(), 0).unwrap();

        assert_eq!(
            page,
            ScriptHistoryPage {
                entries: Vec::new(),
                has_more: true,
            }
        );
    }

    /// The bounds hold every key of the scripthash from the start height,
    /// including the largest possible one, and no key of the next
    /// scripthash.
    #[test]
    fn scan_bounds_cover_exactly_one_scripthash_from_start_height() {
        let scripthash = [0x40; 32];
        let next_scripthash = [0x41; 32];

        let (lower_key, upper_key) = history_scan_bounds(&scripthash, 7);

        assert!(history_key(&scripthash, 6, u32::MAX) < lower_key);
        assert!(history_key(&scripthash, 7, 0) >= lower_key);
        assert!(history_key(&scripthash, u32::MAX, u32::MAX) < upper_key);
        assert!(history_key(&next_scripthash, 0, 0) >= upper_key);
    }

    #[tokio::test]
    async fn confirmed_block_records_payout_script_and_skips_op_return() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let store = chain_store_handle.store_handle().store();
        let coinbase = &blocks[1].transactions[0].0;
        assert!(coinbase.output[1].script_pubkey.is_op_return());
        let payout = script_hash(&coinbase.output[0].script_pubkey);
        let commitment = script_hash(&coinbase.output[1].script_pubkey);

        let payout_history = store.get_script_history(&payout, 1, 10).unwrap();
        let commitment_history = store.get_script_history(&commitment, 0, 10).unwrap();

        assert_eq!(
            payout_history,
            ScriptHistoryPage {
                entries: vec![ScriptHistoryEntry {
                    height: 1,
                    txid: coinbase.compute_txid(),
                }],
                has_more: false,
            }
        );
        assert!(commitment_history.entries.is_empty());
    }

    #[tokio::test]
    async fn genesis_coinbase_is_recorded_at_height_zero() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let store = chain_store_handle.store_handle().store();
        let genesis_coinbase = &blocks[0].transactions[0].0;
        let payout = script_hash(&genesis_coinbase.output[0].script_pubkey);

        let history = store.get_script_history(&payout, 0, 1).unwrap();

        assert_eq!(
            history.entries,
            vec![ScriptHistoryEntry {
                height: 0,
                txid: genesis_coinbase.compute_txid(),
            }]
        );
    }

    #[tokio::test]
    async fn blocks_paying_one_address_are_in_height_order() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let store = chain_store_handle.store_handle().store();
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = store.get_script_history(&payout, 0, 10).unwrap();

        assert_eq!(
            history.entries,
            vec![
                ScriptHistoryEntry {
                    height: 0,
                    txid: blocks[0].transactions[0].0.compute_txid(),
                },
                ScriptHistoryEntry {
                    height: 1,
                    txid: blocks[1].transactions[0].0.compute_txid(),
                },
                ScriptHistoryEntry {
                    height: 2,
                    txid: blocks[2].transactions[0].0.compute_txid(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn block_paying_another_miner_is_in_that_miners_history_only() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let other_miner_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_002)
            .build();
        confirm_test_block(&chain_store_handle, &other_miner_block).await;
        let store = chain_store_handle.store_handle().store();
        let default_payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        let other_coinbase = &other_miner_block.transactions[0].0;
        let other_payout = script_hash(&other_coinbase.output[0].script_pubkey);

        let other_history = store.get_script_history(&other_payout, 0, 10).unwrap();
        let default_history = store.get_script_history(&default_payout, 2, 10).unwrap();

        assert_eq!(
            other_history.entries,
            vec![ScriptHistoryEntry {
                height: 2,
                txid: other_coinbase.compute_txid(),
            }]
        );
        assert!(default_history.entries.is_empty());
    }

    /// The spender pays one script twice and spends block 1's payout, so it
    /// gets one row for the paid script and one for the spent script, after
    /// its block's coinbase at the same height.
    #[tokio::test]
    async fn spending_transaction_records_prevout_and_paid_scripts_once() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let spent_coinbase = &blocks[1].transactions[0].0;
        let paid_script = ScriptBuf::new_witness_program(&make_test_share_program(3));
        let spending_transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(spent_coinbase.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: paid_script.clone(),
                },
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: paid_script.clone(),
                },
            ],
        };
        let spending_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .time(1_700_000_002)
            .add_transaction(spending_transaction.clone())
            .build();
        confirm_test_block(&chain_store_handle, &spending_block).await;
        let store = chain_store_handle.store_handle().store();
        let spent_payout = script_hash(&spent_coinbase.output[0].script_pubkey);

        let paid_history = store
            .get_script_history(&script_hash(&paid_script), 0, 10)
            .unwrap();
        let spent_history = store.get_script_history(&spent_payout, 2, 10).unwrap();

        assert_eq!(
            paid_history.entries,
            vec![ScriptHistoryEntry {
                height: 2,
                txid: spending_transaction.compute_txid(),
            }]
        );
        assert_eq!(
            spent_history.entries,
            vec![
                ScriptHistoryEntry {
                    height: 2,
                    txid: spending_block.transactions[0].0.compute_txid(),
                },
                ScriptHistoryEntry {
                    height: 2,
                    txid: spending_transaction.compute_txid(),
                },
            ]
        );
    }

    #[test]
    fn header_only_confirmation_records_no_history() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let header_only = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_001)
            .build();
        store.create_valid_metadata_only(&header_only);
        let mut metadata = store.get_block_metadata(&header_only.block_hash()).unwrap();
        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(&header_only.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let payout = script_hash(&header_only.transactions[0].0.output[0].script_pubkey);

        let history = store.get_script_history(&payout, 0, 10).unwrap();

        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            header_only.block_hash()
        );
        assert!(history.entries.is_empty());
    }

    #[tokio::test]
    async fn history_from_start_height_skips_lower_heights() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 3).await;
        let store = chain_store_handle.store_handle().store();
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = store.get_script_history(&payout, 2, 10).unwrap();

        assert_eq!(
            history,
            ScriptHistoryPage {
                entries: vec![
                    ScriptHistoryEntry {
                        height: 2,
                        txid: blocks[2].transactions[0].0.compute_txid(),
                    },
                    ScriptHistoryEntry {
                        height: 3,
                        txid: blocks[3].transactions[0].0.compute_txid(),
                    },
                ],
                has_more: false,
            }
        );
    }

    #[tokio::test]
    async fn full_page_reports_more_rows() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 3).await;
        let store = chain_store_handle.store_handle().store();
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let first_page = store.get_script_history(&payout, 0, 2).unwrap();
        let second_page = store.get_script_history(&payout, 2, 2).unwrap();

        assert_eq!(
            first_page
                .entries
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(first_page.has_more);
        assert_eq!(
            second_page
                .entries
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(!second_page.has_more);
    }

    /// Height 2 holds two rows for the spent script (the coinbase and the
    /// spender), so a page that fills up at height 2 still returns both.
    #[tokio::test]
    async fn page_ends_only_at_a_height_boundary() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let spent_coinbase = &blocks[1].transactions[0].0;
        let spending_transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(spent_coinbase.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_witness_program(&make_test_share_program(3)),
            }],
        };
        let spending_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .time(1_700_000_002)
            .add_transaction(spending_transaction)
            .build();
        confirm_test_block(&chain_store_handle, &spending_block).await;
        let store = chain_store_handle.store_handle().store();
        let payout = script_hash(&spent_coinbase.output[0].script_pubkey);

        let page = store.get_script_history(&payout, 0, 3).unwrap();

        assert_eq!(
            page.entries
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 2]
        );
        assert!(!page.has_more);
    }

    #[tokio::test]
    async fn unknown_script_has_empty_history() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;
        let store = chain_store_handle.store_handle().store();
        let unknown = script_hash(&ScriptBuf::new_witness_program(&make_test_share_program(4)));

        let history = store.get_script_history(&unknown, 0, 10).unwrap();

        assert_eq!(
            history,
            ScriptHistoryPage {
                entries: Vec::new(),
                has_more: false,
            }
        );
    }

    /// With the candidate tip at `PAYOUT_DEPTH + 1`, the history window
    /// starts at height 2, so the rows at heights 0 and 1 are on disk but not
    /// returned.
    #[tokio::test]
    async fn rows_below_history_start_are_not_returned() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let store = chain_store_handle.store_handle().store();
        let mut batch = Store::get_write_batch();
        store.set_top_candidate_height(PAYOUT_DEPTH as u32 + 1, &mut batch);
        store.commit_batch(batch).unwrap();
        assert_eq!(store.history_start().unwrap(), 2);
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        let only_kept = vec![ScriptHistoryEntry {
            height: 2,
            txid: blocks[2].transactions[0].0.compute_txid(),
        }];

        let from_zero = store.get_script_history(&payout, 0, 10).unwrap();
        let from_one = store.get_script_history(&payout, 1, 10).unwrap();

        assert_eq!(from_zero.entries, only_kept);
        assert_eq!(from_one.entries, only_kept);
    }

    #[test]
    fn history_start_includes_every_spendable_height() {
        assert_eq!(history_start_for_tip(0), 0);
        assert_eq!(history_start_for_tip(PAYOUT_DEPTH as u32 - 1), 0);
        assert_eq!(history_start_for_tip(PAYOUT_DEPTH as u32), 1);
        assert_eq!(history_start_for_tip(PAYOUT_DEPTH as u32 + 9), 10);
    }

    #[test]
    fn gc_threshold_stays_prune_interval_below_history_start() {
        let confirmed_tip = (PAYOUT_DEPTH + PRUNE_INTERVAL) as u32 + 5;

        assert_eq!(gc_threshold_for_tip(confirmed_tip), 5);
        assert_eq!(
            history_start_for_tip(confirmed_tip) - gc_threshold_for_tip(confirmed_tip),
            PRUNE_INTERVAL as u32 + 1
        );
        assert_eq!(gc_threshold_for_tip(PAYOUT_DEPTH as u32), 0);
    }

    /// The candidate tip puts the window start above height 1, so confirming
    /// a block at height 1 writes nothing; lowering the tip again shows no
    /// row was written.
    #[test]
    fn block_confirmed_below_history_start_records_no_history() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.set_top_candidate_height(PAYOUT_DEPTH as u32 + 10, &mut batch);
        store.commit_batch(batch).unwrap();
        assert!(store.history_start().unwrap() > 1);
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_001)
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, &mut batch).unwrap();
        let mut metadata = BlockMetadata {
            expected_height: Some(1),
            chain_work: block.header.get_work(),
            status: Status::BlockValid,
            chain: ChainMembership::None,
        };
        store
            .update_block_metadata(&block.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(&block.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.set_top_candidate_height(1, &mut batch);
        store.commit_batch(batch).unwrap();
        let payout = script_hash(&block.transactions[0].0.output[0].script_pubkey);

        let history = store.get_script_history(&payout, 0, 10).unwrap();

        assert_eq!(
            store.get_confirmed_at_height(1).unwrap(),
            block.block_hash()
        );
        assert!(history.entries.is_empty());
    }

    #[test]
    fn gc_removes_only_well_formed_rows_below_threshold() {
        let scripthash = script_hash(&ScriptBuf::new_witness_program(&make_test_share_program(1)));
        let mut too_long_key = history_key(&scripthash, 3, 0);
        too_long_key.push(0);

        assert!(matches!(
            script_history_gc_decision(&history_key(&scripthash, 4, 0), 5),
            Decision::Remove
        ));
        assert!(matches!(
            script_history_gc_decision(&history_key(&scripthash, 5, 0), 5),
            Decision::Keep
        ));
        assert!(matches!(
            script_history_gc_decision(&history_key(&scripthash, 4, 0), 0),
            Decision::Keep
        ));
        assert!(matches!(
            script_history_gc_decision(&too_long_key, 5),
            Decision::Keep
        ));
    }

    #[tokio::test]
    async fn compaction_drops_rows_below_threshold_and_keeps_the_rest() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 3).await;
        let store = chain_store_handle.store_handle().store();
        let history_cf = store.db.cf_handle(&ColumnFamily::ScriptHistory).unwrap();
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        store
            .script_history_gc_threshold
            .store(2, Ordering::Relaxed);

        store
            .db
            .compact_range_cf(&history_cf, None::<&[u8]>, None::<&[u8]>);

        assert_eq!(
            store
                .get_script_history(&payout, 0, 10)
                .unwrap()
                .entries
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[tokio::test]
    async fn compaction_with_zero_threshold_keeps_every_row() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 3).await;
        let store = chain_store_handle.store_handle().store();
        let history_cf = store.db.cf_handle(&ColumnFamily::ScriptHistory).unwrap();
        let payout = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        store
            .db
            .compact_range_cf(&history_cf, None::<&[u8]>, None::<&[u8]>);

        assert_eq!(
            store
                .get_script_history(&payout, 0, 10)
                .unwrap()
                .entries
                .iter()
                .map(|entry| entry.height)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn gc_threshold_follows_confirmed_tip() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height((PAYOUT_DEPTH + PRUNE_INTERVAL) as u32 + 7, &mut batch);
        store.commit_batch(batch).unwrap();

        store.update_script_history_gc_threshold().unwrap();

        assert_eq!(store.script_history_gc_threshold(), 7);
    }

    #[test]
    fn gc_threshold_is_unchanged_without_confirmed_tip() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        store
            .script_history_gc_threshold
            .store(7, Ordering::Relaxed);

        store.update_script_history_gc_threshold().unwrap();

        assert_eq!(store.script_history_gc_threshold(), 7);
    }

    /// The spender's prevout row is deleted after the spender's body is
    /// stored, as corruption would. Confirming still succeeds and writes the
    /// spender's other rows; only the spend row is skipped.
    #[test]
    fn missing_prevout_is_skipped_when_writing() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let genesis_coinbase = &genesis.transactions[0].0;
        let paid_script = ScriptBuf::new_witness_program(&make_test_share_program(3));
        let spending_transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(genesis_coinbase.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: paid_script.clone(),
            }],
        };
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_001)
            .add_transaction(spending_transaction.clone())
            .build();
        let mut batch = Store::get_write_batch();
        store.add_share_block(&block, &mut batch).unwrap();
        let mut metadata = BlockMetadata {
            expected_height: Some(1),
            chain_work: block.header.get_work(),
            status: Status::BlockValid,
            chain: ChainMembership::None,
        };
        store
            .update_block_metadata(&block.block_hash(), &metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let outputs_cf = store.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut batch = Store::get_write_batch();
        batch.delete_cf(
            &outputs_cf,
            outpoint_key(&genesis_coinbase.compute_txid(), 0),
        );
        store.commit_batch(batch).unwrap();

        let mut batch = Store::get_write_batch();
        store
            .append_to_confirmed(&block.block_hash(), 1, &mut metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let spent_payout = script_hash(&genesis_coinbase.output[0].script_pubkey);

        let paid_history = store
            .get_script_history(&script_hash(&paid_script), 0, 10)
            .unwrap();
        let spent_history = store.get_script_history(&spent_payout, 1, 10).unwrap();

        assert_eq!(
            paid_history.entries,
            vec![ScriptHistoryEntry {
                height: 1,
                txid: spending_transaction.compute_txid(),
            }]
        );
        assert!(spent_history.entries.is_empty());
    }

    /// Rewinding a block with a spend deletes its coinbase row, the row of
    /// the script it pays and the spend row under the script it spends, and
    /// nothing else: the spent output's own row stays.
    #[tokio::test]
    async fn rewind_removes_spend_rows_of_reorged_out_block() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let spent_coinbase = &blocks[1].transactions[0].0;
        let paid_script = ScriptBuf::new_witness_program(&make_test_share_program(3));
        let spending_transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(spent_coinbase.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: paid_script.clone(),
            }],
        };
        let spending_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_002)
            .add_transaction(spending_transaction.clone())
            .build();
        confirm_test_block(&chain_store_handle, &spending_block).await;
        let store = chain_store_handle.store_handle().store();
        let spent_payout = script_hash(&spent_coinbase.output[0].script_pubkey);
        let spending_coinbase_payout =
            script_hash(&spending_block.transactions[0].0.output[0].script_pubkey);
        let paid = script_hash(&paid_script);
        assert_eq!(
            store
                .get_script_history(&spent_payout, 1, 10)
                .unwrap()
                .entries,
            vec![
                ScriptHistoryEntry {
                    height: 1,
                    txid: spent_coinbase.compute_txid(),
                },
                ScriptHistoryEntry {
                    height: 2,
                    txid: spending_transaction.compute_txid(),
                },
            ]
        );
        assert_eq!(
            store
                .get_script_history(&spending_coinbase_payout, 0, 10)
                .unwrap()
                .entries
                .len(),
            1
        );
        assert_eq!(
            store
                .get_script_history(&paid, 0, 10)
                .unwrap()
                .entries
                .len(),
            1
        );

        let mut batch = Store::get_write_batch();
        store
            .remove_script_history_for_block(2, &spending_block.transactions, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(
            store
                .get_script_history(&spent_payout, 1, 10)
                .unwrap()
                .entries,
            vec![ScriptHistoryEntry {
                height: 1,
                txid: spent_coinbase.compute_txid(),
            }]
        );
        assert!(
            store
                .get_script_history(&spending_coinbase_payout, 0, 10)
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            store
                .get_script_history(&paid, 0, 10)
                .unwrap()
                .entries
                .is_empty()
        );
    }

    /// The spender's rows are written, then its prevout row is deleted, as
    /// corruption would. The rewind still deletes every row it can derive.
    #[tokio::test]
    async fn missing_prevout_is_skipped_when_rewinding() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let spent_coinbase = &blocks[1].transactions[0].0;
        let paid_script = ScriptBuf::new_witness_program(&make_test_share_program(3));
        let spending_transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(spent_coinbase.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: paid_script.clone(),
            }],
        };
        let spending_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .miner_pubkey(PUBKEY_2G)
            .time(1_700_000_002)
            .add_transaction(spending_transaction)
            .build();
        confirm_test_block(&chain_store_handle, &spending_block).await;
        let store = chain_store_handle.store_handle().store();
        let outputs_cf = store.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let mut batch = Store::get_write_batch();
        batch.delete_cf(&outputs_cf, outpoint_key(&spent_coinbase.compute_txid(), 0));
        store.commit_batch(batch).unwrap();
        let spending_coinbase_payout =
            script_hash(&spending_block.transactions[0].0.output[0].script_pubkey);
        assert_eq!(
            store
                .get_script_history(&script_hash(&paid_script), 0, 10)
                .unwrap()
                .entries
                .len(),
            1
        );

        let mut batch = Store::get_write_batch();
        store
            .remove_script_history_for_block(2, &spending_block.transactions, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(
            store
                .get_script_history(&script_hash(&paid_script), 0, 10)
                .unwrap()
                .entries
                .is_empty()
        );
        assert!(
            store
                .get_script_history(&spending_coinbase_payout, 0, 10)
                .unwrap()
                .entries
                .is_empty()
        );
    }
}
