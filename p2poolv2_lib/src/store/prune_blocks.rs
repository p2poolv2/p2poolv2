// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block body pruning.
//!
//! The gates' boundary is derived from the candidate tip, the deletion
//! target from the confirmed tip, and the pruner's start point from the
//! data; nothing is persisted. See `docs/architecture/pruning.md`.

use crate::accounting::payout::sharechain_pplns::pplns_window::{PRUNE_DEPTH, PRUNE_INTERVAL};
use crate::store::Store;
use crate::store::block_tx_metadata::TxMetadata;
use crate::store::column_families::ColumnFamily;
use crate::store::transaction_store::{
    BITCOIN_TXIDS_SUFFIX, BLOCK_TXIDS_SUFFIX, BlockTransactionIds, input_key, outpoint_key,
    txids_key,
};
use crate::store::writer::StoreError;
use bitcoin::consensus::{self, encode};
use bitcoin::{BlockHash, Txid, Wtxid};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

/// Genesis is defined in code and kept whole, so pruning starts above it.
const FIRST_PRUNABLE_HEIGHT: u32 = 1;

/// Counts of what a prune deleted, for logging.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    /// Blocks whose bodies were deleted.
    pub blocks: usize,
    /// Transactions (by wtxid) deleted because no kept block holds them.
    pub transactions: usize,
}

/// What pruning deletes for one txid that the pruned blocks hold.
enum PrunedTransaction {
    /// No kept block references `txid`: delete its outputs, the spends
    /// recorded against them and its `TxidsBlocks` entry, and the metadata
    /// and inputs of every wtxid the pruned blocks hold for it.
    Delete { txid: Txid, wtxids: Vec<Wtxid> },
    /// A kept block references the txid: keep its outputs, and delete the
    /// metadata and inputs of only the wtxids no kept block holds.
    KeepOutputs { wtxids: Vec<Wtxid> },
}

impl PrunedTransaction {
    /// The wtxids whose metadata and inputs are deleted.
    fn wtxids(&self) -> &[Wtxid] {
        match self {
            PrunedTransaction::Delete { wtxids, .. } => wtxids,
            PrunedTransaction::KeepOutputs { wtxids } => wtxids,
        }
    }
}

impl PruneStats {
    /// Add another chunk's counts to these.
    pub fn add(&mut self, other: PruneStats) {
        self.blocks += other.blocks;
        self.transactions += other.transactions;
    }
}

/// Lowest height whose block body a node must hold for a candidate tip.
///
/// Blocks below it are promoted header-only and their bodies are never
/// fetched. The confirmation and ancestry gates use this boundary.
pub fn prune_height_for_tip(candidate_tip_height: u32) -> u32 {
    candidate_tip_height.saturating_sub(PRUNE_DEPTH as u32)
}

/// Height below which block bodies are deleted, for a confirmed tip.
///
/// Measured from the confirmed tip, not the candidate tip, so deletion never
/// reaches heights the confirmed chain has not got to, and does not follow
/// the candidate tip when `mark_invalid` cuts it back. The confirmed tip never
/// passes the candidate tip, so the target stays at least one
/// `PRUNE_INTERVAL` below the gates' `prune_height_for_tip`: peers slightly
/// behind can still fetch bodies near the boundary.
pub fn prune_target_for_tip(confirmed_tip_height: u32) -> u32 {
    confirmed_tip_height.saturating_sub((PRUNE_DEPTH + PRUNE_INTERVAL) as u32)
}

/// The heights `[start, prune_target)` the pruner should delete now, or None
/// when it has nothing to do.
///
/// Pruning runs only while the node is current, and only once the target is
/// above genesis, which also means there is a confirmed tip. The start is
/// `next_prune_start`, where the previous run stopped, or else
/// `find_prune_start` derives it from the store; the search runs only when
/// both gates pass.
pub fn get_range_to_prune(
    is_current: bool,
    prune_target: u32,
    next_prune_start: Option<u32>,
    find_prune_start: impl FnOnce(u32) -> Result<u32, StoreError>,
) -> Result<Option<Range<u32>>, StoreError> {
    if !is_current || prune_target <= FIRST_PRUNABLE_HEIGHT {
        return Ok(None);
    }
    let prune_start = match next_prune_start {
        Some(prune_start) => prune_start,
        None => find_prune_start(prune_target)?,
    };
    Ok((prune_start < prune_target).then_some(prune_start..prune_target))
}

impl Store {
    /// The prune height for the current candidate tip.
    ///
    /// Returns 0 when there is no candidate tip yet. Store read errors are
    /// propagated.
    pub fn prune_height(&self) -> Result<u32, StoreError> {
        match self.get_top_candidate_height() {
            Ok(candidate_tip_height) => Ok(prune_height_for_tip(candidate_tip_height)),
            Err(StoreError::NotFound(_)) => Ok(0),
            Err(error) => Err(error),
        }
    }

    /// The prune target for the current confirmed tip: bodies below it are
    /// deleted and never stored again. The pruner, the writer guard and the
    /// reorg depth limit all read it here.
    ///
    /// Returns 0 when there is no confirmed tip yet. Store read errors are
    /// propagated.
    pub fn prune_target(&self) -> Result<u32, StoreError> {
        match self.get_top_confirmed_height() {
            Ok(confirmed_tip_height) => Ok(prune_target_for_tip(confirmed_tip_height)),
            Err(StoreError::NotFound(_)) => Ok(0),
            Err(error) => Err(error),
        }
    }

    /// Lowest height from which block bodies may still need pruning, below
    /// `target`.
    ///
    /// Binary search for the lowest height whose confirmed block still has
    /// its body. Bodies exist only above the original fetch floor and the
    /// pruned range, so "has a body" is false then true going up the
    /// confirmed chain. Correctness does not depend on the search: a start
    /// too low re-checks heights, and deletes are idempotent; a start too
    /// high leaks a few fork bodies. Returns `target` when nothing below it
    /// has a body.
    pub fn find_prune_start(&self, target: u32) -> Result<u32, StoreError> {
        let search_end = target.min(self.get_top_confirmed_height()?.saturating_add(1));
        let mut low = FIRST_PRUNABLE_HEIGHT;
        let mut high = search_end;
        while low < high {
            let middle = low + (high - low) / 2;
            let blockhash = self.get_confirmed_at_height(middle)?;
            if self.share_block_exists(&blockhash) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        if low >= search_end {
            Ok(target)
        } else {
            Ok(low)
        }
    }

    /// Delete the bodies of every block at heights `[from, to)`, forks and
    /// uncles included, into `batch`.
    ///
    /// Headers, metadata, merkle branches and found blocks are kept. A
    /// transaction's outputs are deleted only when no block at or above `to`
    /// references its txid; otherwise its `TxidsBlocks` list is rewritten
    /// without the pruned blocks. A witness copy's metadata and inputs are
    /// deleted unless a block at or above `to` holds that same wtxid. The
    /// candidate index entries in the range are deleted too, so the caller
    /// must only prune below the confirmed tip.
    pub(crate) fn prune_block_bodies_chunk(
        &self,
        from: u32,
        to: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<PruneStats, StoreError> {
        let from = from.max(FIRST_PRUNABLE_HEIGHT);
        if from >= to {
            return Ok(PruneStats::default());
        }

        //* Find every block in the range that still has a body
        let blockhashes: Vec<BlockHash> = self
            .get_blockhashes_for_height_range(from, to - 1)
            .into_iter()
            .flat_map(|(_height, blockhashes)| blockhashes)
            .collect();
        let bodies = self.get_block_transaction_ids_present(&blockhashes)?;

        //* Delete the transactions that are no longer in any block
        let pruned = self.release_transactions_of_pruned_blocks(&bodies, to, batch)?;
        let deleted_wtxids = self.delete_transactions(&pruned, batch)?;

        //* Delete the per-block body keys and the candidate index entries
        for (blockhash, _block_ids) in &bodies {
            self.delete_block_body_keys(blockhash, batch);
        }
        for height in from..to {
            self.delete_candidate_entry(height, batch);
        }

        Ok(PruneStats {
            blocks: bodies.len(),
            transactions: deleted_wtxids,
        })
    }

    /// The sharechain transaction ids of each block in `blockhashes` that
    /// has a body, read with one `multi_get_cf`. Blocks held header-only are
    /// omitted.
    fn get_block_transaction_ids_present(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<Vec<(BlockHash, BlockTransactionIds)>, StoreError> {
        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        let keys: Vec<_> = blockhashes
            .iter()
            .map(|blockhash| (&block_txids_cf, txids_key(blockhash, BLOCK_TXIDS_SUFFIX)))
            .collect();
        let results = self.db.multi_get_cf(keys);
        let mut bodies = Vec::with_capacity(blockhashes.len());
        for (blockhash, result) in blockhashes.iter().zip(results) {
            if let Some(bytes) = result? {
                let block_ids: BlockTransactionIds =
                    encode::deserialize(&bytes).map_err(|error| {
                        StoreError::Serialization(format!(
                            "Failed to deserialize transaction ids for block {blockhash}: {error}"
                        ))
                    })?;
                bodies.push((*blockhash, block_ids));
            }
        }
        Ok(bodies)
    }

    /// Drop the pruned blocks from the `TxidsBlocks` list of every txid they
    /// hold, and return what pruning deletes for each of those txids.
    ///
    /// A txid no kept block references is deleted with every wtxid the
    /// pruned blocks hold for it. A txid some kept block references keeps its
    /// outputs, and loses only the pruned wtxids that no kept block holds: a
    /// copy with another witness that only pruned blocks held. A referencing
    /// block with no metadata or no height counts as kept, and a kept block
    /// whose transaction ids are not stored keeps every wtxid of the txid, so
    /// nothing is deleted on missing information.
    fn release_transactions_of_pruned_blocks(
        &self,
        bodies: &[(BlockHash, BlockTransactionIds)],
        to: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Vec<PrunedTransaction>, StoreError> {
        //* Collect each pruned txid once, with the distinct wtxids the pruned blocks hold for it
        let transaction_count = bodies
            .iter()
            .map(|(_blockhash, block_ids)| block_ids.0.len())
            .sum();
        let mut pruned_wtxids: HashMap<Txid, Vec<Wtxid>> =
            HashMap::with_capacity(transaction_count);
        let mut txids: Vec<Txid> = Vec::with_capacity(transaction_count);
        for ids in bodies
            .iter()
            .flat_map(|(_blockhash, block_ids)| block_ids.0.iter())
        {
            let wtxids = pruned_wtxids.entry(ids.txid).or_insert_with(|| {
                txids.push(ids.txid);
                Vec::with_capacity(1)
            });
            if !wtxids.contains(&ids.wtxid) {
                wtxids.push(ids.wtxid);
            }
        }

        //* Find the kept referencers of each txid and rewrite its TxidsBlocks list
        let referencers = self.get_blockhashes_for_all_txids(&txids)?;
        let referencing_blockhashes: Vec<BlockHash> =
            referencers.iter().flatten().copied().collect();
        let referencer_heights: HashMap<BlockHash, Option<u32>> = self
            .get_block_metadata_batch(&referencing_blockhashes)?
            .into_iter()
            .map(|(blockhash, metadata)| (blockhash, metadata.expected_height))
            .collect();

        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();
        let mut pruned = Vec::with_capacity(txids.len());
        let mut still_referenced: Vec<(Txid, Vec<BlockHash>)> = Vec::new();
        for (txid, blockhashes) in txids.iter().zip(referencers) {
            let kept: Vec<BlockHash> = blockhashes
                .iter()
                .copied()
                .filter(|blockhash| match referencer_heights.get(blockhash) {
                    Some(Some(height)) => *height >= to,
                    Some(None) | None => true,
                })
                .collect();
            if kept.is_empty() {
                let wtxids = pruned_wtxids.remove(txid).ok_or_else(|| {
                    StoreError::NotFound(format!("No pruned wtxids collected for txid {txid}"))
                })?;
                pruned.push(PrunedTransaction::Delete {
                    txid: *txid,
                    wtxids,
                });
            } else {
                if kept.len() < blockhashes.len() {
                    batch.put_cf(
                        &txids_blocks_cf,
                        txid.as_ref() as &[u8],
                        consensus::serialize(&kept),
                    );
                }
                still_referenced.push((*txid, kept));
            }
        }

        //* For a still referenced txid, delete only the wtxids no kept block holds
        pruned.extend(self.wtxids_no_kept_block_holds(&still_referenced, &pruned_wtxids)?);
        Ok(pruned)
    }

    /// For each still referenced txid, the pruned wtxids that none of its
    /// kept blocks holds, as `KeepOutputs`. A txid with none is omitted. If
    /// any kept block's transaction ids are not stored, every wtxid of that
    /// txid is kept.
    fn wtxids_no_kept_block_holds(
        &self,
        still_referenced: &[(Txid, Vec<BlockHash>)],
        pruned_wtxids: &HashMap<Txid, Vec<Wtxid>>,
    ) -> Result<Vec<PrunedTransaction>, StoreError> {
        if still_referenced.is_empty() {
            return Ok(Vec::new());
        }
        let mut kept_blockhashes: Vec<BlockHash> = still_referenced
            .iter()
            .flat_map(|(_txid, kept)| kept.iter().copied())
            .collect();
        kept_blockhashes.sort();
        kept_blockhashes.dedup();
        let kept_bodies: HashMap<BlockHash, BlockTransactionIds> = self
            .get_block_transaction_ids_present(&kept_blockhashes)?
            .into_iter()
            .collect();

        let mut pruned = Vec::with_capacity(still_referenced.len());
        for (txid, kept) in still_referenced {
            let all_kept_bodies_known = kept
                .iter()
                .all(|blockhash| kept_bodies.contains_key(blockhash));
            if all_kept_bodies_known {
                let kept_wtxids: HashSet<Wtxid> = kept
                    .iter()
                    .flat_map(|blockhash| kept_bodies[blockhash].0.iter())
                    .filter(|ids| ids.txid == *txid)
                    .map(|ids| ids.wtxid)
                    .collect();
                let wtxids: Vec<Wtxid> = pruned_wtxids[txid]
                    .iter()
                    .filter(|wtxid| !kept_wtxids.contains(*wtxid))
                    .copied()
                    .collect();
                if !wtxids.is_empty() {
                    pruned.push(PrunedTransaction::KeepOutputs { wtxids });
                }
            }
        }
        Ok(pruned)
    }

    /// Apply `pruned`: delete the metadata and inputs of each listed wtxid,
    /// and for each `Delete` its txid's outputs, the spends recorded against
    /// them, and its `TxidsBlocks` entry. Returns the number of wtxids
    /// deleted.
    ///
    /// All metadata is read with one `multi_get_cf`. A `Delete`'s output
    /// count is read from the metadata of one of its wtxids: every copy of a
    /// txid has the same outputs.
    fn delete_transactions(
        &self,
        pruned: &[PrunedTransaction],
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<usize, StoreError> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();

        let wtxids: Vec<Wtxid> = pruned
            .iter()
            .flat_map(|transaction| transaction.wtxids().iter().copied())
            .collect();
        let metadatas = self.get_metadata_for_wtxids(&wtxids)?;
        let metadata_by_wtxid: HashMap<Wtxid, TxMetadata> =
            wtxids.iter().copied().zip(metadatas).collect();

        //* Delete each listed wtxid's metadata and inputs
        for (wtxid, metadata) in &metadata_by_wtxid {
            for index in 0..metadata.input_count {
                batch.delete_cf(&inputs_cf, input_key(wtxid, index));
            }
            batch.delete_cf(&tx_cf, wtxid.as_ref() as &[u8]);
        }

        //* Delete the outputs, spends and TxidsBlocks entry of each deleted txid
        for transaction in pruned {
            if let PrunedTransaction::Delete { txid, wtxids } = transaction {
                let output_count = wtxids
                    .first()
                    .map(|wtxid| metadata_by_wtxid[wtxid].output_count)
                    .ok_or_else(|| {
                        StoreError::NotFound(format!("No wtxid to delete for txid {txid}"))
                    })?;
                for index in 0..output_count {
                    let key = outpoint_key(txid, index);
                    batch.delete_cf(&outputs_cf, &key);
                    batch.delete_cf(&spends_index_cf, &key);
                }
                batch.delete_cf(&txids_blocks_cf, txid.as_ref() as &[u8]);
            }
        }
        Ok(wtxids.len())
    }

    /// Delete a block's txid lists and bitcoin coinbase.
    ///
    /// Nothing writes the `BitcoinTxids` CF yet; its key is deleted anyway so
    /// a future writer cannot leak data.
    fn delete_block_body_keys(&self, blockhash: &BlockHash, batch: &mut rocksdb::WriteBatch) {
        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        let bitcoin_txids_cf = self.db.cf_handle(&ColumnFamily::BitcoinTxids).unwrap();
        let bitcoin_coinbase_cf = self.db.cf_handle(&ColumnFamily::BitcoinCoinbase).unwrap();
        batch.delete_cf(&block_txids_cf, txids_key(blockhash, BLOCK_TXIDS_SUFFIX));
        batch.delete_cf(
            &bitcoin_txids_cf,
            txids_key(blockhash, BITCOIN_TXIDS_SUFFIX),
        );
        batch.delete_cf(&bitcoin_coinbase_cf, consensus::serialize(blockhash));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership, Status};
    use crate::test_utils::{
        TestShareBlockBuilder, build_confirmed_test_chain, confirm_test_block,
        setup_test_chain_store_handle,
    };
    use bitcoin::OutPoint;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    #[test]
    fn test_prune_height_for_tip_below_depth_is_zero() {
        assert_eq!(prune_height_for_tip(PRUNE_DEPTH as u32 - 1), 0);
    }

    #[test]
    fn test_prune_height_for_tip_above_depth() {
        assert_eq!(prune_height_for_tip(PRUNE_DEPTH as u32 + 7), 7);
    }

    #[test]
    fn test_prune_target_for_tip_lags_prune_height_by_interval() {
        let candidate_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 7;
        assert_eq!(prune_target_for_tip(candidate_tip_height), 7);
        assert_eq!(
            prune_height_for_tip(candidate_tip_height),
            7 + PRUNE_INTERVAL as u32
        );
    }

    #[test]
    fn test_get_range_to_prune_is_none_when_not_current() {
        let range = get_range_to_prune(false, 100, None, |_| {
            panic!("the start search must not run when not current")
        })
        .unwrap();

        assert_eq!(range, None);
    }

    /// A target of 0 means no confirmed tip, or one below the prune depth;
    /// the search must not run, as it reads the confirmed tip.
    #[test]
    fn test_get_range_to_prune_is_none_when_target_at_genesis() {
        let range = get_range_to_prune(true, 0, None, |_| {
            panic!("the start search must not run without a target above genesis")
        })
        .unwrap();

        assert_eq!(range, None);
    }

    /// Height 1 is the first prunable height, so a target of 1 leaves nothing
    /// to prune.
    #[test]
    fn test_get_range_to_prune_is_none_when_target_at_first_prunable_height() {
        let range = get_range_to_prune(true, 1, None, |_| {
            panic!("the start search must not run with nothing to prune")
        })
        .unwrap();

        assert_eq!(range, None);
    }

    #[test]
    fn test_get_range_to_prune_searches_for_start_when_none_remembered() {
        let range = get_range_to_prune(true, 100, None, |target| {
            assert_eq!(target, 100);
            Ok(40)
        })
        .unwrap();

        assert_eq!(range, Some(40..100));
    }

    #[test]
    fn test_get_range_to_prune_uses_remembered_start_without_searching() {
        let range = get_range_to_prune(true, 100, Some(60), |_| {
            panic!("the start search must not run with a remembered start")
        })
        .unwrap();

        assert_eq!(range, Some(60..100));
    }

    #[test]
    fn test_get_range_to_prune_is_none_when_start_reached_target() {
        let range = get_range_to_prune(true, 100, Some(100), |_| {
            panic!("the start search must not run with a remembered start")
        })
        .unwrap();

        assert_eq!(range, None);
    }

    /// A confirmed tip that dropped since the last run (a confirmed reorg)
    /// leaves the target below the remembered start; nothing is pruned until
    /// the tip passes it again.
    #[test]
    fn test_get_range_to_prune_is_none_when_start_above_target() {
        let range = get_range_to_prune(true, 100, Some(150), |_| {
            panic!("the start search must not run with a remembered start")
        })
        .unwrap();

        assert_eq!(range, None);
    }

    #[test]
    fn test_get_range_to_prune_propagates_start_search_error() {
        let result = get_range_to_prune(true, 100, None, |_| {
            Err(StoreError::Database("read failed".to_string()))
        });

        assert!(matches!(result, Err(StoreError::Database(_))));
    }

    #[test]
    fn test_prune_target_for_tip_below_depth_and_interval_is_zero() {
        assert_eq!(prune_target_for_tip(PRUNE_DEPTH as u32), 0);
    }

    #[test]
    fn test_store_prune_height_without_candidate_tip_is_zero() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        assert_eq!(store.prune_height().unwrap(), 0);
    }

    #[test]
    fn test_store_prune_height_follows_candidate_tip() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let share = TestShareBlockBuilder::new().build();
        let candidate_tip_height = PRUNE_DEPTH as u32 + 11;
        let mut metadata = BlockMetadata {
            expected_height: Some(candidate_tip_height),
            chain_work: share.header.get_work(),
            status: Status::HeaderValid,
            chain: ChainMembership::None,
        };
        let mut batch = Store::get_write_batch();
        store
            .append_to_candidates(
                &share.block_hash(),
                candidate_tip_height,
                &mut metadata,
                &mut batch,
            )
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(store.prune_height().unwrap(), 11);
    }

    #[tokio::test]
    async fn test_prune_deletes_bodies_below_target_and_keeps_bodies_from_target() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;

        let stats = chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        let store = chain_store_handle.store_handle().store();
        assert_eq!(stats.blocks, 5);
        assert!(store.share_block_exists(&blocks[0].block_hash()));
        assert!(!store.share_block_exists(&blocks[1].block_hash()));
        assert!(!store.share_block_exists(&blocks[5].block_hash()));
        assert!(store.share_block_exists(&blocks[6].block_hash()));
        assert!(store.share_block_exists(&blocks[8].block_hash()));
        assert!(store.get_share(&blocks[5].block_hash()).is_none());
        assert_eq!(
            store.get_share(&blocks[6].block_hash()),
            Some(blocks[6].clone())
        );
    }

    #[tokio::test]
    async fn test_prune_keeps_headers_metadata_merkle_branches_and_confirmed_index() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let pruned_hash = blocks[3].block_hash();
        let store = chain_store_handle.store_handle().store();
        let branches_before = store.get_template_merkle_branches(&pruned_hash).unwrap();
        let metadata_before = store.get_block_metadata(&pruned_hash).unwrap();

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert_eq!(
            chain_store_handle.get_share_header(&pruned_hash).unwrap(),
            blocks[3].header
        );
        assert_eq!(
            store.get_block_metadata(&pruned_hash).unwrap(),
            metadata_before
        );
        assert_eq!(
            store.get_template_merkle_branches(&pruned_hash).unwrap(),
            branches_before
        );
        assert_eq!(store.get_confirmed_at_height(3).unwrap(), pruned_hash);
    }

    #[tokio::test]
    async fn test_prune_deletes_transaction_only_a_pruned_block_holds() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let txid = blocks[3].transactions[1].compute_txid();
        let wtxid = blocks[3].transactions[1].compute_wtxid();
        let store = chain_store_handle.store_handle().store();
        let inputs_cf = store.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        assert!(store.get_tx_metadata(&wtxid).is_ok());
        assert!(
            store
                .db
                .get_cf(&inputs_cf, input_key(&wtxid, 0))
                .unwrap()
                .is_some()
        );

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(store.get_tx_metadata(&wtxid).is_err());
        assert!(store.get_output(&txid, 0).is_err());
        assert!(
            store
                .db
                .get_cf(&inputs_cf, input_key(&wtxid, 0))
                .unwrap()
                .is_none()
        );
        assert!(store.get_blockhashes_for_txid(&txid).unwrap().is_empty());
        assert!(
            store
                .get_block_transaction_ids(&blocks[3].block_hash())
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_prune_keeps_transaction_a_kept_block_also_holds() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 5).await;
        let shared_transaction = blocks[2].transactions[1].0.clone();
        let shared_txid = shared_transaction.compute_txid();
        let shared_wtxid = shared_transaction.compute_wtxid();
        let kept_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[5].block_hash().to_string())
            .time(1_700_000_006)
            .add_transaction(shared_transaction)
            .build();
        confirm_test_block(&chain_store_handle, &kept_block).await;

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        let store = chain_store_handle.store_handle().store();
        assert!(!store.share_block_exists(&blocks[2].block_hash()));
        assert!(store.get_tx_metadata(&shared_wtxid).is_ok());
        assert!(store.get_output(&shared_txid, 0).is_ok());
        assert_eq!(
            store.get_blockhashes_for_txid(&shared_txid).unwrap(),
            vec![kept_block.block_hash()]
        );
    }

    /// A kept block holding a pruned block's transaction with another witness
    /// keeps the txid's outputs and its own copy, but not the pruned block's
    /// copy: no kept block holds that wtxid.
    #[tokio::test]
    async fn test_prune_deletes_a_witness_only_pruned_blocks_hold() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 5).await;
        let pruned_copy = blocks[2].transactions[1].0.clone();
        let mut kept_copy = pruned_copy.clone();
        kept_copy.input[0].witness.push([0x42u8; 4]);
        let txid = pruned_copy.compute_txid();
        let kept_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[5].block_hash().to_string())
            .time(1_700_000_006)
            .add_transaction(kept_copy.clone())
            .build();
        confirm_test_block(&chain_store_handle, &kept_block).await;

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        let store = chain_store_handle.store_handle().store();
        assert!(store.get_tx_metadata(&pruned_copy.compute_wtxid()).is_err());
        assert!(store.get_tx_metadata(&kept_copy.compute_wtxid()).is_ok());
        assert!(store.get_output(&txid, 0).is_ok());
        assert_eq!(
            store.get_blockhashes_for_txid(&txid).unwrap(),
            vec![kept_block.block_hash()]
        );
        assert_eq!(
            store
                .get_share(&kept_block.block_hash())
                .unwrap()
                .transactions,
            kept_block.transactions
        );
    }

    /// When only pruned blocks hold a txid, its outputs are deleted, and
    /// every witness copy of it is deleted with them. Here the copies are
    /// the confirmed block's and a fork block's at the same height.
    #[tokio::test]
    async fn test_prune_deletes_every_witness_of_a_transaction_only_pruned_blocks_hold() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let confirmed_copy = blocks[3].transactions[1].0.clone();
        let mut fork_copy = confirmed_copy.clone();
        fork_copy.input[0].witness.push([0x42u8; 4]);
        let txid = confirmed_copy.compute_txid();
        let fork_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(1_700_000_103)
            .add_transaction(fork_copy.clone())
            .build();

        //* Store the fork block at height 3, below the prune target, beside blocks[3]
        chain_store_handle
            .add_share_block(fork_block.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(fork_block.header.clone())
            .await
            .unwrap();
        let store = chain_store_handle.store_handle().store();
        assert!(
            store
                .get_tx_metadata(&confirmed_copy.compute_wtxid())
                .is_ok()
        );
        assert!(store.get_tx_metadata(&fork_copy.compute_wtxid()).is_ok());
        assert_eq!(
            store.get_blockhashes_for_txid(&txid).unwrap(),
            vec![blocks[3].block_hash(), fork_block.block_hash()]
        );

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(
            store
                .get_tx_metadata(&confirmed_copy.compute_wtxid())
                .is_err()
        );
        assert!(store.get_tx_metadata(&fork_copy.compute_wtxid()).is_err());
        assert!(store.get_output(&txid, 0).is_err());
        assert!(store.get_blockhashes_for_txid(&txid).unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_prune_deletes_spends_recorded_against_pruned_outputs() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let funding_txid = blocks[1].transactions[1].compute_txid();
        let spending_transaction = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::new(funding_txid, 0),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let spending_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[1].block_hash().to_string())
            .time(1_700_000_002)
            .add_transaction(spending_transaction)
            .build();
        confirm_test_block(&chain_store_handle, &spending_block).await;
        let store = chain_store_handle.store_handle().store();
        assert!(store.is_spent(&funding_txid, 0).unwrap().is_some());

        chain_store_handle.prune_block_bodies(1, 2).await.unwrap();

        assert!(store.is_spent(&funding_txid, 0).unwrap().is_none());
        assert!(store.share_block_exists(&spending_block.block_hash()));
    }

    #[tokio::test]
    async fn test_prune_deletes_bitcoin_txids_and_bitcoin_coinbase_keys() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 4).await;
        let store = chain_store_handle.store_handle().store();
        let pruned_hash = blocks[2].block_hash();
        let bitcoin_txids_cf = store.db.cf_handle(&ColumnFamily::BitcoinTxids).unwrap();
        let bitcoin_txids_key = txids_key(&pruned_hash, BITCOIN_TXIDS_SUFFIX);
        let mut batch = Store::get_write_batch();
        batch.put_cf(&bitcoin_txids_cf, &bitcoin_txids_key, b"txids");
        store.commit_batch(batch).unwrap();
        assert!(store.get_bitcoin_coinbase(&pruned_hash).unwrap().is_some());

        chain_store_handle.prune_block_bodies(1, 3).await.unwrap();

        assert!(store.get_bitcoin_coinbase(&pruned_hash).unwrap().is_none());
        assert!(
            store
                .db
                .get_cf(&bitcoin_txids_cf, &bitcoin_txids_key)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_prune_deletes_candidate_entries_below_target_and_keeps_entry_at_target() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let store = chain_store_handle.store_handle().store();
        assert_eq!(
            store.get_candidate_at_height(5).unwrap(),
            blocks[5].block_hash()
        );

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(store.get_candidate_at_height(1).is_err());
        assert!(store.get_candidate_at_height(5).is_err());
        assert_eq!(
            store.get_candidate_at_height(6).unwrap(),
            blocks[6].block_hash()
        );
    }

    #[tokio::test]
    async fn test_prune_rerun_over_pruned_range_deletes_nothing() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 8).await;
        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        let stats = chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert_eq!(stats, PruneStats::default());
    }

    #[tokio::test]
    async fn test_prune_deletes_fork_block_body_in_range() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let fork_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(1_700_000_103)
            .build();
        chain_store_handle
            .add_share_block(fork_block.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(fork_block.header.clone())
            .await
            .unwrap();
        let store = chain_store_handle.store_handle().store();
        assert!(store.share_block_exists(&fork_block.block_hash()));

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(!store.share_block_exists(&fork_block.block_hash()));
    }

    /// A reorg forking just above the pruned range still runs. A fork point
    /// inside the pruned range cannot be confirmed, since `reorg_confirmed`
    /// needs the fork point's body; the candidate chain refuses such forks.
    #[tokio::test]
    async fn test_reorg_forking_above_pruned_range_succeeds() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 4).await;
        chain_store_handle.prune_block_bodies(1, 3).await.unwrap();
        let fork_4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[3].block_hash().to_string())
            .time(1_700_000_204)
            .work(2)
            .build();
        let fork_5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork_4.block_hash().to_string())
            .time(1_700_000_205)
            .work(2)
            .build();

        confirm_test_block(&chain_store_handle, &fork_4).await;
        confirm_test_block(&chain_store_handle, &fork_5).await;

        let store = chain_store_handle.store_handle().store();
        assert_eq!(
            store.get_confirmed_at_height(3).unwrap(),
            blocks[3].block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(4).unwrap(),
            fork_4.block_hash()
        );
        assert_eq!(
            store.get_confirmed_at_height(5).unwrap(),
            fork_5.block_hash()
        );
    }

    #[tokio::test]
    async fn test_find_prune_start_is_first_prunable_height_for_fully_bodied_chain() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 8).await;

        assert_eq!(
            chain_store_handle.find_prune_start(6).unwrap(),
            FIRST_PRUNABLE_HEIGHT
        );
    }

    #[tokio::test]
    async fn test_find_prune_start_is_first_bodied_height_after_prune() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 8).await;
        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert_eq!(chain_store_handle.find_prune_start(8).unwrap(), 6);
    }

    #[tokio::test]
    async fn test_find_prune_start_is_target_when_nothing_below_target_has_a_body() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 8).await;
        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert_eq!(chain_store_handle.find_prune_start(5).unwrap(), 5);
    }

    #[test]
    fn test_prune_stats_add_sums_counts() {
        let mut stats = PruneStats {
            blocks: 2,
            transactions: 3,
        };

        stats.add(PruneStats {
            blocks: 5,
            transactions: 7,
        });

        assert_eq!(
            stats,
            PruneStats {
                blocks: 7,
                transactions: 10
            }
        );
    }

    #[tokio::test]
    async fn test_prune_spanning_several_chunks_prunes_every_chunk() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let chunk = PRUNE_INTERVAL;
        let blocks = build_confirmed_test_chain(&chain_store_handle, chunk + 10).await;
        let target = chunk as u32 + 5;

        let stats = chain_store_handle
            .prune_block_bodies(1, target)
            .await
            .unwrap();

        let store = chain_store_handle.store_handle().store();
        assert_eq!(stats.blocks, chunk + 4);
        // Each block holds its share coinbase and its funding transaction.
        assert_eq!(stats.transactions, 2 * (chunk + 4));
        assert!(!store.share_block_exists(&blocks[1].block_hash()));
        assert!(!store.share_block_exists(&blocks[chunk].block_hash()));
        assert!(!store.share_block_exists(&blocks[chunk + 1].block_hash()));
        assert!(!store.share_block_exists(&blocks[chunk + 4].block_hash()));
        assert!(store.share_block_exists(&blocks[chunk + 5].block_hash()));
    }

    #[tokio::test]
    async fn test_prune_chunk_from_zero_keeps_genesis_body() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 4).await;
        let store = chain_store_handle.store_handle().store();
        let mut batch = Store::get_write_batch();

        let stats = store.prune_block_bodies_chunk(0, 3, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert_eq!(stats.blocks, 2);
        assert!(store.share_block_exists(&blocks[0].block_hash()));
        assert!(!store.share_block_exists(&blocks[1].block_hash()));
        assert!(!store.share_block_exists(&blocks[2].block_hash()));
    }

    #[tokio::test]
    async fn test_prune_chunk_with_empty_range_writes_nothing() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 4).await;
        let store = chain_store_handle.store_handle().store();
        let mut batch = Store::get_write_batch();

        let stats = store.prune_block_bodies_chunk(4, 4, &mut batch).unwrap();

        assert_eq!(stats, PruneStats::default());
        assert!(batch.is_empty());
    }

    /// A transaction is never deleted on missing information: a referencing
    /// block with no metadata counts as kept.
    #[tokio::test]
    async fn test_prune_keeps_transaction_whose_other_referencer_has_no_metadata() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let store = chain_store_handle.store_handle().store();
        let txid = blocks[3].transactions[1].compute_txid();
        let wtxid = blocks[3].transactions[1].compute_wtxid();
        let unknown_blockhash = BlockHash::from_byte_array([0x42; 32]);
        let txids_blocks_cf = store.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();
        let mut batch = Store::get_write_batch();
        batch.merge_cf(
            &txids_blocks_cf,
            txid.as_ref() as &[u8],
            consensus::serialize(&unknown_blockhash),
        );
        store.commit_batch(batch).unwrap();

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(store.get_tx_metadata(&wtxid).is_ok());
        assert_eq!(
            store.get_blockhashes_for_txid(&txid).unwrap(),
            vec![unknown_blockhash]
        );
    }

    #[tokio::test]
    async fn test_prune_chunk_propagates_corrupt_block_txids_row() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        let store = chain_store_handle.store_handle().store();
        let block_txids_cf = store.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        let mut corrupt = Store::get_write_batch();
        corrupt.put_cf(
            &block_txids_cf,
            txids_key(&blocks[3].block_hash(), BLOCK_TXIDS_SUFFIX),
            [0xff],
        );
        store.commit_batch(corrupt).unwrap();
        let mut batch = Store::get_write_batch();

        let result = store.prune_block_bodies_chunk(1, 6, &mut batch);

        assert!(matches!(result, Err(StoreError::Serialization(_))));
    }

    /// With every confirmed body below the target pruned, a target above the
    /// confirmed tip must not probe heights that have no confirmed block.
    #[tokio::test]
    async fn test_find_prune_start_with_target_above_confirmed_tip_stops_at_tip() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 4).await;
        chain_store_handle.prune_block_bodies(1, 5).await.unwrap();

        assert_eq!(chain_store_handle.find_prune_start(100).unwrap(), 100);
    }

    #[test]
    fn test_store_prune_target_without_confirmed_tip_is_zero() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        assert_eq!(store.prune_target().unwrap(), 0);
    }

    /// A body below the prune target would be deleted again, so the store
    /// refuses it. This also closes the race between the receiver's check and
    /// a prune committing.
    #[test]
    fn test_add_share_block_below_prune_target_is_refused() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let confirmed_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 2;
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(confirmed_tip_height, &mut batch);
        store.commit_batch(batch).unwrap();
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .time(1_700_000_001)
            .build();
        let mut batch = Store::get_write_batch();

        let result = store.add_share_block(&block, &mut batch);

        assert!(matches!(
            result,
            Err(StoreError::BelowPruneHeight(blockhash)) if blockhash == block.block_hash()
        ));
    }

    #[test]
    fn test_add_share_block_at_prune_target_is_stored() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let confirmed_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 2;
        let parent = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .time(1_700_000_001)
            .build();
        let parent_metadata = BlockMetadata {
            expected_height: Some(1),
            chain_work: genesis.header.get_work(),
            status: Status::HeaderValid,
            chain: ChainMembership::None,
        };
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(confirmed_tip_height, &mut batch);
        store
            .update_block_metadata(&parent.block_hash(), &parent_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent.block_hash().to_string())
            .time(1_700_000_002)
            .build();
        let mut batch = Store::get_write_batch();

        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.share_block_exists(&block.block_hash()));
    }

    /// The candidate tip can run far ahead of a confirmed tip that is still
    /// current, e.g. during header sync at short sim depths. Deletion must
    /// never reach heights the confirmed chain has not got to, so the target
    /// follows the confirmed tip.
    #[test]
    fn test_prune_target_follows_confirmed_tip_when_candidate_runs_ahead() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let confirmed_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 50;
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(confirmed_tip_height, &mut batch);
        store.set_top_candidate_height(confirmed_tip_height + 1000, &mut batch);
        store.commit_batch(batch).unwrap();

        assert_eq!(store.prune_target().unwrap(), 50);
    }

    /// `mark_invalid` can cut the candidate chain back toward the confirmed
    /// tip. The target must not move with it, and must stay at least one
    /// interval below the gates' prune height, or the gates would demand
    /// bodies already deleted.
    #[test]
    fn test_prune_target_unchanged_when_candidate_tip_drops() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let confirmed_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 50;
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(confirmed_tip_height, &mut batch);
        store.set_top_candidate_height(confirmed_tip_height + 1000, &mut batch);
        store.commit_batch(batch).unwrap();
        let target_before_drop = store.prune_target().unwrap();
        let mut batch = Store::get_write_batch();
        store.set_top_candidate_height(confirmed_tip_height + 1, &mut batch);
        store.commit_batch(batch).unwrap();

        let target_after_drop = store.prune_target().unwrap();

        assert_eq!(target_after_drop, target_before_drop);
        assert!(target_after_drop + PRUNE_INTERVAL as u32 <= store.prune_height().unwrap());
    }

    /// A body above the confirmed-based target is still within what this node
    /// keeps, even when the candidate tip runs far ahead, so it is stored.
    #[test]
    fn test_add_share_block_above_confirmed_target_is_stored_when_candidate_runs_ahead() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = TestShareBlockBuilder::new().build();
        let mut batch = Store::get_write_batch();
        store.setup_genesis(&genesis, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();
        let confirmed_tip_height = (PRUNE_DEPTH + PRUNE_INTERVAL) as u32 + 2;
        let parent = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .time(1_700_000_001)
            .build();
        let parent_metadata = BlockMetadata {
            expected_height: Some(1),
            chain_work: genesis.header.get_work(),
            status: Status::HeaderValid,
            chain: ChainMembership::None,
        };
        let mut batch = Store::get_write_batch();
        store.set_top_confirmed_height(confirmed_tip_height, &mut batch);
        store.set_top_candidate_height(confirmed_tip_height + 100, &mut batch);
        store
            .update_block_metadata(&parent.block_hash(), &parent_metadata, &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent.block_hash().to_string())
            .time(1_700_000_002)
            .build();
        let mut batch = Store::get_write_batch();

        store.add_share_block(&block, &mut batch).unwrap();
        store.commit_batch(batch).unwrap();

        assert!(store.share_block_exists(&block.block_hash()));
    }
}
