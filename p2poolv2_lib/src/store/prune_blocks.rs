// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block body pruning.
//!
//! Every boundary is derived from the candidate tip and the pruner's start
//! point is derived from the data; nothing is persisted. See
//! `docs/architecture/pruning.md`.

use crate::accounting::payout::sharechain_pplns::pplns_window::{PRUNE_DEPTH, PRUNE_INTERVAL};
use crate::shares::share_block::Txids;
use crate::store::Store;
use crate::store::column_families::ColumnFamily;
use crate::store::transaction_store::{
    BITCOIN_TXIDS_SUFFIX, BLOCK_TXIDS_SUFFIX, outpoint_key, txids_key,
};
use crate::store::writer::StoreError;
use bitcoin::consensus::{self, encode};
use bitcoin::{BlockHash, Txid};
use std::collections::{HashMap, HashSet};

/// Genesis is defined in code and kept whole, so pruning starts above it.
const FIRST_PRUNABLE_HEIGHT: u32 = 1;

/// Column families holding block body data, compacted after a large prune.
const BODY_COLUMN_FAMILIES: [ColumnFamily; 9] = [
    ColumnFamily::BlockTxids,
    ColumnFamily::BitcoinTxids,
    ColumnFamily::BitcoinCoinbase,
    ColumnFamily::Tx,
    ColumnFamily::Inputs,
    ColumnFamily::Outputs,
    ColumnFamily::TxidsBlocks,
    ColumnFamily::SpendsIndex,
    ColumnFamily::BlockHeight,
];

/// Counts of what a prune deleted, for logging.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    /// Blocks whose bodies were deleted.
    pub blocks: usize,
    /// Transactions deleted because no kept block references them.
    pub transactions: usize,
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

/// Height below which block bodies are deleted for a candidate tip.
///
/// Lags `prune_height_for_tip` by one `PRUNE_INTERVAL`, so a candidate tip
/// that drops by less than an interval never makes the gates demand a
/// deleted body, and peers slightly behind can still fetch bodies near the
/// boundary.
pub fn prune_target_for_tip(candidate_tip_height: u32) -> u32 {
    candidate_tip_height.saturating_sub((PRUNE_DEPTH + PRUNE_INTERVAL) as u32)
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
    /// transaction is deleted only when no block at or above `to` references
    /// it; otherwise its `TxidsBlocks` list is rewritten without the pruned
    /// blocks. The candidate index entries in the range are deleted too, so
    /// the caller must only prune below the confirmed tip.
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
        let bodies = self.get_block_txids_present(&blockhashes)?;

        //* Delete the transactions no kept block references
        let deletable_txids = self.release_txids_of_pruned_blocks(&bodies, to, batch)?;
        self.delete_transactions(&deletable_txids, batch)?;

        //* Delete the per-block body keys and the candidate index entries
        for (blockhash, _txids) in &bodies {
            self.delete_block_body_keys(blockhash, batch);
        }
        for height in from..to {
            self.delete_candidate_entry(height, batch);
        }

        Ok(PruneStats {
            blocks: bodies.len(),
            transactions: deletable_txids.len(),
        })
    }

    /// Compact the column families that hold block body data, so the space
    /// freed by a large prune is reclaimed promptly.
    pub fn compact_body_column_families(&self) {
        for column_family in BODY_COLUMN_FAMILIES {
            let handle = self.db.cf_handle(&column_family).unwrap();
            self.db
                .compact_range_cf(&handle, None::<&[u8]>, None::<&[u8]>);
        }
    }

    /// The sharechain txids of each block in `blockhashes` that has a body,
    /// read with one `multi_get_cf`. Blocks held header-only are omitted.
    fn get_block_txids_present(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<Vec<(BlockHash, Vec<Txid>)>, StoreError> {
        let block_txids_cf = self.db.cf_handle(&ColumnFamily::BlockTxids).unwrap();
        let keys: Vec<_> = blockhashes
            .iter()
            .map(|blockhash| (&block_txids_cf, txids_key(blockhash, BLOCK_TXIDS_SUFFIX)))
            .collect();
        let results = self.db.multi_get_cf(keys);
        let mut bodies = Vec::with_capacity(blockhashes.len());
        for (blockhash, result) in blockhashes.iter().zip(results) {
            if let Some(bytes) = result? {
                let txids: Txids = encode::deserialize(&bytes).map_err(|error| {
                    StoreError::Serialization(format!(
                        "Failed to deserialize txids for block {blockhash}: {error}"
                    ))
                })?;
                bodies.push((*blockhash, txids.0));
            }
        }
        Ok(bodies)
    }

    /// Drop the pruned blocks from the `TxidsBlocks` list of every txid they
    /// hold, and return the txids no block at or above `to` references.
    ///
    /// A referencing block with no metadata or no height is treated as
    /// kept, so a transaction is never deleted on missing information.
    fn release_txids_of_pruned_blocks(
        &self,
        bodies: &[(BlockHash, Vec<Txid>)],
        to: u32,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<Vec<Txid>, StoreError> {
        let txid_count = bodies.iter().map(|(_blockhash, txids)| txids.len()).sum();
        let mut seen = HashSet::with_capacity(txid_count);
        let txids: Vec<Txid> = bodies
            .iter()
            .flat_map(|(_blockhash, txids)| txids.iter().copied())
            .filter(|txid| seen.insert(*txid))
            .collect();

        let referencers = self.get_blockhashes_for_all_txids(&txids)?;
        let referencing_blockhashes: Vec<BlockHash> =
            referencers.iter().flatten().copied().collect();
        let referencer_heights: HashMap<BlockHash, Option<u32>> = self
            .get_block_metadata_batch(&referencing_blockhashes)?
            .into_iter()
            .map(|(blockhash, metadata)| (blockhash, metadata.expected_height))
            .collect();

        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();
        let mut deletable = Vec::with_capacity(txids.len());
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
                deletable.push(*txid);
            } else if kept.len() < blockhashes.len() {
                batch.put_cf(
                    &txids_blocks_cf,
                    txid.as_ref() as &[u8],
                    consensus::serialize(&kept),
                );
            }
        }
        Ok(deletable)
    }

    /// Delete each transaction's metadata, inputs, outputs, the spends
    /// recorded against its outputs, and its `TxidsBlocks` entry.
    fn delete_transactions(
        &self,
        txids: &[Txid],
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), StoreError> {
        let tx_cf = self.db.cf_handle(&ColumnFamily::Tx).unwrap();
        let inputs_cf = self.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        let outputs_cf = self.db.cf_handle(&ColumnFamily::Outputs).unwrap();
        let spends_index_cf = self.db.cf_handle(&ColumnFamily::SpendsIndex).unwrap();
        let txids_blocks_cf = self.db.cf_handle(&ColumnFamily::TxidsBlocks).unwrap();

        for metadata in self.get_metadata_for_txids(txids)? {
            let txid = metadata.txid;
            for index in 0..metadata.input_count {
                batch.delete_cf(&inputs_cf, outpoint_key(&txid, index));
            }
            for index in 0..metadata.output_count {
                let key = outpoint_key(&txid, index);
                batch.delete_cf(&outputs_cf, &key);
                batch.delete_cf(&spends_index_cf, &key);
            }
            batch.delete_cf(&tx_cf, txid.as_ref() as &[u8]);
            batch.delete_cf(&txids_blocks_cf, txid.as_ref() as &[u8]);
        }
        Ok(())
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
        setup_test_chain_store_handle, test_funding_transaction,
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
        let txid = test_funding_transaction(3).compute_txid();
        let store = chain_store_handle.store_handle().store();
        let inputs_cf = store.db.cf_handle(&ColumnFamily::Inputs).unwrap();
        assert!(store.get_tx_metadata(&txid).is_ok());
        assert!(
            store
                .db
                .get_cf(&inputs_cf, outpoint_key(&txid, 0))
                .unwrap()
                .is_some()
        );

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        assert!(store.get_tx_metadata(&txid).is_err());
        assert!(store.get_output(&txid, 0).is_err());
        assert!(
            store
                .db
                .get_cf(&inputs_cf, outpoint_key(&txid, 0))
                .unwrap()
                .is_none()
        );
        assert!(store.get_blockhashes_for_txid(&txid).unwrap().is_empty());
        assert!(
            store
                .get_txids_for_blockhash(&blocks[3].block_hash())
                .0
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_prune_keeps_transaction_a_kept_block_also_holds() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 5).await;
        let shared_transaction = test_funding_transaction(2);
        let shared_txid = shared_transaction.compute_txid();
        let kept_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[5].block_hash().to_string())
            .time(1_700_000_006)
            .add_transaction(shared_transaction)
            .build();
        confirm_test_block(&chain_store_handle, &kept_block).await;

        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();

        let store = chain_store_handle.store_handle().store();
        assert!(!store.share_block_exists(&blocks[2].block_hash()));
        assert!(store.get_tx_metadata(&shared_txid).is_ok());
        assert!(store.get_output(&shared_txid, 0).is_ok());
        assert_eq!(
            store.get_blockhashes_for_txid(&shared_txid).unwrap(),
            vec![kept_block.block_hash()]
        );
    }

    #[tokio::test]
    async fn test_prune_deletes_spends_recorded_against_pruned_outputs() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 1).await;
        let funding_txid = test_funding_transaction(1).compute_txid();
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
        build_confirmed_test_chain(&chain_store_handle, 8).await;
        let store = chain_store_handle.store_handle().store();
        let txid = test_funding_transaction(3).compute_txid();
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

        assert!(store.get_tx_metadata(&txid).is_ok());
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

    #[tokio::test]
    async fn test_compact_body_column_families_keeps_kept_bodies_readable() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 8).await;
        chain_store_handle.prune_block_bodies(1, 6).await.unwrap();
        let store = chain_store_handle.store_handle().store();

        store.compact_body_column_families();

        assert!(!store.share_block_exists(&blocks[5].block_hash()));
        assert_eq!(
            store.get_share(&blocks[6].block_hash()),
            Some(blocks[6].clone())
        );
    }
}
