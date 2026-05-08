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

//! Chain store handle providing chain-level operations with serialized writes.
//!
//! `ChainStoreHandle` wraps `StoreHandle` and adds chain-level logic like
//! height calculation, chain work tracking, and reorg handling. Read operations
//! are synchronous and direct, while writes are serialized through the store writer.

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::block_tx_metadata::{BlockMetadata, Status};
use crate::store::dag_store::{ShareDag, UncleInfo};
use crate::store::writer::{StoreError, StoreHandle};
use bitcoin::{BlockHash, Work};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// A confirmed header with its height, blockhash, and share header.
#[derive(Clone, Debug)]
pub struct ConfirmedHeaderResult {
    pub height: u32,
    pub blockhash: BlockHash,
    pub header: ShareHeader,
}

/// Common ancestor depth we look at when finding common ancestors
/// For now it is the same as PPLNS window
pub(crate) const COMMON_ANCESTOR_DEPTH: usize = 2160; // 6 shares per minute * 60 * 6 hours.

/// Maximum age in seconds for the confirmed chain tip to be considered
/// current. Used to suppress block fetching during initial header sync.
const MAX_TIP_AGE_SECS: u64 = 300;

/// Handle for chain-level store operations.
///
/// Wraps `StoreHandle` to provide chain-level logic like height
/// calculation, chain work tracking, and reorg handling
///
/// Read operations are synchronous (may briefly block tokio threads),
/// while writes are serialized through the store writer.
#[derive(Clone)]
pub struct ChainStoreHandle {
    store_handle: StoreHandle,
    network: bitcoin::Network,
}

impl ChainStoreHandle {
    /// Create a new chain store handle.
    pub fn new(store_handle: StoreHandle, network: bitcoin::Network) -> Self {
        Self {
            store_handle,
            network,
        }
    }

    /// Initialise the chain from an existing store or set up genesis.
    ///
    /// If genesis is already in store, initialises chain state from existing data.
    /// Otherwise, adds genesis block to create a new chain.
    pub async fn init_or_setup_genesis(&self, genesis_block: ShareBlock) -> Result<(), StoreError> {
        let genesis_block_hash = genesis_block.header.block_hash();
        let genesis_in_store = self.store_handle.get_share(&genesis_block_hash);

        if genesis_in_store.is_none() {
            // Set up new chain with genesis
            self.add_share_block(genesis_block).await?;
        } else {
            // Initialise chain state from existing store data
            self.store_handle
                .init_chain_state_from_store(genesis_block_hash)
                .await?;
        }
        Ok(())
    }

    /// Get direct access to the underlying store handle.
    pub fn store_handle(&self) -> &StoreHandle {
        &self.store_handle
    }

    /// Get the network type.
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    // ========================================================================
    // DIRECT READS - These delegate to StoreHandle (may block briefly)
    // ========================================================================

    /// Retrieve all previous outputs spent by a transaction's inputs.
    pub fn get_all_prevouts(
        &self,
        transaction: &bitcoin::Transaction,
    ) -> Result<Vec<(usize, bitcoin::TxOut)>, StoreError> {
        self.store_handle.get_all_prevouts(transaction)
    }

    /// Batch-read all outpoints from the Outputs CF.
    /// Returns an error if any is missing, otherwise returns coinbase outpoints.
    pub fn check_prevouts_and_find_coinbase(
        &self,
        outpoints: &[bitcoin::OutPoint],
    ) -> Result<Vec<bitcoin::OutPoint>, StoreError> {
        self.store_handle
            .check_prevouts_and_find_coinbase(outpoints)
    }

    /// Return the first coinbase outpoint that is not yet mature, or None.
    /// Fetches the current tip height internally.
    pub fn find_immature_coinbase_prevout(
        &self,
        coinbase_outpoints: &[bitcoin::OutPoint],
        min_depth: usize,
    ) -> Result<Option<bitcoin::OutPoint>, StoreError> {
        let tip_height = self.get_tip_height()?.ok_or_else(|| {
            StoreError::NotFound("No tip height available for maturity check".to_string())
        })?;
        self.store_handle
            .find_immature_coinbase_prevout(coinbase_outpoints, min_depth, tip_height)
    }

    /// Batch check the SpendsIndex CF: true if any outpoint is already spent.
    pub fn is_any_prevout_spent(
        &self,
        outpoints: &[bitcoin::OutPoint],
    ) -> Result<bool, StoreError> {
        self.store_handle.is_any_prevout_spent(outpoints)
    }

    /// Returns true if every txid is on the confirmed sharechain.
    pub fn are_all_txids_confirmed(&self, txids: &[bitcoin::Txid]) -> Result<bool, StoreError> {
        self.store_handle.are_all_txids_confirmed(txids)
    }

    /// Retrieve a single transaction output by txid and output index.
    pub fn get_output(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
    ) -> Result<bitcoin::TxOut, StoreError> {
        self.store_handle.get_output(txid, vout)
    }

    /// Check whether a share block exists without deserializing it.
    pub fn share_block_exists(&self, blockhash: &BlockHash) -> bool {
        self.store_handle.share_block_exists(blockhash)
    }

    /// Return the first blockhash from the slice that has a header in the store.
    ///
    /// Uses a bulk query for efficiency. Returns None if no header exists
    /// for any of the hashes.
    pub fn first_existing_share_header(&self, blockhashes: &[BlockHash]) -> Option<BlockHash> {
        self.store_handle.first_existing_share_header(blockhashes)
    }

    /// Get a share from the chain.
    pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock> {
        self.store_handle.get_share(share_hash)
    }

    /// Get shares at a specific height.
    pub fn get_shares_at_height(
        &self,
        height: u32,
    ) -> Result<HashMap<BlockHash, ShareBlock>, StoreError> {
        self.store_handle.get_shares_at_height(height)
    }

    /// Get share headers for multiple blockhashes.
    ///
    /// Returns (BlockHash, ShareHeader) pairs in the same order as input,
    /// skipping any hashes not found.
    pub fn get_share_headers(
        &self,
        share_hashes: &[BlockHash],
    ) -> Result<Vec<(BlockHash, ShareHeader)>, StoreError> {
        self.store_handle.get_share_headers(share_hashes)
    }

    /// Get a single share header by blockhash.
    ///
    /// Delegates to get_share_headers and returns the matching header,
    /// or a NotFound error if no header exists for the given hash.
    pub fn get_share_header(&self, share_hash: &BlockHash) -> Result<ShareHeader, StoreError> {
        let headers = self.get_share_headers(&[*share_hash])?;
        headers
            .into_iter()
            .next()
            .map(|(_, header)| header)
            .ok_or(StoreError::NotFound(share_hash.to_string()))
    }

    /// Get headers for a locator.
    pub fn get_headers_for_locator(
        &self,
        block_hashes: &[BlockHash],
        stop_block_hash: &BlockHash,
        limit: usize,
    ) -> Result<Vec<ShareHeader>, StoreError> {
        self.store_handle
            .store()
            .get_headers_for_locator(block_hashes, stop_block_hash, limit)
    }

    /// Get blockhashes for a locator.
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[BlockHash],
        stop_block_hash: &BlockHash,
        max_blockhashes: usize,
    ) -> Result<Vec<BlockHash>, StoreError> {
        self.store_handle.store().get_blockhashes_for_locator(
            locator,
            stop_block_hash,
            max_blockhashes,
        )
    }

    /// Get the height of the chain tip from the confirmed chain.
    pub fn get_tip_height(&self) -> Result<Option<u32>, StoreError> {
        match self.store_handle.store().get_top_confirmed_height() {
            Ok(height) => {
                debug!("Confirmed chain tip height {}", height);
                Ok(Some(height))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Get the height of the candidate chain tip.
    pub fn get_candidate_tip_height(&self) -> Result<Option<u32>, StoreError> {
        match self.store_handle.store().get_top_candidate_height() {
            Ok(height) => {
                debug!("Candidate chain tip height {}", height);
                Ok(Some(height))
            }
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Get the chain tip blockhash from the confirmed chain.
    pub fn get_chain_tip(&self) -> Result<BlockHash, StoreError> {
        self.store_handle.get_chain_tip()
    }

    /// Get the ShareHeader at the confirmed tip.
    pub fn get_chain_tip_header(&self) -> Result<ShareHeader, StoreError> {
        let tip_blockhash = self.store_handle.get_chain_tip()?;
        let headers = self.get_share_headers(&[tip_blockhash])?;
        headers
            .into_iter()
            .next()
            .map(|(_, header)| header)
            .ok_or_else(|| StoreError::NotFound("No header found for chain tip".into()))
    }

    /// Get the ShareHeader at the candidate chain tip.
    ///
    /// Returns the header of the highest-work block on the candidate
    /// chain. Falls back to the confirmed tip if no candidate is found.
    pub fn get_candidate_tip_header(&self) -> Result<ShareHeader, StoreError> {
        let top_candidate = self.store_handle.store().get_top_candidate();
        match top_candidate {
            Ok(top) => self.get_share_header(&top.hash),
            Err(StoreError::NotFound(_)) => self.get_chain_tip_header(),
            Err(error) => Err(error),
        }
    }

    /// Check whether the confirmed chain tip is current.
    ///
    /// Returns true when the confirmed chain tip timestamp is within
    /// MAX_TIP_AGE_SECS seconds of the current system time. Returns
    /// false when the tip is stale or when any store lookup fails
    /// (e.g. no chain yet).
    ///
    /// Uses the confirmed tip (not candidate) so that during initial
    /// sync the chain is correctly identified as not-current, which
    /// suppresses per-inv getheaders and lets the bulk header-first
    /// pipeline run in batches.
    pub fn is_current(&self) -> bool {
        let tip_header = match self.get_chain_tip_header() {
            Ok(header) => header,
            Err(_) => return false,
        };
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let tip_time = tip_header.time as u64;
        now_secs.saturating_sub(tip_time) <= MAX_TIP_AGE_SECS
    }

    /// Get the confirmed tip height and parent time for ASERT target
    /// calculation.
    ///
    /// Reads the tip blockhash once and derives both height (from
    /// block metadata) and time (from share header) from that same
    /// hash. This avoids a race where the confirmed tip advances
    /// between two independent store queries
    ///
    /// Returns (tip_height, tip_time) where tip_time is the share
    /// chain tip's timestamp (the parent time for the next share
    /// being built).
    pub fn get_tip_height_and_time(&self) -> Result<(u32, u32), StoreError> {
        let tip_blockhash = self.store_handle.get_chain_tip()?;

        let headers = self.get_share_headers(&[tip_blockhash])?;
        let tip_header = headers
            .into_iter()
            .next()
            .map(|(_, header)| header)
            .ok_or_else(|| StoreError::NotFound("No header found for chain tip".into()))?;

        let metadata = self.get_block_metadata(&tip_blockhash)?;
        let tip_height = metadata
            .expected_height
            .ok_or_else(|| StoreError::NotFound("No height in tip metadata".into()))?;

        Ok((tip_height, tip_header.time))
    }

    /// Get the genesis blockhash from the chain.
    pub fn get_genesis_blockhash(&self) -> Option<BlockHash> {
        self.store_handle.get_genesis_blockhash()
    }

    /// Get the ShareHeader at genesis.
    pub fn get_genesis_header(&self) -> Result<ShareHeader, StoreError> {
        let genesis_blockhash = self
            .store_handle
            .get_genesis_blockhash()
            .ok_or_else(|| StoreError::NotFound("No genesis blockhash found".into()))?;
        let headers = self.get_share_headers(&[genesis_blockhash])?;
        headers
            .into_iter()
            .next()
            .map(|(_, header)| header)
            .ok_or_else(|| StoreError::NotFound("No header found at genesis".into()))
    }

    /// Get total work from chain state
    pub fn get_total_work(&self) -> Result<Work, StoreError> {
        self.store_handle.get_total_work()
    }

    /// Get the confirmed blockhash at the height
    pub fn get_confirmed_at_height(&self, height: u32) -> Result<BlockHash, StoreError> {
        self.store_handle.get_confirmed_at_height(height)
    }

    /// Get blockhashes for a specific height.
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        self.store_handle.get_blockhashes_for_height(height)
    }

    /// Get children blockhashes for a given block from the block index.
    pub fn get_children_blockhashes(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<Vec<BlockHash>>, StoreError> {
        self.store_handle.get_children_blockhashes(blockhash)
    }

    /// Get nephew blockhashes for a given uncle from the uncles index.
    pub fn get_nephews(&self, uncle: &BlockHash) -> Option<Vec<BlockHash>> {
        self.store_handle.store().get_nephews(uncle)
    }

    /// Get confirmed share headers for a height range, returned newest-to-oldest.
    ///
    /// Performs two store calls: one range scan on the confirmed height index,
    /// then a batch fetch of share headers. This avoids per-height round trips.
    /// Returns (height, BlockHash, ShareHeader) triples so callers have the
    /// confirmed height without recomputing it.
    pub fn get_confirmed_headers_in_range(
        &self,
        from_height: u32,
        to_height: u32,
    ) -> Result<Vec<ConfirmedHeaderResult>, StoreError> {
        let chain = self
            .store_handle
            .store()
            .get_confirmed(from_height, to_height)?;
        // Collect blockhashes in reverse (newest-to-oldest) for the query
        let blockhashes: Vec<BlockHash> = chain.iter().rev().map(|(_, hash)| *hash).collect();
        // get_share_headers preserves input order, so result is newest-to-oldest
        let headers = self.get_share_headers(&blockhashes)?;

        // Build height lookup from chain (height -> blockhash)
        let height_by_hash: HashMap<BlockHash, u32> = chain
            .iter()
            .map(|(height, hash)| (*hash, *height))
            .collect();

        // Join headers with their heights
        let result = headers
            .into_iter()
            .map(|(blockhash, header)| {
                let height = height_by_hash[&blockhash];
                ConfirmedHeaderResult {
                    height,
                    blockhash,
                    header,
                }
            })
            .collect();

        Ok(result)
    }

    /// Get a ShareDag for the given height range.
    ///
    /// Fetches confirmed headers in the range, extracts uncle references,
    /// and batch-fetches uncle headers. Returns a ShareDag containing all
    /// three pieces of data for payout computation.
    pub fn get_share_dag(&self, from_height: u32, to_height: u32) -> Result<ShareDag, StoreError> {
        let confirmed_headers = self.get_confirmed_headers_in_range(from_height, to_height)?;
        let (all_uncle_hashes, nephew_to_uncles) =
            ShareDag::collect_uncle_references(&confirmed_headers);

        let uncle_headers: HashMap<BlockHash, ShareHeader> = if all_uncle_hashes.is_empty() {
            HashMap::new()
        } else {
            self.get_share_headers(&all_uncle_hashes)?
                .into_iter()
                .collect()
        };

        Ok(ShareDag {
            confirmed_headers,
            nephew_to_uncles,
            uncle_headers,
        })
    }

    /// Build a locator for the chain using only confirmed chain blocks.
    ///
    /// Returns blockhashes at exponentially spaced heights from the
    /// starting height back to genesis. Only confirmed blocks are
    /// included so that the peer can match against its own chain.
    ///
    /// When depth is 0, starts from the confirmed tip (normal
    /// behavior). When depth > 0, starts from confirmed_tip - depth,
    /// providing a deeper locator to cover fork block parents that
    /// the receiver may not have.
    pub fn build_locator(&self, depth: u32) -> Result<Vec<BlockHash>, StoreError> {
        let tip_height = self.get_tip_height()?;
        match tip_height {
            Some(tip_height) => {
                if tip_height == 0 {
                    let Some(genesis) = self.get_genesis_blockhash() else {
                        return Err(StoreError::NotFound(
                            "No genesis found when building locator for empty chain".into(),
                        ));
                    };
                    return Ok(vec![genesis]);
                }
            }
            None => {
                return Ok(vec![]);
            }
        }

        let start_height = tip_height.unwrap().saturating_sub(depth);

        let mut indexes = Vec::new();
        let mut step = 1;

        let mut height = start_height;
        while height > 0 {
            if indexes.len() >= 10 {
                step *= 2;
            }
            indexes.push(height);
            height = height.saturating_sub(step);
        }

        indexes.push(0);

        let mut locator = Vec::with_capacity(indexes.len());
        for height in indexes {
            if let Ok(confirmed_hash) = self.store_handle.get_confirmed_at_height(height) {
                locator.push(confirmed_hash);
            }
        }

        Ok(locator)
    }

    /// Get the chain tip and uncles from the confirmed chain.
    ///
    /// Delegates uncle selection to Store::find_uncles() and removes
    /// the chain tip from the result to guarantee the parent is never
    /// also listed as an uncle.
    pub fn get_chain_tip_and_uncles(&self) -> Result<(BlockHash, HashSet<BlockHash>), StoreError> {
        let chain_tip = self.get_chain_tip()?;
        let uncles: HashSet<BlockHash> = self
            .store_handle
            .store()
            .find_uncles()?
            .into_iter()
            .filter(|uncle| *uncle != chain_tip)
            .collect();
        Ok((chain_tip, uncles))
    }

    /// Check which blockhashes are missing from the chain.
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        self.store_handle.get_missing_blockhashes(blockhashes)
    }

    /// Returns blockhashes on the candidate chain that do not yet have
    /// full block data (status is not BlockValid or Confirmed).
    ///
    /// When `min_scan_height` is provided, the scan extends down to
    /// that height so fork blocks at or below the confirmed tip are
    /// included.
    pub fn get_candidate_blocks_missing_data(
        &self,
        min_scan_height: Option<u32>,
    ) -> Result<Vec<BlockHash>, StoreError> {
        self.store_handle
            .store()
            .get_candidate_blocks_missing_data(min_scan_height)
    }

    /// Check if a blockhash has Candidate status in its metadata.
    pub fn is_candidate(&self, blockhash: &BlockHash) -> bool {
        self.store_handle.store().is_candidate(blockhash)
    }

    /// Get metadata for blockhash.
    pub fn get_block_metadata(&self, hash: &BlockHash) -> Result<BlockMetadata, StoreError> {
        self.store_handle.store().get_block_metadata(hash)
    }

    /// Batch fetch metadata for multiple blockhashes in a single multi_get.
    pub fn get_block_metadata_batch(
        &self,
        blockhashes: &[BlockHash],
    ) -> Vec<(BlockHash, BlockMetadata)> {
        self.store_handle
            .store()
            .get_block_metadata_batch(blockhashes)
    }

    /// Look up full uncle details for a list of uncle blockhashes.
    pub fn get_uncle_infos(&self, uncle_hashes: &[BlockHash]) -> Vec<UncleInfo> {
        self.store_handle.store().get_uncle_infos(uncle_hashes)
    }

    /// Check whether a block's metadata status matches the given status.
    /// Returns false if the block has no metadata in the store.
    pub fn has_status(&self, hash: &BlockHash, status: Status) -> bool {
        self.get_block_metadata(hash)
            .map(|metadata| metadata.status == status)
            .unwrap_or(false)
    }

    /// Get the depth of a blockhash from the confirmed chain tip.
    pub fn get_depth(&self, blockhash: &BlockHash) -> Option<usize> {
        let tip = self.get_chain_tip().ok()?;
        if tip == *blockhash {
            return Some(0);
        }

        let tip_metadata = self.store_handle.store().get_block_metadata(&tip).ok()?;
        let tip_height = tip_metadata.expected_height?;

        let block_metadata = self
            .store_handle
            .store()
            .get_block_metadata(blockhash)
            .ok()?;
        let block_height = block_metadata.expected_height?;

        if tip_height >= block_height {
            Some((tip_height - block_height) as usize)
        } else {
            None
        }
    }

    /// Get PPLNS shares with filtering.
    pub fn get_pplns_shares_filtered(
        &self,
        limit: Option<usize>,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        self.store_handle
            .get_pplns_shares_filtered(limit, start_time, end_time)
    }

    /// Get the current target from the tip share block.
    pub fn get_current_target(&self) -> Result<u32, StoreError> {
        let tip = self.get_chain_tip()?;
        let headers = self.get_share_headers(&[tip])?;
        match headers.first() {
            None => Err(StoreError::NotFound("No tips found".into())),
            Some((_, header)) => Ok(header.bits.to_consensus()),
        }
    }

    /// Set up a share for the chain by setting prev_blockhash and uncles.
    pub fn setup_share_for_chain(
        &self,
        mut share_block: ShareBlock,
    ) -> Result<ShareBlock, StoreError> {
        let (chain_tip, tips) = self.get_chain_tip_and_uncles()?;
        debug!(
            "Setting up share for share blockhash: {:?} with chain_tip: {:?} and tips: {:?}",
            share_block.block_hash(),
            chain_tip,
            tips
        );
        share_block.header.prev_share_blockhash = chain_tip;
        share_block.header.uncles = tips.into_iter().collect();
        Ok(share_block)
    }

    // ========================================================================
    // ASYNC WRITES - These use StoreHandle's serialized write methods
    // ========================================================================

    /// Add a share to the chain.
    ///
    /// Calculates height and chain work and stores the share. Reorgs are handled by OrganiseWorker
    pub async fn add_share_block(&self, share: ShareBlock) -> Result<(), StoreError> {
        debug!("Adding share to chain: {:?}", share.block_hash());

        let share_work = share.header.get_work();
        debug!("Share work: {}", share_work);

        // Handle genesis case
        if self.store_handle.get_genesis_blockhash().is_none() {
            self.store_handle.setup_genesis(share.clone()).await?;
            return Ok(());
        }

        // Store the share
        self.store_handle.add_share_block(share).await
    }

    /// Atomically persist a share block and organise its header into
    /// the candidate chain in a single RocksDB write batch.
    ///
    /// Used by the block receiver so a crash cannot leave the share
    /// persisted but unorganised on the candidate chain.
    pub async fn add_share_block_and_organise_header(
        &self,
        share: ShareBlock,
    ) -> Result<Option<u32>, StoreError> {
        let blockhash = share.block_hash();
        debug!("Adding share and organising header atomically: {blockhash:?}");
        self.store_handle
            .add_share_block_and_organise_header(share)
            .await
    }

    /// Organise a header into the candidate chain.
    /// Returns the new candidate height if the candidate chain changed.
    pub async fn organise_header(&self, header: ShareHeader) -> Result<Option<u32>, StoreError> {
        let blockhash = header.block_hash();
        let result = self.store_handle.organise_header(header).await?;
        info!("Organised header {blockhash} into candidate chain");
        Ok(result)
    }

    /// Promote candidates to confirmed.
    /// Returns the confirmed chain height after organising, if changed.
    pub async fn organise_block(&self) -> Result<Option<u32>, StoreError> {
        let height = self.store_handle.organise_block().await?;
        info!("Organised block at confirmed height {height:?}");
        Ok(height)
    }

    /// Add a block to the candidate chain and promote candidates to confirmed.
    ///
    /// Combines organise_header (which places the block on the candidate
    /// chain) with organise_block (which promotes qualifying candidates to
    /// confirmed). The two steps run as separate write batches because
    /// organise_block reads the candidate state that organise_header just
    /// wrote, and a plain WriteBatch is opaque to reads against the DB.
    /// A crash between the two commits leaves a lingering candidate which
    /// the next promote_block call will pick up.
    pub async fn promote_block(&self, header: ShareHeader) -> Result<Option<u32>, StoreError> {
        let blockhash = header.block_hash();
        self.organise_header(header).await?;
        let height = self.organise_block().await?;
        info!("Promoted block {blockhash} to confirmed height {height:?}");
        Ok(height)
    }

    /// Add a PPLNS share for accounting.
    pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError> {
        self.store_handle.add_pplns_share(pplns_share).await
    }

    /// Add a user.
    pub async fn add_user(&self, btcaddress: String) -> Result<u64, StoreError> {
        self.store_handle.add_user(btcaddress).await
    }

    /// Check if a block is on the confirmed chain or is an uncle of a confirmed block.
    ///
    /// Returns true when the block's metadata status is Confirmed, or when
    /// any nephew that references this block as an uncle is itself confirmed.
    pub fn is_confirmed_or_confirmed_uncle(&self, blockhash: &BlockHash) -> bool {
        if self.store_handle.store().is_confirmed(blockhash) {
            return true;
        }
        if let Some(nephews) = self.store_handle.store().get_nephews(blockhash) {
            return nephews
                .iter()
                .any(|nephew| self.store_handle.store().is_confirmed(nephew));
        }
        false
    }

    /// Get bitcoin addresses for user IDs
    pub fn get_btcaddresses_for_user_ids(
        &self,
        user_ids: &[u64],
    ) -> Result<Vec<(u64, String)>, StoreError> {
        self.store_handle.get_btcaddresses_for_user_ids(user_ids)
    }
}

// Mock for ChainStoreHandle using mockall
// This allows tests to create specific scenarios without real storage
// Use with #[mockall_double::double] to swap real type for mock in tests
#[cfg(test)]
mockall::mock! {
    pub ChainStoreHandle {
        pub fn is_candidate(&self, blockhash: &BlockHash) -> bool;
        pub fn get_block_metadata(&self, hash: &BlockHash) -> Result<BlockMetadata, StoreError>;
        pub fn get_block_metadata_batch(&self, blockhashes: &[BlockHash]) -> Vec<(BlockHash, BlockMetadata)>;
        pub fn get_uncle_infos(&self, uncle_hashes: &[BlockHash]) -> Vec<UncleInfo>;
        pub fn has_status(&self, hash: &BlockHash, status: Status) -> bool;
        pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash>;
        pub fn network(&self) -> bitcoin::Network;
        pub fn get_all_prevouts(&self, transaction: &bitcoin::Transaction) -> Result<Vec<(usize, bitcoin::TxOut)>, StoreError>;
        pub fn check_prevouts_and_find_coinbase(&self, outpoints: &[bitcoin::OutPoint]) -> Result<Vec<bitcoin::OutPoint>, StoreError>;
        pub fn find_immature_coinbase_prevout(&self, coinbase_outpoints: &[bitcoin::OutPoint], min_depth: usize) -> Result<Option<bitcoin::OutPoint>, StoreError>;
        pub fn is_any_prevout_spent(&self, outpoints: &[bitcoin::OutPoint]) -> Result<bool, StoreError>;
        pub fn are_all_txids_confirmed(&self, txids: &[bitcoin::Txid]) -> Result<bool, StoreError>;
        pub fn get_output(&self, txid: &bitcoin::Txid, vout: u32) -> Result<bitcoin::TxOut, StoreError>;
        pub fn share_block_exists(&self, blockhash: &BlockHash) -> bool;
        pub fn first_existing_share_header(&self, blockhashes: &[BlockHash]) -> Option<BlockHash>;
        pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock>;
        pub fn get_shares_at_height(&self, height: u32) -> Result<HashMap<BlockHash, ShareBlock>, StoreError>;
        pub fn get_share_headers(&self, share_hashes: &[BlockHash]) -> Result<Vec<(BlockHash, ShareHeader)>, StoreError>;
        pub fn get_share_header(&self, share_hash: &BlockHash) -> Result<ShareHeader, StoreError>;
        pub fn get_headers_for_locator(&self, block_hashes: &[BlockHash], stop_block_hash: &BlockHash, limit: usize) -> Result<Vec<ShareHeader>, StoreError>;
        pub fn get_blockhashes_for_locator(&self, locator: &[BlockHash], stop_block_hash: &BlockHash, max_blockhashes: usize) -> Result<Vec<BlockHash>, StoreError>;
        pub fn get_tip_height(&self) -> Result<Option<u32>, StoreError>;
        pub fn get_candidate_tip_height(&self) -> Result<Option<u32>, StoreError>;
        pub fn build_locator(&self, depth: u32) -> Result<Vec<BlockHash>, StoreError>;
        pub fn get_chain_tip(&self) -> Result<BlockHash, StoreError>;
        pub fn get_chain_tip_header(&self) -> Result<ShareHeader, StoreError>;
        pub fn get_candidate_tip_header(&self) -> Result<ShareHeader, StoreError>;
        pub fn is_current(&self) -> bool;
        pub fn get_chain_tip_and_uncles(&self) -> Result<(BlockHash, HashSet<BlockHash>), StoreError>;
        pub fn get_tip_height_and_time(&self) -> Result<(u32, u32), StoreError>;
        pub fn get_genesis_blockhash(&self) -> Option<BlockHash>;
        pub fn get_genesis_header(&self) -> Result<ShareHeader, StoreError>;
        pub fn get_children_blockhashes(&self, blockhash: &BlockHash) -> Result<Option<Vec<BlockHash>>, StoreError>;
        pub fn get_nephews(&self, uncle: &BlockHash) -> Option<Vec<BlockHash>>;
        pub fn get_confirmed_headers_in_range(&self, from_height: u32, to_height: u32) -> Result<Vec<ConfirmedHeaderResult>, StoreError>;
        pub fn get_share_dag(&self, from_height: u32, to_height: u32) -> Result<ShareDag, StoreError>;
        pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash>;
        pub fn get_candidate_blocks_missing_data(&self, min_scan_height: Option<u32>) -> Result<Vec<BlockHash>, StoreError>;
        pub fn get_depth(&self, blockhash: &BlockHash) -> Option<usize>;
        pub fn get_pplns_shares_filtered(&self, limit: Option<usize>, start_time: Option<u64>, end_time: Option<u64>) -> Vec<SimplePplnsShare>;
        pub fn get_confirmed_at_height(&self, height: u32) -> Result<BlockHash, StoreError>;
        pub fn get_current_target(&self) -> Result<u32, StoreError>;
        pub fn setup_share_for_chain(&self, share_block: ShareBlock) -> Result<ShareBlock, StoreError>;
        pub fn is_confirmed(&self, share: &ShareBlock) -> bool;
        pub fn is_confirmed_or_confirmed_uncle(&self, blockhash: &BlockHash) -> bool;
        pub fn get_btcaddresses_for_user_ids(&self, user_ids: &[u64]) -> Result<Vec<(u64, String)>, StoreError>;
        pub async fn init_or_setup_genesis(&self, genesis_block: ShareBlock) -> Result<(), StoreError>;
        pub async fn organise_header(&self, header: ShareHeader) -> Result<Option<u32>, StoreError>;
        pub async fn organise_block(&self) -> Result<Option<u32>, StoreError>;
        pub async fn promote_block(&self, header: ShareHeader) -> Result<Option<u32>, StoreError>;
        pub async fn add_share_block(&self, share: ShareBlock) -> Result<(), StoreError>;
        pub async fn add_share_block_and_organise_header(&self, share: ShareBlock) -> Result<Option<u32>, StoreError>;
        pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError>;
        pub async fn add_user(&self, btcaddress: String) -> Result<u64, StoreError>;
    }

    impl Clone for ChainStoreHandle {
        fn clone(&self) -> Self;
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{
        TestShareBlockBuilder, genesis_for_tests, setup_test_chain_store_handle,
    };

    #[tokio::test]
    async fn test_chain_store_handle_creation() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        assert_eq!(chain_handle.network(), bitcoin::Network::Signet);
    }

    #[tokio::test]
    async fn test_chain_store_handle_init_genesis() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Verify genesis is stored
        let stored_genesis = chain_handle.get_share(&genesis.block_hash());
        assert!(stored_genesis.is_some());
        assert_eq!(stored_genesis.unwrap().block_hash(), genesis.block_hash());
    }

    #[tokio::test]
    async fn test_chain_store_handle_add_share_block() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Add a share
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();

        chain_handle.add_share_block(share1.clone()).await.unwrap();

        // Verify share is stored
        let stored_share = chain_handle.get_share(&share1.block_hash());
        assert!(stored_share.is_some());
    }

    #[tokio::test]
    async fn test_build_locator_genesis_only() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        let locator = chain_handle.build_locator(0).unwrap();
        assert_eq!(locator.len(), 1, "Locator should contain exactly genesis");
        assert_eq!(
            locator[0],
            genesis.block_hash(),
            "Locator should contain the genesis blockhash"
        );
    }

    #[tokio::test]
    async fn test_build_locator_empty_chain() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let locator = chain_handle.build_locator(0).unwrap();
        assert!(
            locator.is_empty(),
            "Locator for empty chain should be empty"
        );
    }

    #[tokio::test]
    async fn test_build_locator_short_chain() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Build a chain of 5 shares after genesis
        let mut prev_hash = genesis.block_hash();
        let mut shares = Vec::with_capacity(5);
        for _ in 0..5 {
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
                .work(2)
                .build();
            chain_handle.add_share_block(share.clone()).await.unwrap();
            chain_handle
                .organise_header(share.header.clone())
                .await
                .unwrap();
            chain_handle.organise_block().await.unwrap();
            prev_hash = share.block_hash();
            shares.push(share);
        }

        let locator = chain_handle.build_locator(0).unwrap();
        // With tip at height 5, step=1 for all entries: heights 5,4,3,2,1,0
        assert_eq!(
            locator.len(),
            6,
            "Short chain locator should include all heights"
        );
        // First entry should be the tip (height 5)
        assert_eq!(locator[0], shares[4].block_hash());
        // Last entry should be genesis (height 0)
        assert_eq!(locator[locator.len() - 1], genesis.block_hash());

        // Validate get_confirmed_at_height returns the correct blockhash for each height
        let confirmed_genesis = chain_handle.get_confirmed_at_height(0).unwrap();
        assert_eq!(
            confirmed_genesis,
            genesis.block_hash(),
            "Confirmed at height 0 should be genesis"
        );
        for (index, share) in shares.iter().enumerate() {
            let height = (index + 1) as u32;
            let confirmed = chain_handle.get_confirmed_at_height(height).unwrap();
            assert_eq!(
                confirmed,
                share.block_hash(),
                "Confirmed at height {} should match share {}",
                height,
                index
            );
        }

        // Querying beyond the tip should return an error
        assert!(
            chain_handle.get_confirmed_at_height(6).is_err(),
            "Querying beyond tip height should return an error"
        );
    }

    #[tokio::test]
    async fn test_build_locator_long_chain_step_doubling() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Build a chain of 20 shares
        let mut prev_hash = genesis.block_hash();
        let mut shares = Vec::with_capacity(20);
        for _ in 0..20 {
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
                .work(2)
                .build();
            chain_handle.add_share_block(share.clone()).await.unwrap();
            chain_handle
                .organise_header(share.header.clone())
                .await
                .unwrap();
            chain_handle.organise_block().await.unwrap();
            prev_hash = share.block_hash();
            shares.push(share);
        }

        let locator = chain_handle.build_locator(0).unwrap();
        // The locator should have fewer entries than the chain length
        // due to step doubling after 10 entries
        assert!(
            locator.len() < 21,
            "Long chain locator should be shorter than total chain height + 1"
        );
        // First should be tip
        assert_eq!(locator[0], shares[19].block_hash());
        // Last should be genesis
        assert_eq!(locator[locator.len() - 1], genesis.block_hash());
    }

    #[tokio::test]
    async fn test_chain_store_handle_get_depth() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Add shares
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        chain_handle.add_share_block(share1.clone()).await.unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        chain_handle.add_share_block(share2).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_confirmed_headers_in_range() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        let mut prev_hash = genesis.block_hash();
        let mut shares = vec![genesis.clone()];
        for _ in 0..4 {
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
                .work(2)
                .build();
            chain_handle.add_share_block(share.clone()).await.unwrap();
            chain_handle
                .organise_header(share.header.clone())
                .await
                .unwrap();
            chain_handle.organise_block().await.unwrap();
            prev_hash = share.block_hash();
            shares.push(share);
        }

        // Full range: heights 0..4, returned newest-to-oldest
        let headers = chain_handle.get_confirmed_headers_in_range(0, 4).unwrap();
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[0].blockhash, shares[4].block_hash());
        assert_eq!(headers[4].blockhash, genesis.block_hash());

        // Partial range: heights 2..4, returned newest-to-oldest
        let headers = chain_handle.get_confirmed_headers_in_range(2, 4).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].blockhash, shares[4].block_hash());
        assert_eq!(headers[2].blockhash, shares[2].block_hash());

        // Long range: heights 0..10, returned newest-to-oldest
        let headers = chain_handle.get_confirmed_headers_in_range(0, 10).unwrap();
        assert_eq!(headers.len(), 5);
        assert_eq!(headers[0].blockhash, shares[4].block_hash());
        assert_eq!(headers[4].blockhash, shares[0].block_hash());
    }

    #[tokio::test]
    async fn test_get_confirmed_headers_in_range_empty() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        // No genesis, no confirmed shares -- range query returns empty
        let headers = chain_handle.get_confirmed_headers_in_range(0, 10).unwrap();
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_is_current_returns_false_when_no_chain_tip() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        // No genesis initialised, so get_chain_tip_header will fail
        assert!(!chain_handle.is_current());
    }

    #[tokio::test]
    async fn test_is_current_returns_true_when_tip_is_recent() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let genesis = TestShareBlockBuilder::new().time(now_secs).build();

        chain_handle.init_or_setup_genesis(genesis).await.unwrap();

        assert!(chain_handle.is_current());
    }

    #[tokio::test]
    async fn test_is_current_returns_false_when_tip_is_stale() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // Set the tip timestamp 600 seconds in the past, well beyond the 300s threshold
        let stale_time = now_secs.saturating_sub(600);

        let genesis = TestShareBlockBuilder::new().time(stale_time).build();

        chain_handle.init_or_setup_genesis(genesis).await.unwrap();

        assert!(!chain_handle.is_current());
    }

    #[tokio::test]
    async fn test_is_current_returns_true_at_boundary() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // Set the tip timestamp exactly at the MAX_TIP_AGE_SECS boundary
        let boundary_time = now_secs.saturating_sub(super::MAX_TIP_AGE_SECS as u32);

        let genesis = TestShareBlockBuilder::new().time(boundary_time).build();

        chain_handle.init_or_setup_genesis(genesis).await.unwrap();

        assert!(chain_handle.is_current());
    }

    /// When a non-confirmed block (uncle) exists at the same height as
    /// a confirmed block, the locator must only contain the confirmed
    /// block.
    #[tokio::test]
    async fn test_build_locator_excludes_non_confirmed_blocks() {
        let (chain_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();

        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Build confirmed chain: genesis -> share_a (h:1) -> share_b (h:2)
        let share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain_handle.add_share_block(share_a.clone()).await.unwrap();
        chain_handle
            .organise_header(share_a.header.clone())
            .await
            .unwrap();
        chain_handle.organise_block().await.unwrap();

        let share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain_handle.add_share_block(share_b.clone()).await.unwrap();
        chain_handle
            .organise_header(share_b.header.clone())
            .await
            .unwrap();
        chain_handle.organise_block().await.unwrap();

        // Store an uncle at height 1 (same height as share_a) via the
        // underlying Store, which puts it in the BlockHeight CF without
        // confirming it.
        let uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(999)
            .build();
        chain_handle
            .store_handle()
            .store()
            .store_with_valid_metadata(&uncle);

        // Verify the uncle is indeed stored at height 1
        let blocks_at_height_1 = chain_handle.store_handle().get_blockhashes_for_height(1);
        assert!(
            blocks_at_height_1.contains(&uncle.block_hash()),
            "Uncle should be stored at height 1"
        );
        assert!(
            blocks_at_height_1.len() > 1,
            "Height 1 should have both confirmed share and uncle"
        );

        let locator = chain_handle.build_locator(0).unwrap();

        // Locator should contain only confirmed blocks
        assert!(
            !locator.contains(&uncle.block_hash()),
            "Locator must not contain the non-confirmed uncle"
        );
        assert_eq!(
            locator[0],
            share_b.block_hash(),
            "First entry should be tip"
        );
        assert_eq!(
            locator[locator.len() - 1],
            genesis.block_hash(),
            "Last entry should be genesis"
        );
        // Heights 2, 1, 0 -- all confirmed
        assert_eq!(locator.len(), 3);
        assert_eq!(locator[1], share_a.block_hash());
    }
}
