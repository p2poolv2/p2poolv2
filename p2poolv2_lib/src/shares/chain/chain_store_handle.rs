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

//! Chain store handle providing chain-level operations with serialized writes.
//!
//! `ChainStoreHandle` wraps `StoreHandle` and adds chain-level logic like
//! height calculation, chain work tracking, and reorg handling. Read operations
//! are synchronous and direct, while writes are serialized through the store writer.

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::writer::{StoreError, StoreHandle};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Work};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// Common ancestor depth we look at when finding common ancestors
/// For now it is the same as PPLNS window
pub(crate) const COMMON_ANCESTOR_DEPTH: usize = 2160; // 6 shares per minute * 60 * 6 hours.

/// PPLNS window in shares
const PPLNS_WINDOW: usize = 2160; // 6 shares per minute * 60 * 6 hours.

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

    /// Initialize the chain from an existing store or set up genesis.
    ///
    /// If genesis is already in store, initializes chain state from existing data.
    /// Otherwise, adds genesis block to create a new chain.
    pub async fn init_or_setup_genesis(&self, genesis_block: ShareBlock) -> Result<(), StoreError> {
        let genesis_block_hash = genesis_block.header.block_hash();
        let genesis_in_store = self.store_handle.get_share(&genesis_block_hash);

        if genesis_in_store.is_none() {
            // Set up new chain with genesis
            self.add_share(genesis_block, true).await?;
        } else {
            // Initialize chain state from existing store data
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
    pub fn get_share_headers(
        &self,
        share_hashes: &[BlockHash],
    ) -> Result<Vec<ShareHeader>, StoreError> {
        self.store_handle.get_share_headers(share_hashes)
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

    /// Get the chain tip blockhash from the confirmed chain.
    pub fn get_chain_tip(&self) -> Result<BlockHash, StoreError> {
        self.store_handle.get_chain_tip()
    }

    /// Get the genesis blockhash from the chain.
    pub fn get_genesis_blockhash(&self) -> Option<BlockHash> {
        self.store_handle.get_genesis_blockhash()
    }

    /// Get total work from chain state
    pub fn get_total_work(&self) -> Result<Work, StoreError> {
        self.store_handle.get_total_work()
    }

    /// Get blockhashes for a specific height.
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        self.store_handle.get_blockhashes_for_height(height)
    }

    /// Build a locator for the chain.
    pub fn build_locator(&self) -> Result<Vec<BlockHash>, StoreError> {
        let tip_height = self.get_tip_height()?;
        match tip_height {
            Some(tip_height) => {
                if tip_height == 0 {
                    return Ok(vec![]);
                }
            }
            None => {
                return Ok(vec![]);
            }
        }

        let mut indexes = Vec::new();
        let mut step = 1;

        let mut height = tip_height.unwrap();
        while height > 0 {
            if indexes.len() >= 10 {
                step *= 2;
            }
            indexes.push(height);
            height = height.saturating_sub(step);
        }

        indexes.push(0);

        let mut locator = Vec::new();
        for height in indexes {
            let hashes = self.store_handle.get_blockhashes_for_height(height);
            locator.extend(hashes);
        }

        Ok(locator)
    }

    /// Get the chain tip and uncles from the confirmed chain.
    ///
    /// Delegates uncle selection to Store::find_uncles()
    pub fn get_chain_tip_and_uncles(&self) -> Result<(BlockHash, HashSet<BlockHash>), StoreError> {
        let chain_tip = self.get_chain_tip()?;
        let uncles = self.store_handle.store().find_uncles()?;
        Ok((chain_tip, uncles.into_iter().collect()))
    }

    /// Check which blockhashes are missing from the chain.
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        self.store_handle.get_missing_blockhashes(blockhashes)
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
            Some(header) => Ok(header.bits.to_consensus()),
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
    pub async fn add_share(&self, share: ShareBlock, confirm_txs: bool) -> Result<(), StoreError> {
        debug!("Adding share to chain: {:?}", share.block_hash());

        let blockhash = share.block_hash();
        let prev_share_blockhash = share.header.prev_share_blockhash;
        let share_work = share.header.get_work();
        debug!("Share work: {}", share_work);

        // Handle genesis case
        if self.store_handle.get_genesis_blockhash().is_none() {
            self.store_handle.setup_genesis(share.clone()).await?;
            return Ok(());
        }

        // Calculate height and chain work
        let (new_height, new_chain_work) = match self
            .store_handle
            .store()
            .get_block_metadata(&prev_share_blockhash)
        {
            Ok(prev_metadata) => {
                let prev_height = prev_metadata.expected_height.unwrap_or_default();
                let new_chain_work = prev_metadata.chain_work + share_work;
                (prev_height + 1, new_chain_work)
            }
            Err(_) => (1, share_work),
        };

        debug!(
            "Adding share to store: {:?} at height: {}",
            blockhash, new_height
        );

        // Store the share
        self.store_handle
            .add_share(share, new_height, new_chain_work, confirm_txs)
            .await
    }

    /// Calculate work over PPLNS window.
    fn work_over_pplns_window(&self, start_blockhash: &BlockHash) -> Result<Work, StoreError> {
        let chain_blockhashes = self
            .store_handle
            .store()
            .get_dag_for_depth(start_blockhash, PPLNS_WINDOW)?;

        let chain = self.store_handle.get_shares(&chain_blockhashes)?;

        let zero_work = Work::from_hex("0x00").unwrap();
        let sum = chain
            .iter()
            .fold(zero_work, |acc, (_, share)| acc + share.header.get_work());
        Ok(sum)
    }

    /// Organise a share: update candidate and confirmed indexes atomically.
    /// Returns the confirmed chain height after organising, if changed.
    pub async fn organise_share(&self, share: ShareBlock) -> Result<Option<u32>, StoreError> {
        let blockhash = share.block_hash();
        let height = self.store_handle.organise_share(share).await?;
        info!("Organised share {blockhash} at confirmed height {height:?}");
        Ok(height)
    }

    /// Add a PPLNS share for accounting.
    pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError> {
        self.store_handle.add_pplns_share(pplns_share).await
    }

    /// Add a job with current timestamp.
    pub async fn add_job(&self, serialized_notify: String) -> Result<(), StoreError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        self.store_handle
            .add_job(timestamp_micros, serialized_notify)
            .await?;
        Ok(())
    }

    /// Add a user.
    pub async fn add_user(&self, btcaddress: String) -> Result<u64, StoreError> {
        self.store_handle.add_user(btcaddress).await
    }

    /// Check if a share is confirmed.
    pub fn is_confirmed(&self, share: &ShareBlock) -> bool {
        const MIN_CONFIRMATION_DEPTH: usize = 100;

        if share.header.prev_share_blockhash == BlockHash::all_zeros() {
            return true;
        }
        self.get_depth(&share.block_hash()).unwrap_or_default() > MIN_CONFIRMATION_DEPTH
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
        pub fn network(&self) -> bitcoin::Network;
        pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock>;
        pub fn get_shares_at_height(&self, height: u32) -> Result<HashMap<BlockHash, ShareBlock>, StoreError>;
        pub fn get_share_headers(&self, share_hashes: &[BlockHash]) -> Result<Vec<ShareHeader>, StoreError>;
        pub fn get_headers_for_locator(&self, block_hashes: &[BlockHash], stop_block_hash: &BlockHash, limit: usize) -> Result<Vec<ShareHeader>, StoreError>;
        pub fn get_blockhashes_for_locator(&self, locator: &[BlockHash], stop_block_hash: &BlockHash, max_blockhashes: usize) -> Result<Vec<BlockHash>, StoreError>;
        pub fn get_tip_height(&self) -> Result<Option<u32>, StoreError>;
        pub fn build_locator(&self) -> Result<Vec<BlockHash>, StoreError>;
        pub fn get_chain_tip(&self) -> Result<BlockHash, StoreError>;
        pub fn get_chain_tip_and_uncles(&self) -> Result<(BlockHash, HashSet<BlockHash>), StoreError>;
        pub fn get_genesis_blockhash(&self) -> Option<BlockHash>;
        pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash>;
        pub fn get_depth(&self, blockhash: &BlockHash) -> Option<usize>;
        pub fn get_pplns_shares_filtered(&self, limit: Option<usize>, start_time: Option<u64>, end_time: Option<u64>) -> Vec<SimplePplnsShare>;
        pub fn get_current_target(&self) -> Result<u32, StoreError>;
        pub fn setup_share_for_chain(&self, share_block: ShareBlock) -> Result<ShareBlock, StoreError>;
        pub fn is_confirmed(&self, share: &ShareBlock) -> bool;
        pub fn get_btcaddresses_for_user_ids(&self, user_ids: &[u64]) -> Result<Vec<(u64, String)>, StoreError>;
        pub async fn init_or_setup_genesis(&self, genesis_block: ShareBlock) -> Result<(), StoreError>;
        pub async fn organise_share(&self, share: ShareBlock) -> Result<Option<u32>, StoreError>;
        pub async fn add_share(&self, share: ShareBlock, confirm_txs: bool) -> Result<(), StoreError>;
        pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError>;
        pub async fn add_job(&self, serialized_notify: String) -> Result<(), StoreError>;
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
    async fn test_chain_store_handle_add_share() {
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

        chain_handle.add_share(share1.clone(), true).await.unwrap();

        // Verify share is stored
        let stored_share = chain_handle.get_share(&share1.block_hash());
        assert!(stored_share.is_some());
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

        chain_handle.add_share(share1.clone(), true).await.unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        chain_handle.add_share(share2, true).await.unwrap();
    }
}
