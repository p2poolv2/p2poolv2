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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::shares::ShareBlockHash;
use crate::shares::miner_message::{MinerWorkbase, UserWorkbase};
use crate::shares::{ShareBlock, ShareHeader};
use crate::store::Store;
use rust_decimal::Decimal;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use tracing::{debug, error, info};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// A datastructure representing the main share chain
/// The share chain reorgs when a share is found that has a higher total PoW than the current tip
/// Chain state is now managed by the Store itself
pub struct ChainStore {
    /// RocksDB store used by the chain
    pub store: Arc<Store>,
}

#[allow(dead_code)]
impl ChainStore {
    /// Create a new chain and load data from the store
    /// This will read the entire chain and set the cached metadata
    /// Add the genesis block to the chain if it is not already present
    pub fn new(store: Arc<Store>, genesis_block: ShareBlock) -> Self {
        let genesis_block_hash = genesis_block.cached_blockhash.unwrap();
        let genesis_in_store = store.get_share(&genesis_block_hash);
        let chain = Self { store };

        // Initialize chain state if needed
        if genesis_in_store.is_none() {
            chain.add_share(genesis_block).unwrap();
        } else {
            // Initialize chain state from existing store data
            let _ = chain.store.init_chain_state_from_store(genesis_block_hash);
        }
        chain
    }

    /// Add a share to the chain and update the tips and total difficulty
    pub fn add_share(&self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Adding share to chain: {:?}", share);

        let tips = self.store.get_tips();
        if tips.is_empty() {
            self.store
                .set_genesis_block_hash(share.cached_blockhash.unwrap());
        }
        let blockhash = share.cached_blockhash.unwrap();
        let prev_share_blockhash = share.header.prev_share_blockhash;
        let share_difficulty = share.header.miner_share.diff;

        let height = match self.get_height_for_prevhash(prev_share_blockhash) {
            Some(prev_height) => prev_height + 1,
            None => 0, // If there's no previous height, this is height 0
        };
        // save to share to store for all cases
        tracing::debug!(
            "Adding share to store: {:?} at height: {}",
            share.cached_blockhash,
            height
        );
        self.store.add_share(share.clone(), height);

        // handle new chain by setting tip and total difficulty
        if tips.is_empty() {
            info!("New chain: {:?}", blockhash);
            self.store.add_tip(blockhash);
            self.store.set_total_difficulty(share_difficulty);
            self.store.set_chain_tip(Some(blockhash));
            return Ok(());
        }

        // remove the previous blockhash from tips if it exists
        if let Some(prev) = prev_share_blockhash {
            self.store.remove_tip(&prev);
        }
        // remove uncles from tips
        if !share.header.uncles.is_empty() {
            for uncle in &share.header.uncles {
                self.store.remove_tip(uncle);
            }
        }
        // add the new share as a tip
        self.store.add_tip(blockhash);
        // handle potential reorgs
        // get total difficulty up to prev_share_blockhash
        if let Some(prev_share_blockhash) = prev_share_blockhash {
            tracing::info!("Checking for reorgs at share: {:?}", prev_share_blockhash);
            let chain_upto_prev_share_blockhash = self.store.get_chain_upto(&prev_share_blockhash);
            let total_difficulty_upto_prev_share_blockhash = chain_upto_prev_share_blockhash
                .iter()
                .map(|share| share.header.miner_share.diff)
                .sum::<Decimal>();
            let current_total_difficulty = self.store.get_total_difficulty();
            debug!(
                "Total difficulty up to prev share blockhash: {:?}. Current total difficulty: {:?}",
                total_difficulty_upto_prev_share_blockhash, current_total_difficulty
            );
            if total_difficulty_upto_prev_share_blockhash + share_difficulty
                > current_total_difficulty
            {
                let reorg_result = self.reorg(share, total_difficulty_upto_prev_share_blockhash);
                if reorg_result.is_err() {
                    error!("Failed to reorg chain for share: {:?}", blockhash);
                    return Err(reorg_result.err().unwrap());
                }
            }
        }
        Ok(())
    }

    /// Add PPLNS Share
    /// There is no need to maintain the share chain here, the share is simply added to pplns share column family
    pub fn add_pplns_share(
        &self,
        pplns_share: SimplePplnsShare,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.store.add_pplns_share(pplns_share)
    }

    pub fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        self.store
            .get_pplns_shares_filtered(limit, start_time, end_time)
    }

    /// Get height for the previous blockhash
    fn get_height_for_prevhash(&self, hash: Option<ShareBlockHash>) -> Option<u32> {
        match hash {
            Some(prev) => match self.store.get_block_metadata(&prev) {
                Some(metadata) => metadata.height,
                None => None, // If prev not found in index, treat as genesis
            },
            None => None,
        }
    }

    /// Remove a blockhash from the tips set
    /// If the blockhash is not in the tips set, this is a no-op
    pub fn remove_from_tips(&self, blockhash: &ShareBlockHash) {
        self.store.remove_tip(blockhash);
    }

    /// Add a blockhash to the tips set
    /// If the blockhash is already in the tips set, this is a no-op
    pub fn add_to_tips(&self, blockhash: ShareBlockHash) {
        self.store.add_tip(blockhash);
    }

    /// Reorg the chain to the new share
    /// We do not explicitly mark any blocks as unconfirmed or transactions as unconfirmed. This is because we don't cache the status of the blocks or transactions.
    /// By changing the tips we are effectively marking all the blocks and transactions that were on the old tips as unconfirmed.
    /// When a share is being traded, if it is not on the main chain, it will not be accepted for the trade.
    pub fn reorg(
        &self,
        share: ShareBlock,
        total_difficulty_upto_prev_share_blockhash: Decimal,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!(
            "Reorging chain to share: {:?}",
            share.cached_blockhash.unwrap()
        );
        self.store.set_total_difficulty(
            total_difficulty_upto_prev_share_blockhash + share.header.miner_share.diff,
        );
        self.store.set_chain_tip(share.cached_blockhash);
        Ok(())
    }

    /// Check if a share is confirmed according to the minimum confirmation depth
    pub fn is_confirmed(&self, share: ShareBlock) -> bool {
        if share.header.prev_share_blockhash.is_none() {
            return true;
        }
        self.store
            .get_chain_upto(&share.header.prev_share_blockhash.unwrap())
            .len()
            > MIN_CONFIRMATION_DEPTH
    }

    /// Add a workbase to the chain
    pub fn add_workbase(
        &self,
        workbase: MinerWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Err(e) = self.store.add_workbase(workbase) {
            error!("Failed to add workbase to store: {}", e);
            return Err("Error adding workbase to store".into());
        }
        Ok(())
    }

    /// Add a user workbase to the chain
    pub fn add_user_workbase(
        &self,
        user_workbase: UserWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Err(e) = self.store.add_user_workbase(user_workbase) {
            error!("Failed to add user workbase to store: {}", e);
            return Err("Error adding user workbase to store".into());
        }
        Ok(())
    }

    /// Get a share from the chain given a share hash
    pub fn get_share(&self, share_hash: &ShareBlockHash) -> Option<ShareBlock> {
        self.store.get_share(share_hash)
    }

    /// Get a share from the chain given a height
    pub fn get_shares_at_height(&self, height: u32) -> HashMap<ShareBlockHash, ShareBlock> {
        self.store.get_shares_at_height(height)
    }

    /// Get a share header from the chain given a share hash
    pub fn get_share_headers(&self, share_hashes: &[ShareBlockHash]) -> Vec<ShareHeader> {
        self.store.get_share_headers(share_hashes)
    }

    /// Get blockhashes for locator
    /// Returns a list of shares starting from the earliest block from the block hashes
    pub fn get_headers_for_locator(
        &self,
        block_hashes: &[ShareBlockHash],
        stop_block_hash: &ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        if self.store.get_chain_tip().is_none() {
            return vec![];
        }

        self.store
            .get_headers_for_locator(block_hashes, stop_block_hash, limit)
    }

    /// Get blockhashes for locator
    /// Returns a list of shares starting from the earliest block from the block hashes
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[ShareBlockHash],
        stop_block_hash: &ShareBlockHash,
        max_blockhashes: usize,
    ) -> Vec<ShareBlockHash> {
        if self.store.get_chain_tip().is_none() {
            return vec![];
        }
        self.store
            .get_blockhashes_for_locator(locator, stop_block_hash, max_blockhashes)
    }

    /// Get the height of the chain tip
    pub fn get_tip_height(&self) -> Option<u32> {
        match self.store.get_chain_tip() {
            Some(tip) => {
                let metadata = self
                    .store
                    .get_block_metadata(&tip)
                    .expect("Failed to get metadata for chain tip");
                metadata.height
            }
            None => None,
        }
    }

    /// Get a locator for the chain.
    /// - Start from the tip, go back until we hit genesis block
    /// - After 10 blocks, double the step size each time
    /// - Return the locator
    pub fn build_locator(&self) -> Vec<ShareBlockHash> {
        if self.store.get_chain_tip().is_none() {
            return vec![];
        }

        let tip_height = self.get_tip_height();
        match tip_height {
            Some(tip_height) => {
                if (tip_height) == 0 {
                    return vec![];
                }
            }
            None => {
                return vec![];
            }
        }

        // Calculate the height indexes using the algorithm from libbitcoin
        let mut indexes = Vec::new();
        let mut step = 1;

        // Start at the top of the chain and work backwards
        let mut height = tip_height.unwrap();
        while height > 0 {
            // Push top 10 indexes first, then back off exponentially
            if indexes.len() >= 10 {
                step *= 2;
            }

            indexes.push(height);
            height = height.saturating_sub(step);
        }

        // Push the genesis block index (height 0)
        indexes.push(0);

        // Convert height indexes to block hashes
        let mut locator = Vec::new();

        for height in indexes {
            let hashes = self.store.get_blockhashes_for_height(height);
            locator.extend(hashes);
        }

        locator
    }

    /// Get a workbase from the chain given a workinfoid
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        self.store.get_workbase(workinfoid)
    }

    /// Get workbases from the chain given a list of workinfoids
    pub fn get_workbases(&self, workinfoids: &[u64]) -> Vec<MinerWorkbase> {
        self.store.get_workbases(workinfoids)
    }

    /// Get a user workbase from the chain given a workinfoid
    pub fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase> {
        self.store.get_user_workbase(workinfoid)
    }

    /// Get user workbases from the chain given a list of workinfoids
    pub fn get_user_workbases(&self, workinfoids: &[u64]) -> Vec<UserWorkbase> {
        self.store.get_user_workbases(workinfoids)
    }

    /// Get the total difficulty of the chain
    pub fn get_total_difficulty(&self) -> Decimal {
        self.store.get_total_difficulty()
    }

    /// Get the chain tip and uncles
    pub fn get_chain_tip_and_uncles(&self) -> (Option<ShareBlockHash>, HashSet<ShareBlockHash>) {
        let mut uncles = self.store.get_tips();
        let chain_tip = self.store.get_chain_tip();
        if let Some(tip) = chain_tip {
            uncles.remove(&tip);
        }
        (chain_tip, uncles)
    }

    /// Set up the share to use chain_tip as the previous blockhash and other tips as uncles
    /// This should be used only when the share is being for the local miner.
    /// Shares received from peers should not be modified``.
    pub fn setup_share_for_chain(&self, mut share_block: ShareBlock) -> ShareBlock {
        let (chain_tip, tips) = self.get_chain_tip_and_uncles();
        tracing::debug!(
            "Setting up share for share blockhash: {:?} with chain_tip: {:?} and tips: {:?}",
            share_block.cached_blockhash,
            chain_tip,
            tips
        );
        share_block.header.prev_share_blockhash = chain_tip;
        share_block.header.uncles = tips.into_iter().collect();
        share_block.compute_blockhash();
        share_block
    }

    /// Check which blockhashes from the provided list are missing from the chain
    /// Returns a vector of blockhashes that are not present in the chain
    pub fn get_missing_blockhashes(&self, blockhashes: &[ShareBlockHash]) -> Vec<ShareBlockHash> {
        self.store.get_missing_blockhashes(blockhashes)
    }

    /// Get the depth of a blockhash from chain tip
    /// Returns None if blockhash is not found in chain
    /// Returns 0 if blockhash is the chain tip
    pub fn get_depth(&self, blockhash: &ShareBlockHash) -> Option<usize> {
        // If chain tip is None, return None
        let tip = self.store.get_chain_tip()?;

        // If blockhash is chain tip, return 0
        if tip == *blockhash {
            return Some(0);
        }

        // Get chain from tip to given blockhash
        let chain = self.store.get_chain_upto(blockhash);
        // If chain is empty, blockhash not found
        if chain.is_empty() {
            return None;
        }

        // Return length of chain minus 1 (since chain includes the blockhash)
        Some(chain.len() - 1)
    }

    /// Save a job with timestamp-prefixed key
    /// Uses timestamp in microseconds to enable time-based range queries
    pub fn save_job(&self, serialized_notify: String) -> Result<(), Box<dyn Error + Send + Sync>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_micros = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;

        self.store.save_job(timestamp_micros, serialized_notify)
    }

    /// Get jobs within a time range
    /// Returns jobs ordered by timestamp (newest first)
    pub fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        self.store.get_jobs(start_time, end_time, limit)
    }

    pub fn store_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error>> {
        self.store.store_user(btcaddress)
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub ChainStore {
        pub fn new(store_path: String, genesis_block: ShareBlock) -> Self;
        pub fn get_tips(&self) -> HashSet<ShareBlockHash>;
        pub fn reorg(&self, share_block: ShareBlock, total_difficulty_upto_prev_share_blockhash: Decimal) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn is_confirmed(&self, share_block: ShareBlock) -> Result<bool, Box<dyn Error + Send + Sync>>;
        pub fn add_share(&self, share_block: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn add_workbase(&self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase>;
        pub fn get_chain_tip(&self) -> Option<ShareBlockHash>;
        pub fn get_chain_tip_and_uncles(&self) -> (Option<ShareBlockHash>, HashSet<ShareBlockHash>);
        pub fn get_depth(&self, blockhash: ShareBlockHash) -> Option<usize>;
        pub fn setup_share_for_chain(&self, share_block: ShareBlock) -> ShareBlock;
        pub fn add_user_workbase(&self, user_workbase: UserWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase>;
        pub fn get_share(&self, share_hash: &ShareBlockHash) -> Option<ShareBlock>;
        pub fn get_pplns_shares_filtered(&self, limit: usize, start_time: Option<u64>, end_time: Option<u64>) -> Vec<SimplePplnsShare>;
        pub fn get_shares_at_height(&self, height: u32) -> HashMap<ShareBlockHash, ShareBlock>;
        pub fn get_share_headers(&self, share_hashes: Vec<ShareBlockHash>) -> Vec<ShareHeader>;
        pub fn get_headers_for_locator(&self, block_hashes: &[ShareBlockHash], stop_block_hash: &ShareBlockHash, max_headers: usize) -> Vec<ShareHeader>;
        pub fn get_blockhashes_for_locator(&self, locator: &[ShareBlockHash], stop_block_hash: &ShareBlockHash, max_blockhashes: usize) -> Vec<ShareBlockHash>;
        pub fn build_locator(&self) -> Vec<ShareBlockHash>;
        pub fn get_missing_blockhashes(&self, blockhashes: &[ShareBlockHash]) -> Vec<ShareBlockHash>;
        pub fn get_tip_height(&self) -> Option<u32>;
        pub fn save_job(&self, serialized_notify: String) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn get_jobs(&self, start_time: Option<u64>, end_time: Option<u64>, limit: usize) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>>;
        pub fn store_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error>>;
        pub fn store_worker(&self, user_id: u64, workername: String) -> Result<u64, Box<dyn Error>>;
    }


    impl Clone for ChainStore {
        fn clone(&self) -> Self {
            Self { sender: self.sender.clone() }
        }
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::test_utils::TestBlockBuilder;
    use crate::test_utils::genesis_for_testnet;
    use crate::test_utils::random_hex_string;
    use rust_decimal_macros::dec;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        // Create initial share (1)
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        chain.add_share(share1.clone()).unwrap();

        let mut expected_tips = HashSet::new();
        expected_tips.insert(share1.cached_blockhash.unwrap());
        assert_eq!(chain.store.get_tips().len(), 1);
        assert_eq!(chain.store.get_total_difficulty(), dec!(2.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(share1.cached_blockhash.unwrap())
        );

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // first orphan is a tip
        chain.add_share(uncle1_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.cached_blockhash.unwrap());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(chain.store.get_total_difficulty(), dec!(3.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(uncle1_share2.cached_blockhash.unwrap())
        );

        // second orphan is also a tip
        chain.add_share(uncle2_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.cached_blockhash.unwrap());
        expected_tips.insert(uncle2_share2.cached_blockhash.unwrap());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(chain.store.get_total_difficulty(), dec!(3.0));
        // chain tip doesn't change as uncle2_share2 has same difficulty as uncle1_share2
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(uncle1_share2.cached_blockhash.unwrap())
        );

        // Create share2 with its uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 3)
            .clientid(1)
            .diff(dec!(2.0))
            .sdiff(dec!(2.9041854952356509))
            .build();

        chain.add_share(share2.clone()).unwrap();

        // two tips that will be future uncles and the chain tip
        expected_tips.clear();
        expected_tips.insert(share2.cached_blockhash.unwrap());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(chain.store.get_total_difficulty(), dec!(4.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(share2.cached_blockhash.unwrap())
        );
        // Create uncles for share3
        let uncle1_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(uncle1_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.cached_blockhash.unwrap());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1
        assert_eq!(chain.store.get_total_difficulty(), dec!(5.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(uncle1_share3.cached_blockhash.unwrap())
        );
        chain.add_share(uncle2_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.cached_blockhash.unwrap());
        expected_tips.insert(uncle2_share3.cached_blockhash.unwrap());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1 (not 3.2)
        assert_eq!(chain.store.get_total_difficulty(), dec!(5.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(uncle1_share3.cached_blockhash.unwrap())
        );
        // Create share3 with its uncles
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .uncles(vec![
                uncle1_share3.cached_blockhash.unwrap(),
                uncle2_share3.cached_blockhash.unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 6)
            .clientid(1)
            .diff(dec!(3.0))
            .sdiff(dec!(3.9041854952356509))
            .build();

        chain.add_share(share3.clone()).unwrap();

        expected_tips.clear();
        expected_tips.insert(share3.cached_blockhash.unwrap());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3
        assert_eq!(chain.store.get_total_difficulty(), dec!(7.0));
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(share3.cached_blockhash.unwrap())
        );

        // Verify heights of all shares
        assert_eq!(
            chain.store.get_blockhashes_for_height(1),
            vec![share1.cached_blockhash.unwrap()]
        );

        assert_eq!(
            chain.store.get_blockhashes_for_height(2),
            vec![
                uncle1_share2.cached_blockhash.unwrap(),
                uncle2_share2.cached_blockhash.unwrap(),
                share2.cached_blockhash.unwrap(),
            ]
        );

        assert_eq!(
            chain.store.get_blockhashes_for_height(3),
            vec![
                uncle1_share3.cached_blockhash.unwrap(),
                uncle2_share3.cached_blockhash.unwrap(),
                share3.cached_blockhash.unwrap()
            ]
        );
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        // Create initial chain of MIN_CONFIRMATION_DEPTH + 1 blocks
        let mut prev_hash = None;
        let mut blocks = vec![];
        let mut blockhash_strings = Vec::new(); // Add this to store strings

        // Generate blocks
        for i in 0..=MIN_CONFIRMATION_DEPTH + 1 {
            let mut share_builder =
                TestBlockBuilder::new().blockhash(random_hex_string(64, 8).as_str());
            if prev_hash.is_some() {
                share_builder = share_builder.prev_share_blockhash(prev_hash.unwrap());
            }

            let share = share_builder
                .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
                .workinfoid(7452731920372203525 + i as u64)
                .clientid(1)
                .diff(dec!(1.0))
                .sdiff(dec!(1.9041854952356509))
                .build();

            blocks.push(share.clone());
            chain.add_share(share.clone()).unwrap();
            blockhash_strings.push(share.cached_blockhash.unwrap().to_string());
            prev_hash = Some(blockhash_strings.last().unwrap().as_str().into());

            if i > MIN_CONFIRMATION_DEPTH || i == 0 {
                assert!(chain.is_confirmed(share));
            } else {
                assert!(!chain.is_confirmed(share));
            }
        }
    }

    #[test]
    fn test_add_workbase() {
        use crate::shares::miner_message::CkPoolMessage;
        use std::fs;

        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        // Load test data from JSON file
        let test_data = fs::read_to_string("../tests/test_data/single_node_simple.json")
            .expect("Failed to read test data file");

        // Deserialize into CkPoolMessage array
        let ckpool_messages: Vec<CkPoolMessage> =
            serde_json::from_str(&test_data).expect("Failed to deserialize test data");

        // Find first workbase message
        let workbase = ckpool_messages
            .iter()
            .find_map(|msg| match msg {
                CkPoolMessage::Workbase(wb) => Some(wb.clone()),
                _ => None,
            })
            .expect("No workbase found in test data");

        // Add workbase and verify it succeeds
        let result = chain.add_workbase(workbase.clone());
        assert!(result.is_ok());

        // Verify workbase was stored by checking it matches what we stored
        assert_eq!(chain.get_workbase(workbase.workinfoid), Some(workbase));
    }

    #[test]
    fn test_get_depth() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        // Test when chain is empty (no chain tip)
        let random_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".into();
        assert_eq!(chain.get_depth(&random_hash), None);

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(share1.clone()).unwrap();

        // Test when blockhash is chain tip
        assert_eq!(chain.get_depth(&share1.cached_blockhash.unwrap()), Some(0));

        // Create second share
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203526)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(share2.clone()).unwrap();

        // Test depth of first share when it's not the tip
        assert_eq!(chain.get_depth(&share2.cached_blockhash.unwrap()), Some(0));
        assert_eq!(chain.get_depth(&share1.cached_blockhash.unwrap()), Some(1));

        // Test when blockhash is not found in chain
        let non_existent_hash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7".into();
        assert_eq!(chain.get_depth(&non_existent_hash), None);
    }

    #[test]
    fn test_get_headers_for_locator() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        // Create a chain of 5 shares
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(1)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(share2.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share4 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
            .prev_share_blockhash(share3.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share5 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(share4.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        // Add shares to chain
        chain.add_share(share1.clone()).unwrap();
        chain.add_share(share2.clone()).unwrap();
        chain.add_share(share3.clone()).unwrap();
        chain.add_share(share4.clone()).unwrap();
        chain.add_share(share5.clone()).unwrap();

        // Test 1: Get headers starting from share1 up to share3
        let locator = vec![share1.cached_blockhash.unwrap()];
        let stop_hash = share3.cached_blockhash.unwrap();
        let headers = chain.get_headers_for_locator(&locator, &stop_hash, 500);
        assert_eq!(headers.len(), 2); // Should return share2 and share3
        assert_eq!(headers[0], share2.header);
        assert_eq!(headers[1], share3.header);

        // Test 2: Get headers with limit
        let headers = chain.get_headers_for_locator(&locator, &share5.cached_blockhash.unwrap(), 2);
        assert_eq!(headers.len(), 2); // Should only return 2 headers due to limit
        assert_eq!(headers[0], share2.header);
        assert_eq!(headers[1], share3.header);

        // Test 3: Get headers with non-existent locator
        let non_existent =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6".into();
        let headers =
            chain.get_headers_for_locator(&[non_existent], &share5.cached_blockhash.unwrap(), 500);
        assert_eq!(headers.len(), 1); // Should return genesis when no match found

        // Test 4: Multiple locator hashes, results should start from first found
        let locator = vec![
            non_existent,
            share3.cached_blockhash.unwrap(),
            share2.cached_blockhash.unwrap(),
            share1.cached_blockhash.unwrap(),
        ];
        let headers =
            chain.get_headers_for_locator(&locator, &share5.cached_blockhash.unwrap(), 500);
        assert_eq!(headers.len(), 2); // Should return share4 and share5
        assert_eq!(headers[0], share4.header);
        assert_eq!(headers[1], share5.header);

        // Test 5: Get blockhashes for locator
        let blockhashes =
            chain.get_blockhashes_for_locator(&locator, &share5.cached_blockhash.unwrap(), 500);
        assert_eq!(blockhashes.len(), 2); // Should return share4 and share5
        assert_eq!(blockhashes[0], share4.cached_blockhash.unwrap());
        assert_eq!(blockhashes[1], share5.cached_blockhash.unwrap());
    }

    #[test]
    fn test_build_locator_with_less_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        let mut blocks: Vec<ShareBlock> = Vec::new();

        let block_builder = TestBlockBuilder::new()
            .blockhash(format!("{:064x}", 0).as_str())
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap());
        let block = block_builder.build();
        blocks.push(block.clone());
        chain.add_share(block.clone()).unwrap();

        assert_eq!(
            chain.store.get_chain_tip(),
            Some(block.cached_blockhash.unwrap())
        );

        for i in 1..5 {
            let block_builder = TestBlockBuilder::new().blockhash(format!("{:064x}", i).as_str());
            let block = block_builder
                .prev_share_blockhash(blocks[i - 1].cached_blockhash.unwrap())
                .build();
            blocks.push(block.clone());
            chain.add_share(block.clone()).unwrap();
            assert_eq!(
                chain.store.get_chain_tip(),
                Some(block.cached_blockhash.unwrap())
            );
        }

        assert_eq!(blocks.len(), 5);
        assert_eq!(
            chain.store.get_chain_tip(),
            Some(blocks[4].cached_blockhash.unwrap())
        );

        let locator = chain.build_locator();
        assert_eq!(locator.len(), 6); // Should return all blocks
        // Verify blocks are in reverse order (tip to genesis)
        for i in 0..5 {
            assert_eq!(locator[i], blocks[4 - i].cached_blockhash.unwrap());
        }
    }

    #[test]
    fn test_build_locator_with_more_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(Arc::new(store), genesis_for_testnet());

        let mut blocks: Vec<ShareBlock> = Vec::new();
        for i in 1..=25 {
            let prev_hash = if i == 1 {
                Some(genesis_for_testnet().cached_blockhash.unwrap())
            } else {
                Some(blocks[i - 2].cached_blockhash.unwrap())
            };

            let mut block_builder =
                TestBlockBuilder::new().blockhash(format!("{:064x}", i).as_str());
            if prev_hash.is_some() {
                block_builder = block_builder.prev_share_blockhash(prev_hash.unwrap());
            }
            let block = block_builder.build();
            blocks.push(block.clone());
            chain.add_share(block).unwrap();
        }

        let locator = chain.build_locator();
        // Should return 14 blocks:
        // - First 10 blocks (indexes 24 down to 15)
        // - Then blocks at positions 12 (index 12), 16 (index 8), 24 (index 0)
        // - Plus genesis block
        assert_eq!(locator.len(), 15);

        // Verify first 10 blocks are sequential from tip
        for i in 0..10 {
            assert_eq!(locator[i], blocks[24 - i].cached_blockhash.unwrap());
        }

        // Verify the step blocks
        assert_eq!(locator[10], blocks[14].cached_blockhash.unwrap());
        assert_eq!(locator[11], blocks[12].cached_blockhash.unwrap());
        assert_eq!(locator[12], blocks[8].cached_blockhash.unwrap());
        assert_eq!(locator[13], blocks[0].cached_blockhash.unwrap());
    }
}
