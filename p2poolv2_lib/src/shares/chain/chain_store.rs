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
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::Store;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use tracing::{debug, error, info};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// The maximum depth up to which we include the uncles in the chain
const MAX_UNCLE_DEPTH: usize = 3;

/// A datastructure representing the main share chain
/// The share chain reorgs when a share is found that has a higher total PoW than the current tip
/// Chain state is now managed by the Store itself
pub struct ChainStore {
    /// RocksDB store used by the chain
    pub store: Arc<Store>,
    /// Network type for the chain stored here
    pub network: bitcoin::Network,
}

#[allow(dead_code)]
impl ChainStore {
    /// Create a new chain and load data from the store
    /// This will read the entire chain and set the cached metadata
    /// Add the genesis block to the chain if it is not already present
    pub fn new(store: Arc<Store>, genesis_block: ShareBlock, network: bitcoin::Network) -> Self {
        let genesis_block_hash = genesis_block.header.block_hash();
        let genesis_in_store = store.get_share(&genesis_block_hash);
        let chain = Self { store, network };

        // Initialize chain state if needed
        if genesis_in_store.is_none() {
            chain
                .add_share(genesis_block, true)
                .expect("Should be able to save genesis to create store");
        } else {
            // Initialize chain state from existing store data
            let _ = chain.store.init_chain_state_from_store(genesis_block_hash);
        }
        chain
    }

    /// Add a share to the chain and update the tips and total difficulty
    ///
    /// Figures out the height and the chain work to associate with
    /// the share and then uses store's add share to store the
    /// metadata and the transactions
    ///
    /// Handles the first block as genesis if chain is empty
    pub fn add_share(
        &self,
        share: ShareBlock,
        on_main_chain: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Adding share to chain: {:?}", share);

        let blockhash = share.block_hash();
        let prev_share_blockhash = share.header.prev_share_blockhash;
        let share_work = share.header.get_work();
        debug!("Share work: {:?}", share_work);
        debug!(
            "ADDING SHARE {} WITH WORK {}",
            share.header.block_hash(),
            share_work,
        );

        let tips = self.store.get_tips();

        // Create a new write batch
        let mut batch = Store::get_write_batch();

        if tips.is_empty() {
            self.store.setup_genesis(share, &mut batch)?;
            self.store.commit_batch(batch)?;
            return Ok(());
        }

        let (new_height, new_chain_work) =
            match self.store.get_block_metadata(&prev_share_blockhash) {
                Ok(prev_metadata) => {
                    let prev_height = prev_metadata.height.unwrap_or_default();
                    let new_chain_work = prev_metadata.chain_work + share_work;
                    (prev_height + 1, new_chain_work)
                }
                Err(_) => (1, share_work),
            };

        // save to share to store for all cases
        tracing::debug!(
            "Adding share to store: {:?} at height: {}",
            share.block_hash(),
            new_height
        );
        self.store.add_share(
            share.clone(),
            new_height,
            new_chain_work,
            on_main_chain,
            &mut batch,
        )?;

        // remove the previous blockhash from tips
        self.store.remove_tip(&prev_share_blockhash);

        // remove uncles from tips
        for uncle in &share.header.uncles {
            self.store.remove_tip(uncle);
        }

        // add the new share as a tip
        self.store.add_tip(blockhash);

        // handle potential reorgs
        // get total difficulty up to prev_share_blockhash
        tracing::info!("Checking for reorgs at share: {:?}", prev_share_blockhash);
        let current_total_work = self.store.get_total_work()?;
        debug!(
            "new chain work: {}, Current total work: {}",
            new_chain_work, current_total_work
        );
        if new_chain_work > current_total_work {
            let reorg_result = self.reorg(share, &mut batch);
            if reorg_result.is_err() {
                error!("Failed to reorg chain for share: {:?}", blockhash);
                return Err(reorg_result.err().unwrap());
            }
        }

        self.store
            .commit_batch(batch)
            .map_err(|e| format!("Failed to add share, commit error: {e}").into())
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
        limit: Option<usize>,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        self.store
            .get_pplns_shares_filtered(limit, start_time, end_time)
    }

    /// Remove a blockhash from the tips set
    /// If the blockhash is not in the tips set, this is a no-op
    pub fn remove_from_tips(&self, blockhash: &BlockHash) {
        self.store.remove_tip(blockhash);
    }

    /// Add a blockhash to the tips set
    /// If the blockhash is already in the tips set, this is a no-op
    pub fn add_to_tips(&self, blockhash: BlockHash) {
        self.store.add_tip(blockhash);
    }

    /// Reorg the chain to the new share
    /// We do not explicitly mark any blocks as unconfirmed or transactions as unconfirmed. This is because we don't cache the status of the blocks or transactions.
    /// By changing the tips we are effectively marking all the blocks and transactions that were on the old tips as unconfirmed.
    /// When a share is being traded, if it is not on the main chain, it will not be accepted for the trade.
    fn reorg(
        &self,
        share: ShareBlock,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let share_block_hash = share.block_hash();
        info!("Reorging chain to share: {:?}", share_block_hash);

        let reorged_out_chain = self
            .store
            .get_shares_from_tip_to_blockhash(&share.header.prev_share_blockhash)?;

        for reorged in reorged_out_chain.iter() {
            self.store
                .set_block_on_main_chain(&reorged.block_hash(), false, batch)?;
        }

        self.store.set_chain_tip(share.block_hash());
        Ok(())
    }

    /// Check if a share is confirmed according to the minimum confirmation depth
    /// Genesis is always confirmed - detected from prev share blockhash == null
    /// Get depth and check it is greater than min confirmation depth
    pub fn is_confirmed(&self, share: ShareBlock) -> bool {
        if share.header.prev_share_blockhash == BlockHash::all_zeros() {
            return true;
        }
        self.get_depth(&share.block_hash()).unwrap_or_default() > MIN_CONFIRMATION_DEPTH
    }

    /// Get a share from the chain given a share hash
    pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock> {
        self.store.get_share(share_hash)
    }

    /// Get a share from the chain given a height
    pub fn get_shares_at_height(&self, height: u32) -> HashMap<BlockHash, ShareBlock> {
        self.store.get_shares_at_height(height)
    }

    /// Get a share header from the chain given a share hash
    pub fn get_share_headers(&self, share_hashes: &[BlockHash]) -> Vec<ShareHeader> {
        self.store.get_share_headers(share_hashes)
    }

    /// Get blockhashes for locator
    /// Returns a list of shares starting from the earliest block from the block hashes
    pub fn get_headers_for_locator(
        &self,
        block_hashes: &[BlockHash],
        stop_block_hash: &BlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        self.store
            .get_headers_for_locator(block_hashes, stop_block_hash, limit)
    }

    /// Get blockhashes for locator
    /// Returns a list of shares starting from the earliest block from the block hashes
    pub fn get_blockhashes_for_locator(
        &self,
        locator: &[BlockHash],
        stop_block_hash: &BlockHash,
        max_blockhashes: usize,
    ) -> Vec<BlockHash> {
        self.store
            .get_blockhashes_for_locator(locator, stop_block_hash, max_blockhashes)
    }

    /// Get the height of the chain tip
    pub fn get_tip_height(&self) -> Result<Option<u32>, Box<dyn Error + Send + Sync>> {
        let tip = self.store.get_chain_tip();
        debug!("Chain tip for height {}", tip);
        let metadata = self.store.get_block_metadata(&tip)?;
        Ok(metadata.height)
    }

    /// Get a locator for the chain.
    /// - Start from the tip, go back until we hit genesis block
    /// - After 10 blocks, double the step size each time
    /// - Return the locator
    pub fn build_locator(&self) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>> {
        let tip_height = self.get_tip_height()?;
        match tip_height {
            Some(tip_height) => {
                if (tip_height) == 0 {
                    return Ok(vec![]);
                }
            }
            None => {
                return Ok(vec![]);
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

        Ok(locator)
    }

    /// Get the chain tip and uncles
    /// Limit the uncles to up to max uncle depth from the tip
    ///
    /// Uncles: By picking tips, we make sure we are picking uncles
    /// that haven't been included as an uncle yet.
    pub fn get_chain_tip_and_uncles(&self) -> (BlockHash, HashSet<BlockHash>) {
        let mut uncles = self.store.get_tips();
        uncles.retain(|uncle| {
            self.get_depth(uncle).unwrap_or(MAX_UNCLE_DEPTH + 1) <= MAX_UNCLE_DEPTH
        });
        let chain_tip = self.store.get_chain_tip();
        uncles.remove(&chain_tip);
        (chain_tip, uncles)
    }

    /// Set up the share to use chain_tip as the previous blockhash and other tips as uncles
    /// This should be used only when the share is being for the local miner.
    /// Shares received from peers should not be modified.
    ///
    /// The caller will call ChainStore::add_share and it is then that
    /// the uncles are removed from the tip.
    pub fn setup_share_for_chain(&self, mut share_block: ShareBlock) -> ShareBlock {
        let (chain_tip, tips) = self.get_chain_tip_and_uncles();
        tracing::debug!(
            "Setting up share for share blockhash: {:?} with chain_tip: {:?} and tips: {:?}",
            share_block.block_hash(),
            chain_tip,
            tips
        );
        share_block.header.prev_share_blockhash = chain_tip;
        share_block.header.uncles = tips.into_iter().collect();
        share_block
    }

    /// Check which blockhashes from the provided list are missing from the chain
    /// Returns a vector of blockhashes that are not present in the chain
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        self.store.get_missing_blockhashes(blockhashes)
    }

    /// Get the depth of a blockhash from chain tip
    /// Returns None if blockhash is not found in chain
    /// Returns 0 if blockhash is the chain tip
    pub fn get_depth(&self, blockhash: &BlockHash) -> Option<usize> {
        // If blockhash is chain tip, return 0
        let tip = self.store.get_chain_tip();
        if tip == *blockhash {
            return Some(0);
        }

        // Get the height of the chain tip
        let tip_metadata = self.store.get_block_metadata(&tip).ok()?;
        let tip_height = tip_metadata.height?;

        // Get the height of the target blockhash
        let block_metadata = self.store.get_block_metadata(blockhash).ok()?;
        let block_height = block_metadata.height?;

        // Depth is the difference in heights
        if tip_height >= block_height {
            Some((tip_height - block_height) as usize)
        } else {
            None
        }
    }

    /// Save a job with timestamp-prefixed key
    /// Uses timestamp in microseconds to enable time-based range queries
    pub fn add_job(&self, serialized_notify: String) -> Result<(), Box<dyn Error + Send + Sync>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_micros = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros() as u64;

        self.store.add_job(timestamp_micros, serialized_notify)
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

    pub fn add_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error + Send + Sync>> {
        self.store.add_user(btcaddress)
    }

    /// Get the target for the tip share block
    pub fn get_current_target(&self) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let tip = self.store.get_chain_tip();
        let headers = self.get_share_headers(&[tip]);
        match headers.first() {
            None => Err("No tips found".into()),
            Some(header) => Ok(header.bits.to_consensus()),
        }
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub ChainStore {
        pub fn new(store_path: String, genesis_block: ShareBlock) -> Self;
        pub fn get_tips(&self) -> HashSet<BlockHash>;
        pub fn reorg(&self, share_block: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn is_confirmed(&self, share_block: ShareBlock) -> Result<bool, Box<dyn Error + Send + Sync>>;
        pub fn add_share(&self, share_block: ShareBlock, on_main_chain: bool) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn get_chain_tip(&self) -> Option<BlockHash>;
        pub fn get_chain_tip_and_uncles(&self) -> (BlockHash, HashSet<BlockHash>);
        pub fn get_depth(&self, blockhash: BlockHash) -> Option<usize>;
        pub fn setup_share_for_chain(&self, share_block: ShareBlock) -> ShareBlock;
        pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock>;
        pub fn get_pplns_shares_filtered(&self, limit: Option<usize>, start_time: Option<u64>, end_time: Option<u64>) -> Vec<SimplePplnsShare>;
        pub fn get_shares_at_height(&self, height: u32) -> HashMap<BlockHash, ShareBlock>;
        pub fn get_share_headers(&self, share_hashes: Vec<BlockHash>) -> Vec<ShareHeader>;
        pub fn get_headers_for_locator(&self, block_hashes: &[BlockHash], stop_block_hash: &BlockHash, max_headers: usize) -> Vec<ShareHeader>;
        pub fn get_blockhashes_for_locator(&self, locator: &[BlockHash], stop_block_hash: &BlockHash, max_blockhashes: usize) -> Vec<BlockHash>;
        pub fn build_locator(&self) -> Result<Vec<BlockHash>, Box<dyn Error + Send + Sync>>;
        pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash>;
        pub fn get_tip_height(&self) -> Result<Option<u32>, Box<dyn Error + Send + Sync>>;
        pub fn add_job(&self, serialized_notify: String) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub fn get_jobs(&self, start_time: Option<u64>, end_time: Option<u64>, limit: usize) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>>;
        pub fn add_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error + Send + Sync>>;
        pub fn get_current_target(&self) -> Result<u32, Box<dyn Error + Send + Sync>>;
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
    use crate::test_utils::TestShareBlockBuilder;
    use crate::test_utils::genesis_for_tests;
    use crate::test_utils::multiplied_compact_target_as_work;
    use std::collections::HashSet;
    use std::str::FromStr;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();

        let chain = ChainStore::new(Arc::new(store), genesis.clone(), bitcoin::Network::Signet);

        let genesis_work = genesis.header.get_work();

        assert_eq!(
            chain.store.get_total_work().unwrap().to_string(),
            genesis_work.to_string()
        );

        // Create initial share (1)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_for_tests().block_hash().to_string())
            .work(2)
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        chain.add_share(share1.clone(), true).unwrap();

        let mut expected_tips = HashSet::new();
        expected_tips.insert(share1.block_hash());
        assert_eq!(chain.store.get_tips().len(), 1);
        assert_eq!(
            chain.store.get_total_work().unwrap().to_string(),
            (genesis_work + multiplied_compact_target_as_work(0x01e0377ae, 2)).to_string()
        ); // genesis (1) + share1 (2)
        assert_eq!(chain.store.get_chain_tip(), share1.block_hash());

        // Create uncles for share2
        let uncle1_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xe9695792)
            .build();

        let uncle2_share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xe9695793)
            .build();

        // first orphan is a tip
        chain.add_share(uncle1_share2.clone(), true).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.block_hash());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work + multiplied_compact_target_as_work(0x01e0377ae, 2) + genesis_work
        ); // genesis (1) + share1 (2) + uncle1_share2 (1)
        assert_eq!(chain.store.get_chain_tip(), uncle1_share2.block_hash());

        // second orphan is also a tip
        chain.add_share(uncle2_share2.clone(), true).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.block_hash());
        expected_tips.insert(uncle2_share2.block_hash());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work + multiplied_compact_target_as_work(0x01e0377ae, 2) + genesis_work
        ); // genesis (1) + share1 (2) + uncle1_share2 (1) [same diff uncles, only one is counted]
        // chain tip doesn't change as uncle2_share2 has same difficulty as uncle1_share2
        assert_eq!(chain.store.get_chain_tip(), uncle1_share2.block_hash());

        // Create share2 with its uncles
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .uncles(vec![uncle1_share2.block_hash(), uncle2_share2.block_hash()])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();

        chain.add_share(share2.clone(), true).unwrap();

        // two tips that will be future uncles and the chain tip
        expected_tips.clear();
        expected_tips.insert(share2.block_hash());
        assert_eq!(chain.store.get_tips(), expected_tips);
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
        ); // genesis (1) + share1 (2) + share2 (2) [both uncles not counted as they are removed from main chain]
        assert_eq!(chain.store.get_chain_tip(), share2.block_hash());
        // Create uncles for share3
        let uncle1_share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xe9695793)
            .work(1)
            .build();

        let uncle2_share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xe9695794)
            .work(1)
            .build();

        chain.add_share(uncle1_share3.clone(), true).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.block_hash());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + genesis_work
        ); // genesis (1) + share1 (2) + share2 (2) + uncle1_share3 (1)
        assert_eq!(chain.store.get_chain_tip(), uncle1_share3.block_hash());

        chain.add_share(uncle2_share3.clone(), true).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.block_hash());
        expected_tips.insert(uncle2_share3.block_hash());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total work for the highest work chain, which now is 1, 2, 3.1 (not 3.2)
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + genesis_work
        ); // genesis (1) + share1 (2) + share2 (2) + uncle1_share3 (1)
        assert_eq!(chain.store.get_chain_tip(), uncle1_share3.block_hash());
        // Create share3 with its uncles
        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .uncles(vec![uncle1_share3.block_hash(), uncle2_share3.block_hash()])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(3)
            .build();

        chain.add_share(share3.clone(), true).unwrap();

        expected_tips.clear();
        expected_tips.insert(share3.block_hash());

        assert_eq!(chain.store.get_tips(), expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3
        assert_eq!(
            chain.store.get_total_work().unwrap(),
            genesis_work
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 2)
                + multiplied_compact_target_as_work(0x01e0377ae, 3)
        ); // genesis (1) + share1 (2) + share2 (2) + share3 (3)
        assert_eq!(chain.store.get_chain_tip(), share3.block_hash());

        // Verify heights of all shares
        assert_eq!(
            chain.store.get_blockhashes_for_height(1),
            vec![share1.block_hash()]
        );

        assert_eq!(
            chain.store.get_blockhashes_for_height(2),
            vec![
                uncle1_share2.block_hash(),
                uncle2_share2.block_hash(),
                share2.block_hash(),
            ]
        );

        assert_eq!(
            chain.store.get_blockhashes_for_height(3),
            vec![
                uncle1_share3.block_hash(),
                uncle2_share3.block_hash(),
                share3.block_hash()
            ]
        );
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(
            Arc::new(store),
            genesis_for_tests(),
            bitcoin::Network::Signet,
        );

        // Create initial chain of MIN_CONFIRMATION_DEPTH + 10 blocks
        let mut prev_hash = None;
        let mut blocks = vec![];

        // Generate blocks first
        for i in 0..=MIN_CONFIRMATION_DEPTH + 10 {
            let mut share_builder = TestShareBlockBuilder::new();
            if prev_hash.is_some() {
                share_builder = share_builder.prev_share_blockhash(prev_hash.unwrap());
            }

            let share = share_builder
                .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
                .nonce(i as u32)
                .work(1)
                .build();

            blocks.push(share.clone());
            chain.add_share(share.clone(), true).unwrap();
            prev_hash = Some(share.block_hash().to_string());
        }

        // Now check confirmations: genesis (i=0) is always confirmed
        // Shares with depth > MIN_CONFIRMATION_DEPTH should be confirmed
        for (i, share) in blocks.iter().enumerate() {
            let depth = chain.get_depth(&share.block_hash()).unwrap_or(0);

            if i == 0 {
                // Genesis is always confirmed
                assert!(
                    chain.is_confirmed(share.clone()),
                    "Genesis should always be confirmed"
                );
            } else if depth > MIN_CONFIRMATION_DEPTH {
                // Shares with depth > MIN_CONFIRMATION_DEPTH should be confirmed
                assert!(
                    chain.is_confirmed(share.clone()),
                    "Share at index {i} with depth {depth} should be confirmed (MIN_CONFIRMATION_DEPTH={MIN_CONFIRMATION_DEPTH})"
                );
            } else {
                // Shares with depth <= MIN_CONFIRMATION_DEPTH should not be confirmed
                assert!(
                    !chain.is_confirmed(share.clone()),
                    "Share at index {i} with depth {depth} should NOT be confirmed (MIN_CONFIRMATION_DEPTH={MIN_CONFIRMATION_DEPTH})"
                );
            }
        }
    }

    #[test]
    fn test_get_depth() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(
            Arc::new(store),
            genesis_for_tests(),
            bitcoin::Network::Signet,
        );

        // Test when chain is empty (no chain tip)
        let random_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        assert_eq!(chain.get_depth(&random_hash), None);

        // Create initial share
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_for_tests().block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        chain.add_share(share1.clone(), true).unwrap();

        // Test when blockhash is chain tip
        assert_eq!(chain.get_depth(&share1.block_hash()), Some(0));

        // Create second share
        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        chain.add_share(share2.clone(), true).unwrap();

        // Test depth of first share when it's not the tip
        assert_eq!(chain.get_depth(&share2.block_hash()), Some(0));
        assert_eq!(chain.get_depth(&share1.block_hash()), Some(1));

        // Test when blockhash is not found in chain
        let non_existent_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
                .unwrap();
        assert_eq!(chain.get_depth(&non_existent_hash), None);
    }

    #[test]
    fn test_get_headers_for_locator() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(
            Arc::new(store),
            genesis_for_tests(),
            bitcoin::Network::Signet,
        );

        // Create a chain of 5 shares
        let share1 = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        let share5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        // Add shares to chain
        chain.add_share(share1.clone(), true).unwrap();
        chain.add_share(share2.clone(), true).unwrap();
        chain.add_share(share3.clone(), true).unwrap();
        chain.add_share(share4.clone(), true).unwrap();
        chain.add_share(share5.clone(), true).unwrap();

        // Test 1: Get headers starting from share1 up to share3
        let locator = vec![share1.block_hash()];
        let stop_hash = share3.block_hash();
        let headers = chain.get_headers_for_locator(&locator, &stop_hash, 500);
        assert_eq!(headers.len(), 2); // Should return share2 and share3
        assert_eq!(headers[0], share2.header);
        assert_eq!(headers[1], share3.header);

        // Test 2: Get headers with limit
        let headers = chain.get_headers_for_locator(&locator, &share5.block_hash(), 2);
        assert_eq!(headers.len(), 2); // Should only return 2 headers due to limit
        assert_eq!(headers[0], share2.header);
        assert_eq!(headers[1], share3.header);

        // Test 3: Get headers with non-existent locator
        let non_existent =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
                .unwrap();
        let headers = chain.get_headers_for_locator(&[non_existent], &share5.block_hash(), 500);
        assert_eq!(headers.len(), 1); // Should return genesis when no match found

        // Test 4: Multiple locator hashes, results should start from first found
        let locator = vec![
            non_existent,
            share3.block_hash(),
            share2.block_hash(),
            share1.block_hash(),
        ];
        let headers = chain.get_headers_for_locator(&locator, &share5.block_hash(), 500);
        assert_eq!(headers.len(), 2); // Should return share4 and share5
        assert_eq!(headers[0], share4.header);
        assert_eq!(headers[1], share5.header);

        // Test 5: Get blockhashes for locator
        let blockhashes = chain.get_blockhashes_for_locator(&locator, &share5.block_hash(), 500);
        assert_eq!(blockhashes.len(), 2); // Should return share4 and share5
        assert_eq!(blockhashes[0], share4.block_hash());
        assert_eq!(blockhashes[1], share5.block_hash());
    }

    #[test]
    fn test_build_locator_with_less_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(
            Arc::new(store),
            genesis_for_tests(),
            bitcoin::Network::Signet,
        );

        let mut blocks: Vec<ShareBlock> = Vec::new();

        let block_builder = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_for_tests().block_hash().to_string());
        let block = block_builder.build();
        blocks.push(block.clone());
        chain.add_share(block.clone(), true).unwrap();

        assert_eq!(chain.store.get_chain_tip(), block.block_hash());

        for i in 1..5 {
            let block_builder = TestShareBlockBuilder::new();
            let block = block_builder
                .prev_share_blockhash(blocks[i - 1].block_hash().to_string())
                .build();
            blocks.push(block.clone());
            chain.add_share(block.clone(), true).unwrap();
            assert_eq!(chain.store.get_chain_tip(), block.block_hash());
        }

        assert_eq!(blocks.len(), 5);
        assert_eq!(chain.store.get_chain_tip(), blocks[4].block_hash());

        let locator = chain.build_locator().unwrap();
        assert_eq!(locator.len(), 6); // Should return all blocks
        // Verify blocks are in reverse order (tip to genesis)
        for i in 0..5 {
            assert_eq!(locator[i], blocks[4 - i].block_hash());
        }
    }

    #[test]
    fn test_build_locator_with_more_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = ChainStore::new(
            Arc::new(store),
            genesis_for_tests(),
            bitcoin::Network::Signet,
        );

        let mut blocks: Vec<ShareBlock> = Vec::new();
        for i in 1..=25 {
            let prev_hash = if i == 1 {
                Some(genesis_for_tests().block_hash())
            } else {
                Some(blocks[i - 2].block_hash())
            };

            let mut block_builder = TestShareBlockBuilder::new();
            if prev_hash.is_some() {
                block_builder = block_builder.prev_share_blockhash(prev_hash.unwrap().to_string());
            }
            let block = block_builder.build();
            blocks.push(block.clone());
            chain.add_share(block, true).unwrap();
        }

        let locator = chain.build_locator().unwrap();
        // Should return 14 blocks:
        // - First 10 blocks (indexes 24 down to 15)
        // - Then blocks at positions 12 (index 12), 16 (index 8), 24 (index 0)
        // - Plus genesis block
        assert_eq!(locator.len(), 15);

        // Verify first 10 blocks are sequential from tip
        for i in 0..10 {
            assert_eq!(locator[i], blocks[24 - i].block_hash());
        }

        // Verify the step blocks
        assert_eq!(locator[10], blocks[14].block_hash());
        assert_eq!(locator[11], blocks[12].block_hash());
        assert_eq!(locator[12], blocks[8].block_hash());
        assert_eq!(locator[13], blocks[0].block_hash());
    }

    #[test]
    fn test_get_current_target() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();

        let chain = ChainStore::new(Arc::new(store), genesis.clone(), bitcoin::Network::Signet);

        // Get the current target from genesis block (which is the tip initially)
        let target = chain.get_current_target().unwrap();
        assert_eq!(target, genesis.header.bits.to_consensus());

        // Add a share - it becomes the new tip
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_for_tests().block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();

        chain.add_share(share1.clone(), true).unwrap();

        // Get current target should now return share1's target (the new tip)
        let new_target = chain.get_current_target().unwrap();
        assert_eq!(new_target, share1.header.bits.to_consensus());

        // Verify that chain tip has changed
        assert_eq!(chain.store.get_chain_tip(), share1.block_hash());
    }

    #[test]
    fn test_get_chain_tip_and_uncles_with_deep_tips() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let genesis = genesis_for_tests();

        let chain = ChainStore::new(Arc::new(store), genesis.clone(), bitcoin::Network::Signet);

        // Build a main chain of MAX_UNCLE_DEPTH + 2 shares (3 + 2 = 5)
        let share1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain.add_share(share1.clone(), true).unwrap();

        let share2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share1.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain.add_share(share2.clone(), true).unwrap();

        let share3 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share2.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain.add_share(share3.clone(), true).unwrap();

        let share4 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain.add_share(share4.clone(), true).unwrap();

        let share5 = TestShareBlockBuilder::new()
            .prev_share_blockhash(share4.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(2)
            .build();
        chain.add_share(share5.clone(), true).unwrap();

        // Create an uncle at genesis (will be at depth 5 from share5, which is > MAX_UNCLE_DEPTH=3)
        let deep_uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xdeadbeef)
            .work(1)
            .build();
        chain.add_share(deep_uncle.clone(), false).unwrap();

        // Create an uncle at share3 (will be at depth 1 from share5, which is <= MAX_UNCLE_DEPTH=3)
        let shallow_uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(share3.block_hash().to_string())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .nonce(0xbeefdead)
            .work(1)
            .build();
        chain.add_share(shallow_uncle.clone(), false).unwrap();

        // Verify both are in tips before calling get_chain_tip_and_uncles
        let all_tips = chain.store.get_tips();
        assert!(all_tips.contains(&deep_uncle.block_hash()));
        assert!(all_tips.contains(&shallow_uncle.block_hash()));
        assert!(all_tips.contains(&share5.block_hash()));

        // Verify depths (depth = tip_height - block_height)
        // share5 is at height 5, shallow_uncle at height 4, deep_uncle at height 1
        assert_eq!(chain.get_depth(&share5.block_hash()), Some(0)); // chain tip
        assert_eq!(chain.get_depth(&shallow_uncle.block_hash()), Some(1)); // 5 - 4 = 1, within MAX_UNCLE_DEPTH
        assert_eq!(chain.get_depth(&deep_uncle.block_hash()), Some(4)); // 5 - 1 = 4, beyond MAX_UNCLE_DEPTH=3

        // Get chain tip and uncles - deep_uncle should be filtered out
        let (tip, uncles) = chain.get_chain_tip_and_uncles();

        // Verify the tip is share5
        assert_eq!(tip, share5.block_hash());

        // Verify only shallow_uncle is included in uncles (deep_uncle should be filtered out)
        assert_eq!(uncles.len(), 1);
        assert!(uncles.contains(&shallow_uncle.block_hash()));
        assert!(!uncles.contains(&deep_uncle.block_hash()));
        assert!(!uncles.contains(&share5.block_hash())); // chain tip should not be in uncles
    }
}
