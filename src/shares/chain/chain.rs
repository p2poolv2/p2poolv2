// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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

use crate::shares::miner_message::{MinerWorkbase, UserWorkbase};
use crate::shares::{store::Store, BlockHash, ShareBlock, ShareHeader};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashSet;
use std::error::Error;
use tracing::{error, info};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// A datastructure representing the main share chain
/// The share chain reorgs when a share is found that has a higher total PoW than the current tip
pub struct Chain {
    pub tips: HashSet<BlockHash>,
    pub total_difficulty: Decimal,
    pub store: Store,
    pub chain_tip: Option<BlockHash>,
    pub genesis_block_hash: Option<BlockHash>,
}

#[allow(dead_code)]
impl Chain {
    pub fn new(store: Store) -> Self {
        Self {
            tips: HashSet::new(),
            total_difficulty: dec!(0.0),
            store,
            chain_tip: None,
            genesis_block_hash: None,
        }
    }

    /// Add a share to the chain and update the tips and total difficulty
    pub fn add_share(&mut self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Adding share to chain: {:?}", share);
        if self.tips.is_empty() {
            self.genesis_block_hash = Some(share.header.miner_share.hash.clone());
        }
        let blockhash = share.header.miner_share.hash.clone();
        let prev_share_blockhash = share.header.prev_share_blockhash.clone();
        let share_difficulty = share.header.miner_share.diff;

        // save to share to store for all cases
        self.store.add_share(share.clone());

        // handle new chain by setting tip and total difficulty
        if self.tips.is_empty() {
            info!("New chain: {:?}", blockhash);
            self.tips.insert(blockhash);
            self.total_difficulty = share_difficulty;
            self.chain_tip = Some(blockhash);
            return Ok(());
        }

        // remove the previous blockhash from tips if it exists
        if let Some(prev) = prev_share_blockhash {
            self.tips.remove(&prev);
        }
        // remove uncles from tips
        if !share.header.uncles.is_empty() {
            for uncle in &share.header.uncles {
                self.tips.remove(uncle);
            }
        }
        // add the new share as a tip
        self.tips.insert(blockhash);
        // handle potential reorgs
        // get total difficulty up to prev_share_blockhash
        if let Some(prev_share_blockhash) = prev_share_blockhash {
            tracing::info!("Checking for reorgs at share: {:?}", prev_share_blockhash);
            let chain_upto_prev_share_blockhash = self.store.get_chain_upto(&prev_share_blockhash);
            let total_difficulty_upto_prev_share_blockhash = chain_upto_prev_share_blockhash
                .iter()
                .map(|share| share.header.miner_share.diff)
                .sum::<Decimal>();
            if total_difficulty_upto_prev_share_blockhash + share_difficulty > self.total_difficulty
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

    /// Remove a blockhash from the tips set
    /// If the blockhash is not in the tips set, this is a no-op
    pub fn remove_from_tips(&mut self, blockhash: &BlockHash) {
        self.tips.remove(blockhash);
    }

    /// Add a blockhash to the tips set
    /// If the blockhash is already in the tips set, this is a no-op
    pub fn add_to_tips(&mut self, blockhash: BlockHash) {
        self.tips.insert(blockhash);
    }

    /// Reorg the chain to the new share
    /// We do not explicitly mark any blocks as unconfirmed or transactions as unconfirmed. This is because we don't cache the status of the blocks or transactions.
    /// By changing the tips we are effectively marking all the blocks and transactions that were on the old tips as unconfirmed.
    /// When a share is being traded, if it is not on the main chain, it will not be accepted for the trade.
    pub fn reorg(
        &mut self,
        share: ShareBlock,
        total_difficulty_upto_prev_share_blockhash: Decimal,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!(
            "Reorging chain to share: {:?}",
            share.header.miner_share.hash
        );
        self.total_difficulty =
            total_difficulty_upto_prev_share_blockhash + share.header.miner_share.diff;
        self.chain_tip = Some(share.header.miner_share.hash);
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
        &mut self,
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
        &mut self,
        user_workbase: UserWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Err(e) = self.store.add_user_workbase(user_workbase) {
            error!("Failed to add user workbase to store: {}", e);
            return Err("Error adding user workbase to store".into());
        }
        Ok(())
    }

    /// Get a share from the chain given a share hash
    pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock> {
        self.store.get_share(share_hash)
    }

    /// Get a share header from the chain given a share hash
    pub fn get_share_headers(&self, share_hashes: &Vec<BlockHash>) -> Vec<ShareHeader> {
        self.store.get_share_headers(share_hashes.clone())
    }

    /// Get blockhashes for locator
    /// Returns a list of shares starting from the earliest block from the block hashes
    pub fn get_headers_for_locator(
        &self,
        block_hashes: &Vec<BlockHash>,
        stop_block_hash: &BlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        if self.chain_tip.is_none() {
            return vec![];
        }

        self.store
            .get_headers_for_locator(block_hashes, stop_block_hash, limit)
    }

    /// Get a locator for the chain.
    /// - Start from the tip, go back until we hit genesis block
    /// - After 10 blocks, double the step size each time
    /// - Return the locator
    /// TODO[pool2win, optimisation]: We end up scanning the entire chain here,
    /// we can work with indexes once we add the indexes to the chain handle.
    pub fn build_locator(&self) -> Result<Vec<bitcoin::BlockHash>, Box<dyn Error + Send>> {
        if self.chain_tip.is_none() {
            return Ok(vec![]);
        }
        let tip = self.chain_tip.unwrap();
        let mut step = 1;
        let mut current_hash = tip;
        let mut locator = vec![current_hash];

        // Keep going back until we hit genesis block
        while let Some(block) = self.get_share(&current_hash) {
            // After 10 blocks, double the step size each time
            if locator.len() >= 10 {
                step *= 2;
            }

            // Go back 'step' number of blocks
            let mut next_hash = block.header.prev_share_blockhash;
            for _ in 1..step {
                if let Some(prev_block_hash) = next_hash {
                    if let Some(prev_block) = self.get_share(&prev_block_hash) {
                        next_hash = prev_block.header.prev_share_blockhash;
                    }
                }
            }

            // Break if we hit genesis (no previous hash)
            match next_hash {
                Some(hash) => {
                    current_hash = hash;
                    locator.push(current_hash);
                }
                None => {
                    // push the genesis block if we reached the end
                    if current_hash != self.genesis_block_hash.unwrap() {
                        locator.push(self.genesis_block_hash.unwrap());
                    }
                    break;
                }
            }
        }
        Ok(locator)
    }

    /// Get a workbase from the chain given a workinfoid
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        self.store.get_workbase(workinfoid)
    }

    /// Get a user workbase from the chain given a workinfoid
    pub fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase> {
        self.store.get_user_workbase(workinfoid)
    }

    /// Get the total difficulty of the chain
    pub fn get_total_difficulty(&self) -> Decimal {
        self.total_difficulty
    }

    /// Get the chain tip and uncles
    pub fn get_chain_tip_and_uncles(&self) -> (Option<BlockHash>, HashSet<BlockHash>) {
        let mut uncles = self.tips.clone();
        if let Some(tip) = self.chain_tip {
            uncles.remove(&tip);
        }
        (self.chain_tip, uncles)
    }

    /// Get the depth of a blockhash from chain tip
    /// Returns None if blockhash is not found in chain
    /// Returns 0 if blockhash is the chain tip
    pub fn get_depth(&self, blockhash: &BlockHash) -> Option<usize> {
        // If chain tip is None, return None
        let tip = match self.chain_tip {
            Some(tip) => tip,
            None => return None,
        };

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
        Some(chain.len())
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::test_utils::random_hex_string;
    use crate::test_utils::TestBlockBuilder;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

        // Create initial share (1)
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        chain.add_share(share1.clone()).unwrap();

        let mut expected_tips = HashSet::new();
        expected_tips.insert(share1.header.miner_share.hash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(1.0));
        assert_eq!(chain.chain_tip, Some(share1.header.miner_share.hash));

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // first orphan is a tip
        chain.add_share(uncle1_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.header.miner_share.hash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share2.header.miner_share.hash));

        // second orphan is also a tip
        chain.add_share(uncle2_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.header.miner_share.hash);
        expected_tips.insert(uncle2_share2.header.miner_share.hash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));
        // chain tip doesn't change as uncle2_share2 has same difficulty as uncle1_share2
        assert_eq!(chain.chain_tip, Some(uncle1_share2.header.miner_share.hash));

        // Create share2 with its uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.header.miner_share.hash.to_string().as_str())
            .uncles(vec![
                uncle1_share2.header.miner_share.hash,
                uncle2_share2.header.miner_share.hash,
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
        expected_tips.insert(share2.header.miner_share.hash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(3.0));
        assert_eq!(chain.chain_tip, Some(share2.header.miner_share.hash));
        // Create uncles for share3
        let uncle1_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba")
            .prev_share_blockhash(share2.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(uncle1_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.header.miner_share.hash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1
        assert_eq!(chain.total_difficulty, dec!(4.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share3.header.miner_share.hash));
        chain.add_share(uncle2_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.header.miner_share.hash);
        expected_tips.insert(uncle2_share3.header.miner_share.hash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1 (not 3.2)
        assert_eq!(chain.total_difficulty, dec!(4.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share3.header.miner_share.hash));
        // Create share3 with its uncles
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb")
            .prev_share_blockhash(share2.header.miner_share.hash.to_string().as_str())
            .uncles(vec![
                uncle1_share3.header.miner_share.hash,
                uncle2_share3.header.miner_share.hash,
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 6)
            .clientid(1)
            .diff(dec!(3.0))
            .sdiff(dec!(3.9041854952356509))
            .build();

        chain.add_share(share3.clone()).unwrap();

        expected_tips.clear();
        expected_tips.insert(share3.header.miner_share.hash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3
        assert_eq!(chain.total_difficulty, dec!(6.0));
        assert_eq!(chain.chain_tip, Some(share3.header.miner_share.hash));
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

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
            blockhash_strings.push(share.header.miner_share.hash.to_string()); // Store string
            prev_hash = Some(blockhash_strings.last().unwrap().as_str()); // Use reference to stored string

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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

        // Load test data from JSON file
        let test_data = fs::read_to_string("tests/test_data/single_node_simple.json")
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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

        // Test when chain is empty (no chain tip)
        let random_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
            .parse()
            .unwrap();
        assert_eq!(chain.get_depth(&random_hash), None);

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(share1.clone()).unwrap();

        // Test when blockhash is chain tip
        assert_eq!(chain.get_depth(&share1.header.miner_share.hash), Some(0));

        // Create second share
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203526)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(share2.clone()).unwrap();

        // Test depth of first share when it's not the tip
        assert_eq!(chain.get_depth(&share2.header.miner_share.hash), Some(0));
        assert_eq!(chain.get_depth(&share1.header.miner_share.hash), Some(1));

        // Test when blockhash is not found in chain
        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse()
            .unwrap();
        assert_eq!(chain.get_depth(&non_existent_hash), None);
    }

    #[test]
    fn test_get_headers_for_locator() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

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
            .prev_share_blockhash(share1.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(2)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(share2.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(3)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share4 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
            .prev_share_blockhash(share3.header.miner_share.hash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let share5 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(share4.header.miner_share.hash.to_string().as_str())
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
        let locator = vec![share1.header.miner_share.hash];
        let stop_hash = share3.header.miner_share.hash;
        let headers = chain.get_headers_for_locator(&locator, &stop_hash, 500);
        assert_eq!(headers.len(), 2); // Should return share2 and share3
        assert_eq!(headers[0].miner_share.hash, share2.header.miner_share.hash);
        assert_eq!(headers[1].miner_share.hash, share3.header.miner_share.hash);

        // Test 2: Get headers with limit
        let headers = chain.get_headers_for_locator(&locator, &share5.header.miner_share.hash, 2);
        assert_eq!(headers.len(), 2); // Should only return 2 headers due to limit
        assert_eq!(headers[0].miner_share.hash, share2.header.miner_share.hash);
        assert_eq!(headers[1].miner_share.hash, share3.header.miner_share.hash);

        // Test 3: Get headers with non-existent locator
        let non_existent = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
            .parse()
            .unwrap();
        let headers = chain.get_headers_for_locator(
            &vec![non_existent],
            &share5.header.miner_share.hash,
            500,
        );
        assert_eq!(headers.len(), 0); // Should return empty vec when locator not found

        // Test 4: Multiple locator hashes, results should start from first found
        let locator = vec![
            non_existent,
            share3.header.miner_share.hash,
            share2.header.miner_share.hash,
            share1.header.miner_share.hash,
        ];
        let headers = chain.get_headers_for_locator(&locator, &share5.header.miner_share.hash, 500);
        assert_eq!(headers.len(), 2); // Should return share4 and share5
        assert_eq!(headers[0].miner_share.hash, share4.header.miner_share.hash);
        assert_eq!(headers[1].miner_share.hash, share5.header.miner_share.hash);
    }

    #[test]
    fn test_build_locator_with_less_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

        let mut blocks: Vec<ShareBlock> = Vec::new();

        let block_builder = TestBlockBuilder::new().blockhash(format!("{:064x}", 0).as_str());
        let block = block_builder.build();
        blocks.push(block.clone());
        chain.add_share(block).unwrap();

        for i in 1..5 {
            let block_builder = TestBlockBuilder::new().blockhash(format!("{:064x}", i).as_str());
            let block = block_builder
                .prev_share_blockhash(blocks[i - 1].header.miner_share.hash.to_string().as_str())
                .build();
            blocks.push(block.clone());
            chain.add_share(block).unwrap();
        }

        assert_eq!(blocks.len(), 5);
        // Set chain tip to latest block
        chain.chain_tip = Some(blocks[4].header.miner_share.hash);

        let locator = chain.build_locator().unwrap();
        assert_eq!(locator.len(), 5); // Should return all blocks
                                      // Verify blocks are in reverse order (tip to genesis)
        for i in 0..5 {
            assert_eq!(locator[i], blocks[4 - i].header.miner_share.hash);
        }
    }

    #[test]
    fn test_build_locator_with_more_than_10_blocks() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string()).unwrap();
        let mut chain = Chain::new(store);

        let mut blocks: Vec<ShareBlock> = Vec::new();
        for i in 1..=25 {
            let prev_hash = if i == 1 {
                None
            } else {
                Some(blocks[i - 2].header.miner_share.hash)
            };

            let mut block_builder =
                TestBlockBuilder::new().blockhash(format!("{:064x}", i).as_str());
            if prev_hash.is_some() {
                block_builder =
                    block_builder.prev_share_blockhash(prev_hash.unwrap().to_string().as_str());
            }
            let block = block_builder.build();
            blocks.push(block.clone());
            chain.add_share(block).unwrap();
        }

        // Set chain tip to latest block
        chain.chain_tip = Some(blocks[24].header.miner_share.hash);

        let locator = chain.build_locator().unwrap();
        // Should return 14 blocks:
        // - First 10 blocks (indexes 24 down to 15)
        // - Then blocks at positions 12 (index 12), 16 (index 8), 24 (index 0)
        // - Plus genesis block
        assert_eq!(locator.len(), 14);

        // Verify first 10 blocks are sequential from tip
        for i in 0..10 {
            assert_eq!(locator[i], blocks[24 - i].header.miner_share.hash);
        }

        // Verify the step blocks
        assert_eq!(locator[10], blocks[13].header.miner_share.hash);
        assert_eq!(locator[11], blocks[9].header.miner_share.hash);
        assert_eq!(locator[12], blocks[1].header.miner_share.hash);
        assert_eq!(locator[13], blocks[0].header.miner_share.hash);
    }
}
