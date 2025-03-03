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
use crate::shares::{store::Store, BlockHash, ShareBlock};
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
}

#[allow(dead_code)]
impl Chain {
    pub fn new(store: Store) -> Self {
        Self {
            tips: HashSet::new(),
            total_difficulty: dec!(0.0),
            store,
            chain_tip: None,
        }
    }

    /// Add a share to the chain and update the tips and total difficulty
    pub fn add_share(&mut self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Adding share to chain: {:?}", share);
        let blockhash = share.header.blockhash.clone();
        let prev_share_blockhash = share.header.prev_share_blockhash.clone();
        let share_difficulty = share.miner_share.diff;

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
                .map(|share| share.miner_share.diff)
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
        info!("Reorging chain to share: {:?}", share.header.blockhash);
        self.total_difficulty = total_difficulty_upto_prev_share_blockhash + share.miner_share.diff;
        self.chain_tip = Some(share.header.blockhash);
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
    use bitcoin::sighash::Prevouts;
    use std::collections::btree_set::SymmetricDifference;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
        let mut chain = Chain::new(store);

        // Create initial share (1)
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        chain.add_share(share1.clone()).unwrap();

        let mut expected_tips = HashSet::new();
        expected_tips.insert(share1.header.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(1.0));
        assert_eq!(chain.chain_tip, Some(share1.header.blockhash));

        // Create uncles for share2
        let uncle1_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle2_share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // first orphan is a tip
        chain.add_share(uncle1_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.header.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share2.header.blockhash));

        // second orphan is also a tip
        chain.add_share(uncle2_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.header.blockhash);
        expected_tips.insert(uncle2_share2.header.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));
        // chain tip doesn't change as uncle2_share2 has same difficulty as uncle1_share2
        assert_eq!(chain.chain_tip, Some(uncle1_share2.header.blockhash));

        // Create share2 with its uncles
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share2.header.blockhash,
                uncle2_share2.header.blockhash,
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
        expected_tips.insert(share2.header.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(3.0));
        assert_eq!(chain.chain_tip, Some(share2.header.blockhash));
        // Create uncles for share3
        let uncle1_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 4)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        let uncle2_share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 5)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(uncle1_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.header.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1
        assert_eq!(chain.total_difficulty, dec!(4.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share3.header.blockhash));
        chain.add_share(uncle2_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.header.blockhash);
        expected_tips.insert(uncle2_share3.header.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1 (not 3.2)
        assert_eq!(chain.total_difficulty, dec!(4.0));
        assert_eq!(chain.chain_tip, Some(uncle1_share3.header.blockhash));
        // Create share3 with its uncles
        let share3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb")
            .prev_share_blockhash(share2.header.blockhash.to_string().as_str())
            .uncles(vec![
                uncle1_share3.header.blockhash,
                uncle2_share3.header.blockhash,
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203525 + 6)
            .clientid(1)
            .diff(dec!(3.0))
            .sdiff(dec!(3.9041854952356509))
            .build();

        chain.add_share(share3.clone()).unwrap();

        expected_tips.clear();
        expected_tips.insert(share3.header.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3
        assert_eq!(chain.total_difficulty, dec!(6.0));
        assert_eq!(chain.chain_tip, Some(share3.header.blockhash));
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
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
            blockhash_strings.push(share.header.blockhash.to_string()); // Store string
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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
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
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
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
        assert_eq!(chain.get_depth(&share1.header.blockhash), Some(0));

        // Create second share
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.header.blockhash.to_string().as_str())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .workinfoid(7452731920372203526)
            .clientid(1)
            .diff(dec!(1.0))
            .sdiff(dec!(1.9041854952356509))
            .build();

        chain.add_share(share2.clone()).unwrap();

        // Test depth of first share when it's not the tip
        assert_eq!(chain.get_depth(&share2.header.blockhash), Some(0));
        assert_eq!(chain.get_depth(&share1.header.blockhash), Some(1));

        // Test when blockhash is not found in chain
        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse()
            .unwrap();
        assert_eq!(chain.get_depth(&non_existent_hash), None);
    }
}
