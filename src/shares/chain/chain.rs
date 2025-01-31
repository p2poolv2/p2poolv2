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

use crate::shares::miner_message::MinerWorkbase;
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
}

impl Chain {
    pub fn new(store: Store) -> Self {
        Self {
            tips: HashSet::new(),
            total_difficulty: dec!(0.0),
            store,
        }
    }

    /// Add a share to the chain and update the tips and total difficulty
    pub fn add_share(&mut self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Adding share to chain: {:?}", share);
        let blockhash = share.blockhash.clone();
        let prev_share_blockhash = share.prev_share_blockhash.clone();
        let share_difficulty = share.miner_share.diff;

        // save to share to store for all cases
        self.store.add_share(share.clone());

        // handle new chain by setting tip and total difficulty
        if self.tips.is_empty() {
            info!("New chain: {:?}", blockhash);
            self.tips.insert(blockhash);
            self.total_difficulty = share_difficulty;
            return Ok(());
        }

        // remove the previous blockhash from tips if it exists
        if let Some(prev) = prev_share_blockhash {
            self.tips.remove(&prev);
        }
        // remove uncles from tips
        if !share.uncles.is_empty() {
            for uncle in &share.uncles {
                self.tips.remove(uncle);
            }
        }
        // add the new share as a tip
        self.tips.insert(blockhash);

        // handle potential reorgs
        // get total difficulty up to prev_share_blockhash
        if let Some(prev_share_blockhash) = prev_share_blockhash {
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
        info!("Reorging chain to share: {:?}", share.blockhash);
        self.total_difficulty = total_difficulty_upto_prev_share_blockhash + share.miner_share.diff;
        Ok(())
    }

    /// Check if a share is confirmed according to the minimum confirmation depth
    pub fn is_confirmed(&self, share: ShareBlock) -> bool {
        if share.prev_share_blockhash.is_none() {
            return true;
        }
        self.store
            .get_chain_upto(&share.prev_share_blockhash.unwrap())
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

    /// Get a share from the chain given a share hash
    pub fn get_share(&self, share_hash: &BlockHash) -> Option<ShareBlock> {
        self.store.get_share(share_hash)
    }

    /// Get a workbase from the chain given a workinfoid
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        self.store.get_workbase(workinfoid)
    }

    /// Get the total difficulty of the chain
    pub fn get_total_difficulty(&self) -> Decimal {
        self.total_difficulty
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::test_utils::random_hex_string;
    use crate::test_utils::simple_miner_share;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
        let mut chain = Chain::new(store);

        // Create initial share (1)
        let share1 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                .parse()
                .unwrap(),
            prev_share_blockhash: None,
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        chain.add_share(share1.clone()).unwrap();

        let mut expected_tips = HashSet::new();
        expected_tips.insert(share1.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(1.0));

        // Create uncles for share2
        let uncle1_share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share1.blockhash),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 1),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        let uncle2_share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share1.blockhash),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 2),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        // first orphan is a tip
        chain.add_share(uncle1_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));

        // second orphan is also a tip
        chain.add_share(uncle2_share2.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share2.blockhash);
        expected_tips.insert(uncle2_share2.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(2.0));

        // Create share2 with its uncles
        let share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share1.blockhash),
            uncles: vec![uncle1_share2.blockhash, uncle2_share2.blockhash],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 3),
                Some(1),
                Some(dec!(2.0)),
                Some(dec!(2.9041854952356509)),
            ),
        };
        chain.add_share(share2.clone()).unwrap();

        /// two tips that will be future uncles and the chain tip
        expected_tips.clear();
        expected_tips.insert(share2.blockhash);
        assert_eq!(chain.tips, expected_tips);
        assert_eq!(chain.total_difficulty, dec!(3.0));

        // Create uncles for share3
        let uncle1_share3 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 4),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        let uncle2_share3 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 5),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };

        chain.add_share(uncle1_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1
        assert_eq!(chain.total_difficulty, dec!(4.0));

        chain.add_share(uncle2_share3.clone()).unwrap();
        expected_tips.clear();
        expected_tips.insert(uncle1_share3.blockhash);
        expected_tips.insert(uncle2_share3.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3.1 (not 3.2)
        assert_eq!(chain.total_difficulty, dec!(4.0));

        // Create share3 with its uncles
        let share3 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
            uncles: vec![uncle1_share3.blockhash, uncle2_share3.blockhash],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 6),
                Some(1),
                Some(dec!(3.0)),
                Some(dec!(3.9041854952356509)),
            ),
        };
        chain.add_share(share3.clone()).unwrap();

        expected_tips.clear();
        expected_tips.insert(share3.blockhash);

        assert_eq!(chain.tips, expected_tips);
        // we only look at total difficulty for the highest work chain, which now is 1, 2, 3
        assert_eq!(chain.total_difficulty, dec!(6.0));
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string());
        let mut chain = Chain::new(store);

        // Create initial chain of MIN_CONFIRMATION_DEPTH + 1 blocks
        let mut prev_hash = None;
        let mut blocks = vec![];

        // Generate blocks
        for i in 0..=MIN_CONFIRMATION_DEPTH + 1 {
            let share = ShareBlock {
                blockhash: random_hex_string(64, 8).parse().unwrap(),
                prev_share_blockhash: prev_hash,
                uncles: vec![],
                miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                    .parse()
                    .unwrap(),
                tx_hashes: vec![],
                miner_share: simple_miner_share(
                    Some(7452731920372203525 + i as u64),
                    Some(1),
                    Some(dec!(1.0)),
                    Some(dec!(1.9041854952356509)),
                ),
            };
            blocks.push(share.clone());
            chain.add_share(share.clone()).unwrap();
            prev_hash = Some(share.blockhash);

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
}
