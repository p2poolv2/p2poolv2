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
use std::error::Error;
use tracing::{error, info};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// A datastructure representing the main share chain
/// The share chain reorgs when a share is found that has a higher total PoW than the current tip
pub struct Chain {
    pub tip: Option<BlockHash>,
    pub total_difficulty: Decimal,
    pub store: Store,
}

impl Chain {
    pub fn new(store: Store) -> Self {
        Self {
            tip: None,
            total_difficulty: dec!(0.0),
            store,
        }
    }

    /// Add a share to the chain and update the tip and total difficulty
    pub fn add_share(&mut self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Adding share to chain: {:?}", share);
        let blockhash = share.blockhash.clone();
        let prev_share_blockhash = share.prev_share_blockhash.clone();
        let share_difficulty = share.miner_share.diff;

        // save to share to store for all cases
        self.store.add_share(share.clone());

        // handle new chain by setting tip and total difficulty
        if self.tip.is_none() {
            info!("New chain: {:?}", blockhash);
            self.tip = Some(blockhash);
            self.total_difficulty = share_difficulty;
            return Ok(());
        }

        let current_tip = self.tip.as_ref().unwrap();
        // handle chain extension on current tip
        if prev_share_blockhash == *current_tip {
            info!("Chain extension on current tip: {:?}", blockhash);
            self.tip = Some(blockhash);
            self.total_difficulty += share_difficulty;
            return Ok(());
        }

        // handle potential reorgs
        if prev_share_blockhash != *current_tip {
            info!(
                "Potential reorg: {:?} -> {:?}",
                prev_share_blockhash, blockhash
            );
            // get total difficulty up to prev_share_blockhash
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

    /// Reorg the chain to the new share
    /// We do not explicitly mark any blocks as unconfirmed or transactions as unconfirmed. This is because we don't cache the status of the blocks or transactions.
    /// By changing the tip we are effectively marking all the blocks and transactions that were on the old tip as unconfirmed.
    /// When a share is being traded, if it is not on the main chain, it will not be accepted for the trade.
    ///
    /// The solution above will work as long as all the blocks and transactions are in memory. Once we need to query the chain from disk, we will need to implement a more sophisticated solution.
    /// In favour of avoiding premature optimization, we will implement the solution above first and then optimize it later, if needed.
    pub fn reorg(
        &mut self,
        share: ShareBlock,
        total_difficulty_upto_prev_share_blockhash: Decimal,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        info!("Reorging chain to share: {:?}", share.blockhash);
        self.tip = Some(share.blockhash);
        self.total_difficulty = total_difficulty_upto_prev_share_blockhash + share.miner_share.diff;
        Ok(())
    }

    /// Check if a share is confirmed according to the minimum confirmation depth
    pub fn is_confirmed(&self, share: ShareBlock) -> bool {
        self.store.get_chain_upto(&share.prev_share_blockhash).len() > MIN_CONFIRMATION_DEPTH
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
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::test_utils::fixtures::simple_miner_share;
    use tempfile::tempdir;

    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());
        let mut chain = Chain::new(store);

        // Create initial share (1)
        let share1 = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1].into(),
            prev_share_blockhash: vec![].into(),
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        chain.add_share(share1.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![1].into()));
        assert_eq!(chain.total_difficulty, dec!(1.0));

        // Create uncles for share2
        let uncle1_share2 = ShareBlock {
            nonce: vec![21],
            blockhash: vec![21].into(),
            prev_share_blockhash: vec![1].into(),
            uncles: vec![],
            miner_pubkey: vec![21],
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 1),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        let uncle2_share2 = ShareBlock {
            nonce: vec![22],
            blockhash: vec![22].into(),
            prev_share_blockhash: vec![1].into(),
            uncles: vec![],
            miner_pubkey: vec![22],
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 2),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        chain.add_share(uncle1_share2.clone()).unwrap();
        chain.add_share(uncle2_share2.clone()).unwrap();

        // difficulty remains the same as the previous tip, so there is no reorg
        assert_eq!(chain.tip, Some(vec![21].into()));
        assert_eq!(chain.total_difficulty, dec!(2.0));

        // Create share2 with its uncles
        let share2 = ShareBlock {
            nonce: vec![2].into(),
            blockhash: vec![2].into(),
            prev_share_blockhash: vec![1].into(),
            uncles: vec![vec![21].into(), vec![22].into()],
            miner_pubkey: vec![2].into(),
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 3),
                Some(1),
                Some(dec!(2.0)),
                Some(dec!(2.9041854952356509)),
            ),
        };
        chain.add_share(share2.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![2].into()));
        assert_eq!(chain.total_difficulty, dec!(3.0));

        // Create uncles for share3
        let uncle1_share3 = ShareBlock {
            nonce: vec![31].into(),
            blockhash: vec![31].into(),
            prev_share_blockhash: vec![2].into(),
            uncles: vec![],
            miner_pubkey: vec![31].into(),
            timestamp: 3,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 4),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        let uncle2_share3 = ShareBlock {
            nonce: vec![32].into(),
            blockhash: vec![32].into(),
            prev_share_blockhash: vec![2].into(),
            uncles: vec![],
            miner_pubkey: vec![32].into(),
            timestamp: 3,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 5),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };
        chain.add_share(uncle1_share3.clone()).unwrap();
        chain.add_share(uncle2_share3.clone()).unwrap();

        // if same diff share is added, it doesn't change the tip or total difficulty
        assert_eq!(chain.tip, Some(vec![31].into()));
        assert_eq!(chain.total_difficulty, dec!(4.0));

        // Create share3 with its uncles
        let share3 = ShareBlock {
            nonce: vec![3].into(),
            blockhash: vec![3].into(),
            prev_share_blockhash: vec![2].into(),
            uncles: vec![vec![31].into(), vec![32].into()],
            miner_pubkey: vec![3].into(),
            timestamp: 3,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 6),
                Some(1),
                Some(dec!(3.0)),
                Some(dec!(3.9041854952356509)),
            ),
        };
        chain.add_share(share3.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![3].into()));
        assert_eq!(chain.total_difficulty, dec!(6.0));
    }

    #[test]
    fn test_confirmations() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());
        let mut chain = Chain::new(store);

        // Create initial chain of MIN_CONFIRMATION_DEPTH + 1 blocks
        let mut prev_hash = vec![];
        let mut blocks = vec![];

        // Generate blocks
        for i in 0..=MIN_CONFIRMATION_DEPTH + 1 {
            let share = ShareBlock {
                nonce: vec![i as u8],
                blockhash: vec![i as u8].into(),
                prev_share_blockhash: prev_hash.into(),
                uncles: vec![],
                miner_pubkey: vec![i as u8].into(),
                timestamp: i as u64,
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
            prev_hash = vec![i as u8];

            if i > MIN_CONFIRMATION_DEPTH {
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
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());
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
