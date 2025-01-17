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

use std::error::Error;
use tracing::{error, info};
use crate::shares::{ShareBlock, BlockHash, store::Store};

/// The minimum number of shares that must be on the chain for a share to be considered confirmed
const MIN_CONFIRMATION_DEPTH: usize = 100;

/// A datastructure representing the main share chain
/// The share chain reorgs when a share is found that has a higher total PoW than the current tip
pub struct Chain {
    pub tip: Option<BlockHash>,
    pub total_difficulty: u64,
    pub store: Store,
}

impl Chain {
    pub fn new(store: Store) -> Self {
        Self { tip: None, total_difficulty: 0, store }
    }

    /// Add a share to the chain and update the tip and total difficulty
    pub fn add_share(&mut self, share: ShareBlock) -> Result<(), Box<dyn Error>> {
        info!("Adding share to chain: {:?}", share.blockhash);
        let blockhash = share.blockhash.clone();
        let prev_share_blockhash = share.prev_share_blockhash.clone();
        let share_difficulty = share.difficulty;

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
            info!("Potential reorg: {:?} -> {:?}", prev_share_blockhash, blockhash);
            // get total difficulty up to prev_share_blockhash
            let chain_upto_prev_share_blockhash = self.store.get_chain_upto(&prev_share_blockhash);
            let total_difficulty_upto_prev_share_blockhash = chain_upto_prev_share_blockhash.iter().map(|share| share.difficulty).sum::<u64>();
            if total_difficulty_upto_prev_share_blockhash + share_difficulty > self.total_difficulty {
                let reorg_result =  self.reorg(share, total_difficulty_upto_prev_share_blockhash);
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
    fn reorg(&mut self, share: ShareBlock, total_difficulty_upto_prev_share_blockhash: u64) -> Result<(), Box<dyn Error>> {
        self.tip = Some(share.blockhash);
        self.total_difficulty = total_difficulty_upto_prev_share_blockhash + share.difficulty;
        Ok(())
    }

    /// Check if a share is confirmed according to the minimum confirmation depth
    pub fn is_confirmed(&self, share: ShareBlock) -> bool {
        self.store.get_chain_upto(&share.prev_share_blockhash).len() > MIN_CONFIRMATION_DEPTH
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::miner_message::MinerShare;
    #[test]
    /// Setup a test chain with 3 shares on the main chain, where shares 2 and 3 have two uncles each
    fn test_chain_add_shares() {
        let mut store = Store::new("test_chain_add_shares.db".to_string());
        let mut chain = Chain::new(store);

        // Create initial share (1)
        let share1 = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1],
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            difficulty: 1,
            miner_share: MinerShare::default(),
        };
        chain.add_share(share1.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![1]));
        assert_eq!(chain.total_difficulty, 1);

        // Create uncles for share2
        let uncle1_share2 = ShareBlock {
            nonce: vec![21],
            blockhash: vec![21],
            prev_share_blockhash: vec![1],
            uncles: vec![],
            miner_pubkey: vec![21],
            timestamp: 2,
            tx_hashes: vec![],
            difficulty: 1,
            miner_share: MinerShare::default(),
        };
        let uncle2_share2 = ShareBlock {
            nonce: vec![22], 
            blockhash: vec![22],
            prev_share_blockhash: vec![1],
            uncles: vec![],
            miner_pubkey: vec![22],
            timestamp: 2,
            tx_hashes: vec![],
            difficulty: 1,
            miner_share: MinerShare::default(),
        };
        chain.add_share(uncle1_share2.clone()).unwrap();
        chain.add_share(uncle2_share2.clone()).unwrap();

        // difficulty remains the same as the previous tip, so there is no reorg
        assert_eq!(chain.tip, Some(vec![21]));
        assert_eq!(chain.total_difficulty, 2);

        // Create share2 with its uncles
        let share2 = ShareBlock {
            nonce: vec![2],
            blockhash: vec![2],
            prev_share_blockhash: vec![1],
            uncles: vec![vec![21], vec![22]],
            miner_pubkey: vec![2],
            timestamp: 2,
            tx_hashes: vec![],
            difficulty: 2,
            miner_share: MinerShare::default(),
        };
        chain.add_share(share2.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![2]));
        assert_eq!(chain.total_difficulty, 3);

        // Create uncles for share3
        let uncle1_share3 = ShareBlock {
            nonce: vec![31],
            blockhash: vec![31],
            prev_share_blockhash: vec![2],
            uncles: vec![],
            miner_pubkey: vec![31],
            timestamp: 3,
            tx_hashes: vec![],
            difficulty: 1,
            miner_share: MinerShare::default(),
        };
        let uncle2_share3 = ShareBlock {
            nonce: vec![32],
            blockhash: vec![32],
            prev_share_blockhash: vec![2],
            uncles: vec![],
            miner_pubkey: vec![32],
            timestamp: 3,
            tx_hashes: vec![],
            difficulty: 2,
            miner_share: MinerShare::default(),
        };
        chain.add_share(uncle1_share3.clone()).unwrap();
        chain.add_share(uncle2_share3.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![32]));
        assert_eq!(chain.total_difficulty, 5);

        // Create share3 with its uncles
        let share3 = ShareBlock {
            nonce: vec![3],
            blockhash: vec![3],
            prev_share_blockhash: vec![2],
            uncles: vec![vec![31], vec![32]],
            miner_pubkey: vec![3],
            timestamp: 3,
            tx_hashes: vec![],
            difficulty: 3,
            miner_share: MinerShare::default(),
        };
        chain.add_share(share3.clone()).unwrap();

        assert_eq!(chain.tip, Some(vec![3]));
        assert_eq!(chain.total_difficulty, 6);
    }

    #[test]
    fn test_confirmations() {
        let mut store = Store::new("test_confirmations.db".to_string());
        let mut chain = Chain::new(store);

        // Create initial chain of MIN_CONFIRMATION_DEPTH + 1 blocks
        let mut prev_hash = vec![];
        let mut blocks = vec![];

        // Generate blocks
        for i in 0..=MIN_CONFIRMATION_DEPTH + 1{
            let share = ShareBlock {
                nonce: vec![i as u8],
                blockhash: vec![i as u8],
                prev_share_blockhash: prev_hash,
                uncles: vec![],
                miner_pubkey: vec![i as u8],
                timestamp: i as u64,
                tx_hashes: vec![],
                difficulty: 1,
                miner_share: MinerShare::default(),
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
}