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

use crate::shares::{ShareBlock, BlockHash};
use rocksdb::{DB};
use tracing::debug;
use crate::node::messages::Message;
/// A store for share blocks, for now it is just a simple in-memory store
/// TODO: Implement a persistent store
pub struct Store {
    path: String,
    db: DB,
}

impl Store {
    /// Create a new share store
    pub fn new(path: Option<String>) -> Self {
        let path = path.unwrap_or("store.db".to_string());
        let path = format!("./store/{}", path);
        let db = DB::open_default(path.clone()).unwrap();
        Self { path, db }
    }

    /// Add a share to the store
    pub fn add_share(&mut self, share: ShareBlock) {
        debug!("Adding share to store: {:?}", share.blockhash);
        self.db.put(share.blockhash.clone(), share.cbor_serialize().unwrap()).unwrap();
    }

    /// Get a share from the store
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        if blockhash.is_empty() {
            return None;
        }
        debug!("Getting share from store: {:?}", blockhash);
        let share = self.db.get(blockhash).unwrap().unwrap();
        ShareBlock::cbor_deserialize(&share).ok()
    }

    /// Get the parent of a share as a ShareBlock
    pub fn get_parent(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        let share = self.get_share(blockhash)?;
        let parent_blockhash = share.prev_share_blockhash.clone();
        self.get_share(&parent_blockhash)
    }

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
    pub fn get_uncles(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return vec![];
        }
        let share = share.unwrap();
        share.uncles.iter().map(|uncle| {
            self.get_share(uncle).unwrap()
        }).collect()
    }

    /// Get entire chain from earliest known block to blockhash
    pub fn get_chain_upto(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        debug!("Getting chain upto: {:?}", blockhash);
        std::iter::successors(
            self.get_share(blockhash),
            |share| self.get_share(&share.prev_share_blockhash)
        )
        .collect()
    }

    /// Get common ancestor of two blockhashes
    pub fn get_common_ancestor(&self, blockhash1: &BlockHash, blockhash2: &BlockHash) -> Option<BlockHash> {
        debug!("Getting common ancestor of: {:?} and {:?}", blockhash1, blockhash2);
        let chain1 = self.get_chain_upto(blockhash1);
        let chain2 = self.get_chain_upto(blockhash2);
        if let Some(blockhash) = chain1.iter().rev().find(|share| chain2.contains(share)) {
            Some(blockhash.blockhash.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
impl Drop for Store {
    // Drop created store db only for tests once a test is done
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.path.clone()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_with_uncles() {
        let mut store = Store::new(Some("test_chain_with_uncles.db".to_string()));

        // Create initial share
        let share1 = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1],
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            difficulty: 1,
        };

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
        };

        // Create share2 with uncles
        let share2 = ShareBlock {
            nonce: vec![2],
            blockhash: vec![2],
            prev_share_blockhash: vec![1],
            uncles: vec![vec![21], vec![22]],
            miner_pubkey: vec![2],
            timestamp: 2,
            tx_hashes: vec![],
            difficulty: 1,
        };

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
        };

        let uncle2_share3 = ShareBlock {
            nonce: vec![32],
            blockhash: vec![32],
            prev_share_blockhash: vec![2],
            uncles: vec![],
            miner_pubkey: vec![32],
            timestamp: 3,
            tx_hashes: vec![],
            difficulty: 1,
        };

        // Create share3 with uncles
        let share3 = ShareBlock {
            nonce: vec![3],
            blockhash: vec![3],
            prev_share_blockhash: vec![2],
            uncles: vec![vec![31], vec![32]],
            miner_pubkey: vec![3],
            timestamp: 3,
            tx_hashes: vec![],
            difficulty: 1,
        };

        // Add all shares to store
        store.add_share(share1.clone());
        store.add_share(uncle1_share2.clone());
        store.add_share(uncle2_share2.clone());
        store.add_share(share2.clone());
        store.add_share(uncle1_share3.clone());
        store.add_share(uncle2_share3.clone());
        store.add_share(share3.clone());

        // Get chain up to share3
        let chain = store.get_chain_upto(&vec![3]);

        // Get common ancestor of share3 and share2
        let common_ancestor = store.get_common_ancestor(&vec![3], &vec![2]);
        assert_eq!(common_ancestor, Some(vec![1]));

        // Get chain up to uncle1_share3 (share31)
        let chain_to_uncle = store.get_chain_upto(&vec![31]);
        assert_eq!(chain_to_uncle.len(), 3);
        assert_eq!(chain_to_uncle[0].blockhash, vec![31]);
        assert_eq!(chain_to_uncle[1].blockhash, vec![2]);
        assert_eq!(chain_to_uncle[2].blockhash, vec![1]);

        // Chain should contain share3, share2, share1 in reverse order
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].blockhash, vec![3]);
        assert_eq!(chain[1].blockhash, vec![2]); 
        assert_eq!(chain[2].blockhash, vec![1]);

        // Verify uncles of share2
        let uncles_share2 = store.get_uncles(&vec![2]);
        assert_eq!(uncles_share2.len(), 2);
        assert!(uncles_share2.iter().any(|u| u.blockhash == vec![21]));
        assert!(uncles_share2.iter().any(|u| u.blockhash == vec![22]));

        // Verify uncles of share3
        let uncles_share3 = store.get_uncles(&vec![3]);
        assert_eq!(uncles_share3.len(), 2);
        assert!(uncles_share3.iter().any(|u| u.blockhash == vec![31]));
        assert!(uncles_share3.iter().any(|u| u.blockhash == vec![32]));
    }
}