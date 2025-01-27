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

use crate::node::messages::Message;
use crate::shares::miner_message::MinerWorkbase;
use crate::shares::{BlockHash, ShareBlock};
use rocksdb::DB;
use std::error::Error;
use tracing::debug;

/// A store for share blocks.
/// RocksDB as is used as the underlying database.
pub struct Store {
    path: String,
    db: DB,
}

impl Store {
    /// Create a new share store
    pub fn new(path: String) -> Self {
        let db = DB::open_default(path.clone()).unwrap();
        Self { path, db }
    }

    /// Add a share to the store
    pub fn add_share(&mut self, share: ShareBlock) {
        debug!("Adding share to store: {:?}", share.blockhash);
        self.db
            .put::<&[u8], Vec<u8>>(
                share.blockhash.clone().as_ref(),
                Message::ShareBlock(share).cbor_serialize().unwrap(),
            )
            .unwrap();
    }

    /// Add a workbase to the store
    pub fn add_workbase(&mut self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error>> {
        debug!("Adding workbase to store: {:?}", workbase.workinfoid);
        self.db
            .put(
                workbase.workinfoid.to_string().as_bytes(),
                Message::Workbase(workbase).cbor_serialize().unwrap(),
            )
            .unwrap();
        Ok(())
    }

    /// Get a workbase from the store
    pub fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        let workbase = self.db.get(workinfoid.to_string().as_bytes()).unwrap();
        if workbase.is_none() {
            return None;
        }
        let workbase = Message::cbor_deserialize(&workbase.unwrap()).unwrap();
        let workbase = match workbase {
            Message::Workbase(workbase) => workbase,
            _ => return None,
        };
        Some(workbase)
    }

    /// Get a share from the store
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        debug!("Getting share from store: {:?}", blockhash);
        let share = match self.db.get::<&[u8]>(blockhash.as_ref()) {
            Ok(Some(share)) => share,
            Ok(None) | Err(_) => return None,
        };
        let share = match Message::cbor_deserialize(&share) {
            Ok(share) => share,
            Err(_) => return None,
        };
        let share = match share {
            Message::ShareBlock(share) => share,
            _ => return None,
        };
        Some(share)
    }

    /// Get the parent of a share as a ShareBlock
    pub fn get_parent(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        let share = self.get_share(blockhash)?;
        let parent_blockhash = share.prev_share_blockhash.clone();
        self.get_share(&parent_blockhash.unwrap())
    }

    /// Get the uncles of a share as a vector of ShareBlocks
    /// Panics if an uncle hash is not found in the store
    pub fn get_uncles(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        let share = self.get_share(blockhash);
        if share.is_none() {
            return vec![];
        }
        let share = share.unwrap();
        share
            .uncles
            .iter()
            .map(|uncle| self.get_share(uncle).unwrap())
            .collect()
    }

    /// Get entire chain from earliest known block to blockhash
    pub fn get_chain_upto(&self, blockhash: &BlockHash) -> Vec<ShareBlock> {
        debug!("Getting chain upto: {:?}", blockhash);
        std::iter::successors(self.get_share(blockhash), |share| {
            if share.prev_share_blockhash.is_none() {
                None
            } else {
                let prev_blockhash = share.prev_share_blockhash.unwrap();
                self.get_share(&prev_blockhash)
            }
        })
        .collect()
    }

    /// Get common ancestor of two blockhashes
    pub fn get_common_ancestor(
        &self,
        blockhash1: &BlockHash,
        blockhash2: &BlockHash,
    ) -> Option<BlockHash> {
        debug!(
            "Getting common ancestor of: {:?} and {:?}",
            blockhash1, blockhash2
        );
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
mod tests {
    use super::*;
    use crate::test_utils::fixtures::simple_miner_share;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;
    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create initial share
        let share1 = ShareBlock {
            nonce: 1,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                .parse()
                .unwrap(),
            prev_share_blockhash: None,
            uncles: vec![],
            miner_pubkey: vec![1].into(),
            timestamp: 1,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };

        // Create uncles for share2
        let uncle1_share2 = ShareBlock {
            nonce: 21,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![],
            miner_pubkey: vec![21].into(),
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
            nonce: 22,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![],
            miner_pubkey: vec![22].into(),
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 2),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };

        // Create share2 with uncles
        let share2 = ShareBlock {
            nonce: 2,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![uncle1_share2.blockhash, uncle2_share2.blockhash],
            miner_pubkey: vec![2].into(),
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 3),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };

        // Create uncles for share3
        let uncle1_share3 = ShareBlock {
            nonce: 31,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
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
            nonce: 32,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
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

        // Create share3 with uncles
        let share3 = ShareBlock {
            nonce: 3,
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(share2.blockhash),
            uncles: vec![uncle1_share3.blockhash, uncle2_share3.blockhash],
            miner_pubkey: vec![3].into(),
            timestamp: 3,
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 6),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
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
        let chain = store.get_chain_upto(&share3.blockhash);

        // Get common ancestor of share3 and share2
        let common_ancestor = store.get_common_ancestor(&share3.blockhash, &share2.blockhash);
        assert_eq!(common_ancestor, Some(share1.blockhash));

        // Get chain up to uncle1_share3 (share31)
        let chain_to_uncle = store.get_chain_upto(&uncle1_share3.blockhash);
        assert_eq!(chain_to_uncle.len(), 3);
        assert_eq!(chain_to_uncle[0].blockhash, uncle1_share3.blockhash);
        assert_eq!(chain_to_uncle[1].blockhash, share2.blockhash);
        assert_eq!(chain_to_uncle[2].blockhash, share1.blockhash);

        // Chain should contain share3, share2, share1 in reverse order
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].blockhash, share3.blockhash);
        assert_eq!(chain[1].blockhash, share2.blockhash);
        assert_eq!(chain[2].blockhash, share1.blockhash);

        // Verify uncles of share2
        let uncles_share2 = store.get_uncles(&share2.blockhash);
        assert_eq!(uncles_share2.len(), 2);
        assert!(uncles_share2
            .iter()
            .any(|u| u.blockhash == uncle1_share2.blockhash));
        assert!(uncles_share2
            .iter()
            .any(|u| u.blockhash == uncle2_share2.blockhash));

        // Verify uncles of share3
        let uncles_share3 = store.get_uncles(&share3.blockhash);
        assert_eq!(uncles_share3.len(), 2);
        assert!(uncles_share3
            .iter()
            .any(|u| u.blockhash == uncle1_share3.blockhash));
        assert!(uncles_share3
            .iter()
            .any(|u| u.blockhash == uncle2_share3.blockhash));
    }
}
