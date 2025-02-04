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
use crate::shares::transactions::pool_transaction::PoolTransaction;
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

    /// Add a transaction to the store
    /// The txid is computed and Transaction is serialized using cbor
    pub fn add_transaction(&mut self, pool_tx: PoolTransaction) -> Result<(), Box<dyn Error>> {
        let txid = pool_tx.tx.compute_txid();
        debug!("Adding transaction to store: {:?}", txid);
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&pool_tx, &mut serialized).unwrap();
        self.db
            .put::<&[u8], Vec<u8>>(txid.as_ref(), serialized)
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

    /// Get a transaction from the store using a provided txid
    /// The transaction is deserialized using cbor
    pub fn get_transaction(&self, txid: &bitcoin::Txid) -> Option<PoolTransaction> {
        let tx = match self.db.get::<&[u8]>(txid.as_ref()) {
            Ok(Some(tx)) => tx,
            Ok(None) | Err(_) => return None,
        };
        let tx: PoolTransaction = match ciborium::de::from_reader(tx.as_slice()) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Error deserializing transaction: {:?}", e);
                return None;
            }
        };
        Some(tx)
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

    /// Get entire chain from earliest known block to given blockhash, excluding the given blockhash
    /// When we prune the chain, the oldest share in the chain will be marked as root, by removing it's prev_share_blockhash
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
    use crate::test_utils::simple_miner_share;
    use crate::test_utils::test_coinbase_transaction;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[test]
    fn test_chain_with_uncles() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create initial share
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
            coinbase_tx: test_coinbase_transaction(),
        };

        // Create uncles for share2
        let uncle1_share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
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
            coinbase_tx: test_coinbase_transaction(),
        };

        let uncle2_share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
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
            coinbase_tx: test_coinbase_transaction(),
        };

        // Create share2 with uncles
        let share2 = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![uncle1_share2.blockhash, uncle2_share2.blockhash],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![],
            miner_share: simple_miner_share(
                Some(7452731920372203525 + 3),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
            coinbase_tx: test_coinbase_transaction(),
        };

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
            coinbase_tx: test_coinbase_transaction(),
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
            coinbase_tx: test_coinbase_transaction(),
        };

        // Create share3 with uncles
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
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
            coinbase_tx: test_coinbase_transaction(),
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

    #[test]
    fn test_transaction_store() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        // Create a simple test transaction
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let pool_tx = PoolTransaction::new(tx.clone());

        // Store the transaction
        let txid = tx.compute_txid();
        store.add_transaction(pool_tx.clone()).unwrap();

        // Retrieve the transaction
        let retrieved_tx = store.get_transaction(&txid);
        assert!(retrieved_tx.is_some());
        assert_eq!(retrieved_tx.unwrap().tx, tx);

        // Try getting non-existent transaction
        let fake_txid = "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
            .parse()
            .unwrap();
        assert!(store.get_transaction(&fake_txid).is_none());
    }
}
