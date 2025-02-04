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

pub mod chain;
pub mod ckpool_socket;
pub mod handle_mining_message;
pub mod miner_message;
pub mod receive_mining_message;
pub mod store;
pub mod transactions;
pub mod validation;

use crate::node::messages::Message;
use crate::shares::miner_message::MinerShare;
use bitcoin::{BlockHash, PublicKey, Txid};
use serde::{Deserialize, Serialize};

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ShareBlock {
    /// The block hash of the block the share is generated for
    pub blockhash: BlockHash,

    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: Option<BlockHash>,

    /// The uncles of the share
    pub uncles: Vec<BlockHash>,

    /// Compressed pubkey identifying the miner
    pub miner_pubkey: PublicKey,

    /// Any transactions to be included in the share block
    pub tx_hashes: Vec<Txid>,

    /// The miner work for the share
    pub miner_share: MinerShare,

    /// Coinbase transaction for the share block
    pub coinbase_tx: bitcoin::Transaction,
}

impl ShareBlock {
    pub fn new(
        miner_share: MinerShare,
        miner_pubkey: PublicKey,
        network: bitcoin::Network,
    ) -> Self {
        let share = miner_share.clone();
        let coinbase_tx =
            transactions::create_share_block_coinbase_transaction(&miner_pubkey, network);
        Self {
            blockhash: miner_share.hash.parse().unwrap(),
            prev_share_blockhash: None,
            uncles: vec![],
            miner_pubkey,
            tx_hashes: vec![],
            miner_share: share,
            coinbase_tx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::simple_miner_share;
    use crate::test_utils::test_coinbase_transaction;
    use rust_decimal_macros::dec;

    #[test]
    fn test_share_serialization() {
        let share = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![],
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
            tx_hashes: vec![
                "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
                    .parse()
                    .unwrap(),
            ],
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
            coinbase_tx: test_coinbase_transaction(),
        };

        let serialized = Message::ShareBlock(share.clone()).cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();

        let deserialized = match deserialized {
            Message::ShareBlock(share) => share,
            _ => panic!("Expected ShareBlock variant"),
        };

        assert_eq!(share.blockhash, deserialized.blockhash);
        assert_eq!(
            share.prev_share_blockhash,
            deserialized.prev_share_blockhash
        );
        assert_eq!(share.uncles, deserialized.uncles);
        assert_eq!(share.miner_pubkey, deserialized.miner_pubkey);
        assert_eq!(share.tx_hashes, deserialized.tx_hashes);

        // Only compare non-skipped fields from MinerShare
        assert_eq!(
            share.miner_share.workinfoid,
            deserialized.miner_share.workinfoid
        );
        assert_eq!(
            share.miner_share.clientid,
            deserialized.miner_share.clientid
        );
        assert_eq!(share.miner_share.enonce1, deserialized.miner_share.enonce1);
        assert_eq!(share.miner_share.nonce2, deserialized.miner_share.nonce2);
        assert_eq!(share.miner_share.nonce, deserialized.miner_share.nonce);
        assert_eq!(share.miner_share.ntime, deserialized.miner_share.ntime);
        assert_eq!(share.miner_share.diff, deserialized.miner_share.diff);
        assert_eq!(share.miner_share.sdiff, deserialized.miner_share.sdiff);
        assert_eq!(
            share.miner_share.username,
            deserialized.miner_share.username
        );
    }

    #[test]
    fn test_serialized_share_size() {
        let share = ShareBlock {
            blockhash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb0"
                .parse()
                .unwrap(),
            prev_share_blockhash: Some(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1"
                    .parse()
                    .unwrap(),
            ),
            uncles: vec![
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2"
                    .parse()
                    .unwrap(),
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3"
                    .parse()
                    .unwrap(),
            ],
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

        let serialized = Message::ShareBlock(share).cbor_serialize().unwrap();

        // The serialized size should be less than 1KB since we skip many fields
        assert_eq!(serialized.len(), 616);
    }
}
