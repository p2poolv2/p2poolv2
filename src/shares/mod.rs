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
use bitcoin::{BlockHash, PublicKey, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]

/// Header for the ShareBlock
/// Helps validate PoW and transaction merkle root.
pub struct ShareHeader {
    /// The block hash of the bitcoin weak block received from the ckpool miner
    pub blockhash: BlockHash,

    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: Option<BlockHash>,

    /// The uncles of the share
    pub uncles: Vec<BlockHash>,

    /// Compressed pubkey identifying the miner
    pub miner_pubkey: PublicKey,
}

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ShareBlock {
    /// The header of the share block
    pub header: ShareHeader,
    /// The miner work for the share
    pub miner_share: MinerShare,
    /// Any transactions to be included in the share block
    pub transactions: Vec<Transaction>,
}

impl ShareBlock {
    pub fn new(
        miner_share: MinerShare,
        miner_pubkey: PublicKey,
        network: bitcoin::Network,
    ) -> Self {
        let share = miner_share.clone();
        let coinbase_tx =
            transactions::coinbase::create_coinbase_transaction(&miner_pubkey, network);
        Self {
            header: ShareHeader {
                blockhash: miner_share.hash.parse().unwrap(),
                prev_share_blockhash: None,
                uncles: vec![],
                miner_pubkey,
            },
            miner_share: share,
            transactions: vec![coinbase_tx],
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
            header: ShareHeader {
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
            },
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
            transactions: vec![test_coinbase_transaction()],
        };

        let serialized = Message::ShareBlock(share.clone()).cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();

        let deserialized = match deserialized {
            Message::ShareBlock(share) => share,
            _ => panic!("Expected ShareBlock variant"),
        };

        assert_eq!(share.header.blockhash, deserialized.header.blockhash);
        assert_eq!(
            share.header.prev_share_blockhash,
            deserialized.header.prev_share_blockhash
        );
        assert_eq!(share.header.uncles, deserialized.header.uncles);
        assert_eq!(share.header.miner_pubkey, deserialized.header.miner_pubkey);
        assert_eq!(share.transactions, deserialized.transactions);

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
    fn test_share_block_new_includes_coinbase_transaction() {
        // Create a test public key
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();

        // Create a miner share with test values
        let miner_share = simple_miner_share(
            Some(7452731920372203525),
            Some(1),
            Some(dec!(1.0)),
            Some(dec!(1.9041854952356509)),
        );

        // Create a new share block using ShareBlock::new
        let share = ShareBlock::new(miner_share, pubkey, bitcoin::Network::Regtest);

        // Verify the coinbase transaction exists and has expected properties
        assert!(share.transactions[0].is_coinbase());
        assert_eq!(share.transactions[0].output.len(), 1);
        assert_eq!(share.transactions[0].input.len(), 1);

        // Verify the output is a P2PKH to the miner's public key
        let output = &share.transactions[0].output[0];
        assert_eq!(output.value.to_sat(), 1);

        // Verify the output script is P2PKH for the miner's pubkey
        let expected_address = bitcoin::Address::p2pkh(&pubkey, bitcoin::Network::Regtest);
        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
    }
}
