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
pub mod store;
use crate::node::messages::Message;
use crate::shares::miner_message::MinerShare;
use crate::shares::store::Store;
use hex;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub type Nonce = Vec<u8>;
pub type BlockHash = Vec<u8>;
pub type Timestamp = u64;
pub type TxHash = Vec<u8>;

const MAX_UNCLES: usize = 3;

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
pub struct ShareBlock {
    /// The nonce from the miner
    pub nonce: Nonce,

    /// The block hash of the block the share is generated for
    pub blockhash: BlockHash,

    /// The hash of the prev share block
    pub prev_share_blockhash: BlockHash,

    /// The uncles of the share
    pub uncles: Vec<BlockHash>,

    /// Compressed pubkey identifying the miner
    pub miner_pubkey: Vec<u8>,

    /// Timestamp as unix timestamp for the share generation time
    pub timestamp: Timestamp,

    /// Any transactions to be included in the share block
    pub tx_hashes: Vec<TxHash>,

    /// The miner work for the share
    pub miner_share: MinerShare,
}

impl ShareBlock {
    pub fn new(miner_share: MinerShare) -> Self {
        let share = miner_share.clone();
        Self {
            nonce: hex::decode(miner_share.nonce).unwrap(),
            blockhash: hex::decode(miner_share.hash).unwrap(),
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![],
            timestamp: u64::from_str_radix(&miner_share.ntime, 16).unwrap(),
            tx_hashes: vec![],
            miner_share: share,
        }
    }
}

/// Validate the share block, returning Error in case of failure to validate
/// TODO: validate nonce and blockhash meets difficulty
/// TODO: validate prev_share_blockhash is in store
/// TODO: validate uncles are in store and no more than MAX_UNCLES
/// TODO: validate miner_pubkey is valid
/// TODO: validate timestamp is within the last 10 minutes
/// TODO: validate tx_hashes are valid
pub fn validate(share: &ShareBlock, store: &Store) -> Result<(), Box<dyn Error>> {
    if share.uncles.len() > MAX_UNCLES {
        return Err("Too many uncles".into());
    }
    for uncle in &share.uncles {
        if store.get_share(uncle).is_none() {
            return Err(format!("Uncle {} not found in store", hex::encode(&uncle)).into());
        }
    }
    if let Err(e) = share
        .miner_share
        .validate(share.miner_share.diff, share.miner_share.sdiff)
    {
        return Err(format!("Share validation failed: {}", e).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::fixtures::simple_miner_share;
    use rust_decimal_macros::dec;

    #[test]
    fn test_share_serialization() {
        let share = ShareBlock {
            blockhash: vec![1, 2, 3],
            nonce: vec![1, 2, 3],
            prev_share_blockhash: vec![4, 5, 6],
            uncles: vec![vec![7, 8, 9]],
            miner_pubkey: vec![10, 11, 12],
            timestamp: 1234567890,
            tx_hashes: vec![vec![13, 14, 15]],
            miner_share: simple_miner_share(
                Some(7452731920372203525),
                Some(1),
                Some(dec!(1.0)),
                Some(dec!(1.9041854952356509)),
            ),
        };

        let serialized = Message::ShareBlock(share.clone()).cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();

        let deserialized = match deserialized {
            Message::ShareBlock(share) => share,
            _ => panic!("Expected ShareBlock variant"),
        };

        assert_eq!(share.blockhash, deserialized.blockhash);
        assert_eq!(share.nonce, deserialized.nonce);
        assert_eq!(
            share.prev_share_blockhash,
            deserialized.prev_share_blockhash
        );
        assert_eq!(share.uncles, deserialized.uncles);
        assert_eq!(share.miner_pubkey, deserialized.miner_pubkey);
        assert_eq!(share.timestamp, deserialized.timestamp);
        assert_eq!(share.tx_hashes, deserialized.tx_hashes);
        assert_eq!(share.miner_share, deserialized.miner_share);
    }
}
