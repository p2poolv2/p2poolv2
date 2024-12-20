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
use crate::shares::store::Store;
use hex;
use serde::{Serialize, Deserialize};
use tracing::error;
pub mod store;
pub mod chain;
use crate::node::messages::Message;

pub type Nonce =  Vec<u8>;
pub type BlockHash = Vec<u8>;
pub type Timestamp = u64;
pub type TxHash = Vec<u8>;

const MAX_UNCLES: usize = 3;

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
pub struct ShareBlock{
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

    /// The difficulty of the share
    pub difficulty: u64,
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            difficulty: 100,
        };

        let serialized = Message::ShareBlock(share.clone()).cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();

        let deserialized = match deserialized {
            Message::ShareBlock(share) => share,
            _ => panic!("Expected ShareBlock variant"),
        };

        assert_eq!(share.blockhash, deserialized.blockhash);
        assert_eq!(share.nonce, deserialized.nonce);
        assert_eq!(share.prev_share_blockhash, deserialized.prev_share_blockhash);
        assert_eq!(share.uncles, deserialized.uncles);
        assert_eq!(share.miner_pubkey, deserialized.miner_pubkey);
        assert_eq!(share.timestamp, deserialized.timestamp);
        assert_eq!(share.tx_hashes, deserialized.tx_hashes);
        assert_eq!(share.difficulty, deserialized.difficulty);
    }
}
