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

pub type Nonce =  Vec<u8>;
pub type BlockHash = Vec<u8>;
pub type Timestamp = u64;
pub type TxHash = Vec<u8>;

const MAX_UNCLES: usize = 3;

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Serialize, Deserialize, Default)]
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

impl ShareBlock {
    /// Serialize the share block to a byte vector
    pub fn serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&self, &mut buf) {
            error!("Failed to serialize share: {}", e);
            return Err(e.into());
        }
        Ok(buf)
    }

    /// Deserialize the share block from a byte vector
    pub fn deserialize(buf: &mut [u8]) -> Result<Self, Box<dyn Error>> {
        let share: Self = ciborium::de::from_reader(buf.as_ref()).unwrap();
        Ok(share)
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
    Ok(())
}
