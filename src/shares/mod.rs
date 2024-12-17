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

use prost::Message;
pub mod store;
pub mod chain;

pub type Nonce =  Vec<u8>;
pub type BlockHash = Vec<u8>;
pub type Timestamp = u64;
pub type TxHash = Vec<u8>;

const MAX_UNCLES: usize = 3;

/// Captures a block on the share chain
#[derive(Clone, PartialEq, Message)]
pub struct ShareBlock{
    /// The nonce from the miner
    #[prost(bytes, tag = "1")]
    pub nonce: Nonce,

    /// The block hash of the block the share is generated for
    #[prost(bytes, tag = "2")]
    pub blockhash: BlockHash,

    /// The hash of the prev share block
    #[prost(bytes, tag = "3")]
    pub prev_share_blockhash: BlockHash,

    /// The uncles of the share
    #[prost(bytes, repeated, tag = "4")]
    pub uncles: Vec<BlockHash>,

    /// Compressed pubkey identifying the miner
    #[prost(bytes, tag = "5")]
    pub miner_pubkey: Vec<u8>,

    /// Timestamp as unix timestamp for the share generation time
    #[prost(uint64, tag = "6")]
    pub timestamp: Timestamp,

    /// Any transactions to be included in the share block
    #[prost(bytes, repeated, tag = "7")]
    pub tx_hashes: Vec<TxHash>,

    /// The difficulty of the share
    #[prost(uint64, tag = "8")]
    pub difficulty: u64,
}

/// Validate the share block, returning Error in case of failure to validate
/// TODO: validate nonce and blockhash meets difficulty
/// TODO: validate prev_share_blockhash is in store
/// TODO: validate uncles are in store and no more than MAX_UNCLES
/// TODO: validate miner_pubkey is valid
/// TODO: validate timestamp is within the last 10 minutes
/// TODO: validate tx_hashes are valid
pub fn validate(share: &ShareBlock) -> Result<(), Box<dyn Error>> {
    Ok(())
}
