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

use libp2p::identity::secp256k1::PublicKey;
use serde::{Serialize, Deserialize, Serializer, Deserializer};

type Nonce =  Vec<u8>;
type BlockHash = Vec<u8>;
type Timestamp = u64;
type TxHash = Vec<u8>;

/// Captures a block on the share chain
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ShareBlock{
    // /// The nonce from the miner
    // nonce: Nonce,
    // /// The block hash of the block the share is generated for
    // blockhash: BlockHash,
    // /// The hash of the prev share block
    // prev_share_blockhash: BlockHash,
    // /// Pubkey identifying the miner the share is for
    // #[serde(serialize_with = "serialize_pubkey")]
    // #[serde(deserialize_with = "deserialize_pubkey")]
    // miner_pubkey: PublicKey,
    // /// Timestamp as unix timestamp for the share generation time
    // timestamp: Timestamp,
    // /// Any transactions to be included in the share block
    // tx_hashes: Vec<TxHash>,
    pub data: String,
}

impl Default for ShareBlock {
    fn default() -> Self {
        Self { data: "".to_string() }
    }
}

fn serialize_pubkey<S>(pubkey: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert public key to bytes
    let bytes = pubkey.to_bytes();
    bytes.serialize(serializer)
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
    PublicKey::try_from_bytes(bytes.as_slice())
        .map_err(serde::de::Error::custom)
}
