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

use serde::{Serialize, Deserialize};
use std::error::Error;
use crate::shares::{BlockHash, TxHash, ShareBlock};
use crate::shares::miner_message::MinerWorkbase;


/// Message trait for network messages that can be serialized/deserialized
/// The trait provides a default implementation for serialization/deserialization
/// using the ciborium crate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Inventory(InventoryMessage),
    GetData(GetData),
    ShareBlock(ShareBlock),
    Workbase(MinerWorkbase),
}

impl Message {
    /// Serialize the message to CBOR bytes
    pub fn cbor_serialize(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = Vec::new();
        if let Err(e) = ciborium::ser::into_writer(&self, &mut buf) {
            return Err(e.into());
        }
        Ok(buf)
    }

    /// Deserialize a message from CBOR bytes
    pub fn cbor_deserialize(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        match ciborium::de::from_reader(bytes) {
            Ok(msg) => Ok(msg),
            Err(e) => Err(e.into())
        }
    }
}

/// Message for sending a list of shares to the network
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InventoryMessage {
    pub have_shares: Vec<BlockHash>,
}

/// Message for requesting data from peers
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum GetData {
    BlockHash(BlockHash),
    TxHash(TxHash),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inventory_message_serde() {
        let msg = Message::Inventory(InventoryMessage {
            have_shares: vec![
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![7, 8, 9]
            ]
        });

        // Test serialization
        let serialized = msg.cbor_serialize().unwrap();

        // Test deserialization
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();

        let deserialized = match deserialized {
            Message::Inventory(inventory) => inventory,
            _ => panic!("Expected Inventory variant"),
        };
        // Verify the deserialized message matches original
        assert_eq!(deserialized.have_shares.len(), deserialized.have_shares.len());
        assert_eq!(deserialized.have_shares[0], vec![1, 2, 3]);
        assert_eq!(deserialized.have_shares[1], vec![4, 5, 6]); 
        assert_eq!(deserialized.have_shares[2], vec![7, 8, 9]);
    }

    #[test]
    fn test_get_data_message_serde() {
        // Test BlockHash variant
        let block_msg = Message::GetData(GetData::BlockHash(vec![1, 2, 3]));
        let serialized = block_msg.cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();
        match deserialized {
            Message::GetData(GetData::BlockHash(hash)) => assert_eq!(hash, vec![1, 2, 3]),
            _ => panic!("Expected BlockHash variant")
        }

        // Test TxHash variant
        let tx_msg = Message::GetData(GetData::TxHash(vec![4, 5, 6]));
        let serialized = tx_msg.cbor_serialize().unwrap();
        let deserialized = Message::cbor_deserialize(&serialized).unwrap();
        match deserialized {
            Message::GetData(GetData::TxHash(hash)) => assert_eq!(hash, vec![4, 5, 6]),
            _ => panic!("Expected TxHash variant")
        }
    }
}
