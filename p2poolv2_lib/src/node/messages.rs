// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
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

use crate::shares::share_block::{ShareBlock, ShareHeader, Txids};
use bitcoin::consensus::{Decodable, Encodable, encode};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::io::{Read, Write};
use bitcoin::{BlockHash, Txid, VarInt};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Message type discriminants for determining the message type
/// We use a single byte integer instead of bitcoin's 12 byte string
mod message_discriminants {
    pub const INVENTORY: u8 = 0;
    pub const NOT_FOUND: u8 = 1;
    pub const GET_SHARE_HEADERS: u8 = 2;
    pub const GET_SHARE_BLOCKS: u8 = 3;
    pub const SHARE_HEADERS: u8 = 4;
    pub const SHARE_BLOCK: u8 = 5;
    pub const GET_DATA: u8 = 6;
    pub const TRANSACTION: u8 = 7;
}

/// InventoryMessage discriminants to determine the type of inventory message
mod inventory_discriminants {
    pub const BLOCK_HASHES: u8 = 0;
    pub const TRANSACTION_HASHES: u8 = 1;
}

/// GetData discriminants to determine the type of get data message
mod getdata_discriminants {
    pub const BLOCK: u8 = 0;
    pub const TXID: u8 = 1;
}

/// Network magic bytes for different P2Poolv2 networks
pub mod network_magic {
    /// Mainnet P2Poolv2
    pub const MAINNET: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
    /// Testnet P2Poolv2
    pub const TESTNET: [u8; 4] = [0x0b, 0x11, 0x09, 0x07];
    /// Signet P2Poolv2
    pub const SIGNET: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40];
    /// Regtest P2Poolv2
    pub const REGTEST: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
}

/// P2P network messages, encoded using bitcoin consensus_encode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Inventory(InventoryMessage),
    NotFound(()),
    GetShareHeaders(Vec<BlockHash>, BlockHash),
    GetShareBlocks(Vec<BlockHash>, BlockHash),
    ShareHeaders(Vec<ShareHeader>),
    ShareBlock(ShareBlock),
    GetData(GetData),
    Transaction(bitcoin::Transaction),
}

/// A complete P2P network message with protocol framing
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMessage {
    /// Network magic bytes (4 bytes identifier)
    pub magic: [u8; 4],
    /// The actual message payload
    pub payload: Message,
    /// Length of the payload in bytes
    pub payload_len: u32,
    /// Checksum: first 4 bytes of SHA256d(payload)
    pub checksum: [u8; 4],
}

impl RawMessage {
    /// Create a new RawMessage from magic bytes and a Message
    /// Automatically computes payload_len and checksum
    pub fn new(magic: [u8; 4], payload: Message) -> Self {
        // Encode payload to calculate length and checksum
        let mut engine = sha256d::Hash::engine();
        let payload_len = payload
            .consensus_encode(&mut engine)
            .expect("engine doesn't error");
        let payload_len = u32::try_from(payload_len).expect("payload length fits in u32");

        // Get checksum from hash
        let hash = sha256d::Hash::from_engine(engine);
        let checksum = [hash[0], hash[1], hash[2], hash[3]];

        Self {
            magic,
            payload,
            payload_len,
            checksum,
        }
    }

    /// Consume RawMessage and return the inner payload
    pub fn into_payload(self) -> Message {
        self.payload
    }

    /// Get reference to the payload
    pub fn payload(&self) -> &Message {
        &self.payload
    }

    /// Get the magic bytes
    pub fn magic(&self) -> &[u8; 4] {
        &self.magic
    }
}

impl Display for RawMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawMessage(magic: {:?}, {})", self.magic, self.payload)
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Inventory(_) => write!(f, "Inventory"),
            Message::NotFound(_) => write!(f, "NotFound"),
            Message::GetShareHeaders(_, _) => write!(f, "GetShareHeaders"),
            Message::GetShareBlocks(_, _) => write!(f, "GetShareBlocks"),
            Message::ShareHeaders(_) => write!(f, "ShareHeaders"),
            Message::ShareBlock(_) => write!(f, "ShareBlock"),
            Message::GetData(_) => write!(f, "GetData"),
            Message::Transaction(_) => write!(f, "Transaction"),
        }
    }
}

struct ShareHeaderSerializationWrapper<'a>(&'a Vec<ShareHeader>);

impl<'a> Encodable for ShareHeaderSerializationWrapper<'a> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt::from(self.0.len()).consensus_encode(w)?;
        for share_header in self.0.iter() {
            len += share_header.consensus_encode(w)?;
            len += 0u8.consensus_encode(w)?;
        }
        Ok(len)
    }
}

struct ShareHeaderDeserializationWrapper(Vec<ShareHeader>);

impl Decodable for ShareHeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(encode::Error::ParseFailed(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(ShareHeaderDeserializationWrapper(ret))
    }

    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(
            &mut r.take(bitcoin::p2p::message::MAX_MSG_SIZE as u64),
        )
    }
}

impl Encodable for Message {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        use message_discriminants::*;
        match self {
            Message::Inventory(inv) => {
                let mut len = INVENTORY.consensus_encode(w)?;
                len += inv.consensus_encode(w)?;
                Ok(len)
            }
            Message::NotFound(_) => NOT_FOUND.consensus_encode(w),
            Message::GetShareHeaders(hashes, stop) => {
                let mut len = GET_SHARE_HEADERS.consensus_encode(w)?;
                len += hashes.consensus_encode(w)?;
                len += stop.consensus_encode(w)?;
                Ok(len)
            }
            Message::GetShareBlocks(hashes, stop) => {
                let mut len = GET_SHARE_BLOCKS.consensus_encode(w)?;
                len += hashes.consensus_encode(w)?;
                len += stop.consensus_encode(w)?;
                Ok(len)
            }
            Message::ShareHeaders(headers) => {
                let mut len = SHARE_HEADERS.consensus_encode(w)?;
                len += ShareHeaderSerializationWrapper(headers).consensus_encode(w)?;
                Ok(len)
            }
            Message::ShareBlock(block) => {
                let mut len = SHARE_BLOCK.consensus_encode(w)?;
                len += block.consensus_encode(w)?;
                Ok(len)
            }
            Message::GetData(data) => {
                let mut len = GET_DATA.consensus_encode(w)?;
                len += data.consensus_encode(w)?;
                Ok(len)
            }
            Message::Transaction(tx) => {
                let mut len = TRANSACTION.consensus_encode(w)?;
                len += tx.consensus_encode(w)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for Message {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        use message_discriminants::*;
        let disc = u8::consensus_decode(r)?;
        match disc {
            INVENTORY => Ok(Message::Inventory(InventoryMessage::consensus_decode(r)?)),
            NOT_FOUND => Ok(Message::NotFound(())),
            GET_SHARE_HEADERS => Ok(Message::GetShareHeaders(
                Vec::<BlockHash>::consensus_decode(r)?,
                BlockHash::consensus_decode(r)?,
            )),
            GET_SHARE_BLOCKS => Ok(Message::GetShareBlocks(
                Vec::<BlockHash>::consensus_decode(r)?,
                BlockHash::consensus_decode(r)?,
            )),
            SHARE_HEADERS => Ok(Message::ShareHeaders(
                ShareHeaderDeserializationWrapper::consensus_decode(r)?.0,
            )),
            SHARE_BLOCK => Ok(Message::ShareBlock(ShareBlock::consensus_decode(r)?)),
            GET_DATA => Ok(Message::GetData(GetData::consensus_decode(r)?)),
            TRANSACTION => Ok(Message::Transaction(
                bitcoin::Transaction::consensus_decode(r)?,
            )),
            _ => Err(encode::Error::ParseFailed("Invalid Message discriminant")),
        }
    }
}

impl Encodable for RawMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(w)?;
        len += self.payload_len.consensus_encode(w)?;
        len += self.checksum.consensus_encode(w)?;
        len += self.payload.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for RawMessage {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Read header
        let magic: [u8; 4] = Decodable::consensus_decode(r)?;
        let payload_len: u32 = Decodable::consensus_decode(r)?;
        let expected_checksum: [u8; 4] = Decodable::consensus_decode(r)?;

        // Read payload into buffer
        let mut payload_bytes = vec![0u8; payload_len as usize];
        r.read_exact(&mut payload_bytes)?;

        // Verify checksum
        let hash = sha256d::Hash::hash(&payload_bytes);
        let actual_checksum = [hash[0], hash[1], hash[2], hash[3]];
        if actual_checksum != expected_checksum {
            return Err(encode::Error::ParseFailed("Checksum mismatch"));
        }

        let payload = Message::consensus_decode(&mut &payload_bytes[..])?;

        Ok(RawMessage {
            magic,
            payload_len,
            checksum: expected_checksum,
            payload,
        })
    }
}

/// The inventory message used to tell a peer what we have in our inventory.
/// The message can be used to tell the peer about share headers, blocks, or transactions that this peer has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryMessage {
    BlockHashes(Vec<BlockHash>),
    TransactionHashes(Txids),
}

impl Encodable for InventoryMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        use inventory_discriminants::*;
        match self {
            InventoryMessage::BlockHashes(hashes) => {
                let mut len = BLOCK_HASHES.consensus_encode(w)?;
                len += hashes.consensus_encode(w)?;
                Ok(len)
            }
            InventoryMessage::TransactionHashes(txids) => {
                let mut len = TRANSACTION_HASHES.consensus_encode(w)?;
                len += txids.consensus_encode(w)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for InventoryMessage {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        use inventory_discriminants::*;
        let disc = u8::consensus_decode(r)?;
        match disc {
            BLOCK_HASHES => Ok(InventoryMessage::BlockHashes(
                Vec::<BlockHash>::consensus_decode(r)?,
            )),
            TRANSACTION_HASHES => Ok(InventoryMessage::TransactionHashes(
                Txids::consensus_decode(r)?,
            )),
            _ => Err(encode::Error::ParseFailed(
                "Invalid InventoryMessage discriminant",
            )),
        }
    }
}

/// Message for requesting data from peers
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum GetData {
    Block(BlockHash),
    Txid(Txid),
}

impl Encodable for GetData {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        use getdata_discriminants::*;
        match self {
            GetData::Block(hash) => {
                let mut len = BLOCK.consensus_encode(w)?;
                len += hash.consensus_encode(w)?;
                Ok(len)
            }
            GetData::Txid(txid) => {
                let mut len = TXID.consensus_encode(w)?;
                len += txid.consensus_encode(w)?;
                Ok(len)
            }
        }
    }
}

impl Decodable for GetData {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        use getdata_discriminants::*;
        let disc = u8::consensus_decode(r)?;
        match disc {
            BLOCK => Ok(GetData::Block(BlockHash::consensus_decode(r)?)),
            TXID => Ok(GetData::Txid(Txid::consensus_decode(r)?)),
            _ => Err(encode::Error::ParseFailed("Invalid GetData discriminant")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_inventory_message_serde() {
        let have_shares = vec![
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                .parse::<BlockHash>()
                .unwrap(),
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"
                .parse::<BlockHash>()
                .unwrap(),
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
                .parse::<BlockHash>()
                .unwrap(),
        ];

        let msg = Message::Inventory(InventoryMessage::BlockHashes(have_shares.clone()));

        // Test serialization
        let mut serialized = Vec::new();
        msg.consensus_encode(&mut serialized).unwrap();

        // Test deserialization
        let deserialized = encode::deserialize::<Message>(&mut serialized).unwrap();

        let deserialized: Vec<BlockHash> = match deserialized {
            Message::Inventory(InventoryMessage::BlockHashes(have_shares)) => have_shares,
            _ => panic!("Expected Inventory variant"),
        };

        // Verify the deserialized message matches original
        assert_eq!(deserialized.len(), 3);
        assert!(deserialized.contains(&have_shares[0]));
        assert!(deserialized.contains(&have_shares[1]));
        assert!(deserialized.contains(&have_shares[2]));
    }

    #[test]
    fn test_get_data_message_serde() {
        // Test BlockHash variant
        let block_msg = Message::GetData(GetData::Block(
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                .parse::<BlockHash>()
                .unwrap(),
        ));
        let mut serialized = Vec::new();
        block_msg.consensus_encode(&mut serialized).unwrap();

        // Test deserialization
        let deserialized = encode::deserialize::<Message>(&serialized).unwrap();

        match deserialized {
            Message::GetData(GetData::Block(hash)) => {
                assert_eq!(
                    hash.to_string(),
                    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                )
            }
            _ => panic!("Expected BlockHash variant"),
        }

        // Test Txid variant
        let tx_msg = Message::GetData(GetData::Txid(
            Txid::from_str("d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e")
                .unwrap(),
        ));
        let mut serialized = Vec::new();
        tx_msg.consensus_encode(&mut serialized).unwrap();

        let deserialized = encode::deserialize::<Message>(&serialized).unwrap();
        match deserialized {
            Message::GetData(GetData::Txid(hash)) => {
                assert_eq!(
                    hash,
                    Txid::from_str(
                        "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
                    )
                    .unwrap()
                )
            }
            _ => panic!("Expected Txid variant"),
        }
    }
}
