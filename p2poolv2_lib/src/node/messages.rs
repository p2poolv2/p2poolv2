// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shares::coinbase_proof::MAX_COINBASE_MERKLE_BRANCH_LENGTH;
use crate::shares::share_block::{ShareBlock, ShareHeader, Txids};
use bitcoin::consensus::{Decodable, Encodable, encode};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::io::{Read, Write};
use bitcoin::{BlockHash, TxMerkleNode, Txid, VarInt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

/// Largest P2P message payload this node will decode, in bytes.
///
/// The codec rejects a larger advertised length before allocating, so this
/// bounds the memory one peer message can pin -- including responses queued for
/// the response worker. Sized for P2Pool's own messages rather than bitcoin's
/// 5 MB block-relay limit: the largest legitimate message is a `ShareHeaders`
/// batch of `MAX_HEADERS_IN_RESPONSE` plus up to one height of overshoot
/// (~1 MB of worst-case headers and branches); a `ShareBlock` is bounded by its 200 KB
/// transaction limit. `test_full_share_headers_response_fits_max_message_size`
/// guards the margin.
pub const MAX_P2P_MESSAGE_SIZE: usize = 1024 * 1024;

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
    pub const HANDSHAKE: u8 = 8;
    pub const ACK: u8 = 9;
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

/// P2P network messages, encoded using bitcoin consensus_encode
#[derive(Debug, Clone, PartialEq, Eq)]
// Boxing the large variants would ripple through every match site and every
// consensus encode/decode impl for marginal benefit.
#[allow(clippy::large_enum_variant)]
pub enum Message {
    Inventory(InventoryMessage),
    NotFound(GetData),
    GetShareHeaders(Vec<BlockHash>, BlockHash),
    GetShareBlocks(Vec<BlockHash>, BlockHash),
    ShareHeaders(ShareHeaderBatch),
    ShareBlock(ShareBlock),
    GetData(GetData),
    Transaction(bitcoin::Transaction),
    Handshake(HandshakeData),
    /// Acknowledgment response for request-response messages that
    /// sometimes do not need to send a meaningful return payload
    /// (e.g. Handshake, Inventory). This is a stop gap solution to
    /// avoiding timeout errors from libp2p and timeouts filling up
    /// queues. Ideally we need to build our own stream protocol for
    /// libp2p. Something, we don't want to take on now.
    Ack,
}

/// Handshake data exchanged when a connection is established.
/// Both peers send their confirmed tip height and hash so each
/// side can determine whether it needs to fetch headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeData {
    pub tip_height: u32,
    pub tip_hash: BlockHash,
}

/// A complete P2P network message with protocol framing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMessage {
    /// The actual message payload
    pub payload: Message,
    /// Length of the payload in bytes
    pub payload_len: u32,
    /// Checksum: first 4 bytes of SHA256d(payload)
    pub checksum: [u8; 4],
}

impl RawMessage {
    /// Create a new RawMessage from a Message
    /// Automatically computes payload_len and checksum
    pub fn new(payload: Message) -> Self {
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
}

impl Display for RawMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawMessage({})", self.payload)
    }
}

impl Message {
    /// Returns the variant name as a static string slice.
    ///
    /// We need to avoid allocation for debug logging, when we don't
    /// want to clone message.
    pub fn message_type(&self) -> &'static str {
        match self {
            Message::Inventory(_) => "Inventory",
            Message::NotFound(_) => "NotFound",
            Message::GetShareHeaders(_, _) => "GetShareHeaders",
            Message::GetShareBlocks(_, _) => "GetShareBlocks",
            Message::ShareHeaders(_) => "ShareHeaders",
            Message::ShareBlock(_) => "ShareBlock",
            Message::GetData(_) => "GetData",
            Message::Transaction(_) => "Transaction",
            Message::Handshake(_) => "Handshake",
            Message::Ack => "Ack",
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message_type())
    }
}

/// A `ShareHeaders` response: headers, each with the coinbase merkle branch
/// its `CoinbaseProof` is checked against.
///
/// Each header leaves out its bitcoin merkle root when its proof and branch
/// give it back, which they do for every share but genesis: the receiver
/// derives the root, and a forged proof derives a root whose bitcoin header
/// fails its proof-of-work check.
///
/// Shares mined on one block template share a branch, so each distinct branch
/// is sent once in `branches` and every header names its branch by index. The
/// table belongs to this message alone: a header never refers to another
/// message's table, so dropped, reordered or retried responses cannot leave a
/// header without its branch. Decoding rejects an index outside the table, so
/// `branch` never fails on a decoded batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareHeaderBatch {
    headers: Vec<ShareHeader>,
    /// Index into `branches` for the header at the same position.
    branch_indexes: Vec<u16>,
    branches: Vec<Vec<TxMerkleNode>>,
}

impl ShareHeaderBatch {
    /// Build a batch from headers and their coinbase merkle branches,
    /// storing each distinct branch once.
    pub fn from_headers_with_branches(entries: Vec<(ShareHeader, Vec<TxMerkleNode>)>) -> Self {
        let mut headers = Vec::with_capacity(entries.len());
        let mut branch_indexes = Vec::with_capacity(entries.len());
        let mut branches: Vec<Vec<TxMerkleNode>> = Vec::new();
        let mut index_of_branch: HashMap<Vec<TxMerkleNode>, u16> =
            HashMap::with_capacity(entries.len());
        for (header, branch) in entries {
            let index = match index_of_branch.get(&branch) {
                Some(index) => *index,
                None => {
                    let index = branches.len() as u16;
                    index_of_branch.insert(branch.clone(), index);
                    branches.push(branch);
                    index
                }
            };
            headers.push(header);
            branch_indexes.push(index);
        }
        Self {
            headers,
            branch_indexes,
            branches,
        }
    }

    /// The headers, in message order.
    pub fn headers(&self) -> &[ShareHeader] {
        &self.headers
    }

    /// The coinbase merkle branch of the header at `position`.
    pub fn branch(&self, position: usize) -> &[TxMerkleNode] {
        &self.branches[self.branch_indexes[position] as usize]
    }

    /// Number of distinct branches carried.
    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }

    /// Each header's hash with its branch, for storing the branches of
    /// headers held without their bodies.
    pub fn blockhashes_with_branches(&self) -> Vec<(BlockHash, Vec<TxMerkleNode>)> {
        self.headers
            .iter()
            .enumerate()
            .map(|(position, header)| (header.block_hash(), self.branch(position).to_vec()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

impl Encodable for ShareHeaderBatch {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = VarInt::from(self.branches.len()).consensus_encode(w)?;
        for branch in &self.branches {
            len += VarInt::from(branch.len()).consensus_encode(w)?;
            for node in branch {
                len += node.consensus_encode(w)?;
            }
        }
        len += VarInt::from(self.headers.len()).consensus_encode(w)?;
        for (header, branch_index) in self.headers.iter().zip(&self.branch_indexes) {
            let branch = &self.branches[*branch_index as usize];
            let root_is_derivable = header.coinbase_proof.merkle_root(header, branch).ok()
                == Some(header.bitcoin_header.merkle_root);
            len += branch_index.consensus_encode(w)?;
            len += (!root_is_derivable).consensus_encode(w)?;
            len += header.consensus_encode_with(w, !root_is_derivable)?;
        }
        Ok(len)
    }
}

impl Decodable for ShareHeaderBatch {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        // The reader is bounded by MAX_P2P_MESSAGE_SIZE, so the counts only
        // need capping for the initial allocations.
        let branch_count = VarInt::consensus_decode(r)?.0 as usize;
        let mut branches = Vec::with_capacity(core::cmp::min(branch_count, 1024 * 16));
        for _ in 0..branch_count {
            let node_count = VarInt::consensus_decode(r)?.0 as usize;
            if node_count > MAX_COINBASE_MERKLE_BRANCH_LENGTH {
                return Err(encode::Error::ParseFailed(
                    "Coinbase merkle branch too long",
                ));
            }
            let mut branch = Vec::with_capacity(node_count);
            for _ in 0..node_count {
                branch.push(TxMerkleNode::consensus_decode(r)?);
            }
            branches.push(branch);
        }
        let header_count = VarInt::consensus_decode(r)?.0 as usize;
        let mut headers = Vec::with_capacity(core::cmp::min(header_count, 1024 * 16));
        let mut branch_indexes = Vec::with_capacity(core::cmp::min(header_count, 1024 * 16));
        for _ in 0..header_count {
            let branch_index = u16::consensus_decode(r)?;
            let branch: &Vec<TxMerkleNode> =
                branches
                    .get(branch_index as usize)
                    .ok_or(encode::Error::ParseFailed(
                        "Share header names a branch outside the batch",
                    ))?;
            let includes_bitcoin_merkle_root = bool::consensus_decode(r)?;
            let mut header = ShareHeader::consensus_decode_with(r, includes_bitcoin_merkle_root)?;
            if !includes_bitcoin_merkle_root {
                header.bitcoin_header.merkle_root = header
                    .coinbase_proof
                    .merkle_root(&header, branch)
                    .map_err(|_| {
                        encode::Error::ParseFailed("Cannot derive share header bitcoin merkle root")
                    })?;
            }
            headers.push(header);
            branch_indexes.push(branch_index);
        }
        Ok(Self {
            headers,
            branch_indexes,
            branches,
        })
    }

    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(&mut r.take(MAX_P2P_MESSAGE_SIZE as u64))
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
            Message::NotFound(get_data) => {
                let mut len = NOT_FOUND.consensus_encode(w)?;
                len += get_data.consensus_encode(w)?;
                Ok(len)
            }
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
                len += headers.consensus_encode(w)?;
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
            Message::Handshake(handshake_data) => {
                let mut len = HANDSHAKE.consensus_encode(w)?;
                len += handshake_data.tip_height.consensus_encode(w)?;
                len += handshake_data.tip_hash.consensus_encode(w)?;
                Ok(len)
            }
            Message::Ack => {
                let len = ACK.consensus_encode(w)?;
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
            NOT_FOUND => Ok(Message::NotFound(GetData::consensus_decode(r)?)),
            GET_SHARE_HEADERS => Ok(Message::GetShareHeaders(
                Vec::<BlockHash>::consensus_decode(r)?,
                BlockHash::consensus_decode(r)?,
            )),
            GET_SHARE_BLOCKS => Ok(Message::GetShareBlocks(
                Vec::<BlockHash>::consensus_decode(r)?,
                BlockHash::consensus_decode(r)?,
            )),
            SHARE_HEADERS => Ok(Message::ShareHeaders(ShareHeaderBatch::consensus_decode(
                r,
            )?)),
            SHARE_BLOCK => Ok(Message::ShareBlock(ShareBlock::consensus_decode(r)?)),
            GET_DATA => Ok(Message::GetData(GetData::consensus_decode(r)?)),
            TRANSACTION => Ok(Message::Transaction(
                bitcoin::Transaction::consensus_decode(r)?,
            )),
            HANDSHAKE => Ok(Message::Handshake(HandshakeData {
                tip_height: u32::consensus_decode(r)?,
                tip_hash: BlockHash::consensus_decode(r)?,
            })),
            ACK => Ok(Message::Ack),
            _ => Err(encode::Error::ParseFailed("Invalid Message discriminant")),
        }
    }
}

impl Encodable for RawMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.payload_len.consensus_encode(w)?;
        len += self.checksum.consensus_encode(w)?;
        len += self.payload.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for RawMessage {
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Read header
        let payload_len: u32 = Decodable::consensus_decode(r)?;
        let expected_checksum: [u8; 4] = Decodable::consensus_decode(r)?;

        // Reject an oversized advertised length before allocating, so a
        // malicious peer cannot trigger a multi-gigabyte allocation / OOM.
        if payload_len as usize > MAX_P2P_MESSAGE_SIZE {
            return Err(encode::Error::ParseFailed(
                "Payload length exceeds maximum message size",
            ));
        }

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
    use crate::node::p2p_message_handlers::MAX_HEADERS_IN_RESPONSE;
    use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
    use crate::shares::validation::MAX_UNCLES;
    use crate::shares::witness_commitment::WitnessCommitment;
    use crate::store::dag_store::MAX_BLOCKS_PER_HEIGHT;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::consensus::encode;
    use std::str::FromStr;

    #[test]
    fn test_raw_message_roundtrip() {
        let block_hashes = vec![
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap(),
        ];
        let msg = Message::Inventory(InventoryMessage::BlockHashes(block_hashes.clone()));
        let raw = RawMessage::new(msg.clone());

        // Test encoding
        let mut encoded = Vec::new();
        raw.consensus_encode(&mut encoded).unwrap();

        // Test decoding
        let decoded = RawMessage::consensus_decode(&mut &encoded[..]).unwrap();

        assert_eq!(decoded.payload, msg);
        assert_eq!(decoded.payload_len, raw.payload_len);
        assert_eq!(decoded.checksum, raw.checksum);
    }

    #[test]
    fn test_raw_message_checksum_verification() {
        let msg = Message::NotFound(GetData::Block(BlockHash::all_zeros()));
        let raw = RawMessage::new(msg);

        let mut encoded = Vec::new();
        raw.consensus_encode(&mut encoded).unwrap();

        // Corrupt the checksum. The header is now payload_len (4 bytes) followed
        // by the checksum (4 bytes), so the checksum starts at byte 4.
        encoded[4] ^= 0xFF;

        // Decoding should fail
        let result = RawMessage::consensus_decode(&mut &encoded[..]);
        assert!(result.is_err());
    }

    /// The largest legitimate message -- a full `ShareHeaders` response of
    /// worst-case headers -- must fit under `MAX_P2P_MESSAGE_SIZE`, or header
    /// sync would be rejected by our own codec. Worst case per header: the
    /// maximum uncles, the longest address script (P2WSH) in every address
    /// field, the longest coinbaseaux flags, a witness commitment, the bitcoin
    /// merkle root included, and a distinct coinbase branch of the maximum
    /// length -- no two headers sharing a block template. The sender completes
    /// whole heights, so a response can overshoot `MAX_HEADERS_IN_RESPONSE` by
    /// up to one dense height.
    #[test]
    fn test_full_share_headers_response_fits_max_message_size() {
        let longest_address =
            bitcoin::Address::p2wsh(&bitcoin::ScriptBuf::new(), bitcoin::Network::Regtest);
        let mut header = TestShareBlockBuilder::new()
            .uncles(vec![BlockHash::all_zeros(); MAX_UNCLES])
            .build()
            .header;
        // Changing committed fields after the build leaves the proof unable to
        // derive the root, so the encoder includes it: the larger encoding.
        header.miner_bitcoin_address = longest_address.clone();
        header.donation_address = Some(longest_address.clone());
        header.donation = Some(u16::MAX);
        header.fee_address = Some(longest_address);
        header.fee = Some(u16::MAX);
        header.coinbaseaux_flags = Some(CoinbaseAuxFlags::new(&[0xff; 32]));
        header.witness_commitment = Some(
            WitnessCommitment::from_hex(
                "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
            )
            .unwrap(),
        );

        let header_count = MAX_HEADERS_IN_RESPONSE + MAX_BLOCKS_PER_HEIGHT;
        let mut entries = Vec::with_capacity(header_count);
        for index in 0..header_count as u32 {
            let mut node = [0u8; 32];
            node[..4].copy_from_slice(&index.to_le_bytes());
            let branch = vec![
                bitcoin::TxMerkleNode::from_byte_array(node);
                MAX_COINBASE_MERKLE_BRANCH_LENGTH
            ];
            entries.push((header.clone(), branch));
        }
        let message = Message::ShareHeaders(ShareHeaderBatch::from_headers_with_branches(entries));
        let encoded = encode::serialize(&message);

        assert!(
            encoded.len() < MAX_P2P_MESSAGE_SIZE,
            "a full ShareHeaders response is {} bytes, over the {} byte cap",
            encoded.len(),
            MAX_P2P_MESSAGE_SIZE
        );
    }

    #[test]
    fn test_raw_message_rejects_oversized_payload_len() {
        // A malicious peer advertises a payload length larger than the maximum
        // message size. Decoding must reject it without allocating the buffer.
        let payload_len = (MAX_P2P_MESSAGE_SIZE as u32) + 1;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&[0u8; 4]); // checksum placeholder

        let result = RawMessage::consensus_decode(&mut &encoded[..]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_not_found_roundtrip() {
        let msg = Message::NotFound(GetData::Block(BlockHash::all_zeros()));
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_message_get_share_headers_roundtrip() {
        let hashes = vec![
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap(),
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
                .unwrap(),
        ];
        let stop =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7")
                .unwrap();

        let msg = Message::GetShareHeaders(hashes.clone(), stop);
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        match decoded {
            Message::GetShareHeaders(decoded_hashes, decoded_stop) => {
                assert_eq!(decoded_hashes, hashes);
                assert_eq!(decoded_stop, stop);
            }
            _ => panic!("Expected GetShareHeaders variant"),
        }
    }

    #[test]
    fn test_message_get_share_blocks_roundtrip() {
        let hashes = vec![
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap(),
        ];
        let stop = BlockHash::all_zeros();

        let msg = Message::GetShareBlocks(hashes.clone(), stop);
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        match decoded {
            Message::GetShareBlocks(decoded_hashes, decoded_stop) => {
                assert_eq!(decoded_hashes, hashes);
                assert_eq!(decoded_stop, stop);
            }
            _ => panic!("Expected GetShareBlocks variant"),
        }
    }

    #[test]
    fn test_inventory_message_block_hashes_roundtrip() {
        let hashes = vec![
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap(),
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
                .unwrap(),
        ];

        let inv = InventoryMessage::BlockHashes(hashes.clone());
        let mut encoded = Vec::new();
        inv.consensus_encode(&mut encoded).unwrap();

        let decoded = InventoryMessage::consensus_decode(&mut &encoded[..]).unwrap();
        match decoded {
            InventoryMessage::BlockHashes(decoded_hashes) => {
                assert_eq!(decoded_hashes, hashes);
            }
            _ => panic!("Expected BlockHashes variant"),
        }
    }

    #[test]
    fn test_get_data_block_roundtrip() {
        let hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        let get_data = GetData::Block(hash);
        let mut encoded = Vec::new();
        get_data.consensus_encode(&mut encoded).unwrap();

        let decoded = GetData::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, get_data);
    }

    #[test]
    fn test_get_data_txid_roundtrip() {
        let txid =
            Txid::from_str("d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e")
                .unwrap();

        let get_data = GetData::Txid(txid);
        let mut encoded = Vec::new();
        get_data.consensus_encode(&mut encoded).unwrap();

        let decoded = GetData::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, get_data);
    }

    #[test]
    fn test_message_discriminants_unique() {
        use message_discriminants::*;
        let discriminants = [
            INVENTORY,
            NOT_FOUND,
            GET_SHARE_HEADERS,
            GET_SHARE_BLOCKS,
            SHARE_HEADERS,
            SHARE_BLOCK,
            GET_DATA,
            TRANSACTION,
            HANDSHAKE,
            ACK,
        ];

        // Check all discriminants are unique
        for i in 0..discriminants.len() {
            for j in (i + 1)..discriminants.len() {
                assert_ne!(
                    discriminants[i], discriminants[j],
                    "Discriminants at positions {i} and {j} are not unique"
                );
            }
        }
    }

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
        let deserialized = encode::deserialize::<Message>(&serialized).unwrap();

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

    #[test]
    fn test_handshake_message_roundtrip() {
        let tip_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        let handshake_data = HandshakeData {
            tip_height: 42,
            tip_hash,
        };

        let msg = Message::Handshake(handshake_data.clone());
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        match decoded {
            Message::Handshake(decoded_data) => {
                assert_eq!(decoded_data.tip_height, 42);
                assert_eq!(decoded_data.tip_hash, tip_hash);
            }
            _ => panic!("Expected Handshake variant"),
        }
    }

    #[test]
    fn test_handshake_message_fresh_node_roundtrip() {
        let handshake_data = HandshakeData {
            tip_height: 0,
            tip_hash: BlockHash::all_zeros(),
        };

        let msg = Message::Handshake(handshake_data);
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        match decoded {
            Message::Handshake(decoded_data) => {
                assert_eq!(decoded_data.tip_height, 0);
                assert_eq!(decoded_data.tip_hash, BlockHash::all_zeros());
            }
            _ => panic!("Expected Handshake variant"),
        }
    }

    #[test]
    fn test_ack_message_roundtrip() {
        let msg = Message::Ack;
        let mut encoded = Vec::new();
        msg.consensus_encode(&mut encoded).unwrap();

        let decoded = Message::consensus_decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded, Message::Ack);
    }

    /// Shares mined on one template share a coinbase branch, so the batch
    /// carries it once.
    #[test]
    fn test_share_header_batch_stores_shared_branch_once() {
        let first = TestShareBlockBuilder::new().nonce(1).build().header;
        let second = TestShareBlockBuilder::new().nonce(2).build().header;
        let branch = vec![bitcoin::TxMerkleNode::from_byte_array([0x42; 32])];

        let batch = ShareHeaderBatch::from_headers_with_branches(vec![
            (first, branch.clone()),
            (second, branch.clone()),
        ]);

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.branch_count(), 1);
        assert_eq!(batch.branch(0), branch.as_slice());
        assert_eq!(batch.branch(1), branch.as_slice());
    }

    #[test]
    fn test_share_header_batch_keeps_distinct_branches_apart() {
        let first = TestShareBlockBuilder::new().nonce(1).build().header;
        let second = TestShareBlockBuilder::new().nonce(2).build().header;
        let first_branch = vec![bitcoin::TxMerkleNode::from_byte_array([0x42; 32])];
        let second_branch = vec![bitcoin::TxMerkleNode::from_byte_array([0x43; 32])];

        let batch = ShareHeaderBatch::from_headers_with_branches(vec![
            (first, first_branch.clone()),
            (second, second_branch.clone()),
        ]);

        assert_eq!(batch.branch_count(), 2);
        assert_eq!(batch.branch(0), first_branch.as_slice());
        assert_eq!(batch.branch(1), second_branch.as_slice());
    }

    #[test]
    fn test_share_headers_message_round_trips_with_branches() {
        let first = TestShareBlockBuilder::new().nonce(1).build().header;
        let second = TestShareBlockBuilder::new().nonce(2).build().header;
        let branch = vec![
            bitcoin::TxMerkleNode::from_byte_array([0x42; 32]),
            bitcoin::TxMerkleNode::from_byte_array([0x43; 32]),
        ];
        let message = Message::ShareHeaders(ShareHeaderBatch::from_headers_with_branches(vec![
            (first, branch.clone()),
            (second, Vec::new()),
        ]));

        let decoded: Message = encode::deserialize(&encode::serialize(&message)).unwrap();

        assert_eq!(decoded, message);
    }

    /// A header naming a branch the batch does not carry is a malformed
    /// message, rejected at decode so a decoded batch always resolves.
    #[test]
    fn test_share_header_batch_decode_rejects_branch_index_outside_table() {
        let header = TestShareBlockBuilder::new().build().header;
        let mut bytes = Vec::new();
        VarInt::from(0usize).consensus_encode(&mut bytes).unwrap();
        VarInt::from(1usize).consensus_encode(&mut bytes).unwrap();
        header.consensus_encode(&mut bytes).unwrap();
        0u16.consensus_encode(&mut bytes).unwrap();

        let result: Result<ShareHeaderBatch, _> = encode::deserialize(&bytes);

        assert!(result.is_err());
    }

    /// A header whose proof derives its bitcoin merkle root travels without
    /// it, and the receiver restores it exactly.
    #[test]
    fn test_share_header_batch_omits_derivable_bitcoin_merkle_root() {
        let header = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".to_string(),
            )
            .build()
            .header;
        let derivable =
            ShareHeaderBatch::from_headers_with_branches(vec![(header.clone(), vec![])]);
        let underivable = ShareHeaderBatch::from_headers_with_branches(vec![(
            header.clone(),
            vec![bitcoin::TxMerkleNode::from_byte_array([0x42; 32])],
        )]);

        let derivable_bytes = encode::serialize(&derivable);
        let underivable_bytes = encode::serialize(&underivable);

        // The underivable batch carries one more branch node and the root.
        assert_eq!(underivable_bytes.len() - derivable_bytes.len(), 32 + 32);
        let decoded: ShareHeaderBatch = encode::deserialize(&derivable_bytes).unwrap();
        assert_eq!(decoded.headers(), [header].as_slice());
    }

    /// A sender that leaves the root out under a forged proof makes the
    /// receiver derive a different root, so the bitcoin header the receiver
    /// sees is not the one the proof of work was done on.
    #[test]
    fn test_share_header_batch_forged_proof_derives_a_different_root() {
        let original = TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".to_string(),
            )
            .build()
            .header;
        let mut forged = original.clone();
        forged.coinbase_proof.midstate[0] ^= 1;

        let mut bytes = Vec::new();
        VarInt::from(1usize).consensus_encode(&mut bytes).unwrap();
        VarInt::from(0usize).consensus_encode(&mut bytes).unwrap();
        VarInt::from(1usize).consensus_encode(&mut bytes).unwrap();
        0u16.consensus_encode(&mut bytes).unwrap();
        false.consensus_encode(&mut bytes).unwrap();
        forged.consensus_encode_with(&mut bytes, false).unwrap();

        let decoded: ShareHeaderBatch = encode::deserialize(&bytes).unwrap();

        let decoded_header = &decoded.headers()[0];
        assert_ne!(
            decoded_header.bitcoin_header.merkle_root,
            original.bitcoin_header.merkle_root
        );
        assert_ne!(
            decoded_header.bitcoin_header.block_hash(),
            original.bitcoin_header.block_hash()
        );
    }
}
