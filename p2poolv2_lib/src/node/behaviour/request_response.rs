// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use async_trait::async_trait;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::p2p::message::MAX_MSG_SIZE;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{Codec, OutboundFailure};
use std::io;

use crate::node::messages::{Message, RawMessage};
use bitcoin::BlockHash;

/// Hex characters of the share chain genesis hash carried in the protocol
/// string. Eight is ample: this separates share chains that were never meant
/// to meet, it is not a security boundary, and the Noise handshake the string
/// feeds provides the cryptographic part.
const GENESIS_TAG_LEN: usize = 8;

/// Short, stable tag identifying the share chain a node is built for.
///
/// A share chain is reset by re-anchoring its genesis, which changes this tag
/// without anyone having to remember to bump a version. Two nodes built for
/// different chains therefore cannot derive the same protocol string.
fn genesis_tag(genesis_hash: BlockHash) -> String {
    let mut tag = genesis_hash.to_string();
    tag.truncate(GENESIS_TAG_LEN);
    tag
}

/// Build the libp2p protocol string for a bitcoin network and share chain.
///
/// Network isolation is enforced through protocol negotiation: nodes on
/// different networks, or on share chains with different genesis blocks,
/// derive different protocol strings and therefore fail to negotiate a shared
/// protocol. Centralizing construction here keeps the string consistent across
/// the request-response protocol, Identify, and the Noise prologue.
pub fn protocol_string(network: bitcoin::Network, genesis_hash: BlockHash) -> String {
    format!(
        "/p2pool/{}/{}/1.0.0",
        network.to_core_arg(),
        genesis_tag(genesis_hash)
    )
}

/// Build the Kademlia protocol string for a bitcoin network and share chain.
///
/// Kademlia uses a distinct protocol name from [`protocol_string`] but shares
/// the same network and genesis segments, so it is derived here to keep both
/// in step.
pub fn kad_protocol_string(network: bitcoin::Network, genesis_hash: BlockHash) -> String {
    format!(
        "/p2pool/{}/{}/kad/1.0.0",
        network.to_core_arg(),
        genesis_tag(genesis_hash)
    )
}

// Protocol name for our request-response protocol
#[derive(Debug, Clone)]
pub struct P2PoolRequestResponseProtocol(String);

impl P2PoolRequestResponseProtocol {
    pub fn new(network: bitcoin::Network, genesis_hash: BlockHash) -> Self {
        Self(protocol_string(network, genesis_hash))
    }
}

impl AsRef<str> for P2PoolRequestResponseProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Consensus codec implementation using RawMessage for request-response protocols
#[derive(Clone)]
pub struct ConsensusCodec;

impl ConsensusCodec {
    async fn read_message<T>(&self, io: &mut T) -> io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read header: payload_len (4) + checksum (4) = 8 bytes
        let mut header_bytes = [0u8; 8];
        io.read_exact(&mut header_bytes).await?;

        // Parse payload length and checksum from header
        let payload_len = u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]);
        let expected_checksum = [
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ];

        // Reject an oversized advertised length before allocating, so a
        // malicious peer cannot trigger a multi-gigabyte allocation / OOM.
        let payload_len = payload_len as usize;
        if payload_len > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Payload length exceeds maximum message size",
            ));
        }

        // Read exactly payload_len bytes
        let mut payload_bytes = vec![0u8; payload_len];
        io.read_exact(&mut payload_bytes).await?;

        // Verify the payload checksum before decoding
        let hash = sha256d::Hash::hash(&payload_bytes);
        let actual_checksum = [hash[0], hash[1], hash[2], hash[3]];
        if actual_checksum != expected_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Checksum mismatch",
            ));
        }

        let message = Message::consensus_decode(&mut &payload_bytes[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(message)
    }

    async fn write_message<T>(&self, io: &mut T, msg: Message) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let raw_msg = RawMessage::new(msg);
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await
    }
}

#[async_trait]
impl Codec for ConsensusCodec {
    type Protocol = P2PoolRequestResponseProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_message(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_message(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_message(io, req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_message(io, res).await
    }
}

// Helper type aliases for the request-response behavior
pub type RequestResponseBehaviour = libp2p::request_response::Behaviour<ConsensusCodec>;
pub type RequestResponseEvent = libp2p::request_response::Event<Message, Message>;

// Error type for request-response failures
#[derive(Debug, thiserror::Error)]
pub enum RequestResponseError {
    #[error("Outbound request failed: {0}")]
    OutboundFailure(#[from] OutboundFailure),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::{GENESIS_TAG_LEN, kad_protocol_string, protocol_string};
    use crate::shares::share_block::ShareBlock;

    #[test]
    fn test_protocol_string_carries_network_and_genesis_tag() {
        let genesis_hash = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        assert_eq!(
            protocol_string(bitcoin::Network::Signet, genesis_hash),
            format!("/p2pool/signet/{expected_tag}/1.0.0")
        );
    }

    /// The isolation property a chain reset relies on: re-anchoring genesis
    /// changes the protocol string even though the bitcoin network is
    /// unchanged, so nodes on the old chain cannot negotiate with new ones.
    #[test]
    fn test_protocol_string_differs_when_genesis_differs_on_same_network() {
        let genesis_hash = ShareBlock::build_genesis_for_network(bitcoin::Network::Testnet4)
            .unwrap()
            .block_hash();
        let other_genesis_hash = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet)
            .unwrap()
            .block_hash();
        assert_ne!(genesis_hash, other_genesis_hash);

        assert_ne!(
            protocol_string(bitcoin::Network::Testnet4, genesis_hash),
            protocol_string(bitcoin::Network::Testnet4, other_genesis_hash)
        );
    }

    /// Kademlia negotiates a distinct protocol name, but must isolate on the
    /// same genesis so a peer cannot join the DHT of a chain it is not on.
    #[test]
    fn test_kad_protocol_string_is_distinct_but_carries_same_genesis_tag() {
        let genesis_hash = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        let kad = kad_protocol_string(bitcoin::Network::Signet, genesis_hash);
        assert_eq!(kad, format!("/p2pool/signet/{expected_tag}/kad/1.0.0"));
        assert_ne!(kad, protocol_string(bitcoin::Network::Signet, genesis_hash));
    }
}
