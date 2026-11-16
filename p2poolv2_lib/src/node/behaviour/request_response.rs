// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{Hash, sha256d};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{Codec, OutboundFailure};
use std::io;

use crate::config::Chain;
use crate::node::messages::{MAX_P2P_MESSAGE_SIZE, Message, RawMessage};
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

/// Version of the request-response protocol negotiated on a stream.
///
/// The version selects how version-dependent messages are serialized and how
/// a request is served, so a node can keep talking to peers that only know an
/// older version.
///
/// The version is independent of share chain isolation. A chain reset
/// re-anchors genesis, which changes the genesis tag in every protocol string
/// (see [`network_prologue`]); it does not need, and must not rely on, a
/// version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Original protocol. Header responses truncate each height to
    /// `MAX_BLOCKS_PER_HEIGHT` blocks.
    V1_0,
    /// Header responses serve every block at a height and page with a resume
    /// point inside a height.
    V1_1,
}

impl ProtocolVersion {
    /// Version segment of the protocol string.
    fn as_str(self) -> &'static str {
        match self {
            ProtocolVersion::V1_0 => "1.0.0",
            ProtocolVersion::V1_1 => "1.1.0",
        }
    }
}

/// Request-response versions this node supports, most preferred first.
///
/// Outbound streams offer the versions in this order and multistream-select
/// takes the first one the remote accepts, so two current nodes negotiate the
/// newest version and a current node falls back to 1.0.0 with an older peer.
pub const SUPPORTED_PROTOCOL_VERSIONS: [ProtocolVersion; 2] =
    [ProtocolVersion::V1_1, ProtocolVersion::V1_0];

/// Build the network identifier for a bitcoin chain and share chain.
///
/// Used as the Noise prologue and the Identify protocol version. Network
/// isolation is enforced through the chain and genesis segments: nodes on
/// different networks, or on share chains with different genesis blocks,
/// derive different prologues and therefore fail the Noise handshake. The
/// same two segments are carried by [`request_response_protocol_string`] and
/// [`kad_protocol_string`], so such nodes also fail to negotiate any shared
/// protocol. Centralizing construction here keeps the segments consistent
/// across the Noise prologue, Identify, request-response and Kademlia.
///
/// The string is frozen at the one v0.18 nodes use, including its `1.0.0`
/// suffix, and does not follow the request-response protocol version. Noise
/// requires byte-identical prologues, so changing it would stop old and new
/// nodes from connecting at all and leave nothing to negotiate a version over.
pub fn network_prologue(chain: Chain, genesis_hash: BlockHash) -> String {
    format!(
        "/p2pool/{}/{}/1.0.0",
        chain.as_str(),
        genesis_tag(genesis_hash)
    )
}

/// Build the request-response protocol string for a chain, share chain and
/// protocol version.
///
/// Carries the same network and genesis segments as [`network_prologue`], so
/// nodes on different networks, or on share chains with different genesis
/// blocks, fail to negotiate a stream whatever version they support. Only the
/// last segment varies with `version`. The 1.0.0 string equals the one v0.18
/// nodes offer.
///
/// The chain and genesis segments are not strictly required for 1.1.0, since
/// the Noise prologue already isolates chains, but 1.0.0 needs them for
/// compatibility and keeping them helps debugging.
pub fn request_response_protocol_string(
    chain: Chain,
    genesis_hash: BlockHash,
    version: ProtocolVersion,
) -> String {
    format!(
        "/p2pool/{}/{}/{}",
        chain.as_str(),
        genesis_tag(genesis_hash),
        version.as_str()
    )
}

/// Build the Kademlia protocol string for a bitcoin chain and share chain.
///
/// Kademlia uses a distinct protocol name from [`network_prologue`] but shares
/// the same network and genesis segments, so it is derived here to keep both
/// in step.
pub fn kad_protocol_string(chain: Chain, genesis_hash: BlockHash) -> String {
    format!(
        "/p2pool/{}/{}/kad/1.0.0",
        chain.as_str(),
        genesis_tag(genesis_hash)
    )
}

// Protocol name for our request-response protocol
#[derive(Debug, Clone)]
pub struct P2PoolRequestResponseProtocol {
    name: String,
    version: ProtocolVersion,
}

impl P2PoolRequestResponseProtocol {
    /// Protocol for `version` on the given chain and share chain.
    pub fn new(chain: Chain, genesis_hash: BlockHash, version: ProtocolVersion) -> Self {
        Self {
            name: request_response_protocol_string(chain, genesis_hash, version),
            version,
        }
    }

    /// Version this protocol negotiates.
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }
}

impl AsRef<str> for P2PoolRequestResponseProtocol {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

// Consensus codec implementation using RawMessage for request-response protocols
#[derive(Clone)]
pub struct ConsensusCodec;

impl ConsensusCodec {
    /// Read one framed message, decoding the payload in the layout of the
    /// stream's protocol `version`.
    async fn read_message<T>(&self, version: ProtocolVersion, io: &mut T) -> io::Result<Message>
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
        if payload_len > MAX_P2P_MESSAGE_SIZE {
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

        let message = Message::consensus_decode_with_version(version, &mut &payload_bytes[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(message)
    }

    /// Write one framed message, encoding the payload in the layout of the
    /// stream's protocol `version`.
    async fn write_message<T>(
        &self,
        version: ProtocolVersion,
        io: &mut T,
        msg: Message,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let raw_msg = RawMessage::new_with_version(version, msg);
        let mut bytes = Vec::new();
        raw_msg
            .consensus_encode(&mut bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await
    }
}

impl Codec for ConsensusCodec {
    type Protocol = P2PoolRequestResponseProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_message(protocol.version(), io).await
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_message(protocol.version(), io).await
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_message(protocol.version(), io, req).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_message(protocol.version(), io, res).await
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
    use super::{
        ConsensusCodec, GENESIS_TAG_LEN, P2PoolRequestResponseProtocol, ProtocolVersion,
        kad_protocol_string, network_prologue, request_response_protocol_string,
    };
    use crate::config::Chain;
    use crate::node::messages::{GetShareHeaders, Message};
    use crate::shares::share_block::ShareBlock;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use libp2p::futures::io::Cursor;
    use libp2p::request_response::Codec;
    use std::str::FromStr;

    /// The prologue must stay byte-identical to the string v0.18 nodes use,
    /// or the Noise handshake between old and new nodes fails.
    #[test]
    fn test_network_prologue_carries_network_and_genesis_tag() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        assert_eq!(
            network_prologue(Chain::Signet, genesis_hash),
            format!("/p2pool/signet/{expected_tag}/1.0.0")
        );
    }

    /// The isolation property a chain reset relies on: re-anchoring genesis
    /// changes the prologue even though the bitcoin network is unchanged, so
    /// nodes on the old chain cannot connect to new ones.
    #[test]
    fn test_network_prologue_differs_when_genesis_differs_on_same_network() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Testnet4)
            .unwrap()
            .block_hash();
        let other_genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        assert_ne!(genesis_hash, other_genesis_hash);

        assert_ne!(
            network_prologue(Chain::Testnet4, genesis_hash),
            network_prologue(Chain::Testnet4, other_genesis_hash)
        );
    }

    /// Kademlia negotiates a distinct protocol name, but must isolate on the
    /// same genesis so a peer cannot join the DHT of a chain it is not on.
    #[test]
    fn test_kad_protocol_string_is_distinct_but_carries_same_genesis_tag() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        let kad = kad_protocol_string(Chain::Signet, genesis_hash);
        assert_eq!(kad, format!("/p2pool/signet/{expected_tag}/kad/1.0.0"));
        assert_ne!(kad, network_prologue(Chain::Signet, genesis_hash));
    }

    /// Testnet5 maps to testnet4 for addresses, but its share chain must not
    /// connect to testnet4 nodes.
    #[test]
    fn test_testnet5_network_prologue_differs_from_testnet4() {
        let testnet4_genesis = ShareBlock::build_genesis_for_network(Chain::Testnet4)
            .unwrap()
            .block_hash();
        let testnet5_genesis = ShareBlock::build_genesis_for_network(Chain::Testnet5)
            .unwrap()
            .block_hash();
        let testnet5_tag = &testnet5_genesis.to_string()[..GENESIS_TAG_LEN];

        assert_eq!(
            network_prologue(Chain::Testnet5, testnet5_genesis),
            format!("/p2pool/testnet5/{testnet5_tag}/1.0.0")
        );
        assert_ne!(
            network_prologue(Chain::Testnet5, testnet5_genesis),
            network_prologue(Chain::Testnet4, testnet4_genesis)
        );
    }

    /// A v0.18 node offers exactly this string for request-response, so the
    /// 1.0.0 protocol must keep it for the two to negotiate a stream.
    #[test]
    fn test_v1_0_request_response_protocol_matches_legacy_string() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        assert_eq!(
            request_response_protocol_string(Chain::Signet, genesis_hash, ProtocolVersion::V1_0),
            format!("/p2pool/signet/{expected_tag}/1.0.0")
        );
    }

    #[test]
    fn test_v1_1_request_response_protocol_carries_version() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let expected_tag = &genesis_hash.to_string()[..GENESIS_TAG_LEN];

        assert_eq!(
            request_response_protocol_string(Chain::Signet, genesis_hash, ProtocolVersion::V1_1),
            format!("/p2pool/signet/{expected_tag}/1.1.0")
        );
    }

    /// On a 1.0.0 stream the codec writes the legacy request layout, so the
    /// resume point is not carried, and the reading side records the 1.0.0
    /// stream on the decoded request.
    #[tokio::test]
    async fn test_codec_v1_0_stream_drops_resume_point_and_records_version() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let protocol =
            P2PoolRequestResponseProtocol::new(Chain::Signet, genesis_hash, ProtocolVersion::V1_0);
        let locator_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        let mut request = GetShareHeaders::new(vec![locator_hash], BlockHash::all_zeros());
        request.resume_after = Some(
            BlockHash::from_str("a3fbd2a0e62c42446e4e6d18dab3a479ebc84c279757450e019eafc89dfc1a62")
                .unwrap(),
        );
        let mut codec = ConsensusCodec;
        let mut stream = Cursor::new(Vec::new());

        codec
            .write_request(&protocol, &mut stream, Message::GetShareHeaders(request))
            .await
            .unwrap();
        stream.set_position(0);
        let decoded = codec.read_request(&protocol, &mut stream).await.unwrap();

        assert_eq!(
            decoded,
            Message::GetShareHeaders(GetShareHeaders {
                locator: vec![locator_hash],
                stop: BlockHash::all_zeros(),
                resume_after: None,
                protocol_version: ProtocolVersion::V1_0,
            })
        );
    }

    /// On a 1.1.0 stream the resume point survives the round trip.
    #[tokio::test]
    async fn test_codec_v1_1_stream_carries_resume_point() {
        let genesis_hash = ShareBlock::build_genesis_for_network(Chain::Signet)
            .unwrap()
            .block_hash();
        let protocol =
            P2PoolRequestResponseProtocol::new(Chain::Signet, genesis_hash, ProtocolVersion::V1_1);
        let locator_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();
        let mut request = GetShareHeaders::new(vec![locator_hash], BlockHash::all_zeros());
        request.resume_after = Some(
            BlockHash::from_str("a3fbd2a0e62c42446e4e6d18dab3a479ebc84c279757450e019eafc89dfc1a62")
                .unwrap(),
        );
        let message = Message::GetShareHeaders(request);
        let mut codec = ConsensusCodec;
        let mut stream = Cursor::new(Vec::new());

        codec
            .write_request(&protocol, &mut stream, message.clone())
            .await
            .unwrap();
        stream.set_position(0);
        let decoded = codec.read_request(&protocol, &mut stream).await.unwrap();

        assert_eq!(decoded, message);
    }
}
