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

use async_trait::async_trait;
use bitcoin::consensus::{Decodable, Encodable};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{Codec, OutboundFailure};
use std::io;

use crate::node::messages::{Message, RawMessage, network_magic};

// Protocol name for our request-response protocol
#[derive(Debug, Clone)]
pub struct P2PoolRequestResponseProtocol(String);

impl P2PoolRequestResponseProtocol {
    pub fn new() -> Self {
        Self("/p2pool/1.0.0".to_string())
    }
}

impl Default for P2PoolRequestResponseProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<str> for P2PoolRequestResponseProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// Consensus codec implementation using RawMessage for request-response protocols
#[derive(Clone)]
pub struct ConsensusCodec {
    magic: [u8; 4],
}

impl ConsensusCodec {
    pub fn new(magic: [u8; 4]) -> Self {
        Self { magic }
    }
}

impl Default for ConsensusCodec {
    fn default() -> Self {
        Self {
            magic: network_magic::REGTEST,
        }
    }
}

impl ConsensusCodec {
    async fn read_message<T>(&self, io: &mut T) -> io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read header: magic (4) + payload_len (4) + checksum (4) = 12 bytes
        let mut header_bytes = [0u8; 12];
        io.read_exact(&mut header_bytes).await?;

        // Parse payload length from header
        let payload_len = u32::from_le_bytes([
            header_bytes[4],
            header_bytes[5],
            header_bytes[6],
            header_bytes[7],
        ]);

        // Read exactly payload_len bytes
        let mut payload_bytes = vec![0u8; payload_len as usize];
        io.read_exact(&mut payload_bytes).await?;

        let message = Message::consensus_decode(&mut &payload_bytes[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(message)
    }

    async fn write_message<T>(&self, io: &mut T, msg: Message) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let raw_msg = RawMessage::new(self.magic, msg);
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
