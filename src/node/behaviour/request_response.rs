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

use async_trait::async_trait;
use ciborium::{de::from_reader, ser::into_writer};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{Codec, OutboundFailure};
use serde::{de::DeserializeOwned, Serialize};
use std::io;

// Protocol name for our request-response protocol
#[derive(Debug, Clone)]
pub struct P2PoolRequestResponseProtocol(String);

impl P2PoolRequestResponseProtocol {
    pub fn new() -> Self {
        Self(format!("/p2pool/1.0.0"))
    }
}

// impl ProtocolName for P2PoolRequestResponseProtocol {
//     const VERSION: &'static str = "1.0.0";

//     fn protocol_name(&self) -> &[u8] {
//         self.0.as_bytes()
//     }
// }

impl AsRef<str> for P2PoolRequestResponseProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// CBOR codec implementation for request-response protocols
#[derive(Clone)]
pub struct CborCodec<Request, Response> {
    _phantom: std::marker::PhantomData<(Request, Response)>,
}

impl<Request, Response> Default for CborCodec<Request, Response> {
    fn default() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Request, Response> Codec for CborCodec<Request, Response>
where
    Request: Serialize + DeserializeOwned + Send + 'static,
    Response: Serialize + DeserializeOwned + Send + 'static,
{
    type Protocol = P2PoolRequestResponseProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes).await?;
        from_reader(&bytes[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = Vec::new();
        io.read_to_end(&mut bytes).await?;
        from_reader(&bytes[..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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
        let mut bytes = Vec::new();
        into_writer(&req, &mut bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await
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
        let mut bytes = Vec::new();
        into_writer(&res, &mut bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        io.write_all(&bytes).await
    }
}

// Helper type aliases for the request-response behavior
pub type RequestResponseBehaviour<Request, Response> =
    libp2p::request_response::Behaviour<CborCodec<Request, Response>>;
pub type RequestResponseEvent<Request, Response> =
    libp2p::request_response::Event<Request, Response>;

// Error type for request-response failures
#[derive(Debug, thiserror::Error)]
pub enum RequestResponseError {
    #[error("Outbound request failed: {0}")]
    OutboundFailure(#[from] OutboundFailure),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
