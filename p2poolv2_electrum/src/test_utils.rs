// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared test infrastructure: a stub dispatcher, a current test chain, a
//! server on an ephemeral port, a connection handler over an in-memory
//! duplex stream, and a line oriented client for either.

use crate::connection::handle_connection;
use crate::error::ElectrumServerError;
use crate::protocol::{METHOD_NOT_FOUND, RpcError};
use crate::server::run_server;
use p2poolv2_lib::config::ElectrumConfig;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::test_utils::{
    TestShareBlockBuilder, confirm_test_block, genesis_for_tests, test_funding_transaction,
};
use serde_json::Value;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, Lines,
    ReadHalf, WriteHalf, duplex, split,
};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Bound on every client read, so a broken server fails the test instead
/// of hanging it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// In-memory buffer per direction of a duplex test connection.
const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;

/// Pause between connection attempts in `connect_with_retry`.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);

/// A client over the in-memory end of a duplex test connection.
pub(crate) type DuplexClient = TestClient<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

/// Enabled config bound to an ephemeral localhost port.
pub(crate) fn test_config() -> ElectrumConfig {
    ElectrumConfig {
        enabled: true,
        hostname: "127.0.0.1".to_string(),
        port: 0,
        max_connections: 8,
    }
}

/// Set up `genesis_for_tests` and confirm a linear chain of `length` blocks
/// whose times count up to now, so `is_current()` holds. Like
/// `build_confirmed_test_chain`, every block carries its own funding
/// transaction. Returns the blocks indexed by height, genesis at 0.
pub(crate) async fn build_current_test_chain(
    chain_store_handle: &ChainStoreHandle,
    length: usize,
) -> Vec<ShareBlock> {
    let genesis = genesis_for_tests();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut blocks = Vec::with_capacity(length + 1);
    blocks.push(genesis);
    for height in 1..=length {
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[height - 1].block_hash().to_string())
            .time(now_secs - (length - height) as u32)
            .add_transaction(test_funding_transaction(height as u64))
            .build();
        confirm_test_block(chain_store_handle, &block).await;
        blocks.push(block);
    }
    blocks
}

/// Dispatcher that knows only `server.ping`, for testing the envelope
/// layer without a store.
pub(crate) fn ping_only_dispatch(method: &str, _params: &Value) -> Result<Value, RpcError> {
    match method {
        "server.ping" => Ok(Value::Null),
        _ => Err(RpcError::new(
            METHOD_NOT_FOUND,
            format!("unknown method {method}"),
        )),
    }
}

/// Spawn `run_server` with `test_config` and wait until it is listening.
pub(crate) async fn start_test_server(
    chain_store_handle: ChainStoreHandle,
    shutdown: CancellationToken,
) -> (SocketAddr, JoinHandle<Result<(), ElectrumServerError>>) {
    let config = test_config();
    let (ready_tx, ready_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        run_server(&config, &chain_store_handle, shutdown, Some(ready_tx)).await
    });
    let address = ready_rx.await.unwrap();
    (address, server)
}

/// Connect to `address`, retrying until a server is listening there.
/// Panics after `READ_TIMEOUT`.
pub(crate) async fn connect_with_retry(address: SocketAddr) -> TestClient {
    timeout(READ_TIMEOUT, async {
        let mut stream = TcpStream::connect(address).await;
        while stream.is_err() {
            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            stream = TcpStream::connect(address).await;
        }
        stream
    })
    .await
    .expect("timed out waiting for the Electrum server to listen")
    .map(|stream| {
        let (reader, writer) = stream.into_split();
        TestClient::new(reader, writer)
    })
    .expect("Electrum server connection failed")
}

/// Run `handle_connection` on one end of an in-memory duplex stream and
/// return a client for the other end, plus the handler task.
pub(crate) fn spawn_test_connection(
    chain_store_handle: ChainStoreHandle,
    shutdown: CancellationToken,
) -> (DuplexClient, JoinHandle<()>) {
    let (client_stream, server_stream) = duplex(DUPLEX_BUFFER_SIZE);
    let (server_reader, server_writer) = split(server_stream);
    let peer_address = SocketAddr::from(([127, 0, 0, 1], 0));
    let handler = tokio::spawn(handle_connection(
        server_reader,
        server_writer,
        peer_address,
        chain_store_handle,
        shutdown,
    ));
    let (client_reader, client_writer) = split(client_stream);
    (TestClient::new(client_reader, client_writer), handler)
}

/// A wallet stand-in that writes request lines and reads response lines.
pub(crate) struct TestClient<R = OwnedReadHalf, W = OwnedWriteHalf> {
    lines: Lines<BufReader<R>>,
    writer: W,
}

impl TestClient {
    pub(crate) async fn connect(address: SocketAddr) -> Self {
        let (reader, writer) = TcpStream::connect(address).await.unwrap().into_split();
        Self::new(reader, writer)
    }
}

impl<R, W> TestClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub(crate) fn new(reader: R, writer: W) -> Self {
        Self {
            lines: BufReader::new(reader).lines(),
            writer,
        }
    }

    /// Write `line` followed by a newline.
    pub(crate) async fn send(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await
    }

    /// Read the next line, or `None` on EOF. Panics after `READ_TIMEOUT`.
    pub(crate) async fn read_line(&mut self) -> io::Result<Option<String>> {
        timeout(READ_TIMEOUT, self.lines.next_line())
            .await
            .expect("timed out waiting for the Electrum server")
    }

    /// Send one request line and read the response line.
    pub(crate) async fn request(&mut self, line: &str) -> io::Result<Option<String>> {
        self.send(line).await?;
        self.read_line().await
    }

    /// Send one request line and parse the response. Panics if the
    /// connection closes or the response is not JSON.
    pub(crate) async fn call(&mut self, line: &str) -> Value {
        let response = self
            .request(line)
            .await
            .expect("Electrum connection failed")
            .expect("Electrum connection closed");
        serde_json::from_str(&response).expect("Electrum response is not JSON")
    }
}
