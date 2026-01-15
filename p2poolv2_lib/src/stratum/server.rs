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

#[cfg(not(test))]
use crate::stratum::client_connections::ClientConnectionsHandle;
#[cfg(test)]
#[mockall_double::double]
use crate::stratum::client_connections::ClientConnectionsHandle;

use crate::accounting::stats::metrics;
use crate::shares::chain::chain_store::ChainStore;
use crate::stratum::difficulty_adjuster::{DifficultyAdjuster, DifficultyAdjusterTrait};
use crate::stratum::emission::EmissionSender;
use crate::stratum::error::Error;
use crate::stratum::message_handlers::handle_message;
use crate::stratum::messages::Request;
use crate::stratum::session::Session;
use crate::stratum::session_timeout::{self, check_session_timeouts};
use crate::stratum::work::notify::NotifyCmd;
use crate::stratum::work::tracker::TrackerHandle;
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoindrpc::BitcoinRpcConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::{debug, error, info};

// A struct to represent a Stratum server configuration
// This struct contains the port and address of the Stratum server
pub struct StratumServer {
    pub hostname: String,
    pub port: u16,
    pub start_difficulty: u64,
    pub minimum_difficulty: u64,
    pub maximum_difficulty: Option<u64>,
    pub ignore_difficulty: bool,
    pub validate_addresses: bool,
    pub network: bitcoin::Network,
    pub version_mask: i32,
    shutdown_rx: oneshot::Receiver<()>,
    connections_handle: ClientConnectionsHandle,
    emissions_tx: EmissionSender,
    store: Arc<ChainStore>,
}

/// Builder for StratumServer to avoid dependency on StratumConfig
#[derive(Default)]
pub struct StratumServerBuilder {
    hostname: Option<String>,
    port: Option<u16>,
    start_difficulty: Option<u64>,
    minimum_difficulty: Option<u64>,
    maximum_difficulty: Option<Option<u64>>,
    ignore_difficulty: Option<bool>,
    validate_addresses: Option<bool>,
    network: Option<bitcoin::Network>,
    version_mask: Option<i32>,
    shutdown_rx: Option<oneshot::Receiver<()>>,
    connections_handle: Option<ClientConnectionsHandle>,
    emissions_tx: Option<EmissionSender>,
    zmqpubhashblock: Option<String>,
    store: Option<Arc<ChainStore>>,
}

impl StratumServerBuilder {
    pub fn hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn start_difficulty(mut self, start_difficulty: u64) -> Self {
        self.start_difficulty = Some(start_difficulty);
        self
    }

    pub fn minimum_difficulty(mut self, minimum_difficulty: u64) -> Self {
        self.minimum_difficulty = Some(minimum_difficulty);
        self
    }

    pub fn maximum_difficulty(mut self, maximum_difficulty: Option<u64>) -> Self {
        self.maximum_difficulty = Some(maximum_difficulty);
        self
    }

    pub fn ignore_difficulty(mut self, ignore_difficulty: Option<bool>) -> Self {
        self.ignore_difficulty = ignore_difficulty;
        self
    }

    pub fn validate_addresses(mut self, validate_addresses: Option<bool>) -> Self {
        self.validate_addresses = validate_addresses;
        self
    }

    pub fn network(mut self, network: bitcoin::Network) -> Self {
        self.network = Some(network);
        self
    }

    pub fn version_mask(mut self, version_mask: i32) -> Self {
        self.version_mask = Some(version_mask);
        self
    }

    pub fn shutdown_rx(mut self, shutdown_rx: oneshot::Receiver<()>) -> Self {
        self.shutdown_rx = Some(shutdown_rx);
        self
    }

    pub fn connections_handle(mut self, connections_handle: ClientConnectionsHandle) -> Self {
        self.connections_handle = Some(connections_handle);
        self
    }

    pub fn emissions_tx(mut self, emissions_tx: EmissionSender) -> Self {
        self.emissions_tx = Some(emissions_tx);
        self
    }

    pub fn zmqpubhashblock(mut self, zmqpubhashblock: String) -> Self {
        self.zmqpubhashblock = Some(zmqpubhashblock);
        self
    }

    pub fn store(mut self, store: Arc<ChainStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub async fn build(self) -> Result<StratumServer, Box<dyn std::error::Error + Send + Sync>> {
        Ok(StratumServer {
            hostname: self.hostname.ok_or("hostname is required")?,
            port: self.port.ok_or("port is required")?,
            start_difficulty: self
                .start_difficulty
                .ok_or("start_difficulty is required")?,
            minimum_difficulty: self
                .minimum_difficulty
                .ok_or("minimum_difficulty is required")?,
            maximum_difficulty: self
                .maximum_difficulty
                .ok_or("maximum_difficulty is required")?,
            ignore_difficulty: self.ignore_difficulty.unwrap_or(false),
            validate_addresses: self.validate_addresses.unwrap_or(true),
            network: self.network.ok_or("network is required")?,
            version_mask: self.version_mask.ok_or("version_mask is required")?,
            shutdown_rx: self.shutdown_rx.ok_or("shutdown_rx is required")?,
            connections_handle: self
                .connections_handle
                .ok_or("connections_handle is required")?,
            emissions_tx: self.emissions_tx.ok_or("shares_tx is required")?,
            store: self.store.ok_or("store is required")?,
        })
    }
}

impl StratumServer {
    // A method to start the Stratum server
    pub async fn start(
        &mut self,
        ready_tx: Option<oneshot::Sender<()>>,
        notify_tx: mpsc::Sender<NotifyCmd>,
        tracker_handle: TrackerHandle,
        bitcoinrpc_config: BitcoinRpcConfig,
        metrics: metrics::MetricsHandle,
    ) -> Result<(), Box<dyn std::error::Error + Send>> {
        info!("Starting Stratum server at {}:{}", self.hostname, self.port);

        let bind_address = format!("{}:{}", self.hostname, self.port);
        let listener = match TcpListener::bind(&bind_address).await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to bind to {}: {}", bind_address, e);
                return Err(Box::new(e));
            }
        };

        if let Some(ready_tx) = ready_tx {
            // Notify that the server is ready to accept connections
            info!(
                "Stratum server is ready to accept connections on {}",
                bind_address
            );
            ready_tx.send(()).ok();
        }
        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = &mut self.shutdown_rx => {
                    info!("Shutdown signal received");
                    break;
                }
                connection = listener.accept() => {
                    match connection {
                        Ok(connection) => {
                            let (stream, addr) = connection;
                            info!("New connection from: {}", addr);
                            let (message_rx, shutdown_rx) = self.connections_handle.add(addr).await;
                            let (reader, writer) = stream.into_split();
                            let buf_reader = BufReader::new(reader);

                            let ctx = StratumContext {
                                notify_tx: notify_tx.clone(),
                                tracker_handle: tracker_handle.clone(),
                                bitcoinrpc_config: bitcoinrpc_config.clone(),
                                start_difficulty: self.start_difficulty,
                                minimum_difficulty: self.minimum_difficulty,
                                maximum_difficulty: self.maximum_difficulty,
                                ignore_difficulty: self.ignore_difficulty,
                                validate_addresses: self.validate_addresses,
                                emissions_tx: self.emissions_tx.clone(),
                                network: self.network,
                                metrics: metrics.clone(),
                                store: self.store.clone(),
                            };
                            let version_mask = self.version_mask;
                            // Spawn a new task for each connection
                            tokio::spawn(async move {
                                // Handle the connection with graceful shutdown support
                                if handle_connection(buf_reader, writer, addr, message_rx, shutdown_rx, version_mask, ctx, &SystemTimeProvider{}).await.is_err() {
                                        error!("Error occurred while handling connection {addr}. Closing connection.");
                                }
                            });
                        }
                        Err(e) => {
                            info!("Connection failed: {}", e);
                            continue;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// A context for the Stratum server easing the number of parameters passed around.
#[derive(Clone)]
pub(crate) struct StratumContext {
    pub notify_tx: mpsc::Sender<NotifyCmd>,
    pub tracker_handle: TrackerHandle,
    pub bitcoinrpc_config: BitcoinRpcConfig,
    pub start_difficulty: u64,
    pub minimum_difficulty: u64,
    pub maximum_difficulty: Option<u64>,
    pub ignore_difficulty: bool,
    pub validate_addresses: bool,
    pub emissions_tx: EmissionSender,
    pub network: bitcoin::network::Network,
    pub metrics: metrics::MetricsHandle,
    pub store: Arc<ChainStore>,
}

/// Handles a single connection to the Stratum server.
/// This function reads lines from the connection, processes them,
/// and sends responses back to the client.
async fn handle_connection<R, W, T: TimeProvider>(
    reader: R,
    mut writer: W,
    addr: SocketAddr,
    mut message_rx: mpsc::Receiver<Arc<String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
    version_mask: i32,
    ctx: StratumContext,
    time_provider: &T,
) -> Result<(), Box<dyn std::error::Error + Send>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Create a LinesCodec with a maximum line length of 8KB
    // This prevents potential DoS attacks with extremely long lines
    const MAX_LINE_LENGTH: usize = 8 * 1024; // 8KB

    let mut framed = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE_LENGTH));
    let session = &mut Session::<DifficultyAdjuster>::new(
        ctx.start_difficulty,
        ctx.minimum_difficulty,
        ctx.maximum_difficulty,
        version_mask,
    );

    let mut monitor = tokio::time::interval(tokio::time::Duration::from_secs(
        session_timeout::MONITOR_INTERVAL,
    ));
    monitor.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    monitor.tick().await;

    // Process each line as it arrives
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = &mut shutdown_rx => {
                info!("Shutdown signal received, closing connection from {}", addr);
                break;
            }
            // receive a message on the channel used by server to send_to_all
            Some(message) = message_rx.recv() => {
                if session.username.is_none() {
                    continue; // Ignore messages until the user has authorized
                }
                info!("Tx {addr} {message:?}");
                if let Err(e) = writer.write_all(format!("{message}\n").as_bytes()).await {
                    error!("Failed to write to {}: {}", addr, e);
                    break;
                }
                if let Err(e) = writer.flush().await {
                    error!("Failed to flush writer for {}: {}", addr, e);
                    break;
                }
            }
            // Read a line from the stream
            line = framed.next() => {
                info!("Rx {} {:?}", addr, line);
                match line {
                    Some(Ok(line)) => {
                        if line.is_empty() {
                            continue; // Ignore empty lines
                        }
                        if let Err(e) = process_incoming_message(
                            &line,
                            &mut writer,
                            session,
                            addr,
                            ctx.clone(),
                        ).await {
                            error!("Error processing message from {}: {}", addr, e);
                            return Err(e);
                        }
                    }
                    Some(Err(e)) => {
                        error!("Error reading line from {}: {}", addr, e);
                        return Err(Box::new(e));
                    }
                    None => {
                        info!("Connection closed by client: {}", addr);
                        break; // End of stream
                    }
                }
            }
            _ = monitor.tick() => {
                match check_session_timeouts::<T>(session, time_provider) {
                    Ok(()) => {}
                    Err(Error::TimeoutError) => {
                        info!("{addr} inactive, disconnecting...");
                        break;
                    }
                    Err(err) => {
                        error!("Timeout monitor failed for {addr}: {err}");
                        break;
                    }
                }
            }
        }
    }
    let _ = ctx
        .metrics
        .decrement_worker_count(
            session.btcaddress.clone(),
            session.workername.clone().unwrap_or_default(),
        )
        .await;
    Ok(())
}

async fn process_incoming_message<W, D>(
    line: &str,
    writer: &mut W,
    session: &mut Session<D>,
    addr: SocketAddr,
    ctx: StratumContext,
) -> Result<(), Box<dyn std::error::Error + Send>>
where
    W: AsyncWriteExt + Unpin,
    D: DifficultyAdjusterTrait + Send + Sync,
{
    match serde_json::from_str::<Request>(line) {
        Ok(message) => {
            let responses = handle_message(message, session, addr, ctx).await;

            if let Ok(responses) = responses {
                // Send the response back to the client
                for response in responses {
                    let response_json = match serde_json::to_string(&response) {
                        Ok(json) => json,
                        Err(e) => {
                            error!("Failed to serialize response for {}: {}", addr, e);
                            return Err(Box::new(e));
                        }
                    };

                    info!("Tx {addr} {response_json:?}");
                    if let Err(e) = writer
                        .write_all(format!("{response_json}\n").as_bytes())
                        .await
                    {
                        return Err(Box::new(e));
                    }
                }
                if let Err(e) = writer.flush().await {
                    Err(Box::new(e))
                } else {
                    debug!("Successfully sent response to {}", addr);
                    Ok(())
                }
            } else {
                error!(
                    "Error handling message from {}: {:?}. Closing connection.",
                    addr, responses
                );
                Err(Box::new(responses.unwrap_err()))
            }
        }
        Err(e) => {
            error!("Failed to parse message from {}: {}", addr, e);
            Ok(())
        }
    }
}

#[cfg(test)]
mod stratum_server_tests {
    use super::*;
    use crate::shares::chain::chain_store::ChainStore;
    use crate::shares::share_block::ShareBlock;
    use crate::store::Store;
    use crate::stratum::messages::SimpleRequest;
    use crate::stratum::server;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoindrpc::test_utils::setup_mock_bitcoin_rpc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_create_and_start_server() {
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let connections_handle = ClientConnectionsHandle::default();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let tracker_handle = start_tracker_actor();
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let mut server = StratumServerBuilder::default()
            .hostname("127.0.0.1".to_string())
            .port(12345)
            .start_difficulty(1)
            .minimum_difficulty(1)
            .maximum_difficulty(Some(2))
            .network(bitcoin::network::Network::Regtest)
            .version_mask(0x1fffe000)
            .shutdown_rx(shutdown_rx)
            .connections_handle(connections_handle)
            .emissions_tx(shares_tx)
            .store(store)
            .build()
            .await
            .unwrap();

        // Verify the server was created with the correct parameters
        assert_eq!(server.port, 12345);
        assert_eq!(server.hostname, "127.0.0.1");

        let (ready_tx, ready_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);

        // Start the server in a separate task so we can shut it down
        let server_handle = tokio::spawn(async move {
            // We'll ignore errors here since we'll forcibly shut down the server
            let _ = server
                .start(
                    Some(ready_tx),
                    notify_tx,
                    tracker_handle.clone(),
                    bitcoinrpc_config,
                    metrics_handle,
                )
                .await;
        });

        ready_rx.await.expect("Server should signal readiness");

        // We can't easily assert much more without connecting to the server,
        // but we can at least verify the server task is still running
        assert!(!server_handle.is_finished());

        // Shut down the server task
        server_handle.abort();

        // Wait for the task to complete
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_handle_connection_with_new_subscription_check_response_is_valid() {
        // Mock data
        let request = SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let input_string = serde_json::to_string(&request).unwrap() + "\n";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        // Setup reader and writer
        let reader = input_string.as_bytes();

        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            metrics: metrics_handle,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Regtest,
            store,
        };

        // Run the handler
        let result = handle_connection(
            reader,
            &mut writer,
            addr,
            message_rx,
            shutdown_rx,
            0x1fffe000,
            ctx,
            &SystemTimeProvider {},
        )
        .await;

        // Verify results
        assert!(
            result.is_ok(),
            "handle_connection should not return an error"
        );

        // Check that response was written
        let response = String::from_utf8_lossy(&writer);
        let responses: Vec<&str> = response.split('\n').filter(|s| !s.is_empty()).collect();
        let response_json: serde_json::Value =
            serde_json::from_str(responses[0]).expect("Response should be valid JSON");
        assert!(
            response_json.is_object(),
            "Response should be a JSON object"
        );

        // Check that the response has a 'result' field which is an array
        let result = response_json
            .get("result")
            .expect("Response should have a 'result' field");
        assert!(result.is_array(), "'result' should be an array");

        // For subscribe, result should be an array of length 3
        let result_array = result.as_array().unwrap();
        assert_eq!(result_array.len(), 3, "'result' array should have length 3");

        // The first element should be an array (subscriptions)
        assert!(result_array[0][0].is_array(),);

        assert_eq!(result_array[0][0][0], "mining.notify");
        assert_eq!(result_array[0][0][1].as_str().unwrap().len(), 9); // 8 bytes + 1 for the suffix

        // The second element should be an array (extranonce)
        assert!(result_array[0][1].is_array(),);
        assert_eq!(result_array[0][1][0], "mining.set_difficulty");
        assert_eq!(result_array[0][1][1].as_str().unwrap().len(), 9);

        // The third element can be a string or number (extranonce2_size), just check it exists
        assert!(result_array[1].is_string(),);
        assert_eq!(result_array[1].as_str().unwrap().len(), 8);

        // enonce2 size
        assert_eq!(result_array[2], 8);

        let set_difficulty_response = responses[1];
        let set_difficulty_json: serde_json::Value = serde_json::from_str(set_difficulty_response)
            .expect("Set difficulty response should be valid JSON");
        assert!(
            set_difficulty_json.is_object(),
            "Set difficulty response should be a JSON object"
        );
        assert_eq!(
            set_difficulty_json.get("method").unwrap(),
            "mining.set_difficulty",
            "Set difficulty response should have method 'mining.set_difficulty'"
        );
        assert_eq!(
            set_difficulty_json.get("params").unwrap(),
            &serde_json::json!([10000]),
            "Set difficulty response should have params [10000]"
        );

        assert!(response.ends_with("\n"),);
    }

    #[tokio::test]
    async fn test_handle_connection_invalid_json() {
        // Invalid JSON input
        let input = b"not valid json\n";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Setup reader and writer
        let reader = &input[..];
        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            metrics: metrics_handle,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Regtest,
            store,
        };

        // Run the handler
        let result = handle_connection(
            reader,
            &mut writer,
            addr,
            message_rx,
            shutdown_rx,
            0x1fffe000,
            ctx,
            &SystemTimeProvider {},
        )
        .await;

        // Verify results - even with bad json, we do not return an error to close the connection
        assert!(
            result.is_ok(),
            "handle_connection should handle invalid JSON gracefully"
        );

        // Check that no response was written
        assert!(
            writer.is_empty(),
            "No response should be written for invalid JSON"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_line_too_long() {
        // Create a line that exceeds the max length (8KB)
        let mut long_input = String::with_capacity(10 * 1024);
        long_input.push_str("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"");
        while long_input.len() < 9 * 1024 {
            long_input.push_str("aaaaaaaaaa");
        }
        long_input.push_str("\"]}\n");

        let input = long_input.as_bytes();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Setup reader and writer
        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            metrics: metrics_handle,
            network: bitcoin::network::Network::Regtest,
            store,
        };

        // Run the handler
        let result = handle_connection(
            input,
            &mut writer,
            addr,
            message_rx,
            shutdown_rx,
            0x1fffe000,
            ctx,
            &SystemTimeProvider {},
        )
        .await;

        // Returns an error, so we can close the connection gracefully.
        assert!(
            result.is_err(),
            "handle_connection should handle line-too-long gracefully"
        );

        // No response should be written for a line that's too long
        assert!(
            writer.is_empty(),
            "No response should be written for too-long lines"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_double_subscribe_closes_connection() {
        // Prepare two subscribe requests in a row
        let request1 =
            SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let request2 =
            SimpleRequest::new_subscribe(2, "agent".to_string(), "1.0".to_string(), None);
        let input_string = format!(
            "{}\n{}\n",
            serde_json::to_string(&request1).unwrap(),
            serde_json::to_string(&request2).unwrap()
        );
        let addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            8081,
        );

        // Setup reader and writer
        let reader = input_string.as_bytes();
        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            store,
        };

        // Run the handler
        let result = server::handle_connection(
            reader,
            &mut writer,
            addr,
            message_rx,
            shutdown_rx,
            0x1fffe000,
            ctx,
            &SystemTimeProvider {},
        )
        .await;

        // Should return error, so we can close the connection gracefully.
        assert!(
            result.is_err(),
            "handle_connection should close connection on double subscribe"
        );

        // Only one response should be written (for the first subscribe)
        let response = String::from_utf8_lossy(&writer);
        let responses: Vec<&str> = response.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(responses.len(), 2);

        // The response should be a valid subscribe response
        let response_json: serde_json::Value =
            serde_json::from_str(responses[0]).expect("Response should be valid JSON");
        assert!(
            response_json.is_object(),
            "Response should be a JSON object"
        );
        assert!(
            response_json.get("result").is_some(),
            "Subscribe response should have 'result'"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_should_include_responses_after_authorization() {
        // Create message channel and shutdown channel
        let (message_tx, message_rx) = mpsc::channel(10);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        // Create a channel to get the writer result for verification
        let (writer_tx, writer_rx) = oneshot::channel::<Vec<u8>>();

        // Create input with subscribe and authorize messages
        let subscribe_message =
            SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let subscribe_str = serde_json::to_string(&subscribe_message).unwrap();

        let authorize_message = SimpleRequest::new_authorize(
            2,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            Some("test_password".to_string()),
        );
        let authorize_str = serde_json::to_string(&authorize_message).unwrap();

        // Create mock IO objects
        let mut mock_reader = tokio_test::io::Builder::new()
            .read(format!("{subscribe_str}\n").as_bytes())
            .read(format!("{authorize_str}\n").as_bytes())
            .wait(std::time::Duration::from_millis(10_000)) // Wait for 10 seconds before continuing
            .build();

        let mut writer = Vec::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);

        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            store,
        };

        // Spawn the handler in a separate task
        let handle = tokio::spawn(async move {
            // Wrap the mock reader with a BufReader to implement AsyncBufReadExt
            let buf_reader = tokio::io::BufReader::new(&mut mock_reader);
            let result = handle_connection(
                buf_reader,
                &mut writer,
                addr,
                message_rx,
                shutdown_rx,
                0x1fffe000,
                ctx,
                &SystemTimeProvider {},
            )
            .await;

            assert!(
                result.is_ok(),
                "handle_connection should gracefully handle shutdown"
            );

            // Send the writer content for verification
            let _ = writer_tx.send(writer);
        });

        // Wait for processing to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        message_tx
            .send(Arc::new("test message".to_string()))
            .await
            .expect("Failed to send message");

        // Wait to allow message processing
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Send shutdown signal to end the test
        shutdown_tx
            .send(())
            .expect("Failed to send shutdown signal");

        // Wait for the task to complete
        let _ = handle.await;

        // Get the writer content and verify
        let writer_content = writer_rx.await.expect("Failed to get writer content");
        let response_str = String::from_utf8_lossy(&writer_content);

        // Verify responses were sent for subscribe and authorize
        let responses: Vec<&str> = response_str.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(
            responses.len(),
            5,
            "Should have responses for subscribe, authorize and the test message."
        );

        // Parse and verify each response
        let subscribe_response: serde_json::Value =
            serde_json::from_str(responses[0]).expect("Subscribe response should be valid JSON");
        assert!(
            subscribe_response.get("result").is_some(),
            "Subscribe response should have 'result' field"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_should_not_include_responses_before_authorization() {
        // Create message channel and shutdown channel
        let (message_tx, message_rx) = mpsc::channel(10);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        // Create a channel to get the writer result for verification
        let (writer_tx, writer_rx) = oneshot::channel::<Vec<u8>>();

        // Create input with subscribe and authorize messages
        let subscribe_message =
            SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let subscribe_str = serde_json::to_string(&subscribe_message).unwrap();

        // Create mock IO objects
        let mut mock_reader = tokio_test::io::Builder::new()
            .read(format!("{subscribe_str}\n").as_bytes())
            .wait(std::time::Duration::from_millis(10_000)) // Wait for 10 seconds before continuing
            .build();

        let mut writer = Vec::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::network::Network::Signet),
            bitcoin::network::Network::Signet,
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle: tracker_handle.clone(),
            bitcoinrpc_config,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            store,
        };

        // Spawn the handler in a separate task
        let handle = tokio::spawn(async move {
            // Wrap the mock reader with a BufReader to implement AsyncBufReadExt
            let buf_reader = tokio::io::BufReader::new(&mut mock_reader);
            let result = handle_connection(
                buf_reader,
                &mut writer,
                addr,
                message_rx,
                shutdown_rx,
                0x1fffe000,
                ctx,
                &SystemTimeProvider {},
            )
            .await;

            assert!(
                result.is_ok(),
                "handle_connection should gracefully handle shutdown"
            );

            // Send the writer content for verification
            let _ = writer_tx.send(writer);
        });

        // Wait for processing to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        message_tx
            .send(Arc::new("test message".to_string()))
            .await
            .expect("Failed to send message");

        // Wait to allow message processing
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Send shutdown signal to end the test
        shutdown_tx
            .send(())
            .expect("Failed to send shutdown signal");

        // Wait for the task to complete
        let _ = handle.await;

        // Get the writer content and verify
        let writer_content = writer_rx.await.expect("Failed to get writer content");
        let response_str = String::from_utf8_lossy(&writer_content);

        // Verify responses were sent for subscribe and authorize
        let responses: Vec<&str> = response_str.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(responses.len(), 2, "Should have responses for subscribe");

        // Parse and verify each response
        let subscribe_response: serde_json::Value =
            serde_json::from_str(responses[0]).expect("Subscribe response should be valid JSON");
        assert!(
            subscribe_response.get("result").is_some(),
            "Subscribe response should have 'result' field"
        );
    }

    #[test]
    fn test_handle_connection_first_share_timeout_should_timeout() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            tokio::time::pause();

            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8083);
            let mut writer = Vec::new();
            let (_, message_rx) = mpsc::channel(10);
            let (_shutdown_tx, shutdown_rx) = oneshot::channel();
            let (notify_tx, _notify_rx) = mpsc::channel(10);
            let tracker_handle = start_tracker_actor();
            let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
            let (emissions_tx, _emissions_rx) = mpsc::channel(10);
            let stats_dir = tempfile::tempdir().unwrap();
            let metrics_handle =
                metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
                    .await
                    .unwrap();

            let temp_dir = tempdir().unwrap();
            let store = Arc::new(ChainStore::new(
                Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
                ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
                bitcoin::Network::Signet,
            ));

            let ctx = StratumContext {
                notify_tx,
                tracker_handle: tracker_handle.clone(),
                bitcoinrpc_config,
                metrics: metrics_handle,
                start_difficulty: 10000,
                minimum_difficulty: 1,
                maximum_difficulty: Some(2),
                ignore_difficulty: false,
                validate_addresses: true,
                emissions_tx,
                network: bitcoin::network::Network::Regtest,
                store,
            };

            // wait for subscribe/authorize messages
            let mut mock_reader = tokio_test::io::Builder::new()
                .wait(tokio::time::Duration::from_secs(100_000))
                .build();

            let time_provider = TestTimeProvider::new(std::time::SystemTime::now());
            let mut time_provider_cloned = time_provider.clone();

            let handle = tokio::spawn(async move {
                let buf_reader = tokio::io::BufReader::new(&mut mock_reader);
                handle_connection(
                    buf_reader,
                    &mut writer,
                    addr,
                    message_rx,
                    shutdown_rx,
                    0x1fffe000,
                    ctx,
                    &time_provider,
                )
                .await
            });

            // set time queried for timeout
            time_provider_cloned.set_since_epoch(time_provider_cloned.seconds_since_epoch() + 901);
            // push forward tokio time for triggering tick
            tokio::time::advance(tokio::time::Duration::from_secs(901)).await;

            let result = handle.await.unwrap();
            assert!(result.is_ok());
        });
    }

    #[test_log::test]
    fn test_handle_connection_inactivity_timeout() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            tokio::time::pause();

            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8084);
            let mut writer = Vec::new();
            let (_, message_rx) = mpsc::channel(10);
            let (_shutdown_tx, shutdown_rx) = oneshot::channel();
            let (notify_tx, _notify_rx) = mpsc::channel(10);
            let tracker_handle = start_tracker_actor();
            let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
            let (emissions_tx, _emissions_rx) = mpsc::channel(10);
            let stats_dir = tempfile::tempdir().unwrap();
            let metrics_handle =
                metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
                    .await
                    .unwrap();

            let temp_dir = tempdir().unwrap();
            let store = Arc::new(ChainStore::new(
                Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
                ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
                bitcoin::Network::Signet,
            ));

            let ctx = StratumContext {
                notify_tx,
                tracker_handle: tracker_handle.clone(),
                bitcoinrpc_config,
                metrics: metrics_handle,
                start_difficulty: 10000,
                minimum_difficulty: 1,
                maximum_difficulty: Some(2),
                ignore_difficulty: false,
                validate_addresses: true,
                emissions_tx,
                network: bitcoin::network::Network::Signet,
                store,
            };

            let subscribe_message =
                SimpleRequest::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
            let subscribe_str = serde_json::to_string(&subscribe_message).unwrap();

            let authorize_message = SimpleRequest::new_authorize(
                2,
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                Some("test_password".to_string()),
            );
            let authorize_str = serde_json::to_string(&authorize_message).unwrap();

            // Wait for a long while for new messages
            let mut mock_reader = tokio_test::io::Builder::new()
                .read(format!("{subscribe_str}\n").as_bytes())
                .read(format!("{authorize_str}\n").as_bytes())
                .wait(tokio::time::Duration::from_secs(100_000))
                .build();

            let time_provider = TestTimeProvider::new(std::time::SystemTime::now());
            let mut time_provider_cloned = time_provider.clone();

            let handle = tokio::spawn(async move {
                let buf_reader = tokio::io::BufReader::new(&mut mock_reader);
                handle_connection(
                    buf_reader,
                    &mut writer,
                    addr,
                    message_rx,
                    shutdown_rx,
                    0x1fffe000,
                    ctx,
                    &time_provider,
                )
                .await
            });

            // set time queried for timeout
            time_provider_cloned.set_since_epoch(time_provider_cloned.seconds_since_epoch() + 901);
            // push forward tokio time for triggering tick
            tokio::time::advance(tokio::time::Duration::from_secs(901)).await;

            let result = handle.await.unwrap();
            assert!(result.is_ok());
        });
    }
}
