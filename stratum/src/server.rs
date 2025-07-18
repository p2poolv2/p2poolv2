// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

#[cfg(not(test))]
use crate::client_connections::ClientConnectionsHandle;
#[cfg(test)]
#[mockall_double::double]
use crate::client_connections::ClientConnectionsHandle;

use crate::config::StratumConfig;
use crate::difficulty_adjuster::{DifficultyAdjuster, DifficultyAdjusterTrait};
use crate::message_handlers::handle_message;
use crate::messages::Request;
use crate::session::Session;
use crate::work::notify::NotifyCmd;
use crate::work::tracker::TrackerHandle;
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
    pub config: StratumConfig,
    shutdown_rx: oneshot::Receiver<()>,
    connections_handle: ClientConnectionsHandle,
}

impl StratumServer {
    // A method to create a new Stratum server configuration
    pub async fn new(
        config: StratumConfig,
        shutdown_rx: oneshot::Receiver<()>,
        connections_handle: ClientConnectionsHandle,
    ) -> Self {
        Self {
            config,
            shutdown_rx,
            connections_handle,
        }
    }

    // A method to start the Stratum server
    pub async fn start(
        &mut self,
        ready_tx: Option<oneshot::Sender<()>>,
        notify_tx: mpsc::Sender<NotifyCmd>,
        tracker_handle: TrackerHandle,
        bitcoinrpc_config: BitcoinRpcConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send>> {
        info!(
            "Starting Stratum server at {}:{}",
            self.config.hostname, self.config.port
        );

        let bind_address = format!("{}:{}", self.config.hostname, self.config.port);
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
                                minimum_difficulty: self.config.minimum_difficulty,
                                maximum_difficulty: self.config.maximum_difficulty,
                                network: self.config.network,
                            };
                            let version_mask = self.config.version_mask;
                            // Spawn a new task for each connection
                            tokio::spawn(async move {
                                // Handle the connection with graceful shutdown support
                                let _ = handle_connection(buf_reader, writer, addr, message_rx, shutdown_rx, version_mask, ctx).await;
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
    pub minimum_difficulty: u64,
    pub maximum_difficulty: Option<u64>,
    pub network: bitcoin::network::Network,
}

/// Handles a single connection to the Stratum server.
/// This function reads lines from the connection, processes them,
/// and sends responses back to the client.
async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    addr: SocketAddr,
    mut message_rx: mpsc::Receiver<Arc<String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
    version_mask: i32,
    ctx: StratumContext,
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
        ctx.minimum_difficulty,
        ctx.maximum_difficulty,
        ctx.maximum_difficulty.unwrap_or(ctx.minimum_difficulty),
        version_mask,
    );

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
                debug!("Received message from channel: {}", message);
                if session.username.is_none() {
                    continue; // Ignore messages until the user has authorized
                }
                if let Err(e) = writer.write_all(format!("{}\n", message).as_bytes()).await {
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
                debug!("Read line {:?} from {}...", line, addr);
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
        }
    }
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

                    info!("Sending to {}: {:?}", addr, response_json);
                    if let Err(e) = writer
                        .write_all(format!("{}\n", response_json).as_bytes())
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
    use crate::messages::SimpleRequest;
    use crate::work::tracker::start_tracker_actor;
    use bitcoindrpc::test_utils::setup_mock_bitcoin_rpc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_create_and_start_server() {
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let connections_handle = ClientConnectionsHandle::default();
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        let config = StratumConfig {
            hostname: "127.0.0.1".to_string(),
            port: 12345,
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            solo_address: None,
            zmqpubhashblock: "tcp://127.0.0.1:28332".to_string(),
            network: bitcoin::network::Network::Regtest,
            version_mask: 0x1fffe000,
        };

        let mut server = StratumServer::new(config, shutdown_rx, connections_handle).await;

        // Verify the server was created with the correct parameters
        assert_eq!(server.config.port, 12345);
        assert_eq!(server.config.hostname, "127.0.0.1");

        let (ready_tx, ready_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);

        // Start the server in a separate task so we can shut it down
        let server_handle = tokio::spawn(async move {
            // We'll ignore errors here since we'll forcibly shut down the server
            let _ = server
                .start(Some(ready_tx), notify_tx, tracker_handle, bitcoinrpc_config)
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

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
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
            serde_json::from_str(&responses[0]).expect("Response should be valid JSON");
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
            &serde_json::json!([1]),
            "Set difficulty response should have params [1]"
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

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
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

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
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

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
        };

        // Run the handler
        let result = super::handle_connection(
            reader,
            &mut writer,
            addr,
            message_rx,
            shutdown_rx,
            0x1fffe000,
            ctx,
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

    #[test_log::test(tokio::test)]
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
            "test_user".to_string(),
            Some("test_password".to_string()),
        );
        let authorize_str = serde_json::to_string(&authorize_message).unwrap();

        // Create mock IO objects
        let mut mock_reader = tokio_test::io::Builder::new()
            .read(format!("{}\n", subscribe_str).as_bytes())
            .read(format!("{}\n", authorize_str).as_bytes())
            .wait(std::time::Duration::from_millis(10_000)) // Wait for 10 seconds before continuing
            .build();

        let mut writer = Vec::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);

        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
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

    #[test_log::test(tokio::test)]
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
            .read(format!("{}\n", subscribe_str).as_bytes())
            .wait(std::time::Duration::from_millis(10_000)) // Wait for 10 seconds before continuing
            .build();

        let mut writer = Vec::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082);
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            network: bitcoin::network::Network::Regtest,
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
}
