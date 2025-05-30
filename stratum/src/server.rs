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

use crate::client_connections::{spawn, ClientConnectionsHandle};
use crate::message_handlers::handle_message;
use crate::messages::Request;
use crate::session::Session;
use crate::work::gbt::BlockTemplate;
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
    pub port: u16,
    pub hostname: String,
    shutdown_rx: oneshot::Receiver<()>,
    gbt_rx: mpsc::Receiver<BlockTemplate>,
    connections_handle: ClientConnectionsHandle,
}

impl StratumServer {
    // A method to create a new Stratum server configuration
    pub async fn new(
        hostname: String,
        port: u16,
        shutdown_rx: oneshot::Receiver<()>,
        gbt_rx: mpsc::Receiver<BlockTemplate>,
    ) -> Self {
        let connections_handle = spawn().await;
        Self {
            port,
            hostname,
            shutdown_rx,
            gbt_rx,
            connections_handle,
        }
    }

    // A method to start the Stratum server
    pub async fn start(
        &mut self,
        ready_tx: Option<oneshot::Sender<()>>,
        notifier_tx: mpsc::Sender<Arc<BlockTemplate>>,
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
                // update the block template from the gbt_rx channel
                Some(template) = self.gbt_rx.recv() => {
                    notifier_tx.send(Arc::new(template)).await.ok();
                }
                connection = listener.accept() => {
                    match connection {
                        Ok(connection) => {
                            let (stream, addr) = connection;
                            info!("New connection from: {}", addr);
                            let (message_rx, shutdown_rx) = self.connections_handle.add(addr).await;
                            let (reader, writer) = stream.into_split();
                            let buf_reader = BufReader::new(reader);

                            // Spawn a new task for each connection
                            tokio::spawn(async move {
                                // Handle the connection with graceful shutdown support
                                let _ = handle_connection(buf_reader, writer, addr, message_rx, shutdown_rx).await;
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

/// Handles a single connection to the Stratum server.
/// This function reads lines from the connection, processes them,
/// and sends responses back to the client.
/// The function handles the session data for each connection as required for the Stratum protocol.
#[allow(dead_code)]
async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    addr: SocketAddr,
    mut message_rx: mpsc::Receiver<Arc<String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Create a LinesCodec with a maximum line length of 8KB
    // This prevents potential DoS attacks with extremely long lines
    const MAX_LINE_LENGTH: usize = 8 * 1024; // 8KB

    let mut framed = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE_LENGTH));
    let session = &mut Session::new(1);

    // Process each line as it arrives
    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = &mut shutdown_rx => {
                info!("Shutdown signal received, closing connection from {}", addr);
                break;
            }
            // receive a message from the message channel
            Some(message) = message_rx.recv() => {
                debug!("Received message from channel: {}", message);
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
                        if let Err(e) = process_incoming_message(&line, &mut writer, session, addr).await {
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

async fn process_incoming_message<W>(
    line: &str,
    writer: &mut W,
    session: &mut Session,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send>>
where
    W: AsyncWriteExt + Unpin,
{
    match serde_json::from_str::<Request>(line) {
        Ok(message) => {
            let response = handle_message(message, session).await;

            if let Ok(response) = response {
                // Send the response back to the client
                let response_json = match serde_json::to_string(&response) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Failed to serialize response for {}: {}", addr, e);
                        return Err(Box::new(e));
                    }
                };

                debug!("Sending to {}: {:?}", addr, response_json);
                if let Err(e) = writer
                    .write_all(format!("{}\n", response_json).as_bytes())
                    .await
                {
                    return Err(Box::new(e));
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
                    addr, response
                );
                Err(Box::new(response.unwrap_err()))
            }
        }
        Err(e) => Err(Box::new(e)),
    }
}

#[cfg(test)]
mod stratum_server_tests {
    use super::*;
    use bitcoindrpc::MockBitcoindRpc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_create_and_start_server() {
        let ctx = MockBitcoindRpc::new_context();
        ctx.expect().returning(|_, _, _| {
            let mut mock = MockBitcoindRpc::default();
            mock.expect_getblocktemplate()
                .returning(|_| Box::pin(async move { Ok("".into()) }));
            Ok(mock)
        });
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (_gbt_tx, gbt_rx) = mpsc::channel(10);
        let (notifier_tx, _notifier_rx) = mpsc::channel(10);

        let mut server =
            StratumServer::new("127.0.0.1".to_string(), 12345, shutdown_rx, gbt_rx).await;

        // Verify the server was created with the correct parameters
        assert_eq!(server.port, 12345);
        assert_eq!(server.hostname, "127.0.0.1");

        let (ready_tx, ready_rx) = oneshot::channel();

        // Start the server in a separate task so we can shut it down
        let server_handle = tokio::spawn(async move {
            // We'll ignore errors here since we'll forcibly shut down the server
            let _ = server.start(Some(ready_tx), notifier_tx).await;
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
        let request = Request::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let input_string = serde_json::to_string(&request).unwrap() + "\n";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Setup reader and writer
        let reader = input_string.as_bytes();

        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();

        // Run the handler
        let result = handle_connection(reader, &mut writer, addr, message_rx, shutdown_rx).await;

        // Verify results
        assert!(
            result.is_ok(),
            "handle_connection should not return an error"
        );

        // Check that response was written
        let response = String::from_utf8_lossy(&writer);
        let response_json: serde_json::Value =
            serde_json::from_str(&response).expect("Response should be valid JSON");
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

        // Run the handler
        let result = handle_connection(reader, &mut writer, addr, message_rx, shutdown_rx).await;

        // Verify results
        assert!(
            result.is_err(),
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

        // Run the handler
        let result = handle_connection(input, &mut writer, addr, message_rx, shutdown_rx).await;

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
        let request1 = Request::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);
        let request2 = Request::new_subscribe(2, "agent".to_string(), "1.0".to_string(), None);
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

        // Run the handler
        let result =
            super::handle_connection(reader, &mut writer, addr, message_rx, shutdown_rx).await;

        // Should return error, so we can close the connection gracefully.
        assert!(
            result.is_err(),
            "handle_connection should close connection on double subscribe"
        );

        // Only one response should be written (for the first subscribe)
        let response = String::from_utf8_lossy(&writer);
        let responses: Vec<&str> = response.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(
            responses.len(),
            1,
            "Only one response should be sent before closing connection"
        );

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
    async fn test_update_block_template_success() {
        let template = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .expect("Failed to read block template file");

        let blocktemplate: BlockTemplate =
            serde_json::from_str(&template).expect("Failed to parse block template JSON");

        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (gbt_tx, gbt_rx) = mpsc::channel(1);
        let (notifier_tx, mut notifier_rx) = mpsc::channel(1);

        let mut server =
            StratumServer::new("127.0.0.1".to_string(), 12345, shutdown_rx, gbt_rx).await;

        let (ready_tx, ready_rx) = oneshot::channel();

        tokio::spawn(async move {
            let _ = server.start(Some(ready_tx), notifier_tx).await;
        });
        ready_rx.await.expect("Server should signal readiness");

        gbt_tx.send(blocktemplate).await.unwrap();

        notifier_rx
            .recv()
            .await
            .expect("Notifier should receive block template");
    }
}
