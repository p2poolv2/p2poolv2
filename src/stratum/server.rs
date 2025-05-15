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

use crate::stratum::message_handler::handle_message;
use crate::stratum::messages::Request;
use crate::stratum::session::Session;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::info;

// A struct to represent a Stratum server configuration
// This struct contains the port and address of the Stratum server
pub struct StratumServer {
    pub port: u16,
    pub address: String,
    connections: Arc<Mutex<HashMap<std::net::SocketAddr, oneshot::Sender<()>>>>,
    shutdown_flag: Arc<Mutex<bool>>,
}

impl StratumServer {
    // A method to create a new Stratum server configuration
    pub fn new(port: u16, address: String) -> Self {
        Self {
            port,
            address,
            connections: Arc::new(Mutex::new(HashMap::new())),
            shutdown_flag: Arc::new(Mutex::new(false)),
        }
    }

    // A method to start the Stratum server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting Stratum server at {}:{}", self.address, self.port);

        let bind_address = format!("{}:{}", self.address, self.port);
        let listener = TcpListener::bind(&bind_address)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", bind_address, e))?;

        info!("Stratum server listening on {}", bind_address);

        loop {
            // Check if shutdown was requested
            if *self.shutdown_flag.lock().await {
                break;
            }

            // Accept connections and process them
            let (stream, addr) = match listener.accept().await {
                Ok(connection) => {
                    if *self.shutdown_flag.lock().await {
                        info!("Server is shutting down, not accepting new connections");
                        break;
                    }
                    info!("Accepted connection");
                    connection
                }
                Err(e) => {
                    info!("Connection failed: {}", e);
                    continue;
                }
            };

            info!("New connection from: {}", addr);

            // Clone Arc references for the new task
            let connections = Arc::clone(&self.connections);

            // Spawn a new task for each connection
            tokio::spawn(async move {
                let addr = match stream.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        info!("Failed to get peer address: {}", e);
                        return;
                    }
                };

                // Register the connection
                let shutdown_signal = register_connection(connections.clone(), addr).await;

                let (reader, writer) = stream.into_split();
                let buf_reader = BufReader::new(reader);

                // Handle the connection with graceful shutdown support
                if let Err(e) = handle_connection(buf_reader, writer, addr, shutdown_signal).await {
                    info!("Error handling connection from {}: {}", addr, e);
                }

                // Remove the connection when done
                remove_connection(connections, addr).await;
            });
        }

        Ok(())
    }

    // A method to shut down the Stratum server
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Shutting down Stratum server at {}:{}",
            self.address, self.port
        );

        // Signal all connections to terminate
        {
            // Set shutdown flag to stop accepting new connections
            *self.shutdown_flag.lock().await = true;

            // Send shutdown signal to all active connections
            let mut connections = self.connections.lock().await;
            for (addr, sender) in connections.drain() {
                if sender.send(()).is_err() {
                    info!("Connection to {} already closed", addr);
                }
            }
        }

        // Wait for a short period to allow graceful shutdown
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        info!("Stratum server shutdown complete");

        Ok(())
    }
}

// Register a new connection
async fn register_connection(
    connections: Arc<Mutex<HashMap<std::net::SocketAddr, oneshot::Sender<()>>>>,
    addr: std::net::SocketAddr,
) -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    let mut connections = connections.lock().await;
    connections.insert(addr, tx);
    rx
}

// Remove a connection
async fn remove_connection(
    connections: Arc<Mutex<HashMap<std::net::SocketAddr, oneshot::Sender<()>>>>,
    addr: std::net::SocketAddr,
) {
    let mut connections = connections.lock().await;
    connections.remove(&addr);
}

/// Handles a single connection to the Stratum server.
/// This function reads lines from the connection, processes them,
/// and sends responses back to the client.
/// The function handles the session data for each connection as required for the Stratum protocol.
#[allow(dead_code)]
async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    addr: std::net::SocketAddr,
    mut shutdown_signal: oneshot::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>>
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
            // Handle shutdown signal
            _ = &mut shutdown_signal => {
                info!("Received shutdown signal for connection: {}", addr);
                break;
            }

            // Process incoming messages
            line_result = framed.next() => {
                match line_result {
                    Some(Ok(line)) => {
                        // Process the received JSON message
                        match serde_json::from_str::<Request>(&line) {
                            Ok(message) => {
                                info!("Received message from {}: {:?}", addr, message);

                                let response = handle_message(message, session).await;

                                if let Some(response) = response {
                                    let response_json = serde_json::to_string(&response)?;
                                    writer
                                        .write_all(format!("{}\n", response_json).as_bytes())
                                        .await?;
                                    writer.flush().await?;
                                }
                            }
                            Err(e) => {
                                info!("Error parsing message from {}: {}", addr, e);
                                info!("Raw message: {}", line);
                            }
                        }
                    }
                    Some(Err(e)) => {
                        // This could be a line length error or other I/O error
                        info!("Error reading line from {}: {}", addr, e);
                        break;
                    }
                    None => {
                        // End of stream
                        break;
                    }
                }
            }
        }
    }

    info!("Connection closed: {}", addr);
    Ok(())
}

#[cfg(test)]
mod stratum_server_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_create_and_start_server() {
        // Create a server with test parameters
        let server = StratumServer::new(12345, "127.0.0.1".to_string());

        // Verify the server was created with the correct parameters
        assert_eq!(server.port, 12345);
        assert_eq!(server.address, "127.0.0.1");

        // Start the server in a separate task so we can shut it down
        let server_handle = tokio::spawn(async move {
            // We'll ignore errors here since we'll forcibly shut down the server
            let _ = server.start().await;
        });

        // Give the server a moment to start
        sleep(Duration::from_millis(100)).await;

        // We can't easily assert much more without connecting to the server,
        // but we can at least verify the server task is still running
        assert!(!server_handle.is_finished());

        // Shut down the server task
        server_handle.abort();

        // Wait for the task to complete
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_handle_connection() {
        // Mock data
        let request = Request::new_subscribe(Some(1), "agent".to_string(), "1.0".to_string(), None);
        let input_string = serde_json::to_string(&request).unwrap() + "\n";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Setup reader and writer
        let reader = input_string.as_bytes();
        let mut writer = Vec::new();

        // Run the handler
        let result = handle_connection(reader, &mut writer, addr, oneshot::channel().1).await;

        // Verify results
        assert!(
            result.is_ok(),
            "handle_connection should not return an error"
        );

        // Check that response was written
        let response = String::from_utf8_lossy(&writer);
        println!("Response: {}", response);
        assert!(
            response.contains("\"result\":true"),
            "Response should contain success result as true"
        );
        assert!(
            response.ends_with("\n"),
            "Response should end with a newline"
        );
    }

    #[tokio::test]
    async fn test_handle_connection_invalid_json() {
        // Invalid JSON input
        let input = b"not valid json\n";
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Setup reader and writer
        let reader = &input[..];
        let mut writer = Vec::new();

        // Run the handler
        let result = handle_connection(reader, &mut writer, addr, oneshot::channel().1).await;

        // Verify results
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

        // Run the handler
        let result = handle_connection(input, &mut writer, addr, oneshot::channel().1).await;

        // Verify results - should handle the error gracefully
        assert!(
            result.is_ok(),
            "handle_connection should handle line-too-long gracefully"
        );

        // No response should be written for a line that's too long
        assert!(
            writer.is_empty(),
            "No response should be written for too-long lines"
        );
    }
}
