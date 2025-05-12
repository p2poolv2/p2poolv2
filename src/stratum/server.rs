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

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::{debug, info};

use crate::stratum::messages::StratumMessage;

// A struct to represent a Stratum server configuration
// This struct contains the port and address of the Stratum server
pub struct StratumServer {
    pub port: u16,
    pub address: String,
}

impl StratumServer {
    // A method to create a new Stratum server configuration
    pub fn new(port: u16, address: String) -> Self {
        Self { port, address }
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
            // Accept connections and process them
            let (stream, addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(e) => {
                    info!("Connection failed: {}", e);
                    continue;
                }
            };

            info!("New connection from: {}", addr);

            // Spawn a new task for each connection
            tokio::spawn(async move {
                let addr = match stream.peer_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        info!("Failed to get peer address: {}", e);
                        return;
                    }
                };
                let (reader, writer) = stream.into_split();
                let buf_reader = BufReader::new(reader);
                if let Err(e) = handle_connection(buf_reader, writer, addr).await {
                    info!("Error handling connection from {}: {}", addr, e);
                }
            });
        }
    }
}

#[allow(dead_code)]
async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    addr: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Create a LinesCodec with a maximum line length of 8KB
    // This prevents potential DoS attacks with extremely long lines
    const MAX_LINE_LENGTH: usize = 8 * 1024; // 8KB

    let mut framed = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE_LENGTH));

    // Process each line as it arrives
    while let Some(line_result) = framed.next().await {
        match line_result {
            Ok(line) => {
                // Process the received JSON message
                match serde_json::from_str::<StratumMessage>(&line) {
                    Ok(message) => {
                        info!("Received message from {}: {:?}", addr, message);

                        let response = handle_message(message).await;

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
            Err(e) => {
                // This could be a line length error or other I/O error
                info!("Error reading line from {}: {}", addr, e);
                break;
            }
        }
    }

    info!("Connection closed: {}", addr);
    Ok(())
}

#[allow(dead_code)]
// Handle incoming Stratum messages
// This function processes the incoming Stratum messages and returns a response
async fn handle_message(message: StratumMessage) -> Option<StratumMessage> {
    match message {
        StratumMessage::Request { id, method, params } => {
            debug!(
                "Handling request: id: {:?}, method: {:?}, params: {:?}",
                id, method, params
            );
            Some(StratumMessage::Response {
                id,
                result: Some(serde_json::json!("Success")),
                error: None,
            })
        }
        _ => None,
    }
}
#[cfg(test)]
mod stratum_server_tests {
    use std::time::Duration;
    use tokio::time::sleep;

    use super::*;

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
}
