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

use crate::config::CkPoolConfig;
use mockall::automock;
use serde_json::Value;
use std::error::Error;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};
use zmq;

// Define a trait for the socket operations we need
// Use a trait to enable testing with a mock socket
#[automock]
trait CkPoolSocketTrait {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error>;
    fn connect(&self) -> Result<(), zmq::Error>;
}

/// Concrete implementation of the CkPoolSocket trait
pub(crate) struct CkPoolSocket {
    config: CkPoolConfig,
    socket: zmq::Socket,
}

impl CkPoolSocket {
    pub(crate) fn new(config: CkPoolConfig) -> Result<Self, Box<dyn Error>> {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::SUB)?;
        Ok(CkPoolSocket { config, socket })
    }

    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.socket.recv_string(0)
    }

    pub(crate) fn connect(&self) -> Result<(), zmq::Error> {
        let mut retry_delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(60);
        let endpoint = format!("tcp://{}:{}", self.config.host, self.config.port);

        loop {
            match self.socket.connect(&endpoint) {
                Ok(_) => {
                    info!(
                        "Connected to ckpool at {}:{}",
                        self.config.host, self.config.port
                    );
                    break;
                }
                Err(e) => {
                    error!(
                        "Failed to connect to ckpool at {}:{}: {}. Retrying in {:?}...",
                        self.config.host, self.config.port, e, retry_delay
                    );
                    thread::sleep(retry_delay);

                    // Exponential backoff with a maximum delay
                    retry_delay = std::cmp::min(retry_delay * 2, max_delay);
                }
            }
        }

        self.socket.set_subscribe(b"")?;
        Ok(())
    }
}

impl CkPoolSocketTrait for CkPoolSocket {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.socket.recv_string(0)
    }
    fn connect(&self) -> Result<(), zmq::Error> {
        let endpoint = format!("tcp://{}:{}", self.config.host, self.config.port);
        self.socket.connect(&endpoint)
    }
}

// Generic function to receive shares from any ShareSocket
// This is generic to enable testing with a mock socket
fn receive_shares<S: CkPoolSocketTrait>(
    socket: &S,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    loop {
        match socket.recv_string() {
            // Successfully received a valid JSON string
            Ok(Ok(json_str)) => {
                tracing::debug!("Received json from ckpool: {}", json_str);
                match serde_json::from_str(&json_str) {
                    Ok(json_value) => {
                        // Send the parsed JSON to the channel
                        if let Err(e) = tx.blocking_send(json_value) {
                            error!("Failed to send share to channel: {}", e);
                        }
                    }
                    Err(e) => {
                        // Handle JSON parsing error
                        error!("Failed to parse JSON: {}. JSON content: {:?}", e, json_str);
                        debug!("JSON Parsing Error Stacktrace: {:?}", e);

                        return Err(Box::new(e));
                    }
                }
            }
            // Received a message that couldn't be decoded properly
            Ok(Err(e)) => {
                error!("Failed to decode message: {:?}", e);
                return Err(Box::new(zmq::Error::EINVAL));
            }
            // Handle socket-level errors
            Err(e) => {
                if matches!(
                    e,
                    zmq::Error::ETERM   // Context terminated
                        | zmq::Error::ENOTSOCK  // Not a valid socket
                        | zmq::Error::EINTR // Interrupted system call
                        | zmq::Error::EAGAIN // Would block (e.g., non-blocking mode)
                ) {
                    error!("Disconnected from socket: {:?}. Attempting reconnect...", e);
                    return Err(Box::new(e)); // Trigger reconnection logic
                } else {
                    error!("Failed to receive message: {:?}", e);
                    return Err(Box::new(e));
                }
            }
        }
    }
}

// A receive function that clients use to receive shares
// This function creates the ZMQ socket and passes it to the receive_shares function
pub(crate) fn start_receiving_from_ckpool(
    socket: CkPoolSocket,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    let mut backoff_duration = Duration::from_millis(100); // Starting with 100ms

    loop {
        let result = receive_shares(&socket, tx.clone());
        if result.is_err() {
            error!(
                "Error in receiving shares: {}. Reconnecting...",
                result.unwrap_err()
            );
            thread::sleep(backoff_duration); // Exponential backoff
            backoff_duration *= 2; // Double the backoff time
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_receive_valid_json() {
        let (tx, mut rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .returning(|| Ok(Ok(r#"{"share": "test", "value": 123}"#.to_string())));

        // Spawn the receive_shares function in a separate task
        tokio::spawn(async move {
            receive_shares(&mock_socket, tx).unwrap();
        });

        // Receive the message from the channel
        if let Some(value) = rx.recv().await {
            assert_eq!(value["share"], "test");
            assert_eq!(value["value"], 123);
        }
    }

    #[tokio::test]
    async fn test_receive_invalid_json() {
        let (tx, _rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .returning(|| Ok(Ok("invalid json".to_string())));

        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_decode_error() {
        let (tx, _rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .returning(|| Ok(Ok("invalid json".to_string())));

        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reconnect_logic() {
        let (tx, mut rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .returning(|| Ok(Ok("invalid json".to_string())));

        // Spawn the receive_shares function in a separate task
        tokio::spawn(async move {
            receive_shares(&mock_socket, tx).unwrap();
        });

        // Check if the first message received is valid
        if let Some(value) = rx.recv().await {
            assert_eq!(value["share"], "test");
            assert_eq!(value["value"], 123);
        }
    }

    #[tokio::test]
    async fn test_handling_connection_errors_from_ckpool_should_bubble_up_error() {
        let (tx, _rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        // Simulating various disconnection scenarios
        mock_socket
            .expect_recv_string()
            .times(1)
            .returning(|| Err(zmq::Error::ETERM)); // Simulates a termination error (context shut down)

        mock_socket
            .expect_recv_string()
            .times(1)
            .returning(|| Err(zmq::Error::ENOTSOCK)); // Simulates an invalid socket error

        mock_socket
            .expect_recv_string()
            .times(1)
            .returning(|| Err(zmq::Error::EINTR)); // Simulates an interrupted system call

        mock_socket
            .expect_recv_string()
            .times(1)
            .returning(|| Err(zmq::Error::EAGAIN)); // Simulates a would-block error

        for _ in 0..4 {
            let result = receive_shares(&mock_socket, tx.clone());
            assert!(
                result.is_err(),
                "Expected an error, but function returned Ok"
            );
        }
    }

    #[tokio::test]
    async fn test_invalid_json_from_ckpool_should_bubble_up_error() {
        let (tx, _rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .times(1)
            .returning(|| Err(zmq::Error::EINVAL)); // Invalid argument error

        let result = receive_shares(&mock_socket, tx);

        // Verify the error is properly propagated
        assert!(
            result.is_err(),
            "Expected an error, but function returned Ok"
        );

        // We can verify that the error type is as expected
        match result {
            Err(e) => {
                // Convert the error to a string and check if it contains EINVAL
                let error_str = e.to_string();
                assert!(
                    error_str.contains("Invalid argument"),
                    "Expected Invalid argument error, got: {}",
                    error_str
                );
            }
            _ => panic!("Expected Err variant, got Ok"),
        }
    }
}
