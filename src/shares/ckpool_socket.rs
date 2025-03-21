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
use serde_json::Value;
use std::error::Error;
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};
use zmq;
// Define a trait for the socket operations we need
// Use a trait to enable testing with a mock socket
trait MinerSocket {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error>;
}

// Implement the trait for the real ZMQ socket
impl MinerSocket for zmq::Socket {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.recv_string(0)
    }
}

// Function to create the real ZMQ socket
fn create_zmq_socket(config: &CkPoolConfig) -> Result<zmq::Socket, Box<dyn Error>> {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::SUB)?;
    socket.connect(format!("tcp://{}:{}", config.host, config.port).as_str())?;
    socket.set_subscribe(b"")?;
    info!("Connected to ckpool at {}:{}", config.host, config.port);
    Ok(socket)
}

// Generic function to receive shares from any ShareSocket
// This is generic to enable testing with a mock socket
fn receive_shares<S: MinerSocket>(
    socket: &S,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    loop {
        match socket.recv_string() {
            Ok(Ok(json_str)) => {
                tracing::debug!("Received json from ckpool: {}", json_str);
                match serde_json::from_str(&json_str) {
                    Ok(json_value) => {
                        if let Err(e) = tx.blocking_send(json_value) {
                            error!("Failed to send share to channel: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse JSON: {}", e);
                        return Err(Box::new(e));
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Failed to decode message: {:?}", e);
                return Err(Box::new(zmq::Error::EINVAL));
            }
            Err(e) => {
                error!("Failed to receive message: {:?}", e);
                return Err(Box::new(e));
            }
        }
    }
}

// A receive function that clients use to receive shares
// This function creates the ZMQ socket and passes it to the receive_shares function
pub fn receive_from_ckpool(
    config: &CkPoolConfig,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    let mut backoff_duration = Duration::from_millis(100); // Starting with 100ms

    loop {
        match create_zmq_socket(config) {
            Ok(socket) => {
                if let Err(e) = receive_shares(&socket, tx.clone()) {
                    error!("Error in receiving shares: {}. Reconnecting...", e);
                    thread::sleep(backoff_duration); // Exponential backoff
                    backoff_duration = backoff_duration * 2; // Double the backoff time
                }
            }
            Err(e) => {
                error!(
                    "Failed to connect to ZMQ: {}. Retrying in {}ms...",
                    e,
                    backoff_duration.as_millis()
                );
                thread::sleep(backoff_duration); // Exponential backoff
                backoff_duration = backoff_duration * 2; // Double the backoff time
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    // Mock socket for testing
    struct MockSocket {
        messages: Vec<Result<Result<String, Vec<u8>>, zmq::Error>>,
        current: usize,
    }

    impl MockSocket {
        fn new(messages: Vec<Result<Result<String, Vec<u8>>, zmq::Error>>) -> Self {
            Self {
                messages,
                current: 0,
            }
        }
    }

    impl MinerSocket for MockSocket {
        fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
            if self.current >= self.messages.len() {
                panic!("No more mock messages");
            }
            self.messages[self.current].clone()
        }
    }

    #[tokio::test]
    async fn test_receive_valid_json() {
        let (tx, mut rx) = mpsc::channel(100);

        let mock_messages = vec![Ok(Ok(r#"{"share": "test", "value": 123}"#.to_string()))];
        let mock_socket = MockSocket::new(mock_messages);

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

        let mock_messages = vec![Ok(Ok("invalid json".to_string()))];
        let mock_socket = MockSocket::new(mock_messages);

        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_receive_decode_error() {
        let (tx, _rx) = mpsc::channel(100);

        let mock_messages = vec![
            Ok(Err(vec![1, 2, 3])), // Simulating decode error
        ];
        let mock_socket = MockSocket::new(mock_messages);

        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn test_reconnect_logic() {
        let (tx, mut rx) = mpsc::channel(100);

        // Mock socket to simulate a failure and then success
        let mock_messages = vec![
            Ok(Err(vec![1, 2, 3])),                                   // Simulate failure
            Ok(Ok(r#"{"share": "test", "value": 123}"#.to_string())), // Simulate success
        ];

        let mock_socket = MockSocket::new(mock_messages);

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
}
