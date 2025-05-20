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

use crate::config::CkPoolConfig;
#[cfg(test)]
use mockall::automock;
use serde_json::Value;
use std::error::Error;
use std::thread;
use std::time::Duration;
use tracing::{debug, info};
use zmq;

/// The delay between reconnect attempts
const RECONNECT_DELAY: u64 = 1;
/// The maximum delay between reconnect attempts
const MAX_RECONNECT_DELAY: u64 = 60;

/// Trait for zmq socket operations. We implement this for the zmq::Socket type and mock it for testing
#[cfg_attr(any(test), automock)]
pub(crate) trait ZMQSocketTrait {
    fn recv_string(&self, flags: i32) -> Result<Result<String, Vec<u8>>, zmq::Error>;
    fn connect(&self, endpoint: &str) -> Result<(), zmq::Error>;
    fn set_subscribe(&self, topic: &[u8]) -> Result<(), zmq::Error>;
}

impl ZMQSocketTrait for zmq::Socket {
    fn recv_string(&self, flags: i32) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.recv_string(flags)
    }
    fn connect(&self, endpoint: &str) -> Result<(), zmq::Error> {
        self.connect(endpoint)
    }
    fn set_subscribe(&self, topic: &[u8]) -> Result<(), zmq::Error> {
        self.set_subscribe(topic)
    }
}

/// Trait for ckpool socket operations.
/// This helps us mock the CkPoolSocket for testing.
#[cfg_attr(any(test), automock)]
pub(crate) trait CkPoolSocketTrait {
    fn connect(&self) -> Result<(), zmq::Error>;
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error>;
}

/// Concrete implementation of the CkPoolSocket trait
pub(crate) struct CkPoolSocket<S: ZMQSocketTrait> {
    config: CkPoolConfig,
    socket: S,
}

pub(crate) fn create_zmq_socket() -> Result<zmq::Socket, Box<dyn Error>> {
    let ctx = zmq::Context::new();
    let socket = ctx.socket(zmq::SUB)?;
    Ok(socket)
}

impl CkPoolSocket<zmq::Socket> {
    pub(crate) fn new(config: CkPoolConfig, socket: zmq::Socket) -> Result<Self, Box<dyn Error>> {
        Ok(CkPoolSocket { config, socket })
    }
}

impl<S: ZMQSocketTrait> CkPoolSocketTrait for CkPoolSocket<S> {
    /// Connect to the ckpool socket
    /// We use exponential backoff with a maximum delay of 60 seconds
    fn connect(&self) -> Result<(), zmq::Error> {
        let mut retry_delay = Duration::from_secs(RECONNECT_DELAY);
        let max_delay = Duration::from_secs(MAX_RECONNECT_DELAY);
        let endpoint = format!("tcp://{}:{}", self.config.host, self.config.port);

        loop {
            match self.socket.connect(&endpoint) {
                Ok(_) => {
                    info!("Connected to ckpool at {}", endpoint);
                    break;
                }
                Err(e) => {
                    info!(
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

    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.socket.recv_string(0)
    }
}

/// Generic function to receive shares from any ShareSocket
/// This is generic to enable testing with a mock socket
/// We don't need a reconnect logic here as ZMQ sockets automatically reconnect
fn receive_shares<S: CkPoolSocketTrait>(
    socket: &S,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    if let Ok(Ok(json_str)) = socket.recv_string() {
        info!("Mining message received. Length {}", json_str.len());
        match serde_json::from_str(&json_str) {
            Ok(json_value) => {
                // Send the parsed JSON to the channel
                if let Err(e) = tx.blocking_send(json_value) {
                    debug!("Failed to send share to channel: {}", e);
                }
            }
            Err(e) => {
                // Handle JSON parsing error
                debug!("Failed to parse JSON: {}. JSON content: {:?}", e, json_str);
            }
        }
    }
    Ok(())
}

// A receive function that clients use to receive shares
// This function creates the ZMQ socket and passes it to the receive_shares function
pub(crate) fn start_receiving_from_ckpool<S: ZMQSocketTrait>(
    socket: CkPoolSocket<S>,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let _ = receive_shares(&socket, tx.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::eq;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
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
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_receive_decode_error() {
        let (tx, _rx) = mpsc::channel(100);

        let mut mock_socket = MockCkPoolSocketTrait::default();
        mock_socket
            .expect_recv_string()
            .returning(|| Ok(Ok("invalid json".to_string())));

        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ckpool_socket_connect_success() {
        // Create a mock ZMQSocketTrait
        let mut mock_zmq_socket = MockZMQSocketTrait::new();

        // Set up expectations for the mock
        mock_zmq_socket
            .expect_connect()
            .times(1)
            .with(eq("tcp://localhost:3333"))
            .returning(|_| Ok(()));

        mock_zmq_socket
            .expect_set_subscribe()
            .times(1)
            .returning(|_| Ok(()));

        // Create a CkPoolConfig with test values
        let config = CkPoolConfig {
            host: "localhost".to_string(),
            port: 3333,
        };

        // Create a CkPoolSocket with the mock
        let ckpool_socket = CkPoolSocket {
            config,
            socket: mock_zmq_socket,
        };

        // Call connect and verify it succeeds
        let result = ckpool_socket.connect();
        assert!(
            result.is_ok(),
            "Expected successful connection, but got error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_ckpool_socket_connect_retry_success() {
        // Create a mock ZMQSocketTrait
        let mut mock_zmq_socket = MockZMQSocketTrait::new();

        // Set up expectations for the mock
        // First attempt fails
        mock_zmq_socket
            .expect_connect()
            .times(1)
            .with(eq("tcp://localhost:3333"))
            .returning(|_| Err(zmq::Error::ECONNREFUSED));

        // Second attempt succeeds
        mock_zmq_socket
            .expect_connect()
            .times(1)
            .with(eq("tcp://localhost:3333"))
            .returning(|_| Ok(()));

        mock_zmq_socket
            .expect_set_subscribe()
            .times(1)
            .returning(|_| Ok(()));

        // Create a CkPoolConfig with test values
        let config = CkPoolConfig {
            host: "localhost".to_string(),
            port: 3333,
        };

        // Create a CkPoolSocket with the mock
        let ckpool_socket = CkPoolSocket {
            config,
            socket: mock_zmq_socket,
        };

        // Call connect and verify it succeeds despite the initial failure
        let result = ckpool_socket.connect();
        assert!(
            result.is_ok(),
            "Expected successful connection after retry, but got error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_start_receiving_from_ckpool_success() {
        let (tx, mut rx) = mpsc::channel(100);
        let tx_clone = tx.clone();

        // Create a flag to track if we've already returned a value
        let has_returned = Arc::new(AtomicBool::new(false));
        let has_errored = Arc::new(AtomicBool::new(false));
        let has_returned_clone = has_returned.clone();

        // Create a mock ZMQSocketTrait
        let mut mock_zmq_socket = MockZMQSocketTrait::default();
        mock_zmq_socket.expect_recv_string().returning(move |_| {
            // First time: return an error, next time a value and then block indefinitely
            if !has_returned.load(Ordering::SeqCst) {
                if !has_errored.load(Ordering::SeqCst) {
                    has_errored.store(true, Ordering::SeqCst);
                    Err(zmq::Error::ETERM)
                } else {
                    has_returned.store(true, Ordering::SeqCst);
                    Ok(Ok(r#"{"share": "test1", "value": 123}"#.to_string()))
                }
            } else {
                // Subsequent calls: block indefinitely
                std::thread::sleep(Duration::from_secs(3600)); // Sleep for an hour (effectively blocking)
                Ok(Ok(
                    r#"{"share": "never_returned", "value": 999}"#.to_string()
                ))
            }
        });

        // Create a CkPoolConfig with test values
        let config = CkPoolConfig {
            host: "localhost".to_string(),
            port: 3333,
        };

        // Create a CkPoolSocket with the mock
        let ckpool_socket = CkPoolSocket {
            config,
            socket: mock_zmq_socket,
        };

        // Create a mock implementation of CkPoolSocketTrait for the socket
        let mut mock_ckpool_socket = MockCkPoolSocketTrait::default();
        mock_ckpool_socket.expect_recv_string().returning(move || {
            // First time: return a value
            if !has_returned_clone.load(Ordering::SeqCst) {
                has_returned_clone.store(true, Ordering::SeqCst);
                Ok(Ok(r#"{"share": "test1", "value": 123}"#.to_string()))
            } else {
                // Subsequent calls: block indefinitely
                std::thread::sleep(Duration::from_secs(3600)); // Sleep for an hour (effectively blocking)
                Ok(Ok(
                    r#"{"share": "never_returned", "value": 999}"#.to_string()
                ))
            }
        });

        // Spawn the start_receiving_from_ckpool function in a separate task
        let _handle = thread::spawn(move || {
            let result = start_receiving_from_ckpool(ckpool_socket, tx_clone);
            assert!(result.is_ok());
        });

        // Receive the first message from the channel
        if let Some(value) = rx.recv().await {
            assert_eq!(value["share"], "test1");
            assert_eq!(value["value"], 123);
        } else {
            panic!("Expected to receive first message");
        }

        // Use tokio's timeout to ensure the test doesn't run indefinitely
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            // Just wait for the timeout to expire
            tokio::time::sleep(Duration::from_millis(200)).await;
        })
        .await;

        drop(tx);
    }
}
