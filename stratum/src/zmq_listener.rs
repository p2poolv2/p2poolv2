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

use tracing::{debug, info};

#[allow(dead_code)]
const ZMQ_PUB_BLOCKHASH: &str = "hashblock"; // all messages
#[allow(dead_code)]
const ZMQ_CHANNEL_SIZE: usize = 1;

#[derive(Debug)]
pub struct ZmqError {
    pub message: String,
}
impl std::fmt::Display for ZmqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZMQ Error: {}", self.message)
    }
}
impl std::error::Error for ZmqError {}

#[allow(dead_code)]
pub trait ZmqListenerTrait {
    /// Starts the ZeroMQ subscriber socket.
    /// Asynchronously listens for messages on the specified address and topic, sending unit message to a channel.
    /// Returns the receiver end of the channel.
    fn start(&self, address: &str) -> Result<tokio::sync::mpsc::Receiver<()>, ZmqError>;
}

#[allow(dead_code)]
#[derive(Default)]
pub struct ZmqListener;

impl ZmqListenerTrait for ZmqListener {
    fn start(&self, address: &str) -> Result<tokio::sync::mpsc::Receiver<()>, ZmqError> {
        let context = zmq::Context::new();
        let socket = context.socket(zmq::SUB).map_err(|e| ZmqError {
            message: format!("Failed to create ZMQ socket: {:?}", e),
        })?;
        socket
            .set_subscribe(ZMQ_PUB_BLOCKHASH.as_bytes())
            .map_err(|e| ZmqError {
                message: format!("Failed to set ZMQ subscription: {}", e),
            })?;
        socket.connect(address).map_err(|e| ZmqError {
            message: format!("Failed to connect ZMQ socket: {}", e),
        })?;

        let (tx, rx) = tokio::sync::mpsc::channel::<()>(ZMQ_CHANNEL_SIZE);
        tokio::spawn(async move {
            loop {
                match socket.recv_msg(0) {
                    Ok(msg) => {
                        if msg.is_empty() {
                            continue; // Skip empty messages
                        }
                        tx.send(()).await.unwrap();
                    }
                    Err(e) => {
                        info!("Failed to receive ZMQ message: {}", e);
                    }
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;

    // Helper function to start a ZMQ publisher in a background thread
    fn start_zmq_publisher(address: &str, topic: &str, message: &[u8]) {
        let address = address.to_string();
        let topic = topic.as_bytes().to_vec();
        let message = message.to_vec();
        thread::spawn(move || {
            let ctx = zmq::Context::new();
            let publisher = ctx.socket(zmq::PUB).unwrap();
            publisher.bind(&address).unwrap();
            // Give the subscriber time to connect
            thread::sleep(Duration::from_millis(2000));
            let mut msg = topic.clone();
            msg.extend_from_slice(&message);
            publisher.send(msg, 0).unwrap();
        });
    }

    #[test]
    fn test_zmq_error_display() {
        let err = ZmqError {
            message: "test error".to_string(),
        };
        assert_eq!(format!("{}", err), "ZMQ Error: test error");
    }

    #[test_log::test]
    fn test_start_should_receive_message_when_zmq_socket_receieves_a_message() {
        let rt = Runtime::new().unwrap();
        let address = "tcp://127.0.0.1:28333";
        let topic = ZMQ_PUB_BLOCKHASH;
        let message = b"blockhashdata";

        // Use a latch to ensure the publisher is ready
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let publisher_thread = thread::spawn(move || {
            let ctx = zmq::Context::new();
            let publisher = ctx.socket(zmq::PUB).unwrap();
            publisher.bind(&address).unwrap();

            // Signal that we're ready
            ready_tx.send(()).unwrap();

            // Give the subscriber time to connect
            thread::sleep(Duration::from_millis(300));

            // Send the message
            let mut msg = topic.as_bytes().to_vec();
            msg.extend_from_slice(message);
            publisher.send(msg, 0).unwrap();

            // Keep the socket alive for a bit
            thread::sleep(Duration::from_millis(100));
        });

        // Wait for publisher to be ready
        ready_rx.recv().unwrap();

        let mut received = false;

        rt.block_on(async {
            let mut rx = ZmqListener
                .start(address)
                .expect("Should create zmq listener");

            // Wait for the publisher to send the message with longer timeout
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(_)) => {
                    received = true;
                }
                Ok(None) => panic!("Channel closed without receiving message"),
                Err(_) => panic!("Timeout waiting for ZMQ message"),
            }
        });
        assert!(received, "Message should have been received");
        rt.shutdown_background();
    }

    #[test]
    fn test_start_invalid_address() {
        let invalid_address = "invalid-address";
        let result = ZmqListener.start(invalid_address);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.message.contains("Failed to connect ZMQ socket"));
    }
}
