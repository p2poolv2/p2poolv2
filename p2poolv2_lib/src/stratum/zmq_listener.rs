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

use tracing::info;

const BLOCK_HASH_SIZE: usize = 32;

#[allow(dead_code)]
const ZMQ_PUB_BLOCKHASH: &str = "hashblock"; // blockhash messages only
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
            message: format!("Failed to create ZMQ socket: {e:?}"),
        })?;
        socket
            .set_subscribe(ZMQ_PUB_BLOCKHASH.as_bytes())
            .map_err(|e| ZmqError {
                message: format!("Failed to set ZMQ subscription: {e}"),
            })?;
        socket.connect(address).map_err(|e| ZmqError {
            message: format!("Failed to connect ZMQ socket: {e}"),
        })?;

        let (tx, rx) = tokio::sync::mpsc::channel::<()>(ZMQ_CHANNEL_SIZE);
        std::thread::spawn(move || {
            // Create a dedicated runtime for this thread
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime in ZMQ listener thread");

            loop {
                match socket.recv_multipart(0) {
                    Ok(parts) => {
                        if parts.len() != 3 || parts[1].len() != BLOCK_HASH_SIZE {
                            continue; // Skip empty messages
                        }
                        if let Err(e) = rt.block_on(tx.send(())) {
                            info!("Failed to send ZMQ message: {}", e);
                            break; // Exit if the channel is closed
                        }
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
mod zmq_tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use zmq;

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

            // Send a multipart message compatible with recv_multipart
            let hash = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ];
            let seq = [0x01, 0x02, 0x03, 0x04];

            // Send the multipart message
            publisher
                .send_multipart(&[topic.as_bytes(), &hash[..], &seq[..]], 0)
                .unwrap();

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
        publisher_thread.join().unwrap();

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
