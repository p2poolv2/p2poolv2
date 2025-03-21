
use crate::config::CkPoolConfig;
use serde_json::Value;
use std::error::Error;
use std::thread;
use std::time::Duration;
use tracing::{error, info, debug};
use zmq;

// Define a trait for socket operations (used for testing)
trait MinerSocket {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error>;
}

// Implement the trait for ZMQ socket
impl MinerSocket for zmq::Socket {
    fn recv_string(&self) -> Result<Result<String, Vec<u8>>, zmq::Error> {
        self.recv_string(0) // Receive message without blocking
    }
}

// Function to create a new ZMQ subscriber socket
fn create_zmq_socket(config: &CkPoolConfig) -> Result<zmq::Socket, Box<dyn Error>> {
    let ctx = zmq::Context::new(); // Create new ZMQ context
    let socket = ctx.socket(zmq::SUB)?; // Create subscriber socket
    socket.connect(format!("tcp://{}:{}", config.host, config.port).as_str())?;
    socket.set_subscribe(b"")?; // Subscribe to all messages
    info!("Connected to ckpool at {}:{}", config.host, config.port);
    Ok(socket)
}

// Function to handle receiving shares from the ZMQ socket
fn receive_shares<S: MinerSocket>(
    socket: &S,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    loop {
        match socket.recv_string() {
            Ok(Ok(json_str)) => {
                debug!("Received JSON from ckpool: {}", json_str);
                match serde_json::from_str(&json_str) {
                    Ok(json_value) => {
                        if let Err(e) = tx.blocking_send(json_value) {
                            error!("Failed to send share to channel: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Invalid JSON received: {}", e);
                        return Err(Box::new(e));
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Message decode error: {:?}", e);
                return Err(Box::new(zmq::Error::EINVAL));
            }
            Err(e) => {
                error!("ZMQ receive error: {:?}. Retrying in 5 seconds...", e);
                thread::sleep(Duration::from_secs(5)); // Wait before retrying
            }
        }
    }
}

// Function to initialize the subscriber and handle reconnections
pub fn receive_from_ckpool(
    config: &CkPoolConfig,
    tx: tokio::sync::mpsc::Sender<Value>,
) -> Result<(), Box<dyn Error>> {
    loop {
        match create_zmq_socket(config) {
            Ok(socket) => {
                if let Err(e) = receive_shares(&socket, tx.clone()) {
                    error!("Error in receiving shares: {}. Reconnecting...", e);
                }
            }
            Err(e) => {
                error!("Failed to connect to ZMQ: {}. Retrying in 5 seconds...", e);
                thread::sleep(Duration::from_secs(5));
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
            Self { messages, current: 0 }
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
        
        tokio::spawn(async move {
            receive_shares(&mock_socket, tx).unwrap();
        });

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
        let mock_messages = vec![Ok(Err(vec![1, 2, 3]))]; // Simulate decode error
        let mock_socket = MockSocket::new(mock_messages);
        let result = receive_shares(&mock_socket, tx);
        assert!(result.is_err());
    }
}