use libp2p::PeerId;
use p2poolv2_lib::node::actor::NodeHandle;
use std::error::Error;
use std::time::{Duration, Instant};

/// Trait for querying peers, allowing for easier testing.
pub trait PeerQuerier: Send + Sync {
    async fn get_peers(&self) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>>;
}

impl PeerQuerier for NodeHandle {
    async fn get_peers(&self) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>> {
        self.get_peers().await
    }
}

/// Waits for an expected number of peers or returns an error
pub async fn wait_for_peers<T: PeerQuerier>(
    handle: &T,
    expected: usize,
    timeout: Duration,
) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>> {
    let start = Instant::now();
    loop {
        let peers = handle.get_peers().await?;
        if peers.len() >= expected {
            return Ok(peers);
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "Timed out waiting for peers (expected {expected}, got {}): {peers:?}",
                peers.len()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use std::io;
    use std::sync::Mutex;

    struct MockPeerQuerier {
        responses: Mutex<Vec<Result<Vec<PeerId>, String>>>,
    }

    impl PeerQuerier for MockPeerQuerier {
        async fn get_peers(&self) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(vec![])
            } else {
                responses
                    .remove(0)
                    .map_err(|e| Box::new(io::Error::new(io::ErrorKind::Other, e)).into())
            }
        }
    }

    fn create_test_peer_ids(count: usize) -> Vec<PeerId> {
        (0..count).map(|_| PeerId::random()).collect()
    }

    #[tokio::test]
    async fn test_wait_for_peers_immediate_success() {
        let peers = create_test_peer_ids(3);
        let mock = MockPeerQuerier {
            responses: Mutex::new(vec![Ok(peers.clone())]),
        };

        let result = wait_for_peers(&mock, 3, Duration::from_secs(5))
            .await
            .expect("Should succeed");
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_wait_for_peers_eventual_success() {
        let peers_1 = create_test_peer_ids(1);
        let peers_2 = create_test_peer_ids(2);
        let mock = MockPeerQuerier {
            responses: Mutex::new(vec![Ok(peers_1), Ok(peers_2)]),
        };

        let result = wait_for_peers(&mock, 2, Duration::from_secs(5))
            .await
            .expect("Should eventually succeed");
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_wait_for_peers_get_peers_error() {
        let mock = MockPeerQuerier {
            responses: Mutex::new(vec![Err("Connection error".to_string())]),
        };

        let result = wait_for_peers(&mock, 1, Duration::from_secs(1)).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Connection error"));
    }

    #[tokio::test]
    async fn test_wait_for_peers_timeout() {
        let mock = MockPeerQuerier {
            responses: Mutex::new(vec![Ok(vec![])]),
        };

        let result = wait_for_peers(&mock, 1, Duration::from_millis(50)).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Timed out waiting for peers")
        );
    }
}
