use crate::config::NetworkConfig;
use crate::node::messages::Message;
use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// A counter that keeps track of recent timestamps.
#[derive(Debug)]
pub struct RecentCounter {
    timestamps: Mutex<VecDeque<Instant>>,
}

impl RecentCounter {
    fn new() -> Self {
        Self {
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    async fn increment(&self, window: Duration) -> bool {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock().await;

        // Remove timestamps outside the current window
        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);
        true
    }

    async fn count(&self, window: Duration) -> usize {
        let now = Instant::now();
        let mut timestamps = self.timestamps.lock().await;

        // Prune old entries
        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.len()
    }
}

/// Rate limiter to prevent DoS attacks by limiting the number of messages
#[derive(Debug, Default)]
pub struct RateLimiter {
    limits: Mutex<HashMap<PeerId, HashMap<u8, RecentCounter>>>,
    window: Duration,
}

impl RateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            window,
        }
    }

    // Get a numeric discriminant from the message variant
    fn get_message_discriminant(message: &Message) -> u8 {
        match message {
            Message::Workbase(_) => 0,
            Message::UserWorkbase(_) => 1,
            Message::MiningShare(_) => 2,
            Message::Inventory(_) => 3,
            Message::Transaction(_) => 4,
            Message::NotFound(_) => 5,
            Message::GetShareHeaders(_, _) => 6,
            Message::GetShareBlocks(_, _) => 7,
            Message::ShareHeaders(_) => 8,
            Message::ShareBlock(_) => 9,
            Message::GetData(_) => 10,
        }
    }

    /// Checks if the rate limit for a given peer and message type is exceeded.
    pub async fn check_rate_limit(
        &self,
        peer_id: &PeerId,
        message: Message,
        config: &NetworkConfig,
    ) -> bool {
        let max_allowed = match message {
            Message::Workbase(_) => config.max_workbase_per_second,
            Message::UserWorkbase(_) => config.max_userworkbase_per_second,
            Message::MiningShare(_) => config.max_miningshare_per_second,
            Message::Inventory(_) => config.max_inventory_per_second,
            Message::Transaction(_) => config.max_transaction_per_second,
            _ => return true,
        };

        // Get the discriminant value for the HashMap key
        let discriminant = Self::get_message_discriminant(&message);

        let mut limits = self.limits.lock().await;
        let peer_limits = limits.entry(*peer_id).or_insert_with(HashMap::new);
        let counter = peer_limits
            .entry(discriminant)
            .or_insert_with(RecentCounter::new);

        let current_count = counter.count(self.window).await;
        if current_count >= max_allowed as usize {
            warn!(
                "Rate limit exceeded for peer {} and message type {:?}",
                peer_id, message
            );
            false
        } else {
            counter.increment(self.window).await;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::shares::miner_message::{Gbt, MinerWorkbase};
    use libp2p::PeerId;

    fn test_config() -> NetworkConfig {
        NetworkConfig {
            listen_address: "".to_string(),
            dial_peers: vec![],
            enable_mdns: false,
            max_pending_incoming: 0,
            max_pending_outgoing: 0,
            max_established_incoming: 0,
            max_established_outgoing: 0,
            max_established_per_peer: 0,
            max_workbase_per_second: 2,
            max_userworkbase_per_second: 1,
            max_miningshare_per_second: 100,
            max_inventory_per_second: 100,
            max_transaction_per_second: 100,
            rate_limit_window_secs: 1,
        }
    }

    fn create_test_workbase() -> Message {
        // Create a minimal valid MinerWorkbase for testing
        let workbase = MinerWorkbase {
            workinfoid: 7460787496608071691,
            gbt: Gbt {
                capabilities: vec!["proposal".to_string()],
                version: 536870912,
                rules: vec![
                    "csv".to_string(),
                    "!segwit".to_string(),
                    "!signet".to_string(),
                    "taproot".to_string(),
                ],
                vbavailable: serde_json::Value::Object(serde_json::Map::new()),
                vbrequired: 0,
                previousblockhash:
                    "00000000eefbb1ae2a6ca9e826209f19d9a9f00c1ea443fa062debf89a32fcfc".to_string(),
                transactions: vec![],
                coinbaseaux: serde_json::Value::Object(serde_json::Map::new()),
                coinbasevalue: 5000000000,
                longpollid: "00000000eefbb1ae2a6ca9e826209f19d9a9f00c1ea443fa062debf89a32fcfc1"
                    .to_string(),
                target: "00000377ae000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                mintime: 1736687181,
                mutable: vec![
                    "time".to_string(),
                    "transactions".to_string(),
                    "prevblock".to_string(),
                ],
                noncerange: "00000000ffffffff".to_string(),
                sigoplimit: 80000,
                sizelimit: 4000000,
                weightlimit: 4000000,
                curtime: bitcoin::absolute::Time::from_consensus(1737100205).unwrap(),
                bits: "1e0377ae".to_string(),
                height: 99,
                signet_challenge: "51".to_string(),
                default_witness_commitment:
                    "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                        .to_string(),
                diff: 0.001126515290698186,
                ntime: bitcoin::absolute::Time::from_consensus(1737100205).unwrap(),
                bbversion: "20000000".to_string(),
                nbit: "1e0377ae".to_string(),
            },
            txns: vec![],
            merkles: vec![],
            coinb1:
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
                    .to_string(),
            coinb2: "ffffffff0100f2052a01000000".to_string(),
            coinb3: "".to_string(),
            header: "00000020fc2fa389bfde62a03f44eac1009f9a9df10962829ecaa6e21abbfeee00000000"
                .to_string(),
        };

        Message::Workbase(workbase)
    }

    #[tokio::test]
    async fn test_rate_limiter_sliding_window() {
        let config = test_config();
        let limiter = RateLimiter::new(Duration::from_secs(1));
        let peer_id = PeerId::random();

        // fill the window
        assert!(
            limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );
        assert!(
            limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );
        assert!(
            !limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );

        // wait for the window to slide
        tokio::time::sleep(Duration::from_secs(1)).await;

        // new messages in the next window
        assert!(
            limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );
        assert!(
            limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );
        assert!(
            !limiter
                .check_rate_limit(&peer_id, create_test_workbase(), &config)
                .await
        );
    }
}
