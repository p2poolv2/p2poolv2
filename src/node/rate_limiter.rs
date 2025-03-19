use crate::config::NetworkConfig;
use crate::node::messages::Message;
use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

/// Represents the type of message for rate limiting purposes.
///
/// We use a separate enum from `messages::Message` to have explicit control to avoid accidentally applying a rate limit to a new message type added in the future.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum MessageType {
    Workbase,
    UserWorkbase,
    MiningShare,
    Inventory,
    Transaction,
    Other,
}

impl From<&Message> for MessageType {
    fn from(msg: &Message) -> Self {
        match msg {
            Message::Workbase(_) => MessageType::Workbase,
            Message::UserWorkbase(_) => MessageType::UserWorkbase,
            Message::MiningShare(_) => MessageType::MiningShare,
            Message::Inventory(_) => MessageType::Inventory,
            Message::Transaction(_) => MessageType::Transaction,
            _ => MessageType::Other,
        }
    }
}

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
    limits: Mutex<HashMap<PeerId, HashMap<MessageType, RecentCounter>>>,
    window: Duration,
}

impl RateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Checks if the rate limit for a given peer and message type is exceeded.
    pub async fn check_rate_limit(
        &self,
        peer_id: &PeerId,
        message_type: MessageType,
        config: &NetworkConfig,
    ) -> bool {
        let max_allowed = match message_type {
            MessageType::Workbase => config.max_workbase_per_second,
            MessageType::UserWorkbase => config.max_userworkbase_per_second,
            MessageType::MiningShare => config.max_miningshare_per_second,
            MessageType::Inventory => config.max_inventory_per_second,
            MessageType::Transaction => config.max_transaction_per_second,
            MessageType::Other => return true,
        };

        let mut limits = self.limits.lock().await;
        let peer_limits = limits.entry(*peer_id).or_insert_with(HashMap::new);
        let counter = peer_limits
            .entry(message_type.clone())
            .or_insert_with(RecentCounter::new);

        let current_count = counter.count(self.window).await;
        if current_count >= max_allowed as usize {
            warn!(
                "Rate limit exceeded for peer {} and message type {:?}",
                peer_id, message_type
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

    #[tokio::test]
    async fn test_rate_limiter_sliding_window() {
        let config = test_config();
        let limiter = RateLimiter::new(Duration::from_secs(1));
        let peer_id = PeerId::random();

        // fill the window
        assert!(
            limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );
        assert!(
            limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );
        assert!(
            !limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );

        // wait for the window to slide
        tokio::time::sleep(Duration::from_secs(1)).await;

        // new messages in the next window
        assert!(
            limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );
        assert!(
            limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );
        assert!(
            !limiter
                .check_rate_limit(&peer_id, MessageType::Workbase, &config)
                .await
        );
    }
}
