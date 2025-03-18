use crate::config::NetworkConfig;
use crate::node::messages::Message;
use libp2p::PeerId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::warn;

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

#[derive(Debug, Clone)]
pub struct RecentCounter {
    count: u32,
    last_update: Instant,
}

impl RecentCounter {
    fn new() -> Self {
        Self {
            count: 0,
            last_update: Instant::now(),
        }
    }

    fn increment(&mut self) {
        self.count += 1;
        self.last_update = Instant::now();
    }

    fn reset(&mut self) {
        self.count = 0;
        self.last_update = Instant::now();
    }

    fn count(&self, window: Duration) -> u32 {
        if self.last_update.elapsed() > window {
            // If the last update was too long ago, treat as 0
            0
        } else {
            self.count
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimiter {
    limits: HashMap<PeerId, HashMap<MessageType, RecentCounter>>,
    window: Duration,
}

impl RateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            limits: HashMap::new(),
            window,
        }
    }

    pub fn check_rate_limit(
        &mut self,
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
            MessageType::Other => return true, // Don't rate limit other messages for now.
        };

        let peer_limits = self.limits.entry(*peer_id).or_insert_with(HashMap::new);
        let counter = peer_limits
            .entry(message_type.clone())
            .or_insert_with(RecentCounter::new);

        if counter.count(self.window) >= max_allowed {
            warn!(
                "Rate limit exceeded for peer {} and message type {:?}",
                peer_id, message_type
            );
            false
        } else {
            counter.increment();
            true
        }
    }

    pub fn decay(&mut self) {
        let now = Instant::now();
        for peer_limits in self.limits.values_mut() {
            for counter in peer_limits.values_mut() {
                if now.duration_since(counter.last_update) > self.window {
                    counter.reset();
                }
            }
        }
    }
}
