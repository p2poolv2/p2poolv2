// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

/// Manages reconnection attempts to configured dial_peers with exponential backoff.
///
/// When a peer disconnects or a dial fails, the reconnector schedules a retry
/// with increasing delays (capped at RECONNECT_MAX_DELAY_SECS). On successful
/// connection, the backoff resets for that peer.
use std::time::Duration;

use libp2p::Multiaddr;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Initial delay before first reconnect attempt
const RECONNECT_INITIAL_DELAY_SECS: u64 = 5;

/// Maximum delay between reconnect attempts (backoff cap)
const RECONNECT_MAX_DELAY_SECS: u64 = 300;

/// How often the reconnect check runs
const RECONNECT_CHECK_INTERVAL_SECS: u64 = 5;

/// Backoff state for a single dial_peer address
struct PeerBackoff {
    address: Multiaddr,
    current_delay: Duration,
    next_attempt_at: Instant,
}

impl PeerBackoff {
    fn new(address: Multiaddr) -> Self {
        Self {
            address,
            current_delay: Duration::from_secs(RECONNECT_INITIAL_DELAY_SECS),
            next_attempt_at: Instant::now(),
        }
    }

    fn is_ready(&self) -> bool {
        Instant::now() >= self.next_attempt_at
    }

    /// Schedule the next attempt at now + current_delay. Called when a dial
    /// is initiated so we don't retry again until the backoff expires.
    fn schedule_next_attempt(&mut self) {
        self.next_attempt_at = Instant::now() + self.current_delay;
    }

    /// Double the backoff delay and schedule the next attempt.
    fn record_failure(&mut self) {
        let max_delay = Duration::from_secs(RECONNECT_MAX_DELAY_SECS);
        self.current_delay = (self.current_delay * 2).min(max_delay);
        self.next_attempt_at = Instant::now() + self.current_delay;
        warn!(
            address = %self.address,
            next_retry_secs = self.current_delay.as_secs(),
            "Reconnect failed, backing off"
        );
    }

    fn reset_backoff(&mut self) {
        self.current_delay = Duration::from_secs(RECONNECT_INITIAL_DELAY_SECS);
        debug!(address = %self.address, "Reconnect backoff reset on successful connection");
    }
}

/// Tracks dial_peers and manages reconnection with exponential backoff.
pub struct PeerReconnector {
    peers: Vec<PeerBackoff>,
}

impl PeerReconnector {
    /// Create a reconnector from the configured dial_peer address strings.
    /// Invalid multiaddrs are logged and skipped.
    pub fn new(dial_peers: &[String]) -> Self {
        let peers = dial_peers
            .iter()
            .filter_map(|addr_str| match addr_str.parse::<Multiaddr>() {
                Ok(addr) => Some(PeerBackoff::new(addr)),
                Err(error) => {
                    warn!(
                        address = addr_str.as_str(),
                        %error,
                        "Skipping invalid dial_peer address for reconnector"
                    );
                    None
                }
            })
            .collect();
        Self { peers }
    }

    /// Returns the check interval for the reconnect timer.
    pub fn check_interval() -> Duration {
        Duration::from_secs(RECONNECT_CHECK_INTERVAL_SECS)
    }

    /// Returns true if there are dial_peers configured for reconnection.
    pub fn has_peers(&self) -> bool {
        !self.peers.is_empty()
    }

    /// Returns addresses that are ready for a reconnect attempt and are not
    /// currently connected. Each returned address has its next attempt scheduled
    /// so it will not be returned again until the backoff expires.
    pub fn addresses_to_reconnect(&mut self, connected_addresses: &[Multiaddr]) -> Vec<Multiaddr> {
        let mut result = Vec::new();
        for peer_backoff in &mut self.peers {
            if peer_backoff.is_ready() && !connected_addresses.contains(&peer_backoff.address) {
                result.push(peer_backoff.address.clone());
                peer_backoff.schedule_next_attempt();
            }
        }
        result
    }

    /// Record a failed dial attempt for the given address.
    pub fn record_dial_failure(&mut self, address: &Multiaddr) {
        if let Some(peer_backoff) = self
            .peers
            .iter_mut()
            .find(|peer_backoff| peer_backoff.address == *address)
        {
            peer_backoff.record_failure();
        }
    }

    /// Reset backoff for the given address after a successful connection.
    pub fn record_dial_success(&mut self, address: &Multiaddr) {
        if let Some(peer_backoff) = self
            .peers
            .iter_mut()
            .find(|peer_backoff| peer_backoff.address == *address)
        {
            peer_backoff.reset_backoff();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::advance;

    #[tokio::test(start_paused = true)]
    async fn new_reconnector_has_peers_ready_immediately() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);

        assert!(reconnector.has_peers());
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn skips_connected_addresses() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);

        let connected: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();
        let addresses = reconnector.addresses_to_reconnect(&[connected]);
        assert!(addresses.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn exponential_backoff_on_failure() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);

        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        // First failure: backoff doubles from 5s to 10s
        reconnector.record_dial_failure(&address);
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(addresses.is_empty(), "Should not be ready during backoff");

        // Advance past the 10s backoff
        advance(Duration::from_secs(11)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses.len(), 1, "Should be ready after backoff expires");

        // Second failure: backoff doubles to 20s
        reconnector.record_dial_failure(&address);
        advance(Duration::from_secs(15)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(addresses.is_empty(), "Should still be in 20s backoff");

        advance(Duration::from_secs(6)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses.len(), 1, "Should be ready after 20s backoff");
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_caps_at_max() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);

        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        // Fail many times: 5->10->20->40->80->160->300(cap)->300
        for _ in 0..10 {
            reconnector.record_dial_failure(&address);
        }

        // Advance just under the cap
        advance(Duration::from_secs(299)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(addresses.is_empty());

        // Advance past the cap
        advance(Duration::from_secs(2)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_backoff() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);

        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        // Fail several times to build up backoff
        for _ in 0..5 {
            reconnector.record_dial_failure(&address);
        }

        // Reset on success
        reconnector.record_dial_success(&address);

        // Fail once more -- should be back to initial 5->10s backoff
        reconnector.record_dial_failure(&address);
        advance(Duration::from_secs(11)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(
            addresses.len(),
            1,
            "Backoff should have reset to initial delay"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_addresses_are_skipped() {
        let mut reconnector = PeerReconnector::new(&[
            "not-a-valid-multiaddr".to_string(),
            "/ip4/127.0.0.1/tcp/6884".to_string(),
        ]);

        assert!(reconnector.has_peers());
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_dial_peers_has_no_peers() {
        let reconnector = PeerReconnector::new(&[]);
        assert!(!reconnector.has_peers());
    }
}
