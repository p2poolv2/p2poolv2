// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Manages reconnection attempts to configured dial_peers with exponential backoff.
///
/// The reconnector makes every dial to a dial_peer, including the first one
/// at startup, and remembers the ConnectionId of the dial in flight. While a
/// dial is pending the address is not dialed again. Only the outcome of the
/// reconnector's own dial moves the backoff: a failure doubles the delay
/// (capped at RECONNECT_MAX_DELAY_SECS) and a success resets it. Dials of the
/// same address made by Kademlia or DNS seeds do not count.
use std::time::Duration;

use libp2p::Multiaddr;
use libp2p::swarm::ConnectionId;
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
    /// Connection id of the reconnector's dial in flight, if any.
    pending_dial: Option<ConnectionId>,
}

impl PeerBackoff {
    fn new(address: Multiaddr) -> Self {
        Self {
            address,
            current_delay: Duration::from_secs(RECONNECT_INITIAL_DELAY_SECS),
            next_attempt_at: Instant::now(),
            pending_dial: None,
        }
    }

    /// Ready when the backoff has expired and no dial is in flight.
    fn is_ready(&self) -> bool {
        self.pending_dial.is_none() && Instant::now() >= self.next_attempt_at
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
    /// so it will not be returned again until the backoff expires. The caller
    /// dials each one and reports the result with record_dial_started or
    /// record_dial_failure.
    pub fn addresses_to_reconnect(&mut self, connected_addresses: &[Multiaddr]) -> Vec<Multiaddr> {
        let mut result = Vec::with_capacity(self.peers.len());
        for peer_backoff in &mut self.peers {
            if peer_backoff.is_ready() && !connected_addresses.contains(&peer_backoff.address) {
                result.push(peer_backoff.address.clone());
                peer_backoff.schedule_next_attempt();
            }
        }
        result
    }

    /// Record that a dial to `address` is in flight on `connection_id`. The
    /// address is not returned by addresses_to_reconnect until the dial ends.
    pub fn record_dial_started(&mut self, address: &Multiaddr, connection_id: ConnectionId) {
        if let Some(peer_backoff) = self.find_by_address(address) {
            peer_backoff.pending_dial = Some(connection_id);
        }
    }

    /// Record a dial to `address` that the swarm refused synchronously, so no
    /// connection was ever pending.
    pub fn record_dial_failure(&mut self, address: &Multiaddr) {
        if let Some(peer_backoff) = self.find_by_address(address) {
            peer_backoff.record_failure();
        }
    }

    /// Record a failed outgoing connection. Backs off only when it is the
    /// reconnector's pending dial; other dials are ignored.
    pub fn record_connection_failure(&mut self, connection_id: ConnectionId) {
        if let Some(peer_backoff) = self.find_by_pending_dial(connection_id) {
            peer_backoff.pending_dial = None;
            peer_backoff.record_failure();
        }
    }

    /// Record an established connection. Resets the backoff only when it is
    /// the reconnector's pending dial; other connections are ignored.
    pub fn record_connection_established(&mut self, connection_id: ConnectionId) {
        if let Some(peer_backoff) = self.find_by_pending_dial(connection_id) {
            peer_backoff.pending_dial = None;
            peer_backoff.reset_backoff();
        }
    }

    fn find_by_address(&mut self, address: &Multiaddr) -> Option<&mut PeerBackoff> {
        self.peers
            .iter_mut()
            .find(|peer_backoff| peer_backoff.address == *address)
    }

    fn find_by_pending_dial(&mut self, connection_id: ConnectionId) -> Option<&mut PeerBackoff> {
        self.peers
            .iter_mut()
            .find(|peer_backoff| peer_backoff.pending_dial == Some(connection_id))
    }

    /// The connection id of the pending dial to `address`, for tests.
    #[cfg(test)]
    pub(crate) fn pending_dial(&self, address: &Multiaddr) -> Option<ConnectionId> {
        self.peers
            .iter()
            .find(|peer_backoff| peer_backoff.address == *address)
            .and_then(|peer_backoff| peer_backoff.pending_dial)
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

        // Reset on success of the reconnector's own dial
        let connection_id = ConnectionId::new_unchecked(1);
        reconnector.record_dial_started(&address, connection_id);
        reconnector.record_connection_established(connection_id);

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

    #[tokio::test(start_paused = true)]
    async fn addresses_to_reconnect_skips_address_with_pending_dial() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses, vec![address.clone()]);
        reconnector.record_dial_started(&address, ConnectionId::new_unchecked(1));

        // Well past the 5s delay, but the first dial has not finished yet
        advance(Duration::from_secs(20)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(
            addresses.is_empty(),
            "Must not redial while a dial is pending"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connection_failure_for_unrelated_connection_is_ignored() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        reconnector.addresses_to_reconnect(&[]);
        reconnector.record_dial_started(&address, ConnectionId::new_unchecked(1));
        reconnector.record_connection_failure(ConnectionId::new_unchecked(2));

        assert_eq!(
            reconnector.pending_dial(&address),
            Some(ConnectionId::new_unchecked(1))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connection_failure_for_pending_dial_doubles_backoff() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        reconnector.addresses_to_reconnect(&[]);
        reconnector.record_dial_started(&address, ConnectionId::new_unchecked(1));
        reconnector.record_connection_failure(ConnectionId::new_unchecked(1));
        assert_eq!(reconnector.pending_dial(&address), None);

        // Backoff doubled from 5s to 10s
        advance(Duration::from_secs(9)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(addresses.is_empty(), "Should still be in 10s backoff");

        advance(Duration::from_secs(2)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses, vec![address]);
    }

    #[tokio::test(start_paused = true)]
    async fn connection_established_for_pending_dial_resets_backoff() {
        let mut reconnector = PeerReconnector::new(&["/ip4/127.0.0.1/tcp/6884".to_string()]);
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();

        // Build up a 20s backoff
        reconnector.record_dial_failure(&address);
        reconnector.record_dial_failure(&address);
        advance(Duration::from_secs(21)).await;

        reconnector.addresses_to_reconnect(&[]);
        reconnector.record_dial_started(&address, ConnectionId::new_unchecked(1));
        reconnector.record_connection_established(ConnectionId::new_unchecked(1));
        assert_eq!(reconnector.pending_dial(&address), None);

        // The next failure doubles from the initial 5s, not from 20s
        reconnector.record_dial_failure(&address);
        advance(Duration::from_secs(9)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert!(addresses.is_empty(), "Should still be in 10s backoff");

        advance(Duration::from_secs(2)).await;
        let addresses = reconnector.addresses_to_reconnect(&[]);
        assert_eq!(addresses, vec![address]);
    }
}
