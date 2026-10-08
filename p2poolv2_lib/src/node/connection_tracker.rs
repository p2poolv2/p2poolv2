// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use libp2p::core::ConnectedPoint;
use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;
use tracing::warn;

/// Ping failures, as reported by libp2p, after which a connection is treated as
/// unresponsive and closed.
///
/// libp2p's ping handler stays silent on the first real failure and reports from
/// the second on, so 3 reported failures are 4 real ones -- roughly two to three
/// minutes of a connection that negotiated but cannot exchange messages.
pub(crate) const PING_FAILURE_THRESHOLD: u32 = 3;

/// Direction of a peer connection.
#[derive(Debug, Clone, Serialize)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Metadata about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: Multiaddr,
    pub ip: Option<IpAddr>,
    pub connected_at: Instant,
    pub direction: ConnectionDirection,
}

/// Serializable peer info returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfoResponse {
    pub peer_id: String,
    pub ip: Option<String>,
    pub address: String,
    pub direction: ConnectionDirection,
    pub connected_secs: u64,
}

/// Result of processing a new connection.
pub(crate) enum ConnectionAction {
    /// Connection accepted, proceed with handshake.
    Accept(PeerInfo),
    /// Connection blocked, disconnect the peer.
    Block,
}

/// Extract the IP address from a Multiaddr.
fn extract_ip_from_multiaddr(address: &Multiaddr) -> Option<IpAddr> {
    for protocol in address.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            libp2p::multiaddr::Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }
    None
}

/// Tracks connected peers, their metadata, and the IP blocklist.
pub(crate) struct ConnectionTracker {
    /// Metadata for currently connected peers, from each peer's first
    /// connection. A peer stays here until its last connection closes.
    connected_peers: HashMap<PeerId, PeerInfo>,
    /// The peer last reached at each address we dialed. Configured dial peers
    /// are bare addresses, so a peer's id is only known after a successful dial;
    /// this lets the reconnector see a dial peer as connected however it is
    /// connected, including over an inbound connection it opened to us.
    dial_peer_ids: HashMap<Multiaddr, PeerId>,
    /// IP addresses blocked from connecting
    blocked_ips: HashSet<IpAddr>,
    /// Consecutive reported ping failures per connection; cleared on a
    /// successful ping and when the connection closes.
    ping_failures: HashMap<ConnectionId, u32>,
    /// Connections accepted since start, for P2P health metrics.
    connections_total: u64,
    /// Ping failures reported since start, for P2P health metrics.
    ping_failures_total: u64,
    /// Connections closed for failing ping, for P2P health metrics.
    connections_closed_unresponsive_total: u64,
}

impl ConnectionTracker {
    pub(crate) fn new(blocked_ips: HashSet<IpAddr>) -> Self {
        Self {
            connected_peers: HashMap::new(),
            dial_peer_ids: HashMap::new(),
            blocked_ips,
            ping_failures: HashMap::new(),
            connections_total: 0,
            ping_failures_total: 0,
            connections_closed_unresponsive_total: 0,
        }
    }

    /// Process a new connection. Returns Block if the IP is blocked,
    /// otherwise returns Accept with the peer info and records the
    /// connection in the tracker.
    pub(crate) fn handle_established(
        &mut self,
        peer_id: PeerId,
        endpoint: &ConnectedPoint,
    ) -> ConnectionAction {
        let (address, direction) = match endpoint {
            ConnectedPoint::Dialer { address, .. } => {
                (address.clone(), ConnectionDirection::Outbound)
            }
            ConnectedPoint::Listener { send_back_addr, .. } => {
                (send_back_addr.clone(), ConnectionDirection::Inbound)
            }
        };

        let ip = extract_ip_from_multiaddr(&address);

        if let Some(peer_ip) = ip
            && self.blocked_ips.contains(&peer_ip)
        {
            warn!(
                "Blocking connection from {} (IP {}), disconnecting",
                peer_id, peer_ip
            );
            return ConnectionAction::Block;
        }

        if let ConnectedPoint::Dialer { address, .. } = endpoint {
            self.dial_peer_ids.insert(address.clone(), peer_id);
        }

        let peer_info = PeerInfo {
            address,
            ip,
            connected_at: Instant::now(),
            direction,
        };
        self.connected_peers
            .entry(peer_id)
            .or_insert_with(|| peer_info.clone());
        self.connections_total += 1;
        ConnectionAction::Accept(peer_info)
    }

    /// Record a closed connection. `remaining_connections` is libp2p's count of
    /// connections still open to the peer; the peer is forgotten only when it
    /// reaches zero, so closing one of several connections does not make a
    /// still-connected peer look disconnected (which made the reconnector dial
    /// it again on every close).
    pub(crate) fn handle_closed(&mut self, peer_id: &PeerId, remaining_connections: u32) {
        if remaining_connections == 0 {
            self.connected_peers.remove(peer_id);
        }
    }

    /// Dial addresses whose peer is currently connected, in either direction.
    pub(crate) fn connected_dial_addresses(&self) -> Vec<Multiaddr> {
        self.dial_peer_ids
            .iter()
            .filter(|(_, peer_id)| self.connected_peers.contains_key(*peer_id))
            .map(|(address, _)| address.clone())
            .collect()
    }

    /// Record a reported ping failure on a connection and return the number of
    /// consecutive failures so far.
    pub(crate) fn record_ping_failure(&mut self, connection_id: ConnectionId) -> u32 {
        self.ping_failures_total += 1;
        let failures = self.ping_failures.entry(connection_id).or_insert(0);
        *failures += 1;
        *failures
    }

    /// Count a connection closed for failing ping.
    pub(crate) fn record_unresponsive_close(&mut self) {
        self.connections_closed_unresponsive_total += 1;
    }

    /// Number of peers with at least one open connection.
    pub(crate) fn connected_peer_count(&self) -> u64 {
        self.connected_peers.len() as u64
    }

    /// Connections accepted since start.
    pub(crate) fn connections_total(&self) -> u64 {
        self.connections_total
    }

    /// Ping failures reported since start.
    pub(crate) fn ping_failures_total(&self) -> u64 {
        self.ping_failures_total
    }

    /// Connections closed for failing ping since start.
    pub(crate) fn connections_closed_unresponsive_total(&self) -> u64 {
        self.connections_closed_unresponsive_total
    }

    /// Clear a connection's ping failure count, after a successful ping or when
    /// the connection is closed.
    pub(crate) fn clear_ping_failures(&mut self, connection_id: ConnectionId) {
        self.ping_failures.remove(&connection_id);
    }

    /// Consecutive reported ping failures on a connection.
    #[cfg(test)]
    pub(crate) fn ping_failures(&self, connection_id: ConnectionId) -> u32 {
        self.ping_failures.get(&connection_id).copied().unwrap_or(0)
    }

    /// Add an IP to the blocklist.
    pub(crate) fn block_ip(&mut self, ip: IpAddr) {
        self.blocked_ips.insert(ip);
    }

    /// Remove an IP from the blocklist.
    pub(crate) fn unblock_ip(&mut self, ip: IpAddr) {
        self.blocked_ips.remove(&ip);
    }

    /// Return all blocked IPs.
    pub(crate) fn get_blocked_ips(&self) -> Vec<IpAddr> {
        self.blocked_ips.iter().copied().collect()
    }

    /// Build a list of connected peer info responses.
    pub(crate) fn get_peer_infos(&self) -> Vec<PeerInfoResponse> {
        let now = Instant::now();
        self.connected_peers
            .iter()
            .map(|(peer_id, info)| PeerInfoResponse {
                peer_id: peer_id.to_string(),
                ip: info.ip.map(|ip| ip.to_string()),
                address: info.address.to_string(),
                direction: info.direction.clone(),
                connected_secs: now.duration_since(info.connected_at).as_secs(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::transport::PortUse;
    use libp2p::core::{ConnectedPoint, Endpoint};

    fn make_dialer_endpoint(address: &str) -> ConnectedPoint {
        let multiaddr: Multiaddr = address.parse().unwrap();
        ConnectedPoint::Dialer {
            address: multiaddr,
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    }

    fn make_listener_endpoint(send_back: &str) -> ConnectedPoint {
        let send_back_addr: Multiaddr = send_back.parse().unwrap();
        let local_addr: Multiaddr = "/ip4/0.0.0.0/tcp/46884".parse().unwrap();
        ConnectedPoint::Listener {
            local_addr,
            send_back_addr,
        }
    }

    #[test]
    fn test_accept_outbound_connection() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        let action = tracker.handle_established(peer_id, &endpoint);
        assert!(matches!(action, ConnectionAction::Accept(_)));
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(tracker.connected_dial_addresses().len(), 1);

        let info = &tracker.connected_peers[&peer_id];
        assert_eq!(info.ip, Some("1.2.3.4".parse().unwrap()));
        assert!(matches!(info.direction, ConnectionDirection::Outbound));
    }

    #[test]
    fn test_accept_inbound_connection() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let endpoint = make_listener_endpoint("/ip4/5.6.7.8/tcp/12345");

        let action = tracker.handle_established(peer_id, &endpoint);
        assert!(matches!(action, ConnectionAction::Accept(_)));
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(
            tracker.connected_dial_addresses().len(),
            0,
            "inbound connections should not be added to dial addresses"
        );

        let info = &tracker.connected_peers[&peer_id];
        assert_eq!(info.ip, Some("5.6.7.8".parse().unwrap()));
        assert!(matches!(info.direction, ConnectionDirection::Inbound));
    }

    #[test]
    fn test_block_connection_from_blocked_ip() {
        let blocked: HashSet<IpAddr> = ["1.2.3.4"]
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let mut tracker = ConnectionTracker::new(blocked);
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        let action = tracker.handle_established(peer_id, &endpoint);
        assert!(matches!(action, ConnectionAction::Block));
        assert_eq!(
            tracker.connected_peers.len(),
            0,
            "blocked peer should not be tracked"
        );
    }

    #[test]
    fn test_allow_connection_from_non_blocked_ip() {
        let blocked: HashSet<IpAddr> = ["1.2.3.4"]
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let mut tracker = ConnectionTracker::new(blocked);
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/5.6.7.8/tcp/46884");

        let action = tracker.handle_established(peer_id, &endpoint);
        assert!(matches!(action, ConnectionAction::Accept(_)));
        assert_eq!(tracker.connected_peers.len(), 1);
    }

    #[test]
    fn test_handle_closed_removes_peer_when_last_connection_closes() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        tracker.handle_established(peer_id, &endpoint);
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(tracker.connected_dial_addresses().len(), 1);

        tracker.handle_closed(&peer_id, 0);
        assert_eq!(tracker.connected_peers.len(), 0);
        assert_eq!(tracker.connected_dial_addresses().len(), 0);
    }

    /// Closing one of two connections to a peer released its dial
    /// address, so the reconnector dialed the still connected peer
    /// again on every close.
    #[test]
    fn test_closing_one_of_two_connections_keeps_peer_connected() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");
        tracker.handle_established(peer_id, &endpoint);
        tracker.handle_established(peer_id, &endpoint);

        tracker.handle_closed(&peer_id, 1);

        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(
            tracker.connected_dial_addresses(),
            vec!["/ip4/1.2.3.4/tcp/46884".parse::<Multiaddr>().unwrap()],
            "a dial peer with a connection still open must not be redialed"
        );
    }

    /// A dial peer that is connected to us inbound is connected: the reconnector
    /// must not open a second, outbound connection to it.
    #[test]
    fn test_dial_peer_connected_inbound_counts_as_connected() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let dial_endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        // Learn the dial address's peer from an earlier outbound connection.
        tracker.handle_established(peer_id, &dial_endpoint);
        tracker.handle_closed(&peer_id, 0);
        assert!(tracker.connected_dial_addresses().is_empty());

        // The peer now connects to us instead.
        tracker.handle_established(peer_id, &make_listener_endpoint("/ip4/1.2.3.4/tcp/51234"));

        assert_eq!(
            tracker.connected_dial_addresses(),
            vec!["/ip4/1.2.3.4/tcp/46884".parse::<Multiaddr>().unwrap()]
        );
    }

    #[test]
    fn test_handle_closed_inbound_preserves_dial_addresses() {
        let mut tracker = ConnectionTracker::new(HashSet::new());

        let outbound_peer = PeerId::random();
        let outbound_endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");
        tracker.handle_established(outbound_peer, &outbound_endpoint);

        let inbound_peer = PeerId::random();
        let inbound_endpoint = make_listener_endpoint("/ip4/5.6.7.8/tcp/12345");
        tracker.handle_established(inbound_peer, &inbound_endpoint);

        assert_eq!(tracker.connected_peers.len(), 2);
        assert_eq!(tracker.connected_dial_addresses().len(), 1);

        tracker.handle_closed(&inbound_peer, 0);
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(
            tracker.connected_dial_addresses().len(),
            1,
            "closing inbound should not remove outbound dial address"
        );
    }

    #[test]
    fn test_get_peer_infos_returns_connected_peers() {
        let mut tracker = ConnectionTracker::new(HashSet::new());

        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        tracker.handle_established(peer_a, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));
        tracker.handle_established(peer_b, &make_listener_endpoint("/ip4/5.6.7.8/tcp/12345"));

        let infos = tracker.get_peer_infos();
        assert_eq!(infos.len(), 2);

        let ips: Vec<Option<String>> = infos.iter().map(|info| info.ip.clone()).collect();
        assert!(ips.contains(&Some("1.2.3.4".to_string())));
        assert!(ips.contains(&Some("5.6.7.8".to_string())));
    }

    #[test]
    fn test_extract_ip_from_multiaddr_ipv4() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/8080".parse().unwrap();
        assert_eq!(
            extract_ip_from_multiaddr(&addr),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_ip_from_multiaddr_ipv6() {
        let addr: Multiaddr = "/ip6/::1/tcp/8080".parse().unwrap();
        assert_eq!(
            extract_ip_from_multiaddr(&addr),
            Some("::1".parse().unwrap())
        );
    }

    #[test]
    fn test_blocked_outbound_does_not_leave_stale_dial_address() {
        let blocked: HashSet<IpAddr> = ["1.2.3.4"]
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let mut tracker = ConnectionTracker::new(blocked);
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        let action = tracker.handle_established(peer_id, &endpoint);
        assert!(matches!(action, ConnectionAction::Block));
        assert_eq!(
            tracker.connected_dial_addresses().len(),
            0,
            "blocked outbound should not leave a stale dial address"
        );
    }

    #[test]
    fn test_duplicate_outbound_not_added_twice() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        tracker.handle_established(peer_a, &endpoint);
        tracker.handle_established(peer_b, &endpoint);

        assert_eq!(
            tracker.connected_dial_addresses().len(),
            1,
            "same address should not be added twice"
        );
    }

    #[test]
    fn test_ping_failures_count_consecutively_per_connection() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let connection = ConnectionId::new_unchecked(1);

        assert_eq!(tracker.record_ping_failure(connection), 1);
        assert_eq!(tracker.record_ping_failure(connection), 2);
        assert_eq!(
            tracker.record_ping_failure(connection),
            PING_FAILURE_THRESHOLD
        );
    }

    #[test]
    fn test_ping_failures_are_tracked_independently_per_connection() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let failing = ConnectionId::new_unchecked(1);
        let sibling = ConnectionId::new_unchecked(2);

        tracker.record_ping_failure(failing);
        tracker.record_ping_failure(failing);

        assert_eq!(tracker.record_ping_failure(sibling), 1);
    }

    #[test]
    fn test_clearing_ping_failures_restarts_the_count() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let connection = ConnectionId::new_unchecked(1);
        tracker.record_ping_failure(connection);
        tracker.record_ping_failure(connection);

        tracker.clear_ping_failures(connection);

        assert_eq!(tracker.record_ping_failure(connection), 1);
    }

    #[test]
    fn test_connections_total_counts_accepted_connections_only() {
        let blocked: HashSet<IpAddr> = ["5.6.7.8"]
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let mut tracker = ConnectionTracker::new(blocked);
        let peer_id = PeerId::random();

        tracker.handle_established(peer_id, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));
        tracker.handle_established(peer_id, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));
        tracker.handle_established(
            PeerId::random(),
            &make_dialer_endpoint("/ip4/5.6.7.8/tcp/46884"),
        );

        assert_eq!(tracker.connections_total(), 2);
        assert_eq!(tracker.connected_peer_count(), 1);
    }
}
