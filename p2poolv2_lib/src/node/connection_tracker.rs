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

use core::time::Duration;
use libp2p::core::ConnectedPoint;
use libp2p::{Multiaddr, PeerId};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::IpAddr;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::node::compact_block_relay::CompactBlockRelayStatus;

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
    /// Whether we should send compact blocks
    pub compact_block_to: CompactBlockRelayStatus,
    /// Whether we should expect compact blocks
    pub compact_block_from: CompactBlockRelayStatus,
    pub connected_at: Instant,
    pub direction: ConnectionDirection,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            address: "/ip4/0.0.0.0/tcp/46889".parse().unwrap(),
            ip: Default::default(),
            compact_block_to: Default::default(),
            compact_block_from: Default::default(),
            connected_at: Instant::now(),
            direction: ConnectionDirection::Inbound,
        }
    }
}

/// Serializable peer info returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfoResponse {
    pub peer_id: String,
    pub ip: Option<String>,
    pub address: String,
    pub direction: ConnectionDirection,
    pub connected_secs: u64,
    pub compact_block_to: CompactBlockRelayStatus,
    pub compact_block_from: CompactBlockRelayStatus,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for PeerInfoResponse {
    fn default() -> Self {
        Self {
            peer_id: PeerId::random().to_string(),
            address: "/ip4/127.0.0.1/tcp/46889".to_string(),
            ip: Some("127.0.0.1".to_string()),
            compact_block_to: Default::default(),
            compact_block_from: Default::default(),
            connected_secs: 0,
            direction: ConnectionDirection::Inbound,
        }
    }
}

/// Result of processing a new connection.
#[derive(Debug)]
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
    /// Metadata for currently connected peers
    connected_peers: HashMap<PeerId, PeerInfo>,
    /// Tracks Multiaddrs of currently connected outbound peers for reconnection logic
    pub(crate) connected_dial_addresses: Vec<Multiaddr>,
    /// IP addresses blocked from connecting
    blocked_ips: HashSet<IpAddr>,
}

pub(crate) struct ConnectionTrackerActor {
    /// Inner task that processes all commands
    join_handle: tokio::task::JoinHandle<()>,
    /// Channel to send commands to connection tracker
    ct_cmd_tx: mpsc::Sender<ConnectionTrackerCommand>,
}

impl ConnectionTrackerActor {
    /// Get a handle to talk to the actor
    pub(crate) fn handle_owned(&self) -> ConnectionTrackerHandle {
        ConnectionTrackerHandle::new(self.ct_cmd_tx.clone())
    }

    pub(crate) async fn shutdown(&mut self) {
        if let Err(err) = self
            .ct_cmd_tx
            .send(ConnectionTrackerCommand::Shutdown)
            .await
        {
            error!(%err, "Failed to send shutdown command to connection tracker");
        }

        let join_handle = &mut self.join_handle;
        let timeout = tokio::time::sleep(Duration::from_secs(1));

        tokio::select! {
            _ = join_handle => {
                debug!("Cleanly exited connection actor")
            },
            _ = timeout => {
                self.join_handle.abort();
                warn!("Had to abort connection actor for taking too long to shutdown")
            }
        }
    }
}

impl From<ConnectionTracker> for ConnectionTrackerActor {
    fn from(connection_tracker: ConnectionTracker) -> Self {
        debug!("connection actor started");

        let (ct_cmd_tx, ct_cmd_rx) = mpsc::channel(16);

        let join_handle = tokio::spawn(connection_tracker.process_commands(ct_cmd_rx));

        Self {
            join_handle,
            ct_cmd_tx,
        }
    }
}

impl Drop for ConnectionTrackerActor {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

impl ConnectionTracker {
    pub(crate) fn new(blocked_ips: HashSet<IpAddr>) -> Self {
        Self {
            connected_peers: HashMap::new(),
            connected_dial_addresses: Vec::new(),
            blocked_ips,
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

        if let Some(peer_ip) = ip {
            if self.blocked_ips.contains(&peer_ip) {
                warn!(
                    "Blocking connection from {} (IP {}), disconnecting",
                    peer_id, peer_ip
                );
                return ConnectionAction::Block;
            }
        }

        if let ConnectedPoint::Dialer { address, .. } = endpoint {
            if !self.connected_dial_addresses.contains(address) {
                self.connected_dial_addresses.push(address.clone());
            }
        }

        let peer_info = PeerInfo {
            address,
            ip,
            connected_at: Instant::now(),
            direction,
            compact_block_from: Default::default(),
            compact_block_to: Default::default(),
        };
        self.connected_peers.insert(peer_id, peer_info.clone());
        ConnectionAction::Accept(peer_info)
    }

    /// Remove a peer from the tracker when the connection closes.
    pub(crate) fn handle_closed(&mut self, peer_id: &PeerId, endpoint: &ConnectedPoint) {
        if let ConnectedPoint::Dialer { address, .. } = endpoint {
            self.connected_dial_addresses.retain(|addr| addr != address);
        }
        self.connected_peers.remove(peer_id);
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

    /// Count peers currently in HighBandwidth mode (for the sendcmpct receiver cap).
    pub(crate) fn count_high_bandwidth_peers(&self) -> u8 {
        self.connected_peers
            .values()
            .filter(|p| matches!(p.compact_block_from, CompactBlockRelayStatus::HighBandwidth))
            .count() as u8
    }

    /// Count peers that are not in Disabled mode (for the sender-side decision on connection established).
    pub(crate) fn count_compact_capable_peers(&self) -> u32 {
        self.connected_peers
            .values()
            .filter(|p| !matches!(p.compact_block_from, CompactBlockRelayStatus::Disabled))
            .count() as u32
    }

    /// Set a peer's compact_block_from status. No-op (with debug log) if peer not tracked.
    pub(crate) fn set_compact_block_from(
        &mut self,
        peer_id: &PeerId,
        status: CompactBlockRelayStatus,
    ) {
        match self.connected_peers.get_mut(peer_id) {
            Some(info) => info.compact_block_from = status,
            None => debug!(%peer_id, "set_compact_block_from: peer not tracked"),
        }
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
                compact_block_from: info.compact_block_from,
                compact_block_to: info.compact_block_to,
            })
            .collect()
    }

    /// Runs the command-processing loop for this [`ConnectionTracker`], consuming `self`.
    ///
    /// Awaits [`ConnectionTrackerCommand`] messages on `cmd_rx`, dispatches each to the
    /// appropriate handler, and sends the result back via the embedded oneshot channel
    /// (if present). The loop exits when the command channel is closed.
    pub(crate) async fn process_commands(
        self,
        mut cmd_rx: mpsc::Receiver<ConnectionTrackerCommand>,
    ) {
        let mut tracker = self;

        while let Some(cmd) = cmd_rx.recv().await {
            let (response, resp_tx) = match cmd {
                ConnectionTrackerCommand::AddConnection {
                    peer_id,
                    endpoint,
                    resp,
                } => {
                    let action = tracker.handle_established(peer_id, &endpoint);
                    (ConnectionTrackerResponse::ConnectionAction(action), resp)
                }
                ConnectionTrackerCommand::RemoveConnection(peer_id, endpoint) => {
                    tracker.handle_closed(&peer_id, &endpoint);
                    (ConnectionTrackerResponse::Ok, None)
                }
                ConnectionTrackerCommand::BlockIp(ip) => {
                    tracker.block_ip(ip);
                    (ConnectionTrackerResponse::Ok, None)
                }
                ConnectionTrackerCommand::UnblockIp(ip) => {
                    tracker.unblock_ip(ip);
                    (ConnectionTrackerResponse::Ok, None)
                }
                ConnectionTrackerCommand::GetBlockedIps { resp } => (
                    ConnectionTrackerResponse::BlockedIps(tracker.get_blocked_ips()),
                    resp,
                ),
                ConnectionTrackerCommand::CountHighBandwidthPeers { resp } => (
                    ConnectionTrackerResponse::HighBandwidthPeers(
                        tracker.count_high_bandwidth_peers(),
                    ),
                    resp,
                ),
                ConnectionTrackerCommand::CountCompactCapablePeers { resp } => (
                    ConnectionTrackerResponse::CompactCapablePeers(
                        tracker.count_compact_capable_peers(),
                    ),
                    resp,
                ),
                ConnectionTrackerCommand::SetCompactBlockFrom(peer_id, status) => {
                    tracker.set_compact_block_from(&peer_id, status);
                    (ConnectionTrackerResponse::Ok, None)
                }
                ConnectionTrackerCommand::GetPeerInfos { resp } => (
                    ConnectionTrackerResponse::PeerInfos(tracker.get_peer_infos()),
                    resp,
                ),
                ConnectionTrackerCommand::Shutdown => {
                    debug!("Received shutdown. Draining.");

                    // close to allow the buffer to drain and cleanly exit
                    cmd_rx.close();

                    (ConnectionTrackerResponse::Ok, None)
                }
            };

            if let Some(res) = resp_tx.and_then(|s| s.send(response).err()) {
                error!(?res, "failed to send response, receiver dropped");
            }
        }
    }
}

/// Commands that can be sent to a [`ConnectionTracker`] running in a dedicated task.
#[derive(Debug)]
pub(crate) enum ConnectionTrackerCommand {
    AddConnection {
        peer_id: PeerId,
        endpoint: ConnectedPoint,
        resp: Option<oneshot::Sender<ConnectionTrackerResponse>>,
    },
    RemoveConnection(PeerId, ConnectedPoint),
    BlockIp(IpAddr),
    UnblockIp(IpAddr),
    GetBlockedIps {
        resp: Option<oneshot::Sender<ConnectionTrackerResponse>>,
    },
    CountHighBandwidthPeers {
        resp: Option<oneshot::Sender<ConnectionTrackerResponse>>,
    },
    CountCompactCapablePeers {
        resp: Option<oneshot::Sender<ConnectionTrackerResponse>>,
    },
    SetCompactBlockFrom(PeerId, CompactBlockRelayStatus),
    GetPeerInfos {
        resp: Option<oneshot::Sender<ConnectionTrackerResponse>>,
    },
    Shutdown,
}

impl ConnectionTrackerCommand {
    fn set_response_sender(&mut self) -> Option<oneshot::Receiver<ConnectionTrackerResponse>> {
        match self {
            ConnectionTrackerCommand::AddConnection { resp, .. }
            | ConnectionTrackerCommand::GetBlockedIps { resp }
            | ConnectionTrackerCommand::CountHighBandwidthPeers { resp }
            | ConnectionTrackerCommand::CountCompactCapablePeers { resp }
            | ConnectionTrackerCommand::GetPeerInfos { resp } => {
                let (resp_tx, resp_rx) = oneshot::channel();
                *resp = Some(resp_tx);
                Some(resp_rx)
            }
            // ignore exhaustively ones w/o resp
            ConnectionTrackerCommand::BlockIp { .. }
            | ConnectionTrackerCommand::UnblockIp { .. }
            | ConnectionTrackerCommand::SetCompactBlockFrom { .. }
            | ConnectionTrackerCommand::Shutdown
            | ConnectionTrackerCommand::RemoveConnection { .. } => None,
        }
    }
}

/// Responses returned by a [`ConnectionTracker`] task for each command.
#[derive(Debug)]
pub(crate) enum ConnectionTrackerResponse {
    Ok,
    ConnectionAction(ConnectionAction),
    BlockedIps(Vec<IpAddr>),
    HighBandwidthPeers(u8),
    CompactCapablePeers(u32),
    PeerInfos(Vec<PeerInfoResponse>),
}

/// Cloneable handle for communicating with a [`ConnectionTracker`] running in a dedicated task.
///
/// Wraps the command sender for a single [`ConnectionTracker`] instance.
/// Each instance is tied to one tracker task; cloning shares the underlying channel.
#[derive(Clone)]
pub struct ConnectionTrackerHandle {
    cmd_tx: mpsc::Sender<ConnectionTrackerCommand>,
}

impl ConnectionTrackerHandle {
    pub(crate) fn new(cmd_tx: mpsc::Sender<ConnectionTrackerCommand>) -> Self {
        Self { cmd_tx }
    }

    async fn send_command(
        &self,
        mut cmd: ConnectionTrackerCommand,
    ) -> Result<ConnectionTrackerResponse, Box<dyn Error + Send + Sync>> {
        let resp_rx = cmd.set_response_sender();

        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|e| -> Box<dyn Error + Send + Sync> {
                format!("Failed to send command: {e}").into()
            })?;

        match resp_rx {
            Some(resp_rx) => resp_rx.await.map_err(|e| -> Box<dyn Error + Send + Sync> {
                format!("Failed to receive response: {e}").into()
            }),
            None => Ok(ConnectionTrackerResponse::Ok),
        }
    }

    pub(crate) async fn add_connection(
        &self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    ) -> Result<ConnectionAction, Box<dyn Error + Send + Sync>> {
        let resp = self
            .send_command(ConnectionTrackerCommand::AddConnection {
                peer_id,
                endpoint,
                resp: None,
            })
            .await?;

        match resp {
            ConnectionTrackerResponse::ConnectionAction(a) => Ok(a),
            _ => unexpected_resp(resp),
        }
    }

    pub async fn remove_connection(
        &self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_command(ConnectionTrackerCommand::RemoveConnection(
            peer_id, endpoint,
        ))
        .await
        .map(drop)
    }

    pub async fn block_ip(&self, ip: IpAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_command(ConnectionTrackerCommand::BlockIp(ip))
            .await
            .map(drop)
    }

    pub async fn unblock_ip(&self, ip: IpAddr) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_command(ConnectionTrackerCommand::UnblockIp(ip))
            .await
            .map(drop)
    }

    pub async fn get_blocked_ips(&self) -> Result<Vec<IpAddr>, Box<dyn Error + Send + Sync>> {
        let resp = self
            .send_command(ConnectionTrackerCommand::GetBlockedIps { resp: None })
            .await?;
        match resp {
            ConnectionTrackerResponse::BlockedIps(ips) => Ok(ips),
            other => unexpected_resp(other),
        }
    }

    pub async fn count_high_bandwidth_peers(&self) -> Result<u8, Box<dyn Error + Send + Sync>> {
        let resp = self
            .send_command(ConnectionTrackerCommand::CountHighBandwidthPeers { resp: None })
            .await?;
        match resp {
            ConnectionTrackerResponse::HighBandwidthPeers(count) => Ok(count),
            other => unexpected_resp(other),
        }
    }

    pub async fn count_compact_capable_peers(&self) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let resp = self
            .send_command(ConnectionTrackerCommand::CountCompactCapablePeers { resp: None })
            .await?;
        match resp {
            ConnectionTrackerResponse::CompactCapablePeers(count) => Ok(count),
            other => unexpected_resp(other),
        }
    }

    pub async fn set_compact_block_from(
        &self,
        peer_id: PeerId,
        status: CompactBlockRelayStatus,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_command(ConnectionTrackerCommand::SetCompactBlockFrom(
            peer_id, status,
        ))
        .await
        .map(drop)
    }

    pub async fn get_peer_infos(
        &self,
    ) -> Result<Vec<PeerInfoResponse>, Box<dyn Error + Send + Sync>> {
        let resp = self
            .send_command(ConnectionTrackerCommand::GetPeerInfos { resp: None })
            .await?;
        match resp {
            ConnectionTrackerResponse::PeerInfos(infos) => Ok(infos),
            other => unexpected_resp(other),
        }
    }
}

#[inline]
fn unexpected_resp<T>(res: ConnectionTrackerResponse) -> Result<T, Box<dyn Error + Send + Sync>> {
    error!(?res, "Unexpected response");
    debug_assert!(false, "Unexpected response");
    Err("Unexpected response".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::{ConnectedPoint, Endpoint};

    fn make_dialer_endpoint(address: &str) -> ConnectedPoint {
        let multiaddr: Multiaddr = address.parse().unwrap();
        ConnectedPoint::Dialer {
            address: multiaddr,
            role_override: Endpoint::Dialer,
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
        assert_eq!(tracker.connected_dial_addresses.len(), 1);

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
            tracker.connected_dial_addresses.len(),
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
    fn test_handle_closed_removes_peer() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884");

        tracker.handle_established(peer_id, &endpoint);
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(tracker.connected_dial_addresses.len(), 1);

        tracker.handle_closed(&peer_id, &endpoint);
        assert_eq!(tracker.connected_peers.len(), 0);
        assert_eq!(tracker.connected_dial_addresses.len(), 0);
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
        assert_eq!(tracker.connected_dial_addresses.len(), 1);

        tracker.handle_closed(&inbound_peer, &inbound_endpoint);
        assert_eq!(tracker.connected_peers.len(), 1);
        assert_eq!(
            tracker.connected_dial_addresses.len(),
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
            tracker.connected_dial_addresses.len(),
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
            tracker.connected_dial_addresses.len(),
            1,
            "same address should not be added twice"
        );
    }

    #[test]
    fn test_set_compact_block_from_tracked_peer() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_id = PeerId::random();
        tracker.handle_established(peer_id, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));

        assert_eq!(
            tracker.connected_peers[&peer_id].compact_block_from,
            CompactBlockRelayStatus::Handshake
        );

        tracker.set_compact_block_from(&peer_id, CompactBlockRelayStatus::HighBandwidth);
        assert_eq!(
            tracker.connected_peers[&peer_id].compact_block_from,
            CompactBlockRelayStatus::HighBandwidth
        );
    }

    #[test]
    fn test_set_compact_block_from_untracked_peer_is_noop() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let untracked = PeerId::random();
        tracker.set_compact_block_from(&untracked, CompactBlockRelayStatus::HighBandwidth);
        assert_eq!(tracker.connected_peers.len(), 0);
    }

    #[test]
    fn test_count_high_bandwidth_peers() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        tracker.handle_established(peer_a, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));
        tracker.handle_established(peer_b, &make_listener_endpoint("/ip4/5.6.7.8/tcp/12345"));
        tracker.handle_established(peer_c, &make_dialer_endpoint("/ip4/9.0.1.2/tcp/46884"));

        assert_eq!(tracker.count_high_bandwidth_peers(), 0);

        tracker.set_compact_block_from(&peer_a, CompactBlockRelayStatus::HighBandwidth);
        assert_eq!(tracker.count_high_bandwidth_peers(), 1);

        tracker.set_compact_block_from(&peer_b, CompactBlockRelayStatus::HighBandwidth);
        assert_eq!(tracker.count_high_bandwidth_peers(), 2);

        // LowBandwidth should not count
        tracker.set_compact_block_from(&peer_c, CompactBlockRelayStatus::LowBandwidth);
        assert_eq!(tracker.count_high_bandwidth_peers(), 2);
    }

    #[test]
    fn test_count_compact_capable_peers() {
        let mut tracker = ConnectionTracker::new(HashSet::new());
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        tracker.handle_established(peer_a, &make_dialer_endpoint("/ip4/1.2.3.4/tcp/46884"));
        tracker.handle_established(peer_b, &make_listener_endpoint("/ip4/5.6.7.8/tcp/12345"));
        tracker.handle_established(peer_c, &make_dialer_endpoint("/ip4/9.0.1.2/tcp/46884"));

        // All start as Handshake (default), which counts as compact-capable
        assert_eq!(tracker.count_compact_capable_peers(), 3);

        tracker.set_compact_block_from(&peer_a, CompactBlockRelayStatus::HighBandwidth);
        tracker.set_compact_block_from(&peer_b, CompactBlockRelayStatus::LowBandwidth);
        assert_eq!(tracker.count_compact_capable_peers(), 3);

        // Disabled does not count
        tracker.set_compact_block_from(&peer_c, CompactBlockRelayStatus::Disabled);
        assert_eq!(tracker.count_compact_capable_peers(), 2);
    }

    #[tokio::test]
    async fn test_process_commands_block_ip_and_get_blocked() {
        let tracker = ConnectionTracker::new(HashSet::new());
        let (cmd_tx, cmd_rx) = mpsc::channel(16);

        tokio::spawn(tracker.process_commands(cmd_rx));

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        cmd_tx
            .send(ConnectionTrackerCommand::BlockIp(ip))
            .await
            .unwrap();

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ConnectionTrackerCommand::GetBlockedIps {
                resp: Some(resp_tx),
            })
            .await
            .unwrap();
        match resp_rx.await {
            Ok(ConnectionTrackerResponse::BlockedIps(ips)) => {
                assert_eq!(ips.len(), 1);
                assert!(ips.contains(&ip));
            }
            other => panic!("expected BlockedIps, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_process_commands_add_connection_and_get_peer_infos() {
        let tracker = ConnectionTracker::new(HashSet::new());
        let (cmd_tx, cmd_rx) = mpsc::channel(16);

        tokio::spawn(tracker.process_commands(cmd_rx));

        let peer_id = PeerId::random();
        let endpoint = make_dialer_endpoint("/ip4/42.42.42.42/tcp/8333");

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ConnectionTrackerCommand::AddConnection {
                peer_id,
                endpoint,
                resp: Some(resp_tx),
            })
            .await
            .unwrap();
        match resp_rx.await {
            Ok(ConnectionTrackerResponse::ConnectionAction(action)) => {
                assert!(matches!(action, ConnectionAction::Accept(_)));
            }
            other => panic!("expected ConnectionAction, got {:?}", other),
        }

        let (resp_tx, resp_rx) = oneshot::channel();
        cmd_tx
            .send(ConnectionTrackerCommand::GetPeerInfos {
                resp: Some(resp_tx),
            })
            .await
            .unwrap();
        match resp_rx.await {
            Ok(ConnectionTrackerResponse::PeerInfos(infos)) => {
                assert_eq!(infos.len(), 1);
                assert_eq!(infos[0].peer_id, peer_id.to_string());
                assert_eq!(infos[0].ip, Some("42.42.42.42".to_string()));
            }
            other => panic!("expected PeerInfos, got {:?}", other),
        }
    }
}
