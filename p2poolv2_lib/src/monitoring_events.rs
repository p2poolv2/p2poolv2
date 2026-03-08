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

//! Broadcast event types for monitoring via WebSocket subscriptions.
//!
//! Workers emit `MonitoringEvent` values to a `tokio::sync::broadcast`
//! channel. Each WebSocket client subscribes to the channel and filters
//! events by topic.
//!
//! Share events use `ShareInfo` from the store directly so there is
//! a single source of truth for the wire format.

use crate::store::dag_store::ShareInfo;
use serde::Serialize;
use tokio::sync::broadcast;

/// Capacity of the broadcast channel. A slow consumer that falls behind
/// this many messages receives a `Lagged` error and loses intermediate
/// events.
const MONITORING_EVENT_CHANNEL_CAPACITY: usize = 256;

/// JSON response for chain state information.
#[derive(Clone, Debug, Serialize)]
pub struct ChainInfo {
    pub genesis_blockhash: Option<String>,
    pub chain_tip_height: Option<u32>,
    pub total_work: String,
    pub chain_tip_blockhash: Option<String>,
    pub top_candidate_height: Option<u32>,
    pub top_candidate_blockhash: Option<String>,
}

/// JSON response for a peer event.
#[derive(Clone, Debug, Serialize)]
pub struct PeerResponse {
    pub peer_id: String,
    pub status: PeerStatus,
}

/// Whether a peer connected or disconnected.
#[derive(Clone, Debug, Serialize)]
pub enum PeerStatus {
    Connected,
    Disconnected,
}

/// Events pushed to WebSocket subscribers.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "topic", content = "data")]
pub enum MonitoringEvent {
    /// A new share was confirmed on the chain, with full uncle details.
    Share(ShareInfo),
    /// A peer connected or disconnected.
    Peer(PeerResponse),
}

/// Sender half of the monitoring event broadcast channel.
pub type MonitoringEventSender = broadcast::Sender<MonitoringEvent>;

/// Receiver half of the monitoring event broadcast channel.
pub type MonitoringEventReceiver = broadcast::Receiver<MonitoringEvent>;

/// Creates a broadcast channel for monitoring events.
///
/// The returned receiver can be dropped immediately -- each WebSocket
/// client obtains its own receiver via `sender.subscribe()`.
pub fn create_monitoring_event_channel() -> (MonitoringEventSender, MonitoringEventReceiver) {
    broadcast::channel(MONITORING_EVENT_CHANNEL_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::dag_store::UncleInfo;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};

    #[test]
    fn test_share_event_serialization() {
        let share = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 100,
            miner_pubkey: "02aa".to_string(),
            timestamp: 1700000000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![],
        };
        let event = MonitoringEvent::Share(share);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"topic\":\"Share\""));
        assert!(json.contains("\"height\":100"));
        assert!(json.contains("\"miner_pubkey\":\"02aa\""));
    }

    #[test]
    fn test_peer_connected_event_serialization() {
        let event = MonitoringEvent::Peer(PeerResponse {
            peer_id: "12D3KooW".to_string(),
            status: PeerStatus::Connected,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"topic\":\"Peer\""));
        assert!(json.contains("\"peer_id\":\"12D3KooW\""));
        assert!(json.contains("\"status\":\"Connected\""));
    }

    #[test]
    fn test_peer_disconnected_event_serialization() {
        let event = MonitoringEvent::Peer(PeerResponse {
            peer_id: "12D3KooW".to_string(),
            status: PeerStatus::Disconnected,
        });
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"status\":\"Disconnected\""));
    }

    #[test]
    fn test_share_info_event_serialization() {
        let share = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 42,
            miner_pubkey: "02aabbccdd".to_string(),
            timestamp: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![],
        };

        let event = MonitoringEvent::Share(share);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"height\":42"));
        assert!(json.contains("\"miner_pubkey\":\"02aabbccdd\""));
        assert!(json.contains("\"timestamp\":1700000000"));
    }

    #[test]
    fn test_share_event_with_uncles_serialization() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02uncle".to_string(),
            timestamp: 1_700_000_010,
            height: Some(41),
        };

        let share = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 42,
            miner_pubkey: "02parent".to_string(),
            timestamp: 1_700_000_020,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![uncle],
        };

        let event = MonitoringEvent::Share(share);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"uncles\""));
        assert!(json.contains("\"02uncle\""));
        assert!(json.contains("\"height\":42"));
    }

    #[test]
    fn test_broadcast_channel_send_receive() {
        let (sender, mut receiver) = create_monitoring_event_channel();
        let event = MonitoringEvent::Peer(PeerResponse {
            peer_id: "12D3KooW".to_string(),
            status: PeerStatus::Connected,
        });
        sender.send(event.clone()).unwrap();
        let received = receiver.try_recv().unwrap();
        match received {
            MonitoringEvent::Peer(peer) => {
                assert_eq!(peer.peer_id, "12D3KooW");
            }
            _ => panic!("unexpected event variant"),
        }
    }
}
