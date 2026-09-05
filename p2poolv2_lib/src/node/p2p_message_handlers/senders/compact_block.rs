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

use crate::node::Message;
use crate::node::SwarmSend;
use crate::node::compact_block_relay::CompactBlockRelayMode;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// This is our latest version of compact relay
///
/// Compares to Bitcoin's `2`, we always assume segwit.
const COMPACT_BLOCK_RELAY_VERSION: u64 = 1;

/// Send initial compact block relay negotiation message (sendcmpct) to a peer.
///
/// As per BIP152, nodes should send sendcmpct messages upon connection establishment
/// to negotiate compact block support. High-bandwidth mode (announce=true) is limited
/// to up to 3 peers, while all other peers use low-bandwidth mode.
///
/// # Arguments
/// * `peer_id` - The peer to send the message to
/// * `compact_block_peer_count` - Current number of peers with high-bandwidth compact block relay enabled
/// * `swarm_tx` - Channel to send the message through
///
/// # Returns
/// Returns Ok(()) on success, or an error if the message could not be sent
pub async fn send_send_compact<C: 'static>(
    peer_id: libp2p::PeerId,
    hb_peer_count: u8,
    swarm_tx: &mpsc::Sender<SwarmSend<C>>,
) -> Result<CompactBlockRelayMode, Box<dyn Error + Send + Sync>> {
    // BIP152: Send high-bandwidth mode to up to 3 peers, low-bandwidth to others
    let (announce, mode) = if hb_peer_count < 3 {
        (true, CompactBlockRelayMode::HighBandwidth)
    } else {
        (false, CompactBlockRelayMode::LowBandwidth)
    };

    let message = Message::SendCompact(announce, COMPACT_BLOCK_RELAY_VERSION);

    if let Err(e) = swarm_tx.send(SwarmSend::Request(peer_id, message)).await {
        return Err(format!("Failed to send {} sendcmpct message: {}", mode, e).into());
    }

    info!("Sent {} sendcmpct message to peer {}", mode, peer_id);

    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use tokio::sync::mpsc::channel;

    #[tokio::test]
    async fn test_send_initial_compact_relay_high_bandwidth() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();

        // When peer count < 3, should send high-bandwidth mode (announce=true)
        let result = send_send_compact(peer_id, 2, &swarm_tx).await;
        assert_eq!(result.unwrap(), CompactBlockRelayMode::HighBandwidth);

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::SendCompact(announce, version) => {
                    assert!(announce, "Should announce in high-bandwidth mode");
                    assert_eq!(version, 1, "Should use version 1");
                }
                _ => panic!("Expected SendCompact message"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_initial_compact_relay_low_bandwidth() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();

        // When peer count >= 3, should send low-bandwidth mode (announce=false)
        let result = send_send_compact(peer_id, 3, &swarm_tx).await;
        assert_eq!(result.unwrap(), CompactBlockRelayMode::LowBandwidth);

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::SendCompact(announce, version) => {
                    assert!(!announce, "Should not announce in low-bandwidth mode");
                    assert_eq!(version, 1, "Should use version 1");
                }
                _ => panic!("Expected SendCompact message"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_initial_compact_relay_high_bandwidth_exactly_three() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();

        // When peer count == 3, should send low-bandwidth mode (announce=false)
        let result = send_send_compact(peer_id, 3, &swarm_tx).await;
        assert_eq!(result.unwrap(), CompactBlockRelayMode::LowBandwidth);

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::SendCompact(announce, version) => {
                    assert!(!announce, "Should not announce when exactly 3 peers");
                    assert_eq!(version, 1);
                }
                _ => panic!("Expected SendCompact message"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_initial_compact_relay_channel_closed() {
        let (swarm_tx, _) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();

        // Drop the receiver to close the channel
        drop(swarm_tx.clone());

        let result = send_send_compact(peer_id, 0, &swarm_tx).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to send high-bandwidth sendcmpct message")
        );
    }

    #[tokio::test]
    async fn test_send_initial_compact_relay_returns_low_bandwidth_for_huge_count() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();

        let result = send_send_compact(peer_id, 255, &swarm_tx).await;
        assert_eq!(result.unwrap(), CompactBlockRelayMode::LowBandwidth);

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::SendCompact(announce, version) => {
                    assert!(!announce);
                    assert_eq!(version, 1);
                }
                _ => panic!("Expected SendCompact message"),
            }
        } else {
            panic!("No message received");
        }
    }
}
