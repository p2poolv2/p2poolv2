// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use crate::node::SwarmSend;
use crate::node::messages::{InventoryMessage, Message};
use crate::node::request_response_handler::peer_block_knowledge::PeerBlockKnowledge;
use bitcoin::BlockHash;
use libp2p::PeerId;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Send a block inventory announcement to one or all connected peers.
///
/// If `target_peer` is Some, sends the inv to just that peer.
/// If `target_peer` is None, sends the inv to all `connected_peers`.
/// Peers that are already known to have the block (tracked in
/// `peer_block_knowledge`) are skipped.
pub async fn send_block_inventory<C: 'static + Send + Sync>(
    block_hash: BlockHash,
    target_peer: Option<PeerId>,
    connected_peers: &[PeerId],
    peer_block_knowledge: &PeerBlockKnowledge,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(vec![block_hash]));

    let target_peers: Vec<PeerId> = match target_peer {
        Some(peer_id) => vec![peer_id],
        None => connected_peers.to_vec(),
    };

    for peer_id in target_peers {
        if peer_block_knowledge.peer_knows_block(&peer_id, &block_hash) {
            debug!("Skipping inv to peer {peer_id}: already knows block {block_hash}");
        } else {
            info!("Sending inventory for block {block_hash} to peer {peer_id}");
            swarm_tx
                .send(SwarmSend::Request(peer_id, inventory_message.clone()))
                .await
                .map_err(|send_error| {
                    format!("Failed to send inventory to peer {peer_id}: {send_error}")
                })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn make_block_hash(value: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        BlockHash::from_byte_array(bytes)
    }

    #[tokio::test]
    async fn test_send_block_inventory_to_single_peer() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_id = PeerId::random();
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let result =
            send_block_inventory(block_hash, Some(peer_id), &[], &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        if let Some(SwarmSend::Request(sent_peer_id, sent_message)) = swarm_rx.recv().await {
            assert_eq!(sent_peer_id, peer_id);
            match sent_message {
                Message::Inventory(InventoryMessage::BlockHashes(hashes)) => {
                    assert_eq!(hashes, vec![block_hash]);
                }
                _ => panic!("Unexpected message type"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_block_inventory_to_all_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let connected = vec![peer_a, peer_b, peer_c];
        let result = send_block_inventory(block_hash, None, &connected, &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        // Should receive 3 messages, one for each peer
        let mut received_peers = Vec::with_capacity(3);
        for _ in 0..3 {
            if let Some(SwarmSend::Request(sent_peer_id, Message::Inventory(_))) =
                swarm_rx.recv().await
            {
                received_peers.push(sent_peer_id);
            } else {
                panic!("Expected SwarmSend::Request with Inventory message");
            }
        }

        assert!(received_peers.contains(&peer_a));
        assert!(received_peers.contains(&peer_b));
        assert!(received_peers.contains(&peer_c));

        // No more messages
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_send_block_inventory_filters_known_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let block_hash = make_block_hash(1);

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);

        let connected = vec![peer_a, peer_b];
        let result = send_block_inventory(block_hash, None, &connected, &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        // Only peer_b should receive the message (peer_a already knows)
        if let Some(SwarmSend::Request(sent_peer_id, _)) = swarm_rx.recv().await {
            assert_eq!(sent_peer_id, peer_b);
        } else {
            panic!("Expected message for peer_b");
        }

        // No more messages
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_send_block_inventory_skips_known_single_peer() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_id = PeerId::random();
        let block_hash = make_block_hash(1);

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_id, block_hash);

        let result =
            send_block_inventory(block_hash, Some(peer_id), &[], &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        // No message should be sent since the peer already knows
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_send_block_inventory_no_connected_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let result = send_block_inventory(block_hash, None, &[], &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        // No messages sent
        assert!(swarm_rx.try_recv().is_err());
    }
}
