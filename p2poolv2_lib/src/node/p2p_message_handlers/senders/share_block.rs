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

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::request_response_handler::peer_block_knowledge::PeerBlockKnowledge;
use crate::shares::share_block::ShareBlock;
use libp2p::PeerId;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Broadcast a full ShareBlock to all connected peers.
///
/// Peers that are already known to have the block (tracked in
/// `peer_block_knowledge`) are skipped. Returns the list of peers
/// that were sent the block, so the caller can record outbound
/// knowledge.
pub async fn send_share_block_broadcast<C: Send + Sync>(
    share_block: ShareBlock,
    connected_peers: &[PeerId],
    peer_block_knowledge: &PeerBlockKnowledge,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<Vec<PeerId>, Box<dyn Error + Send + Sync>> {
    let block_hash = share_block.block_hash();
    let mut sent_to_peers = Vec::with_capacity(connected_peers.len());

    for peer_id in connected_peers {
        if peer_block_knowledge.peer_knows_block(peer_id, &block_hash) {
            debug!("Skipping broadcast to peer {peer_id}: already knows block {block_hash}");
        } else {
            debug!("Broadcasting ShareBlock {block_hash} to peer {peer_id}");
            swarm_tx
                .send(SwarmSend::Request(
                    *peer_id,
                    Message::ShareBlock(share_block.clone()),
                ))
                .await
                .map_err(|send_error| {
                    format!("Failed to send ShareBlock to peer {peer_id}: {send_error}")
                })?;
            sent_to_peers.push(*peer_id);
        }
    }

    Ok(sent_to_peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestShareBlockBuilder;

    #[tokio::test]
    async fn test_broadcast_to_all_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let knowledge = PeerBlockKnowledge::default();

        let connected = vec![peer_a, peer_b, peer_c];
        let result =
            send_share_block_broadcast(share_block, &connected, &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        let sent_to = result.unwrap();
        assert_eq!(sent_to.len(), 3);
        assert!(sent_to.contains(&peer_a));
        assert!(sent_to.contains(&peer_b));
        assert!(sent_to.contains(&peer_c));

        let mut received_peers = Vec::with_capacity(3);
        for _ in 0..3 {
            if let Some(SwarmSend::Request(sent_peer_id, Message::ShareBlock(ref block))) =
                swarm_rx.recv().await
            {
                assert_eq!(block.block_hash(), block_hash);
                received_peers.push(sent_peer_id);
            } else {
                panic!("Expected SwarmSend::Request with ShareBlock message");
            }
        }

        assert!(received_peers.contains(&peer_a));
        assert!(received_peers.contains(&peer_b));
        assert!(received_peers.contains(&peer_c));

        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_broadcast_filters_known_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);

        let connected = vec![peer_a, peer_b];
        let result =
            send_share_block_broadcast(share_block, &connected, &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        let sent_to = result.unwrap();
        assert_eq!(sent_to.len(), 1);
        assert_eq!(sent_to[0], peer_b);

        if let Some(SwarmSend::Request(sent_peer_id, _)) = swarm_rx.recv().await {
            assert_eq!(sent_peer_id, peer_b);
        } else {
            panic!("Expected message for peer_b");
        }

        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_broadcast_skips_all_known_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);
        knowledge.record_block_known(&peer_b, block_hash);

        let connected = vec![peer_a, peer_b];
        let result =
            send_share_block_broadcast(share_block, &connected, &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        let sent_to = result.unwrap();
        assert!(sent_to.is_empty());
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_broadcast_no_connected_peers() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(10);
        let share_block = TestShareBlockBuilder::new().build();
        let knowledge = PeerBlockKnowledge::default();

        let result = send_share_block_broadcast(share_block, &[], &knowledge, swarm_tx).await;
        assert!(result.is_ok());

        let sent_to = result.unwrap();
        assert!(sent_to.is_empty());
        assert!(swarm_rx.try_recv().is_err());
    }
}
