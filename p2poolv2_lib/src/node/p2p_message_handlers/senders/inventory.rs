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

use crate::node::messages::{InventoryMessage, Message};
use crate::node::request_response_handler::peer_block_knowledge::PeerBlockKnowledge;
use crate::node::request_sender::RequestSender;
use bitcoin::BlockHash;
use libp2p::PeerId;
use tracing::debug;

/// Send a block inventory announcement to one or all connected peers.
///
/// If `target_peer` is Some, sends the inv to just that peer.
/// If `target_peer` is None, sends the inv to all `connected_peers`.
/// Peers that are already known to have the block (tracked in
/// `peer_block_knowledge`) are skipped.
///
/// Sends directly via the swarm to avoid deadlocking the actor's
/// select loop (which would happen if we awaited on the bounded
/// swarm_tx channel that the actor also drains).
pub fn send_block_inventory(
    block_hash: BlockHash,
    target_peer: Option<PeerId>,
    connected_peers: &[PeerId],
    peer_block_knowledge: &PeerBlockKnowledge,
    request_sender: &mut impl RequestSender,
) {
    let inventory_message = Message::Inventory(InventoryMessage::BlockHashes(vec![block_hash]));

    let target_peers: Vec<PeerId> = match target_peer {
        Some(peer_id) => vec![peer_id],
        None => connected_peers.to_vec(),
    };

    for peer_id in target_peers {
        if peer_block_knowledge.peer_knows_block(&peer_id, &block_hash) {
            debug!("Skipping inv to peer {peer_id}: already knows block {block_hash}");
        } else {
            debug!("Sending Inv for block {block_hash} to peer {peer_id}");
            request_sender.send_request(&peer_id, inventory_message.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_sender::MockRequestSender;
    use bitcoin::hashes::Hash as _;

    fn make_block_hash(value: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        BlockHash::from_byte_array(bytes)
    }

    #[test]
    fn test_send_block_inventory_to_single_peer() {
        let peer_id = PeerId::random();
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .withf(move |sent_peer_id, message| {
                *sent_peer_id == peer_id
                    && matches!(
                        message,
                        Message::Inventory(InventoryMessage::BlockHashes(hashes))
                        if hashes == &vec![block_hash]
                    )
            })
            .times(1)
            .returning(|_, _| ());

        send_block_inventory(block_hash, Some(peer_id), &[], &knowledge, &mut mock_sender);
    }

    #[test]
    fn test_send_block_inventory_to_all_peers() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .times(3)
            .returning(|_, _| ());

        let connected = vec![peer_a, peer_b, peer_c];
        send_block_inventory(block_hash, None, &connected, &knowledge, &mut mock_sender);
    }

    #[test]
    fn test_send_block_inventory_filters_known_peers() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let block_hash = make_block_hash(1);

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .withf(move |sent_peer_id, _| *sent_peer_id == peer_b)
            .times(1)
            .returning(|_, _| ());

        let connected = vec![peer_a, peer_b];
        send_block_inventory(block_hash, None, &connected, &knowledge, &mut mock_sender);
    }

    #[test]
    fn test_send_block_inventory_skips_known_single_peer() {
        let peer_id = PeerId::random();
        let block_hash = make_block_hash(1);

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_id, block_hash);

        let mut mock_sender = MockRequestSender::new();
        mock_sender.expect_send_request().never();

        send_block_inventory(block_hash, Some(peer_id), &[], &knowledge, &mut mock_sender);
    }

    #[test]
    fn test_send_block_inventory_no_connected_peers() {
        let block_hash = make_block_hash(1);
        let knowledge = PeerBlockKnowledge::default();

        let mut mock_sender = MockRequestSender::new();
        mock_sender.expect_send_request().never();

        send_block_inventory(block_hash, None, &[], &knowledge, &mut mock_sender);
    }
}
