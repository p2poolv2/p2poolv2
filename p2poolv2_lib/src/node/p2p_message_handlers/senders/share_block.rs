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

use crate::node::messages::Message;
use crate::node::request_response_handler::peer_block_knowledge::PeerBlockKnowledge;
use crate::node::request_sender::RequestSender;
use crate::shares::share_block::ShareBlock;
use libp2p::PeerId;
use tracing::debug;

/// Broadcast a full ShareBlock to all connected peers.
///
/// Peers that are already known to have the block (tracked in
/// `peer_block_knowledge`) are skipped. Each recipient is recorded
/// in `peer_block_knowledge` so that subsequent broadcasts of the
/// same block are suppressed.
///
/// Sends directly via the swarm to avoid deadlocking the actor's
/// select loop (which would happen if we awaited on the bounded
/// swarm_tx channel that the actor also drains).
pub fn send_share_block_broadcast(
    share_block: ShareBlock,
    connected_peers: &[PeerId],
    peer_block_knowledge: &mut PeerBlockKnowledge,
    request_sender: &mut impl RequestSender,
) {
    let block_hash = share_block.block_hash();

    for peer_id in connected_peers {
        if peer_block_knowledge.peer_knows_block(peer_id, &block_hash) {
            debug!("Skipping broadcast to peer {peer_id}: already knows block {block_hash}");
        } else {
            debug!("Broadcasting ShareBlock {block_hash} to peer {peer_id}");
            request_sender.send_request(peer_id, Message::ShareBlock(share_block.clone()));
            peer_block_knowledge.record_block_known(peer_id, block_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_sender::MockRequestSender;
    use crate::test_utils::TestShareBlockBuilder;

    #[test]
    fn test_broadcast_to_all_peers() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let peer_c = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let mut knowledge = PeerBlockKnowledge::default();

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .times(3)
            .returning(|_, _| ());

        let connected = vec![peer_a, peer_b, peer_c];
        send_share_block_broadcast(share_block, &connected, &mut knowledge, &mut mock_sender);

        assert!(knowledge.peer_knows_block(&peer_a, &block_hash));
        assert!(knowledge.peer_knows_block(&peer_b, &block_hash));
        assert!(knowledge.peer_knows_block(&peer_c, &block_hash));
    }

    #[test]
    fn test_broadcast_filters_known_peers() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .withf(move |sent_peer_id, _| *sent_peer_id == peer_b)
            .times(1)
            .returning(|_, _| ());

        let connected = vec![peer_a, peer_b];
        send_share_block_broadcast(share_block, &connected, &mut knowledge, &mut mock_sender);

        assert!(knowledge.peer_knows_block(&peer_b, &block_hash));
    }

    #[test]
    fn test_broadcast_skips_all_known_peers() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut knowledge = PeerBlockKnowledge::default();
        knowledge.record_block_known(&peer_a, block_hash);
        knowledge.record_block_known(&peer_b, block_hash);

        let mut mock_sender = MockRequestSender::new();
        mock_sender.expect_send_request().never();

        let connected = vec![peer_a, peer_b];
        send_share_block_broadcast(share_block, &connected, &mut knowledge, &mut mock_sender);
    }

    #[test]
    fn test_broadcast_no_connected_peers() {
        let share_block = TestShareBlockBuilder::new().build();
        let mut knowledge = PeerBlockKnowledge::default();

        let mut mock_sender = MockRequestSender::new();
        mock_sender.expect_send_request().never();

        send_share_block_broadcast(share_block, &[], &mut knowledge, &mut mock_sender);
    }
}
