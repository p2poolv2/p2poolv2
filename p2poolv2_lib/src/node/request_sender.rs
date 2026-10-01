// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::behaviour::P2PoolBehaviour;
use crate::node::messages::Message;
use libp2p::{PeerId, Swarm};
use tracing::{debug, error};

/// Trait for driving the swarm directly from the node's event loop.
///
/// Abstracts the swarm calls (`send_request`, `disconnect_peer_id`) so that the
/// request-response handler can perform them synchronously -- without awaiting a
/// send on `swarm_tx`, which the loop itself drains -- and so they can be tested
/// against a mock rather than a real swarm.
#[cfg_attr(test, mockall::automock)]
pub trait RequestSender {
    fn send_request(&mut self, peer_id: &PeerId, message: Message);
    fn disconnect_peer(&mut self, peer_id: PeerId);
}

impl RequestSender for Swarm<P2PoolBehaviour> {
    fn send_request(&mut self, peer_id: &PeerId, message: Message) {
        self.behaviour_mut()
            .request_response
            .send_request(peer_id, message);
    }

    fn disconnect_peer(&mut self, peer_id: PeerId) {
        if self.disconnect_peer_id(peer_id).is_err() {
            error!("Error disconnecting peer {peer_id}");
        } else {
            debug!("Disconnected peer: {peer_id}");
        }
    }
}
