// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::behaviour::P2PoolBehaviour;
use crate::node::messages::Message;
use libp2p::{PeerId, Swarm};

/// Trait for sending request-response messages directly via the swarm.
///
/// Abstracts the `swarm.behaviour_mut().request_response.send_request()`
/// call so that sender functions can be tested without a real swarm.
#[cfg_attr(test, mockall::automock)]
pub trait RequestSender {
    fn send_request(&mut self, peer_id: &PeerId, message: Message);
}

impl RequestSender for Swarm<P2PoolBehaviour> {
    fn send_request(&mut self, peer_id: &PeerId, message: Message) {
        self.behaviour_mut()
            .request_response
            .send_request(peer_id, message);
    }
}
