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
