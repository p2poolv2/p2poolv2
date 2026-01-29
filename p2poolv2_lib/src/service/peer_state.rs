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

/*!
 * [PeerState] exists to store information of how to communicate with a peer
 */

use std::{collections::HashMap, fmt::Display, ops::Deref, sync::Arc};

use crate::node::bip152::CompactBlockRelay;
use libp2p::PeerId;
use parking_lot::{RawRwLock, lock_api::RwLock};

pub type PeerStates = RwLock<RawRwLock, HashMap<PeerId, Arc<PeerState>>>;

/// The state of a p2p peer. Equivalent to CNode.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub id: PeerId,
    /// Whether we should send compact blocks
    pub compact_block_to: Option<CompactBlockRelay>,
    /// Whether we should expect compact blocks
    pub compact_block_from: Option<CompactBlockRelay>,
}

impl PeerState {
    pub fn new(id: PeerId) -> Self {
        Self {
            id,
            compact_block_to: Default::default(),
            compact_block_from: Default::default(),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn random() -> Self {
        Self::new(PeerId::random())
    }
}

impl Display for PeerState {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerState({}, {:?})", self.id, self.compact_block_to)
    }
}

impl Into<PeerState> for PeerId {
    #[inline]
    fn into(self) -> PeerState {
        PeerState::new(self)
    }
}

impl Deref for PeerState {
    type Target = libp2p::PeerId;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.id
    }
}
