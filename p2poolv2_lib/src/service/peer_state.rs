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

use std::{collections::HashMap, fmt::Debug, fmt::Display, ops::Deref, sync::Arc};

use crate::node::bip152::CompactBlockRelay;
use libp2p::PeerId;
use parking_lot::{Mutex, RwLock};

#[derive(Default)]
pub struct PeerStates {
    inner: RwLock<HashMap<PeerId, Arc<Mutex<PeerState>>>>,
}

impl PeerStates {
    pub fn all(&self) -> Vec<Arc<PeerState>> {
        let peers: Vec<Arc<Mutex<PeerState>>> = self.inner.read().values().cloned().collect();
        peers
            .into_iter()
            .map(|peer| Arc::new(peer.lock().clone()))
            .collect()
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<Arc<PeerState>> {
        let peer = self.inner.read().get(peer_id).cloned();
        peer.map(|peer| Arc::new(peer.lock().clone()))
    }

    pub fn get_or_insert(&self, peer_id: &PeerId) -> Arc<PeerState> {
        let peer = {
            let mut peers = self.inner.write();
            let peer_id = *peer_id;
            peers
                .entry(peer_id)
                .or_insert_with(|| Arc::new(Mutex::new(PeerState::new(peer_id))))
                .clone()
        };
        Arc::new(peer.lock().clone())
    }

    pub fn remove(&self, peer_id: &PeerId) -> bool {
        self.inner.write().remove(peer_id).is_some()
    }

    pub fn update(&self, peer_id: PeerId, mut mutator: PeerStateMutation) -> bool {
        let peer = self.inner.read().get(&peer_id).cloned();
        match peer {
            Some(peer) => {
                mutator.0(&mut peer.lock());
                true
            }
            None => false,
        }
    }
}

pub struct PeerStateMutation(pub Box<dyn FnMut(&mut PeerState) + Send + Sync>);

impl Debug for PeerStateMutation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PeerStateMutation").finish()
    }
}

/// The state of a p2p peer. Equivalent to CNode.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub id: PeerId,
    /// Whether we should send compact blocks
    pub compact_block_to: CompactBlockRelay,
    /// Whether we should expect compact blocks
    pub compact_block_from: CompactBlockRelay,
}

impl PeerState {
    pub fn new(id: PeerId) -> Self {
        Self {
            id,
            compact_block_to: CompactBlockRelay::Disabled,
            compact_block_from: CompactBlockRelay::Disabled,
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

impl From<PeerId> for PeerState {
    #[inline]
    fn from(val: PeerId) -> Self {
        PeerState::new(val)
    }
}

impl Deref for PeerState {
    type Target = libp2p::PeerId;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.id
    }
}
