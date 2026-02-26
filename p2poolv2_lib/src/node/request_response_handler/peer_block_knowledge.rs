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

use bitcoin::BlockHash;
use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};

/// Maximum number of block hashes tracked per peer. When this limit is reached,
/// the oldest entry is evicted (FIFO) before inserting a new one.
const MAX_KNOWN_BLOCKS_PER_PEER: usize = 100;

/// Initial capacity for the peer map, based on expected number of connected peers.
const INITIAL_PEER_CAPACITY: usize = 32;

/// Tracks which block hashes each peer is known to have either
/// through inv or getdata block responses.
///
/// Used to avoid sending redundant inventory messages to peers that already
/// know about a block (either because they sent us the block, or because
/// they sent us an inv announcing it).
///
/// Each peer's knowledge is stored as a bounded VecDeque with FIFO eviction.
/// With at most 100 entries of 32-byte BlockHashes per peer, linear scan
/// via `contains()` is fast and cache-friendly.
pub struct PeerBlockKnowledge {
    known_blocks: HashMap<PeerId, VecDeque<BlockHash>>,
}

impl Default for PeerBlockKnowledge {
    /// Creates an empty PeerBlockKnowledge tracker.
    fn default() -> Self {
        Self {
            known_blocks: HashMap::with_capacity(INITIAL_PEER_CAPACITY),
        }
    }
}

impl PeerBlockKnowledge {
    /// Records that a peer knows about a given block hash.
    ///
    /// If the peer already has this hash recorded, this is a no-op.
    /// If the peer's deque is at capacity, the oldest entry is evicted first.
    pub fn record_block_known(&mut self, peer_id: &PeerId, block_hash: BlockHash) {
        let deque = self
            .known_blocks
            .entry(*peer_id)
            .or_insert_with(|| VecDeque::with_capacity(MAX_KNOWN_BLOCKS_PER_PEER));

        if deque.contains(&block_hash) {
            return;
        }

        if deque.len() >= MAX_KNOWN_BLOCKS_PER_PEER {
            deque.pop_front();
        }

        deque.push_back(block_hash);
    }

    /// Returns true if the peer is known to have the given block hash.
    pub fn peer_knows_block(&self, peer_id: &PeerId, block_hash: &BlockHash) -> bool {
        self.known_blocks
            .get(peer_id)
            .is_some_and(|deque| deque.contains(block_hash))
    }

    /// Removes all tracked knowledge for a peer. Called on disconnect.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.known_blocks.remove(peer_id);
    }
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

    #[test]
    fn test_record_and_query() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();
        let hash = make_block_hash(1);

        assert!(!knowledge.peer_knows_block(&peer, &hash));

        knowledge.record_block_known(&peer, hash);
        assert!(knowledge.peer_knows_block(&peer, &hash));
    }

    #[test]
    fn test_unknown_peer_returns_false() {
        let knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();
        let hash = make_block_hash(1);

        assert!(!knowledge.peer_knows_block(&peer, &hash));
    }

    #[test]
    fn test_unknown_block_returns_false() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();
        let known_hash = make_block_hash(1);
        let unknown_hash = make_block_hash(2);

        knowledge.record_block_known(&peer, known_hash);
        assert!(!knowledge.peer_knows_block(&peer, &unknown_hash));
    }

    #[test]
    fn test_remove_peer() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();
        let hash = make_block_hash(1);

        knowledge.record_block_known(&peer, hash);
        assert!(knowledge.peer_knows_block(&peer, &hash));

        knowledge.remove_peer(&peer);
        assert!(!knowledge.peer_knows_block(&peer, &hash));
    }

    #[test]
    fn test_remove_nonexistent_peer_is_noop() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();
        knowledge.remove_peer(&peer);
    }

    #[test]
    fn test_fifo_eviction() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();

        // Record MAX_KNOWN_BLOCKS_PER_PEER + 1 blocks
        for index in 0..=MAX_KNOWN_BLOCKS_PER_PEER as u8 {
            knowledge.record_block_known(&peer, make_block_hash(index));
        }

        // The first block (index 0) should have been evicted
        assert!(!knowledge.peer_knows_block(&peer, &make_block_hash(0)));

        // The second block (index 1) should still be present
        assert!(knowledge.peer_knows_block(&peer, &make_block_hash(1)));

        // The last block should be present
        assert!(
            knowledge.peer_knows_block(&peer, &make_block_hash(MAX_KNOWN_BLOCKS_PER_PEER as u8))
        );
    }

    #[test]
    fn test_duplicate_insert_is_noop() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer = PeerId::random();

        // Fill to capacity
        for index in 0..MAX_KNOWN_BLOCKS_PER_PEER as u8 {
            knowledge.record_block_known(&peer, make_block_hash(index));
        }

        // Re-insert an existing hash -- should not evict anything
        knowledge.record_block_known(&peer, make_block_hash(0));

        // The first block should still be present (not evicted)
        assert!(knowledge.peer_knows_block(&peer, &make_block_hash(0)));

        // All blocks should still be present
        for index in 0..MAX_KNOWN_BLOCKS_PER_PEER as u8 {
            assert!(knowledge.peer_knows_block(&peer, &make_block_hash(index)));
        }
    }

    #[test]
    fn test_multiple_peers_independent() {
        let mut knowledge = PeerBlockKnowledge::default();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let hash = make_block_hash(1);

        knowledge.record_block_known(&peer_a, hash);

        assert!(knowledge.peer_knows_block(&peer_a, &hash));
        assert!(!knowledge.peer_knows_block(&peer_b, &hash));
    }
}
