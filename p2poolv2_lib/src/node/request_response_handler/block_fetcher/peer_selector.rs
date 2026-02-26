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

//! Round-robin peer selection with per-peer capacity tracking.

use super::MAX_IN_FLIGHT_PER_PEER;
use libp2p::PeerId;
use std::collections::HashMap;

/// Manages peer selection for block fetching using round-robin distribution.
///
/// Uses a single `HashMap<PeerId, usize>` where keys are the known peers
/// and values are their in-flight request counts. The round-robin index
/// advances on each call to `select_peer` so that requests are spread
/// evenly.
pub(super) struct PeerSelector {
    /// Known peers mapped to their in-flight request count.
    peers: HashMap<PeerId, usize>,
    /// Index for round-robin peer selection.
    next_peer_index: usize,
}

impl PeerSelector {
    pub(super) fn new() -> Self {
        Self {
            peers: HashMap::new(),
            next_peer_index: 0,
        }
    }

    /// Replace the peers list with a new set of peers.
    ///
    /// Resets the round-robin index. Peers not in the new list are
    /// removed; new peers start with a count of zero.
    pub(super) fn update_peers(&mut self, new_peers: Vec<PeerId>) {
        self.peers.retain(|peer_id, _| new_peers.contains(peer_id));
        for peer_id in new_peers {
            self.peers.entry(peer_id).or_insert(0);
        }
        self.next_peer_index = 0;
    }

    /// Add a single peer if not already known (starts with count zero).
    pub(super) fn add_peer(&mut self, peer_id: PeerId) {
        self.peers.entry(peer_id).or_insert(0);
    }

    /// Select a peer using round-robin, skipping peers at capacity.
    ///
    /// Returns None if all peers are at capacity or no peers are known.
    pub(super) fn select_peer(&mut self) -> Option<PeerId> {
        let peer_count = self.peers.len();
        if peer_count == 0 {
            return None;
        }

        for _ in 0..peer_count {
            let index = self.next_peer_index % peer_count;
            self.next_peer_index = (self.next_peer_index + 1) % peer_count;

            let (&peer_id, &count) = self.peers.iter().nth(index).unwrap();
            if count < MAX_IN_FLIGHT_PER_PEER {
                return Some(peer_id);
            }
        }
        None
    }

    /// Record that a request was dispatched to a peer (increments count).
    pub(super) fn record_dispatch(&mut self, peer_id: PeerId) {
        if let Some(count) = self.peers.get_mut(&peer_id) {
            *count += 1;
        }
    }

    /// Record that a request completed for a peer (decrements count).
    pub(super) fn record_completion(&mut self, peer_id: PeerId) {
        if let Some(count) = self.peers.get_mut(&peer_id) {
            *count = count.saturating_sub(1);
        }
    }

    /// Returns true if there are known peers.
    pub(super) fn has_peers(&self) -> bool {
        !self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_selector_no_peers_returns_none() {
        let mut selector = PeerSelector::new();
        assert!(!selector.has_peers());
        assert!(selector.select_peer().is_none());
    }

    #[test]
    fn test_peer_selector_round_robin() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        selector.update_peers(vec![peer_a, peer_b]);

        assert!(selector.has_peers());

        // Two consecutive selections should return different peers
        let first = selector.select_peer().unwrap();
        let second = selector.select_peer().unwrap();
        assert_ne!(first, second, "round-robin should alternate between peers");
        assert!(
            (first == peer_a || first == peer_b) && (second == peer_a || second == peer_b),
            "both selections must be known peers"
        );

        // Third selection wraps around to the first peer again
        let third = selector.select_peer().unwrap();
        assert_eq!(third, first);
    }

    #[test]
    fn test_peer_selector_skips_peer_at_capacity() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        selector.update_peers(vec![peer_a, peer_b]);

        // Fill peer_a to capacity
        for _ in 0..MAX_IN_FLIGHT_PER_PEER {
            selector.record_dispatch(peer_a);
        }

        // All selections should return peer_b since peer_a is at capacity
        let selected = selector.select_peer().unwrap();
        assert_eq!(selected, peer_b);
    }

    #[test]
    fn test_peer_selector_all_at_capacity_returns_none() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        selector.update_peers(vec![peer_a, peer_b]);

        // Fill both to capacity
        for _ in 0..MAX_IN_FLIGHT_PER_PEER {
            selector.record_dispatch(peer_a);
            selector.record_dispatch(peer_b);
        }

        assert!(selector.select_peer().is_none());
    }

    #[test]
    fn test_peer_selector_record_completion_frees_capacity() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        selector.update_peers(vec![peer_a]);

        // Fill to capacity
        for _ in 0..MAX_IN_FLIGHT_PER_PEER {
            selector.record_dispatch(peer_a);
        }
        assert!(selector.select_peer().is_none());

        // Free one slot
        selector.record_completion(peer_a);
        assert_eq!(selector.select_peer().unwrap(), peer_a);
    }

    #[test]
    fn test_peer_selector_add_peer_no_duplicates() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();

        selector.add_peer(peer_a);
        selector.add_peer(peer_a);

        // Should still have exactly one peer -- selecting twice wraps around
        let first = selector.select_peer().unwrap();
        let second = selector.select_peer().unwrap();
        assert_eq!(first, peer_a);
        assert_eq!(second, peer_a);
    }

    #[test]
    fn test_peer_selector_update_peers_cleans_counts() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        selector.update_peers(vec![peer_a, peer_b]);

        // Fill peer_a to capacity
        for _ in 0..MAX_IN_FLIGHT_PER_PEER {
            selector.record_dispatch(peer_a);
        }

        // Replace peers -- peer_a is removed, its counts should be cleaned
        let peer_c = PeerId::random();
        selector.update_peers(vec![peer_b, peer_c]);

        // Both peer_b and peer_c should be selectable
        let first = selector.select_peer().unwrap();
        let second = selector.select_peer().unwrap();
        assert_ne!(first, second, "should select both peers");
        let selected_set: std::collections::HashSet<PeerId> = [first, second].into_iter().collect();
        let expected_set: std::collections::HashSet<PeerId> =
            [peer_b, peer_c].into_iter().collect();
        assert_eq!(selected_set, expected_set);
    }

    #[test]
    fn test_peer_selector_completion_saturates_at_zero() {
        let mut selector = PeerSelector::new();
        let peer_a = PeerId::random();
        selector.update_peers(vec![peer_a]);

        // Complete without any dispatches -- should not underflow
        selector.record_completion(peer_a);
        selector.record_completion(peer_a);

        // Peer should still be selectable
        assert_eq!(selector.select_peer().unwrap(), peer_a);
    }
}
