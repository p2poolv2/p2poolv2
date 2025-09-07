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

//! Worker statistics management for P2Pool accounting
//!
//! This module provides functionality for tracking and managing worker statistics
//! in the P2Pool mining ecosystem. It handles:
//!
//! - Worker identification through unique IDs derived from usernames and worker names
//! - Hash rate tracking across multiple time windows
//! - Share submission statistics including valid and stale shares
//!
//! Worker records serve as the basis for tracking individual miner performance
//! and calculating rewards distribution using the accounting modules.

use bitcoin::hashes::{Hash, sha256};
use serde::{Deserialize, Serialize};

/// Worker record, captures username, id, and hashrate stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    /// Unique identifier for the user, a hash of the user's username
    #[serde(skip)]
    pub id: [u8; 32],
    /// Worker name as provided by the user
    pub workername: String,
    /// Timestamp of the last share submitted by the worker, time since epoch in ms
    pub last_share_at: u64,
    /// Difficulty share per second 1min window
    pub share_per_second_1min: u32,
    /// Difficulty share per second 5min window
    pub share_per_second_5min: u32,
    /// Difficulty share per second 1h window
    pub share_per_second_1h: u32,
    /// Difficulty share per second 24h window
    pub share_per_second_24h: u32,
    /// Difficulty share per second 7d window
    pub share_per_second_7d: u32,
    /// Valid share submissions
    pub shares_valid: u32,
    /// Stale share submissions
    pub shares_stale: u32,
}

impl Worker {
    /// Create a new worker record for a new signing up worker.
    pub fn new(username: String, workername: String) -> Self {
        let hash: [u8; 32] = generate_worker_id(&username, &workername);
        Worker {
            id: hash,
            workername,
            last_share_at: 0,
            share_per_second_1min: 0,
            share_per_second_5min: 0,
            share_per_second_1h: 0,
            share_per_second_24h: 0,
            share_per_second_7d: 0,
            shares_valid: 0,
            shares_stale: 0,
        }
    }
}

/// Generate an id for the a given Bitcoin address to be used as user id.
pub fn generate_worker_id(username: &str, workername: &str) -> [u8; 32] {
    sha256::Hash::hash(format!("{username}:{workername}").as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_creation() {
        let worker = Worker::new("user1".to_string(), "worker1".to_string());

        // Verify the ID is calculated correctly
        let expected_id = sha256::Hash::hash(format!("user1:worker1").as_bytes()).to_byte_array();
        assert_eq!(worker.id, expected_id);

        // Verify default values
        assert_eq!(worker.last_share_at, 0);
        assert_eq!(worker.share_per_second_1min, 0);
        assert_eq!(worker.share_per_second_5min, 0);
        assert_eq!(worker.share_per_second_1h, 0);
        assert_eq!(worker.share_per_second_24h, 0);
        assert_eq!(worker.share_per_second_7d, 0);
        assert_eq!(worker.shares_valid, 0);
        assert_eq!(worker.shares_stale, 0);
    }
}
