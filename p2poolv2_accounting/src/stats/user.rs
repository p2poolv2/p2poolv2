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

//! User management and statistics for P2Poolv2.
//!
//! This module provides functionality for tracking users and their mining statistics.
//! It includes mechanisms for:
//!
//! - Creating and managing user records
//! - Tracking user hashrate across various time windows
//! - Managing user workers
//! - Generating unique user IDs from Bitcoin addresses
//!
//! User statistics are maintained in memory during runtime and are persisted
//! to disk every 5 minutes.

use crate::stats::worker::Worker;
use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const INITIAL_WORKER_MAP_CAPACITY: usize = 10;

/// User record, captures username, id, and hashrate stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user, a hash of the user's username
    #[serde(skip)]
    pub id: [u8; 32],
    /// Timestamp of the last share submitted by the user, time since epoch in ms
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
    /// Workers for the user, we maintain list of disconnected workers for persistent stats
    pub workers: HashMap<String, Worker>,
}

impl User {
    /// Create a new user record for a new signing up user.
    ///
    /// A user with a given bitcoin address will always have the same id and
    /// therefore we'll be able to load the historical shares from the data store.
    ///
    /// On server restarts the stats will be forgotten in the new process, even though the stats views can load the last stats from disk.
    pub fn new(btcaddress: &str) -> Self {
        let hash: [u8; 32] = generate_user_id(btcaddress);
        User {
            id: hash,
            last_share_at: 0,
            share_per_second_1min: 0,
            share_per_second_5min: 0,
            share_per_second_1h: 0,
            share_per_second_24h: 0,
            share_per_second_7d: 0,
            shares_valid: 0,
            shares_stale: 0,
            workers: HashMap::with_capacity(INITIAL_WORKER_MAP_CAPACITY),
        }
    }
}

/// Generate an id for the a given Bitcoin address to be used as user id.
pub fn generate_user_id(btcaddress: &str) -> [u8; 32] {
    sha256::Hash::hash(btcaddress.as_bytes()).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let btc_address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let user = User::new(btc_address);

        // Verify the ID is calculated correctly
        let expected_id = sha256::Hash::hash(btc_address.as_bytes()).to_byte_array();
        assert_eq!(user.id, expected_id);

        // Verify default values
        assert_eq!(user.last_share_at, 0);
        assert_eq!(user.share_per_second_1min, 0);
        assert_eq!(user.share_per_second_5min, 0);
        assert_eq!(user.share_per_second_1h, 0);
        assert_eq!(user.share_per_second_24h, 0);
        assert_eq!(user.share_per_second_7d, 0);
        assert!(user.workers.capacity() >= INITIAL_WORKER_MAP_CAPACITY);
        assert_eq!(user.workers.len(), 0);
    }
}
