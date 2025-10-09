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

use crate::accounting::stats::computed::ComputedHashrate;
use crate::accounting::stats::worker::Worker;
use bitcoin::hashes::{Hash, sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const INITIAL_WORKER_MAP_CAPACITY: usize = 10;

/// User record, captures username, id, and hashrate stats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// Timestamp of the last share submitted by the user, time since epoch in ms
    pub last_share_at: u64,
    /// Valid share submissions
    pub shares_valid_total: u32,
    /// Workers for the user, we maintain list of disconnected workers for persistent stats
    pub workers: HashMap<String, Worker>,
    /// Best share in this instance of the server
    pub best_share: u64,
    /// Best ever share, loaded from disk on startup
    pub best_share_ever: Option<u64>,
    /// Unaccounted for difficulty
    #[serde(skip)]
    pub unaccounted_difficulty: u64,
    /// Computed stats holding hashrate and share rate metrics
    pub computed_hash_rate: ComputedHashrate,
}

impl Default for User {
    fn default() -> Self {
        User {
            last_share_at: 0,
            shares_valid_total: 0,
            workers: HashMap::with_capacity(INITIAL_WORKER_MAP_CAPACITY),
            best_share: 0,
            best_share_ever: None,
            computed_hash_rate: ComputedHashrate::default(),
            unaccounted_difficulty: 0,
        }
    }
}

impl User {
    /// Get a mutable reference to a worker by name, if it exists.
    pub fn get_worker_mut(&mut self, workername: &str) -> Option<&mut Worker> {
        self.workers.get_mut(workername)
    }

    /// Record a share submission for the user, updating stats accordingly.
    pub fn record_share(&mut self, workername: &str, difficulty: u64, current_time_stamp: u64) {
        self.last_share_at = current_time_stamp;
        self.shares_valid_total += 1;
        self.unaccounted_difficulty += difficulty;
        if difficulty > self.best_share {
            self.best_share = difficulty;
        }
        if let Some(best_ever) = self.best_share_ever {
            if difficulty > best_ever {
                self.best_share_ever = Some(difficulty);
            }
        } else {
            self.best_share_ever = Some(difficulty);
        }

        let worker = self.get_or_add_worker(workername);
        worker.record_share(difficulty, current_time_stamp);
    }

    /// Get a mutable reference to a worker by name, adding it if it doesn't exist.
    pub fn get_or_add_worker(&mut self, workername: &str) -> &mut Worker {
        self.workers.entry(workername.to_string()).or_default()
    }

    pub fn reset(&mut self) {
        self.unaccounted_difficulty = 0;
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
        let user = User::default();

        // Verify default values
        assert_eq!(user.last_share_at, 0);
        assert_eq!(user.computed_hash_rate.hashrate_1m, 0);
        assert_eq!(user.computed_hash_rate.hashrate_5m, 0);
        assert_eq!(user.computed_hash_rate.hashrate_1hr, 0);
        assert_eq!(user.computed_hash_rate.hashrate_6hr, 0);
        assert_eq!(user.computed_hash_rate.hashrate_1d, 0);
        assert!(user.workers.capacity() >= INITIAL_WORKER_MAP_CAPACITY);
        assert_eq!(user.workers.len(), 0);
    }

    #[test]
    fn test_record_share_updates_stats_and_worker() {
        let worker_name = "worker1";
        let mut user = User::default();

        // Initial state
        assert_eq!(user.shares_valid_total, 0);
        assert_eq!(user.best_share, 0);
        assert_eq!(user.best_share_ever, None);
        assert_eq!(user.workers.len(), 0);

        // Record a share
        let difficulty = 1000;
        let timestamp = 1234567890;
        user.record_share(worker_name, difficulty, timestamp);

        // User stats updated
        assert_eq!(user.shares_valid_total, 1);
        assert_eq!(user.last_share_at, timestamp);
        assert_eq!(user.best_share, difficulty);
        assert_eq!(user.best_share_ever, Some(difficulty));
        assert_eq!(user.workers.len(), 1);

        // Worker stats updated
        let worker = user.workers.get(worker_name).unwrap();
        assert_eq!(worker.last_share_at, timestamp);
        assert_eq!(worker.shares_valid_total, 1);
        assert_eq!(worker.best_share, difficulty);
        assert_eq!(worker.best_share_ever, Some(difficulty));

        // Record a lower difficulty share
        user.record_share(worker_name, 500, timestamp + 1);
        assert_eq!(user.shares_valid_total, 2);
        assert_eq!(user.best_share, difficulty); // unchanged
        assert_eq!(user.best_share_ever, Some(difficulty));
        let worker = user.workers.get(worker_name).unwrap();
        assert_eq!(worker.shares_valid_total, 2);
        assert_eq!(worker.best_share, difficulty);

        // Record a higher difficulty share
        user.record_share(worker_name, 2000, timestamp + 2);
        assert_eq!(user.shares_valid_total, 3);
        assert_eq!(user.best_share, 2000);
        assert_eq!(user.best_share_ever, Some(2000));
        let worker = user.workers.get(worker_name).unwrap();
        assert_eq!(worker.shares_valid_total, 3);
        assert_eq!(worker.best_share, 2000);
    }

    #[test]
    fn test_multiple_workers() {
        let mut user = User::default();

        user.record_share("worker1", 100, 1);
        user.record_share("worker2", 200, 2);

        assert_eq!(user.workers.len(), 2);

        let worker1 = user.workers.get("worker1").unwrap();
        let worker2 = user.workers.get("worker2").unwrap();

        assert_eq!(worker1.shares_valid_total, 1);
        assert_eq!(worker1.best_share, 100);
        assert_eq!(worker2.shares_valid_total, 1);
        assert_eq!(worker2.best_share, 200);
    }

    #[test]
    fn test_get_worker_mut_and_get_or_add_worker() {
        let mut user = User::default();

        // Should not exist yet
        assert!(user.get_worker_mut("worker1").is_none());

        // Add worker
        let worker = user.get_or_add_worker("worker1");
        assert_eq!(worker.shares_valid_total, 0);

        // Now should exist
        let worker_mut = user.get_worker_mut("worker1").unwrap();
        worker_mut.shares_valid_total = 42;
        assert_eq!(user.workers.get("worker1").unwrap().shares_valid_total, 42);
    }
}
