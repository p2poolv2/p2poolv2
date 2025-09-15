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

use crate::stats::computed::ComputedHashrate;
use serde::{Deserialize, Serialize};

/// Worker record, captures username, id, and hashrate stats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Worker {
    /// Timestamp of the last share submitted by the worker, time since epoch in ms
    pub last_share_at: u64,
    /// Valid share submissions
    pub shares_valid: u32,
    /// Active state
    pub active: bool,
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

impl Default for Worker {
    fn default() -> Self {
        Self {
            last_share_at: 0,
            shares_valid: 0,
            active: true,
            best_share: 0,
            best_share_ever: None,
            computed_hash_rate: ComputedHashrate::default(),
            unaccounted_difficulty: 0,
        }
    }
}

impl Worker {
    /// Create a new worker record for a new signing up worker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a share submission for the worker, updating stats accordingly.
    pub fn record_share(&mut self, difficulty: u64, unix_timestamp: u64) {
        self.last_share_at = unix_timestamp;
        self.shares_valid += 1;
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
    }

    pub fn reset(&mut self) {
        self.unaccounted_difficulty = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_creation() {
        let worker = Worker::default();

        // Verify default values
        assert_eq!(worker.last_share_at, 0);
        assert_eq!(worker.computed_hash_rate.hashrate_1m, 0);
        assert_eq!(worker.computed_hash_rate.hashrate_5m, 0);
        assert_eq!(worker.computed_hash_rate.hashrate_1hr, 0);
        assert_eq!(worker.computed_hash_rate.hashrate_6hr, 0);
        assert_eq!(worker.computed_hash_rate.hashrate_1d, 0);
        assert_eq!(worker.shares_valid, 0);
    }

    #[test]
    fn test_record_share_updates_stats() {
        let mut worker = Worker::default();
        let timestamp = 1_650_000_000_000;
        let difficulty = 1000;

        // Initial state
        assert_eq!(worker.last_share_at, 0);
        assert_eq!(worker.shares_valid, 0);
        assert_eq!(worker.best_share, 0);
        assert_eq!(worker.best_share_ever, None);

        // First share
        worker.record_share(difficulty, timestamp);
        assert_eq!(worker.last_share_at, timestamp);
        assert_eq!(worker.shares_valid, 1);
        assert_eq!(worker.best_share, difficulty);
        assert_eq!(worker.best_share_ever, Some(difficulty));

        /// New best share
        worker.record_share(2000, timestamp + 1000);
        assert_eq!(worker.last_share_at, timestamp + 1000);
        assert_eq!(worker.shares_valid, 2);
        assert_eq!(worker.best_share, 2000);
        assert_eq!(worker.best_share_ever, Some(2000));

        // Submit a lower difficulty share, best_share and best_share_ever should not change
        worker.record_share(500, timestamp + 2000);
        assert_eq!(worker.last_share_at, timestamp + 2000);
        assert_eq!(worker.shares_valid, 3);
        assert_eq!(worker.best_share, 2000);
        assert_eq!(worker.best_share_ever, Some(2000));
    }
}
