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

use serde::{Deserialize, Serialize};

/// Workers inactive for longer than this are removed from stats.
pub const WORKER_EXPIRY_SECS: u64 = 6 * 60 * 60;

/// Worker record, captures username, id, and hashrate stats
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Worker {
    /// Timestamp of the last share submitted by the worker, time since epoch in ms
    pub last_share_at: u64,
    /// Valid share submissions
    pub shares_valid_total: u64,
    /// Active state
    pub active: bool,
    /// Best share in this instance of the server
    pub best_share: u64,
    /// Best ever share, loaded from disk on startup
    pub best_share_ever: u64,
}

impl Worker {
    /// Create a new worker record for a new signing up worker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if worker should be removed from stats.
    /// A worker is removed if it never submitted a share, or if it is inactive
    /// and its last share was more than 6 hours ago.
    pub fn should_remove(&self, current_time: u64) -> bool {
        if self.last_share_at == 0 {
            return true;
        }
        !self.active && current_time.saturating_sub(self.last_share_at) > WORKER_EXPIRY_SECS
    }

    /// Record a share submission for the worker, updating stats accordingly.
    pub fn record_share(&mut self, difficulty: u64, truediff: u64, unix_timestamp: u64) {
        self.last_share_at = unix_timestamp;
        self.shares_valid_total += difficulty;

        self.best_share = self.best_share.max(truediff);
        self.best_share_ever = self.best_share_ever.max(truediff);

        self.active = true;
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
        assert_eq!(worker.shares_valid_total, 0);
    }

    #[test]
    fn test_record_share_updates_stats() {
        let mut worker = Worker::default();
        let timestamp = 1_650_000_000_000;
        let difficulty = 1000;

        // Initial state
        assert_eq!(worker.last_share_at, 0);
        assert_eq!(worker.shares_valid_total, 0);
        assert_eq!(worker.best_share, 0);
        assert_eq!(worker.best_share_ever, 0);
        assert!(!worker.active);

        // First share
        worker.record_share(difficulty, 1100, timestamp);

        assert_eq!(worker.last_share_at, timestamp);
        assert_eq!(worker.shares_valid_total, 1000);
        assert_eq!(worker.best_share, 1100);
        assert_eq!(worker.best_share_ever, 1100);
        assert!(worker.active);

        // New best share
        worker.record_share(2000, 2200, timestamp + 1000);
        assert_eq!(worker.last_share_at, timestamp + 1000);
        assert_eq!(worker.shares_valid_total, 3000);
        assert_eq!(worker.best_share, 2200);
        assert_eq!(worker.best_share_ever, 2200);

        // Submit a lower difficulty share, best_share and best_share_ever should not change
        worker.record_share(500, 550, timestamp + 2000);
        assert_eq!(worker.last_share_at, timestamp + 2000);
        assert_eq!(worker.shares_valid_total, 3500);
        assert_eq!(worker.best_share, 2200);
        assert_eq!(worker.best_share_ever, 2200);
    }

    #[test]
    fn test_should_remove() {
        let base_time = 1_000_000u64;

        // Worker that never submitted a share should be removed
        let fresh_worker = Worker::default();
        assert!(fresh_worker.should_remove(base_time));

        // Active worker should not be removed
        let mut active_worker = Worker::default();
        active_worker.record_share(1000, 1100, base_time);
        assert!(!active_worker.should_remove(base_time + WORKER_EXPIRY_SECS + 1));

        // Inactive worker within grace period should not be removed
        let mut recent_inactive = Worker::default();
        recent_inactive.record_share(1000, 1100, base_time);
        recent_inactive.active = false;
        assert!(!recent_inactive.should_remove(base_time + WORKER_EXPIRY_SECS - 1));

        // Inactive worker past grace period should be removed
        assert!(recent_inactive.should_remove(base_time + WORKER_EXPIRY_SECS + 1));
    }
}
