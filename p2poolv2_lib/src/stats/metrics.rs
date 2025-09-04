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

use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug)]
pub struct PoolMetrics {
    /// Tracks the number of shares since last stats update
    pub unaccounted_shares: u64,
    /// Tracks the total difficulty since last stats update
    pub unaccounted_difficulty: u64,
    /// Tracks the number of rejected shares since last stats update
    pub unaccounted_rejected: u64,
    /// Tracks the total number of users
    pub num_users: u32,
    /// Tracks the number of workers
    pub num_workers: u32,
    /// Tracks the number of disconnected workers
    pub num_disconnected_workers: u32,
    /// Timestamp for last share received
    pub last_share_at: Option<std::time::SystemTime>,
    /// Start time
    pub start_time: std::time::Instant,
    /// Highest difficulty share
    pub highest_share_difficulty: u64,
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            unaccounted_shares: 0,
            unaccounted_difficulty: 0,
            unaccounted_rejected: 0,
            num_users: 0,
            num_workers: 0,
            num_disconnected_workers: 0,
            last_share_at: None,
            start_time: std::time::Instant::now(),
            highest_share_difficulty: 0,
        }
    }
}

impl PoolMetrics {
    /// Reset metrics to their default values using default
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Update metrics from accepted share
    pub fn record_share_accepted(&mut self, difficulty: u64) {
        self.unaccounted_shares += 1;
        self.unaccounted_difficulty += difficulty;
        self.last_share_at = Some(SystemTime::now());
        if self.highest_share_difficulty < difficulty {
            self.highest_share_difficulty = difficulty;
        }
    }

    /// Update metrics from rejected share
    pub fn record_share_rejected(&mut self) {
        self.unaccounted_rejected += 1;
    }

    /// Commit metrics
    /// Export current metrics as json, returning the serialized json
    /// Reset the metrics to start again
    pub fn commit(&mut self) -> String {
        let lastupdate = match self.last_share_at {
            Some(time) => time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            None => 0,
        };
        let json = serde_json::json!({
            "runtime": self.start_time.elapsed().as_secs(),
            "lastupdate": lastupdate
        });

        self.reset();
        serde_json::to_string(&json).unwrap()
    }
}

pub type PoolMetricsWithGuard = Arc<RwLock<PoolMetrics>>;

/// Construct a new pool metrics with rw lock and arc wrappers
pub fn build_metrics() -> PoolMetricsWithGuard {
    Arc::new(RwLock::new(PoolMetrics::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant, SystemTime};

    #[test]
    fn test_pool_metrics_default() {
        let metrics = PoolMetrics::default();
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 0);
        assert_eq!(metrics.num_workers, 0);
        assert_eq!(metrics.num_disconnected_workers, 0);
        assert!(metrics.last_share_at.is_none());
        assert!(metrics.highest_share_difficulty == 0);
    }

    #[test]
    fn test_pool_metrics_reset() {
        let mut metrics = PoolMetrics::default();
        metrics.unaccounted_shares = 10;
        metrics.unaccounted_difficulty = 1000;
        metrics.unaccounted_rejected = 5;
        metrics.num_users = 3;
        metrics.num_workers = 5;
        metrics.num_disconnected_workers = 2;
        metrics.last_share_at = Some(SystemTime::now());
        metrics.highest_share_difficulty = 500;

        metrics.reset();

        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 0);
        assert_eq!(metrics.num_workers, 0);
        assert_eq!(metrics.num_disconnected_workers, 0);
        assert!(metrics.last_share_at.is_none());
        assert_eq!(metrics.highest_share_difficulty, 0);
    }

    #[test]
    fn test_build_metrics() {
        let metrics = build_metrics();
        let metrics_guard = metrics.try_read().unwrap();
        assert_eq!(metrics_guard.unaccounted_shares, 0);
        assert_eq!(metrics_guard.unaccounted_difficulty, 0);
        assert_eq!(metrics_guard.unaccounted_rejected, 0);
    }

    #[test]
    fn test_record_share_accepted() {
        let mut metrics = PoolMetrics::default();
        metrics.record_share_accepted(100);
        assert_eq!(metrics.unaccounted_shares, 1);
        assert_eq!(metrics.unaccounted_difficulty, 100);
        assert!(metrics.last_share_at.is_some());
        assert_eq!(metrics.highest_share_difficulty, 100);

        // Test that highest difficulty is updated correctly
        metrics.record_share_accepted(50);
        assert_eq!(metrics.unaccounted_shares, 2);
        assert_eq!(metrics.unaccounted_difficulty, 150);
        assert_eq!(metrics.highest_share_difficulty, 100);

        metrics.record_share_accepted(200);
        assert_eq!(metrics.unaccounted_shares, 3);
        assert_eq!(metrics.unaccounted_difficulty, 350);
        assert_eq!(metrics.highest_share_difficulty, 200);
    }

    #[test]
    fn test_record_share_rejected() {
        let mut metrics = PoolMetrics::default();
        metrics.record_share_rejected();
        assert_eq!(metrics.unaccounted_rejected, 1);
        metrics.record_share_rejected();
        assert_eq!(metrics.unaccounted_rejected, 2);
    }

    #[test]
    fn test_commit() {
        let mut metrics = PoolMetrics::default();

        // Set up a known start time for testing
        let start_time = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap();
        metrics.start_time = start_time;

        metrics.record_share_accepted(100);
        metrics.record_share_accepted(200);
        metrics.record_share_rejected();

        let json_str = metrics.commit();
        let json: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Check runtime is approximately 1 hour (3600 seconds)
        let runtime = json["runtime"].as_u64().unwrap();
        assert!(
            runtime >= 3595 && runtime <= 3605,
            "Runtime is not close to 3600: {}",
            runtime
        );

        // Check that lastupdate exists and is a recent timestamp
        assert!(json["lastupdate"].as_u64().is_some());

        // After commit, the metrics should be reset
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.highest_share_difficulty, 0);
    }
}
