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
use tokio::sync::RwLock;

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug, Default)]
pub struct PoolMetrics {
    /// Tracks the number of shares since last stats update
    pub unaccounted_shares: u64,
    /// Tracks the total difficulty since last stats update
    pub unaccounted_difficulty: u64,
    /// Tracks the number of rejected shares since last stats update
    pub unaccounted_rejected: u64,
    /// Tracks the total number of users
    pub num_users: u32,
    /// Tracks the number of idle workers
    pub num_idle_workers: u32,
    /// Tracks the number of disconnected workers
    pub num_disconnected_workers: u32,
    /// Timestamp for last share received
    pub last_share_at: Option<std::time::Instant>,
}

impl PoolMetrics {
    /// Create a new PoolMetrics instance with all values initialized to zero
    pub fn new() -> Self {
        PoolMetrics::default()
    }

    /// Reset the metrics to their initial state
    pub fn reset(&mut self) {
        *self = PoolMetrics::default();
    }

    pub fn record_share_accepted(&mut self, difficulty: u64) {
        self.unaccounted_shares += 1;
        self.unaccounted_difficulty += difficulty;
        self.last_share_at = Some(std::time::Instant::now());
    }

    pub fn record_share_rejected(&mut self) {
        self.unaccounted_rejected += 1;
    }
}

pub type PoolMetricsWithGuard = Arc<RwLock<PoolMetrics>>;

/// Construct a new pool metrics with rw lock and arc wrappers
pub fn build_metrics() -> PoolMetricsWithGuard {
    Arc::new(RwLock::new(PoolMetrics::default()))
}
