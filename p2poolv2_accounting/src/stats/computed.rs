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

use crate::calc;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use tracing::debug;

const HASHES_PER_SHARE: u64 = 2_u64.pow(32);

/// Struct to hold computed statistics like hashrate over various time windows
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputedStats {
    /// Hashrate in H/s over the last 1 minute
    pub hashrate_1m: u64,
    /// Hashrate in H/s over the last 5 minutes
    pub hashrate_5m: u64,
    /// Hashrate in H/s over the last 15 minutes
    pub hashrate_15m: u64,
    /// Hashrate in H/s over the last 1 hour
    pub hashrate_1hr: u64,
    /// Hashrate in H/s over the last 6 hours
    pub hashrate_6hr: u64,
    /// Hashrate in H/s over the last 1 day
    pub hashrate_1d: u64,
    /// Hashrate in H/s over the last 7 days
    pub hashrate_7d: u64,
    /// Shares per second over the last 1 minute
    pub shares_per_second_1m: u64,
    /// Shares per second over the last 5 minutes
    pub shares_per_second_5m: u64,
    /// Shares per second over the last 15 minutes
    pub shares_per_second_15m: u64,
    /// Shares per second over the last 1 hour
    pub shares_per_second_1h: u64,
}

impl ComputedStats {
    /// Compute hashrate for various windows based on the shares received
    /// Decay the hashrate using the exponential decay from calc::decay_time.
    /// The decay is since the last update
    pub fn set_hashrate_metrics(&mut self, lastupdate: Option<u64>, unaccounted_difficulty: u64) {
        let time_since_last_update = if let Some(lastupdate) = lastupdate {
            calc::sane_time_diff(
                SystemTime::now(),
                Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(lastupdate)),
            ) as u64
        } else {
            0
        };
        debug!("Time since last update: {}", time_since_last_update);
        if time_since_last_update == 0 {
            return;
        }
        self.hashrate_1m = calculate_metric_with_decay(
            self.hashrate_1m,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            60,
        );
        self.hashrate_5m = calculate_metric_with_decay(
            self.hashrate_5m,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            300,
        );
        self.hashrate_15m = calculate_metric_with_decay(
            self.hashrate_15m,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            900,
        );
        self.hashrate_1hr = calculate_metric_with_decay(
            self.hashrate_1hr,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            3600,
        );
        self.hashrate_6hr = calculate_metric_with_decay(
            self.hashrate_6hr,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            21600,
        );
        self.hashrate_1d = calculate_metric_with_decay(
            self.hashrate_1d,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            86400,
        );
        self.hashrate_7d = calculate_metric_with_decay(
            self.hashrate_7d,
            unaccounted_difficulty * HASHES_PER_SHARE,
            time_since_last_update,
            604800,
        );
    }

    /// Compute the share rate metrics, decaying it since the last update
    fn set_share_rate_metrics(&mut self, lastupdate: Option<u64>, unaccounted_shares: u64) {
        let time_since_last_update = if let Some(lastupdate) = lastupdate {
            calc::sane_time_diff(
                SystemTime::now(),
                Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(lastupdate)),
            ) as u64
        } else {
            0
        };
        if time_since_last_update == 0 {
            return;
        }
        self.shares_per_second_1m = calculate_metric_with_decay(
            self.shares_per_second_1m,
            unaccounted_shares,
            time_since_last_update,
            60,
        );
        self.shares_per_second_5m = calculate_metric_with_decay(
            self.shares_per_second_5m,
            unaccounted_shares,
            time_since_last_update,
            300,
        );
        self.shares_per_second_15m = calculate_metric_with_decay(
            self.shares_per_second_15m,
            unaccounted_shares,
            time_since_last_update,
            900,
        );
        self.shares_per_second_1h = calculate_metric_with_decay(
            self.shares_per_second_1h,
            unaccounted_shares,
            time_since_last_update,
            3600,
        );
    }
}

/// Calculate hashrate from difficulty and time period in seconds
/// Returns hashrate in H/s
pub fn calculate_metric_with_decay(
    current_metric: u64,
    unaccounted_metric: u64,
    secs_since_last_update: u64,
    interval: u64,
) -> u64 {
    debug!(
        "Calculating metric with decay: current_metric={}, unaccounted_metric={}, secs_since_last_update={}, interval={}",
        current_metric, unaccounted_metric, secs_since_last_update, interval
    );
    if secs_since_last_update == 0 {
        return 0;
    }
    let result = calc::decay_time(
        current_metric as f64,
        unaccounted_metric / interval,
        secs_since_last_update as f64,
        interval,
    ) as u64;
    debug!("Calculated metric: {}", result);
    result
}
