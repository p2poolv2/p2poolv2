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

use crate::calc::{self, decay_time};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Struct to hold computed statistics like hashrate over various time windows
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ComputedHashrate {
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
}

/// Calculate time since last update in seconds
pub fn time_since(lastupdate: Option<u64>) -> u64 {
    if let Some(lastupdate) = lastupdate {
        calc::sane_time_diff(
            SystemTime::now(),
            Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(lastupdate)),
        ) as u64
    } else {
        0
    }
}

impl ComputedHashrate {
    /// Compute hashrate for various windows based on the shares received
    /// Decay the hashrate using the exponential decay from calc::decay_time.
    /// The decay is since the last update
    pub fn set_hashrate_metrics(
        &mut self,
        time_since_last_update: u64,
        unaccounted_difficulty: u64,
    ) {
        self.hashrate_1m = decay_time(
            self.hashrate_1m as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            60,
        ) as u64;
        self.hashrate_5m = decay_time(
            self.hashrate_5m as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            300,
        ) as u64;
        self.hashrate_15m = decay_time(
            self.hashrate_15m as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            900,
        ) as u64;
        self.hashrate_1hr = decay_time(
            self.hashrate_1hr as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            3600,
        ) as u64;
        self.hashrate_6hr = decay_time(
            self.hashrate_6hr as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            21600,
        ) as u64;
        self.hashrate_1d = decay_time(
            self.hashrate_1d as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            86400,
        ) as u64;
        self.hashrate_7d = decay_time(
            self.hashrate_7d as f64,
            unaccounted_difficulty,
            time_since_last_update as f64,
            604800,
        ) as u64;
    }
}

/// Computed share rate. Right now used only for the pool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]

pub struct ComputedShareRate {
    /// Shares per second over the last 1 minute
    pub shares_per_second_1m: f64,
    /// Shares per second over the last 5 minutes
    pub shares_per_second_5m: f64,
    /// Shares per second over the last 15 minutes
    pub shares_per_second_15m: f64,
    /// Shares per second over the last 1 hour
    pub shares_per_second_1h: f64,
}

impl ComputedShareRate {
    /// Compute the share rate metrics, decaying it since the last update
    pub fn set_share_rate_metrics(&mut self, time_since_last_update: u64, unaccounted_shares: u64) {
        self.shares_per_second_1m = decay_time(
            self.shares_per_second_1m,
            unaccounted_shares,
            time_since_last_update as f64,
            60,
        );
        self.shares_per_second_5m = decay_time(
            self.shares_per_second_5m,
            unaccounted_shares,
            time_since_last_update as f64,
            300,
        );
        self.shares_per_second_15m = decay_time(
            self.shares_per_second_15m,
            unaccounted_shares,
            time_since_last_update as f64,
            900,
        );
        self.shares_per_second_1h = decay_time(
            self.shares_per_second_1h,
            unaccounted_shares,
            time_since_last_update as f64,
            3600,
        );
    }
}
