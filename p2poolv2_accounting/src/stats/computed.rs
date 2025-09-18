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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_computed_share_rate_serde_default() {
        let default_share_rate = ComputedShareRate::default();

        let json_str =
            serde_json::to_string(&default_share_rate).expect("Failed to serialize to JSON");

        let deserialized_json: ComputedShareRate =
            serde_json::from_str(&json_str).expect("Failed to deserialize from JSON");
        assert_eq!(default_share_rate, deserialized_json);
    }

    #[test]
    fn test_computed_share_rate_serde_with_values() {
        let share_rate = ComputedShareRate {
            shares_per_second_1m: 1.5,
            shares_per_second_5m: 2.0,
            shares_per_second_15m: 1.8,
            shares_per_second_1h: 1.2,
        };

        let json_str = serde_json::to_string(&share_rate).expect("Failed to serialize to JSON");

        let deserialized_json: ComputedShareRate =
            serde_json::from_str(&json_str).expect("Failed to deserialize from JSON");
        assert_eq!(share_rate, deserialized_json);
    }

    #[test]
    fn test_computed_share_rate_set_metrics() {
        let mut share_rate = ComputedShareRate::default();

        // Test that we can update metrics normally
        share_rate.set_share_rate_metrics(60, 100); // 60 seconds, 100 shares

        // Verify that values have been updated from default
        assert!(share_rate.shares_per_second_1m > 0.0);
        assert!(share_rate.shares_per_second_5m > 0.0);
        assert!(share_rate.shares_per_second_15m > 0.0);
        assert!(share_rate.shares_per_second_1h > 0.0);

        // Test serialization after updating
        let json_str =
            serde_json::to_string(&share_rate).expect("Failed to serialize updated share_rate");

        let deserialized: ComputedShareRate =
            serde_json::from_str(&json_str).expect("Failed to deserialize updated share_rate");
        assert_eq!(share_rate, deserialized);

        // Test that the problematic case (elapsed_time = 0)
        let mut problematic_share_rate = ComputedShareRate::default();
        problematic_share_rate.set_share_rate_metrics(0, 100); // This used to cause NaN

        // Verify that no NaN values are present
        assert!(problematic_share_rate.shares_per_second_1m.is_finite());
        assert!(problematic_share_rate.shares_per_second_5m.is_finite());
        assert!(problematic_share_rate.shares_per_second_15m.is_finite());
        assert!(problematic_share_rate.shares_per_second_1h.is_finite());

        // Test that it can be serialized and deserialized successfully
        let problematic_json = serde_json::to_string(&problematic_share_rate)
            .expect("Failed to serialize problematic case");

        let deserialized_problematic: ComputedShareRate = serde_json::from_str(&problematic_json)
            .expect("Failed to deserialize problematic case");
        assert_eq!(problematic_share_rate, deserialized_problematic);

        // Verify the JSON doesn't contain null values
        assert!(
            !problematic_json.contains("null"),
            "JSON should not contain null values"
        );
    }

    #[test]
    fn test_computed_hashrate_serde() {
        // Also test ComputedHashrate to ensure consistency
        let default_hashrate = ComputedHashrate::default();

        let json_str =
            serde_json::to_string(&default_hashrate).expect("Failed to serialize ComputedHashrate");

        let deserialized: ComputedHashrate =
            serde_json::from_str(&json_str).expect("Failed to deserialize ComputedHashrate");
        assert_eq!(default_hashrate, deserialized);
    }
}
