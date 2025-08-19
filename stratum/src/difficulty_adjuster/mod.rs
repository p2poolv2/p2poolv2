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

//! Difficulty adjuster module based on CKPool's algorithm.
//!
//! This module implements the difficulty adjustment algorithm described in the
//! CKPool documentation. It tracks the client's share rate and dynamically
//! adjusts the difficulty to maintain an optimal share submission frequency.

mod calc;

#[cfg(test)]
use mockall::automock;
use std::time::{Duration, SystemTime};
use tracing::{debug, info};

use crate::difficulty_adjuster::calc::sane_time_diff;

/// The target Difficulty Rate Ratio (DRR) for standard clients
/// This aims for about 1 share every 3.33 seconds
pub const TARGET_DRR: f64 = 0.3;

/// Lower bound for DRR before triggering difficulty adjustment
pub const MIN_DRR_THRESHOLD: f64 = 0.15;

/// Upper bound for DRR before triggering difficulty adjustment
pub const MAX_DRR_THRESHOLD: f64 = 0.4;

/// The number of shares required before adjusting difficulty
pub const MIN_SHARES_BEFORE_ADJUST: u32 = 72;

/// The minimum time in seconds between difficulty adjustments
pub const MIN_SECONDS_BEFORE_ADJUST: u64 = 240; // 4 minutes

/// Time constant for the bias calculation (in seconds)
pub const BIAS_TIME_CONSTANT: f64 = 300.0; // 5 minutes

/// Minimum time between decays in seconds
pub const MIN_DECAY_INTERVAL: f64 = 0.05;

/// DifficultyAdjuster implements the dynamic difficulty adjustment algorithm based on CKPool.
///
/// It tracks client performance metrics and calculates the optimal difficulty setting
/// based on their actual hashrate over time.
pub struct DifficultyAdjuster {
    /// Share submission difficulty counter - tracks shares since last difficulty change
    pub share_submission_difficulty_counter: u32,
    /// Current client difficulty setting
    pub current_difficulty: u64,
    /// Previous difficulty before a change
    pub old_difficulty: u64,
    /// Timestamp when client submitted first share
    pub first_share_timestamp: Option<SystemTime>,
    /// Last difficulty change timestamp
    pub last_difficulty_change_timestamp: Option<SystemTime>,
    /// Timestamp when last decay was successfully applied
    pub last_decay_timestamp: Option<SystemTime>,
    /// Difficulty shares per second over 1 minute window
    pub difficulty_shares_per_second_1min_window: f64,
    /// Difficulty shares per second over 5 minute window
    pub difficulty_shares_per_second_5min_window: f64,
    /// Difficulty shares per second over 1 hour window
    pub difficulty_shares_per_second_1hour_window: f64,
    /// Difficulty shares per second over 24 hour window
    pub difficulty_shares_per_second_24hour_window: f64,
    /// Difficulty shares per second over 7 day window
    pub difficulty_shares_per_second_7day_window: f64,
    /// Job ID when difficulty was last changed
    pub last_diff_change_job_id: Option<u64>,
    /// Pool minimum difficulty
    pub pool_minimum_difficulty: u64,
    /// Pool maximum difficulty
    pub pool_maximum_difficulty: Option<u64>,
    /// Unaccounted shares
    pub unaccounted_shares: u64,
}

#[cfg_attr(test, automock)]
pub trait DifficultyAdjusterTrait {
    /// Create a new DifficultyAdjuster with the given minimum difficulty
    fn new(
        start_difficulty: u64,
        pool_minimum_difficulty: u64,
        pool_maximum_difficulty: Option<u64>,
    ) -> Self;

    /// Records a share submission and updates metrics
    ///
    /// Returns a tuple of (Option<u32>, bool) where the first element is the new difficulty
    /// if it changed, and the second element is true if this was the first share.
    fn record_share_submission(
        &mut self,
        share_diff: u128,
        job_id: u64,
        suggested_difficulty: Option<u64>,
        current_timestamp: SystemTime,
    ) -> (Option<u64>, bool);

    /// Calculate the optimal difficulty based on client performance
    fn calculate_new_difficulty(
        &self,
        suggested_difficulty: Option<u64>,
        time_since_first_share: f64,
    ) -> u64;

    /// Update the difficulty shares per second metric for a given time window
    fn update_difficulty_shares_per_second_metric(
        &mut self,
        time_window_seconds: f64,
        window_duration_seconds: f64,
        current_timestamp: SystemTime,
    );

    /// Update the DSPS (Difficulty Shares Per Second) metrics using exponential decay
    fn apply_difficulty_constraints(&self, new_diff: u64, suggested_difficulty: Option<u64>)
        -> u64;

    /// Convert a u128 value to u64, saturating at u64::MAX if the value exceeds it.
    #[inline]
    fn saturated_to_u64(&self, value: u128) -> u64 {
        if value > u64::MAX as u128 {
            u64::MAX
        } else {
            value as u64
        }
    }

    fn set_current_difficulty(&mut self, difficulty: u64);
}

impl DifficultyAdjusterTrait for DifficultyAdjuster {
    fn new(
        start_difficulty: u64,
        pool_minimum_difficulty: u64,
        pool_maximum_difficulty: Option<u64>,
    ) -> Self {
        Self {
            share_submission_difficulty_counter: 0,
            current_difficulty: start_difficulty,
            old_difficulty: start_difficulty,
            first_share_timestamp: None,
            last_difficulty_change_timestamp: None,
            last_decay_timestamp: None,
            difficulty_shares_per_second_1min_window: 0.0,
            difficulty_shares_per_second_5min_window: 0.0,
            difficulty_shares_per_second_1hour_window: 0.0,
            difficulty_shares_per_second_24hour_window: 0.0,
            difficulty_shares_per_second_7day_window: 0.0,
            last_diff_change_job_id: None,
            pool_minimum_difficulty,
            pool_maximum_difficulty,
            unaccounted_shares: 0,
        }
    }

    fn record_share_submission(
        &mut self,
        share_diff: u128,
        job_id: u64,
        suggested_difficulty: Option<u64>,
        current_timestamp: SystemTime,
    ) -> (Option<u64>, bool) {
        let mut first_share = false;

        // If this is the first share, initialize timestamps
        if self.first_share_timestamp.is_none() {
            debug!("First share submission received, initializing timestamps.");
            self.first_share_timestamp = Some(current_timestamp);
            self.last_difficulty_change_timestamp = Some(current_timestamp);
            first_share = true;
            return (None, first_share);
        }

        debug!("Recording share submission with difficulty: {}", share_diff);

        // Update the share submission counter
        self.share_submission_difficulty_counter += 1;

        // Calculate time elapsed since the first share
        let time_since_first_share = current_timestamp
            .duration_since(self.first_share_timestamp.unwrap())
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();

        debug!(
            "Time since first share: {:.2} seconds",
            time_since_first_share
        );

        // Calculate time elapsed since last difficulty change
        let time_since_last_difficulty_change =
            sane_time_diff(current_timestamp, self.last_difficulty_change_timestamp);
        debug!(
            "Time since last difficulty change: {:.2} seconds",
            time_since_last_difficulty_change
        );

        // Update the DSPS (Difficulty Shares Per Second) metrics using current difficulty
        self.update_difficulty_shares_per_second_metric(1.0, 60.0, current_timestamp); // 1 minute window
        self.update_difficulty_shares_per_second_metric(5.0, 300.0, current_timestamp); // 5 minute window
        self.update_difficulty_shares_per_second_metric(60.0, 3600.0, current_timestamp); // 1 hour window
        self.update_difficulty_shares_per_second_metric(1440.0, 86400.0, current_timestamp); // 24 hour window
        self.update_difficulty_shares_per_second_metric(10080.0, 604800.0, current_timestamp); // 7 day window

        // Check if we should adjust difficulty
        let should_adjust = (self.share_submission_difficulty_counter >= MIN_SHARES_BEFORE_ADJUST
            || time_since_last_difficulty_change > MIN_SECONDS_BEFORE_ADJUST as f64)
            && time_since_first_share > 30.0; // Wait at least 30 seconds since first share

        debug!(
            "Share submission counter: {}, should adjust: {}",
            self.share_submission_difficulty_counter, should_adjust
        );

        if should_adjust {
            let new_diff =
                self.calculate_new_difficulty(suggested_difficulty, time_since_first_share);

            debug!(
                "Calculated new difficulty: {}, current difficulty: {}",
                new_diff, self.current_difficulty
            );

            // Only change if the difficulty is meaningfully different
            if new_diff != self.current_difficulty {
                self.old_difficulty = self.current_difficulty;
                self.current_difficulty = new_diff;
                self.share_submission_difficulty_counter = 0; // Reset the share counter
                self.last_difficulty_change_timestamp = Some(current_timestamp); // Update last difficulty change time
                self.last_diff_change_job_id = Some(job_id);

                info!(
                    "Difficulty changed from {} to {} based on DRR calculation",
                    self.old_difficulty, self.current_difficulty
                );

                return (Some(new_diff), first_share);
            }
        }

        (None, first_share)
    }

    fn calculate_new_difficulty(
        &self,
        suggested_difficulty: Option<u64>,
        time_since_first_share: f64,
    ) -> u64 {
        let bias = calc::time_bias(time_since_first_share, BIAS_TIME_CONSTANT);

        // Adjust dsps for bias
        let difficulty_shares_per_second = self.difficulty_shares_per_second_5min_window / bias;

        let difficulty_rate_ratio = difficulty_shares_per_second / self.current_difficulty as f64;

        debug!(
            "DRR calculation: dsps={}, bias={}, current_diff={}, drr={}",
            self.difficulty_shares_per_second_5min_window,
            bias,
            self.current_difficulty,
            difficulty_rate_ratio
        );

        // Only adjust difficulty if DRR is outside the acceptable range
        if (MIN_DRR_THRESHOLD..=MAX_DRR_THRESHOLD).contains(&difficulty_rate_ratio) {
            return self.current_difficulty;
        }

        // Calculate optimal difficulty: dsps × 3.33 (since target DRR is 0.3)
        let optimal_diff = (difficulty_shares_per_second * (1.0 / TARGET_DRR)).round() as u128;

        let saturated = self.saturated_to_u64(optimal_diff);

        // Apply constraints to the calculated difficulty
        let constrained_diff = self.apply_difficulty_constraints(saturated, suggested_difficulty);

        debug!(
            "Difficulty adjustment: dsps5={}, bias={}, adjusted_dsps={}, drr={}, optimal={}, constrained={}",
            self.difficulty_shares_per_second_5min_window, bias, difficulty_shares_per_second, difficulty_rate_ratio, optimal_diff, constrained_diff
        );

        constrained_diff
    }

    /// Apply constraints to difficulty given the pool min/max difficulty and the optionally provided client's suggested difficulty
    fn apply_difficulty_constraints(
        &self,
        calculated_diff: u64,
        suggested_difficulty: Option<u64>,
    ) -> u64 {
        debug!(
            "Applying difficulty constraints: calculated={}, pool_min={}, pool_max={}",
            calculated_diff,
            self.pool_minimum_difficulty,
            match self.pool_maximum_difficulty {
                Some(max) => max.to_string(),
                None => "None".to_string(),
            },
        );
        // Maximum of pool minimum difficulty and calculated optimal
        let mut diff = calculated_diff.max(self.pool_minimum_difficulty);

        // Use max of difficulty suggested by client and the calculated optimal
        if let Some(suggested) = suggested_difficulty {
            diff = diff.max(suggested);
        }

        // Cap diff to pool maximum difficulty
        if self.pool_maximum_difficulty.is_some() {
            diff = diff.min(self.pool_maximum_difficulty.unwrap());
        }
        diff
    }

    /// Update the difficulty shares per second metric for a specific time window
    /// Return true if decay occurred, false otherwise.
    fn update_difficulty_shares_per_second_metric(
        &mut self,
        which_dsps: f64,
        interval: f64,
        current_timestamp: SystemTime,
    ) {
        debug!("Last decay timestamp: {:?}", self.last_decay_timestamp);
        if sane_time_diff(current_timestamp, self.last_decay_timestamp) < MIN_DECAY_INTERVAL {
            self.unaccounted_shares += self.current_difficulty;
            debug!("Skipping update, last decay was too recent.");
            return;
        }

        let difficulty = self.current_difficulty + self.unaccounted_shares;
        self.unaccounted_shares = 0; // Reset unaccounted shares after applying

        // Get the appropriate dsps field
        let dsps = match which_dsps as u32 {
            1 => &mut self.difficulty_shares_per_second_1min_window,
            5 => &mut self.difficulty_shares_per_second_5min_window,
            60 => &mut self.difficulty_shares_per_second_1hour_window,
            1440 => &mut self.difficulty_shares_per_second_24hour_window,
            10080 => &mut self.difficulty_shares_per_second_7day_window,
            _ => return,
        };

        // Use the decay_time algorithm
        let elapsed_time = if self.last_difficulty_change_timestamp.is_some() {
            current_timestamp
                .duration_since(self.last_difficulty_change_timestamp.unwrap())
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs_f64()
        } else {
            1.0 // Default to 1 second if no last difficulty change time
        };

        debug!("elapsed_time={}", elapsed_time);

        // Calculate fprop = 1 - (1 / e^(elapsed_time/interval))
        let fprop = 1.0 - (1.0 / (elapsed_time / interval).exp());

        debug!("fprop={}", fprop);

        // Update dsps using the formula:
        // f_new = (f_old + (diff_share * fprop / elapsed_time)) / (1 + fprop)
        *dsps = (*dsps + (difficulty as f64 * fprop / elapsed_time)) / (1.0 + fprop);

        debug!("Updated dsps={}", *dsps);
    }

    /// Set current difficulty
    fn set_current_difficulty(&mut self, difficulty: u64) {
        self.current_difficulty = difficulty;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_difficulty_adjuster() {
        let min_diff = 1000;
        let pool_max_diff = 100000;
        let start_difficulty = 100;
        let adjuster = DifficultyAdjuster::new(start_difficulty, min_diff, Some(pool_max_diff));

        assert_eq!(adjuster.current_difficulty, start_difficulty);
        assert_eq!(adjuster.old_difficulty, start_difficulty);
        assert_eq!(adjuster.share_submission_difficulty_counter, 0);
        assert_eq!(adjuster.difficulty_shares_per_second_1min_window, 0.0);
        assert_eq!(adjuster.difficulty_shares_per_second_5min_window, 0.0);
        assert_eq!(adjuster.difficulty_shares_per_second_1hour_window, 0.0);
        assert_eq!(adjuster.difficulty_shares_per_second_24hour_window, 0.0);
        assert_eq!(adjuster.difficulty_shares_per_second_7day_window, 0.0);
        assert!(adjuster.first_share_timestamp.is_none());
        assert!(adjuster.last_difficulty_change_timestamp.is_none());
        assert!(adjuster.last_diff_change_job_id.is_none());
    }

    #[test]
    fn test_first_share_submission() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        let (new_diff, is_first) =
            adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        assert!(is_first);
        assert!(new_diff.is_none());
        assert_eq!(adjuster.share_submission_difficulty_counter, 0);
        assert!(adjuster.first_share_timestamp.is_some());
        assert!(adjuster.last_difficulty_change_timestamp.is_some());
    }

    #[test]
    fn test_difficulty_not_changed_before_minimum_shares() {
        let min_diff = 1000;
        let start_difficulty = 100;
        let mut adjuster = DifficultyAdjuster::new(start_difficulty, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Submit several shares but less than MIN_SHARES_BEFORE_ADJUST
        for i in 0..(MIN_SHARES_BEFORE_ADJUST - 1) {
            let (new_diff, is_first) = adjuster.record_share_submission(
                min_diff as u128,
                (i + 2) as u64,
                None,
                current_timestamp + Duration::from_secs(i as u64),
            );
            assert!(!is_first);
            assert!(new_diff.is_none());
        }

        assert_eq!(
            adjuster.share_submission_difficulty_counter,
            MIN_SHARES_BEFORE_ADJUST - 1
        );
        assert_eq!(adjuster.current_difficulty, start_difficulty);
    }

    #[test_log::test]
    fn test_difficulty_adjustment_after_minimum_time() {
        let min_diff = 1;
        let start_difficulty = 100;
        let mut adjuster = DifficultyAdjuster::new(start_difficulty, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Force the timestamps to be old enough to trigger adjustment
        let past_time = SystemTime::now() - Duration::from_secs(MIN_SECONDS_BEFORE_ADJUST + 10);
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Simulate a miner with high performance by setting dsps5 directly
        adjuster.difficulty_shares_per_second_5min_window = 0.5; // This should increase the difficulty

        // Submit a share that should trigger adjustment
        let (new_diff, _) =
            adjuster.record_share_submission(min_diff as u128, 2, None, current_timestamp);

        // We expect difficulty to increase because dsps5/bias is higher than the target DRR
        assert!(new_diff.is_some());
        assert!(new_diff.unwrap() > min_diff);
        assert_eq!(adjuster.current_difficulty, new_diff.unwrap());
        assert_eq!(adjuster.old_difficulty, start_difficulty);
        assert_eq!(adjuster.share_submission_difficulty_counter, 0); // Counter should be reset
    }

    #[test_log::test]
    fn test_difficulty_adjustment_after_enough_shares() {
        let min_diff = 1;
        let mut adjuster = DifficultyAdjuster::new(1, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Force the timestamps to be old enough
        let past_time = SystemTime::now() - Duration::from_secs(31); // Just over 30 seconds
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Simulate a miner with low performance
        adjuster.difficulty_shares_per_second_5min_window = 100.0; // This should increase the difficulty

        // Submit enough shares to trigger adjustment
        for i in 0..MIN_SHARES_BEFORE_ADJUST {
            if i < MIN_SHARES_BEFORE_ADJUST - 1 {
                let (new_diff, _) = adjuster.record_share_submission(
                    min_diff as u128,
                    (i + 2) as u64,
                    None,
                    current_timestamp + Duration::from_secs(i as u64),
                );
                assert!(new_diff.is_none());
            } else {
                // The last share should trigger adjustment
                let (new_diff, _) = adjuster.record_share_submission(
                    min_diff as u128,
                    (i + 2) as u64,
                    None,
                    current_timestamp + Duration::from_secs(i as u64),
                );
                assert!(new_diff.is_some());
                assert_eq!(new_diff.unwrap(), 1156);
            }
        }
    }

    #[test]
    fn test_difficulty_constraints() {
        let min_diff = 1000;
        let pool_max_diff = 100_000;
        let adjuster = DifficultyAdjuster::new(100, min_diff, Some(pool_max_diff));

        // Test minimum constraint
        let calculated = 500; // Below pool minimum
        let constrained = adjuster.apply_difficulty_constraints(calculated, None);
        assert_eq!(constrained, min_diff);

        // Test maximum pool constraint
        let calculated = 150_000; // Above pool maximum
        let constrained = adjuster.apply_difficulty_constraints(calculated, None);
        assert_eq!(constrained, pool_max_diff);

        // Test cap with suggested difficulty
        let calculated = 500;
        let constrained = adjuster.apply_difficulty_constraints(calculated, Some(2000));
        assert_eq!(constrained, 2000);
    }

    #[test]
    fn test_adjust_dsps_bias_and_drr() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, Some(100_000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Set a 30-minute-old first share time to get bias close to 1.0
        let past_time = current_timestamp - Duration::from_secs(1800);
        adjuster.first_share_timestamp = Some(past_time);

        // Set dsps5 to a value that should result in diff change
        // For a current diff of 1000 and TARGET_DRR of 0.3,
        // a dsps5 of 600 should give us a DRR of 0.6, which is > MAX_DRR_THRESHOLD
        adjuster.difficulty_shares_per_second_5min_window = 600.0;

        // Calculate new difficulty
        let new_diff = adjuster.calculate_new_difficulty(None, 1800.0);

        // Expected optimal diff with dsps=600 and TARGET_DRR=0.3 is about 2000
        assert!(new_diff > min_diff);
        // With bias close to 1.0, should be close to dsps/TARGET_DRR = 600/0.3 = 2000
        assert!(new_diff >= 1900 && new_diff <= 2100);
    }

    #[test]
    fn test_no_change_within_drr_threshold() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Set bias close to 1.0 with an old first share time
        let past_time = current_timestamp - Duration::from_secs(1800);
        adjuster.first_share_timestamp = Some(past_time);

        // Set dsps5 to result in a DRR within thresholds
        // For diff=1000, a dsps of 200 gives DRR=0.2, which is within [0.15, 0.4]
        adjuster.difficulty_shares_per_second_5min_window = 200.0;

        // Calculate new difficulty
        let new_diff = adjuster.calculate_new_difficulty(None, 1800.0);

        // Should not change as DRR is within acceptable range
        assert_eq!(new_diff, min_diff);
    }

    #[test_log::test]
    fn test_time_bias_effect() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, Some(100000));
        let current_timestamp = SystemTime::now();

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff as u128, 1, None, current_timestamp);

        // Set a first share time that's recent (1 minute ago)
        // This should result in a significant bias effect
        let past_time = current_timestamp - Duration::from_secs(60);
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Set dsps5 to a high value
        adjuster.difficulty_shares_per_second_5min_window = 600.0;

        // Calculate new difficulty with 1-minute bias
        let new_diff_with_bias = adjuster.calculate_new_difficulty(None, 60.0);

        // Now simulate the same miner after 30 minutes (bias close to 1.0)
        adjuster.first_share_timestamp = Some(current_timestamp - Duration::from_secs(1800));

        // Calculate difficulty again with reduced bias
        let new_diff_no_bias = adjuster.calculate_new_difficulty(None, 1800.0);

        // With bias closer to 1.0, the adjusted rate is lower, resulting in lower difficulty
        assert!(new_diff_no_bias < new_diff_with_bias);
    }

    #[test]
    fn test_update_difficulty_shares_per_second_metric() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, None);
        let current_timestamp = SystemTime::now();

        // Set the last difficulty change timestamp to a known value
        let past_time = current_timestamp - Duration::from_secs(60); // 1 minute ago
        adjuster.last_difficulty_change_timestamp = Some(past_time);
        adjuster.last_decay_timestamp = Some(past_time);

        // Initial value is zero
        assert_eq!(adjuster.difficulty_shares_per_second_5min_window, 0.0);

        // Apply a difficulty share of 2000
        adjuster.current_difficulty = 2000;
        adjuster.update_difficulty_shares_per_second_metric(5.0, 300.0, current_timestamp);

        // Calculate expected value:
        // elapsed_time = 60 seconds
        // fprop = 1 - (1 / e^(60/300)) ≈ 0.181
        // dsps = (0 + (2000 * 0.181 / 60)) / (1 + 0.181) ≈ 5.09

        // Allow for some floating point variance
        assert!(adjuster.difficulty_shares_per_second_5min_window > 5.0);
        assert!(adjuster.difficulty_shares_per_second_5min_window < 5.2);

        // Apply another share to see exponential decay behavior
        adjuster.current_difficulty = 3000;
        adjuster.update_difficulty_shares_per_second_metric(5.0, 300.0, current_timestamp);

        // The value should increase due to the higher difficulty share
        assert!(adjuster.difficulty_shares_per_second_5min_window > 7.0);
    }

    #[test]
    fn test_update_difficulty_shares_per_second_metric_should_not_adjust_when_too_soon() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(100, min_diff, None);
        let current_timestamp = SystemTime::now();

        // Set the last difficulty change timestamp to a known value
        let past_time = current_timestamp - Duration::from_millis(49); // 49 milliseconds ago
        adjuster.last_difficulty_change_timestamp = Some(past_time);
        adjuster.last_decay_timestamp = Some(past_time);

        // Initial value is zero
        assert_eq!(adjuster.difficulty_shares_per_second_5min_window, 0.0);

        let initial_value = adjuster.difficulty_shares_per_second_5min_window;

        // Apply a difficulty share of 2000
        adjuster.current_difficulty = 2000;
        adjuster.update_difficulty_shares_per_second_metric(5.0, 300.0, current_timestamp);

        assert_eq!(
            adjuster.difficulty_shares_per_second_5min_window,
            initial_value
        );
    }
}
