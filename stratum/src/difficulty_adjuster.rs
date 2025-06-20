// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

#[cfg(test)]
use mockall::automock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

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

/// DifficultyAdjuster implements the dynamic difficulty adjustment algorithm based on CKPool.
///
/// It tracks client performance metrics and calculates the optimal difficulty setting
/// based on their actual hashrate over time.
pub struct DifficultyAdjuster {
    /// Share submission difficulty counter - tracks shares since last difficulty change
    pub share_submission_difficulty_counter: u32,
    /// Current client difficulty setting
    pub current_difficulty: u128,
    /// Previous difficulty before a change
    pub old_difficulty: u128,
    /// Timestamp when client submitted first share
    pub first_share_timestamp: Option<SystemTime>,
    /// Last difficulty change timestamp
    pub last_difficulty_change_timestamp: Option<SystemTime>,
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
    pub pool_minimum_difficulty: u128,
    /// Pool maximum difficulty
    pub pool_maximum_difficulty: Option<u128>,
    /// Network difficulty
    pub network_difficulty: u128,
}

#[cfg_attr(test, automock)]
pub trait DifficultyAdjusterTrait {
    /// Create a new DifficultyAdjuster with the given minimum difficulty
    fn new(
        pool_minimum_difficulty: u128,
        pool_maximum_difficulty: Option<u128>,
        network_difficulty: u128,
    ) -> Self;

    /// Records a share submission and updates metrics
    ///
    /// Returns a tuple of (Option<u32>, bool) where the first element is the new difficulty
    /// if it changed, and the second element is true if this was the first share.
    fn record_share_submission(&mut self, share_diff: u128, job_id: u64) -> (Option<u128>, bool);

    /// Calculate the optimal difficulty based on client performance
    fn calculate_new_difficulty(&self) -> u128;

    /// Update the difficulty shares per second metric for a given time window
    fn update_difficulty_shares_per_second_metric(
        &mut self,
        share_diff: u128,
        time_window_seconds: f64,
        window_duration_seconds: f64,
    );

    /// Update the DSPS (Difficulty Shares Per Second) metrics using exponential decay
    fn apply_difficulty_constraints(&self, new_diff: u128) -> u128;

    /// Get the current difficulty
    fn current_difficulty(&self) -> u128;

    /// Reset the difficulty adjuster with a new minimum difficulty
    fn reset(&mut self, pool_minimum_difficulty: u128);

    /// Set the network difficulty
    fn set_network_difficulty(&mut self, network_difficulty: u128);
}

impl DifficultyAdjusterTrait for DifficultyAdjuster {
    fn new(
        pool_minimum_difficulty: u128,
        pool_maximum_difficulty: Option<u128>,
        network_difficulty: u128,
    ) -> Self {
        Self {
            share_submission_difficulty_counter: 0,
            current_difficulty: pool_minimum_difficulty,
            old_difficulty: pool_minimum_difficulty,
            first_share_timestamp: None,
            last_difficulty_change_timestamp: None,
            difficulty_shares_per_second_1min_window: 0.0,
            difficulty_shares_per_second_5min_window: 0.0,
            difficulty_shares_per_second_1hour_window: 0.0,
            difficulty_shares_per_second_24hour_window: 0.0,
            difficulty_shares_per_second_7day_window: 0.0,
            last_diff_change_job_id: None,
            pool_minimum_difficulty,
            pool_maximum_difficulty,
            network_difficulty,
        }
    }

    fn record_share_submission(&mut self, share_diff: u128, job_id: u64) -> (Option<u128>, bool) {
        let now = SystemTime::now();
        let mut first_share = false;

        // If this is the first share, initialize timestamps
        if self.first_share_timestamp.is_none() {
            debug!("First share submission received, initializing timestamps.");
            self.first_share_timestamp = Some(now);
            self.last_difficulty_change_timestamp = Some(now);
            first_share = true;
            return (None, first_share);
        }

        debug!("Recording share submission with difficulty: {}", share_diff);

        // Update the share submission counter
        self.share_submission_difficulty_counter += 1;

        // Calculate time elapsed since the first share
        let time_since_first_share = now
            .duration_since(self.first_share_timestamp.unwrap())
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();

        debug!(
            "Time since first share: {:.2} seconds",
            time_since_first_share
        );

        // Calculate time elapsed since last difficulty change
        let time_since_last_difficulty_change = now
            .duration_since(self.last_difficulty_change_timestamp.unwrap())
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();

        debug!(
            "Time since last difficulty change: {:.2} seconds",
            time_since_last_difficulty_change
        );

        // Update the DSPS (Difficulty Shares Per Second) metrics
        self.update_difficulty_shares_per_second_metric(share_diff, 1.0, 60.0); // 1 minute window
        self.update_difficulty_shares_per_second_metric(share_diff, 5.0, 300.0); // 5 minute window
        self.update_difficulty_shares_per_second_metric(share_diff, 60.0, 3600.0); // 1 hour window
        self.update_difficulty_shares_per_second_metric(share_diff, 1440.0, 86400.0); // 24 hour window
        self.update_difficulty_shares_per_second_metric(share_diff, 10080.0, 604800.0); // 7 day window

        // Check if we should adjust difficulty
        let should_adjust = (self.share_submission_difficulty_counter >= MIN_SHARES_BEFORE_ADJUST
            || time_since_last_difficulty_change > MIN_SECONDS_BEFORE_ADJUST as f64)
            && time_since_first_share > 30.0; // Wait at least 30 seconds since first share

        debug!(
            "Share submission counter: {}, should adjust: {}",
            self.share_submission_difficulty_counter, should_adjust
        );

        if should_adjust {
            let new_diff = self.calculate_new_difficulty();

            info!(
                "Calculated new difficulty: {}, current difficulty: {}",
                new_diff, self.current_difficulty
            );

            // Only change if the difficulty is meaningfully different
            if new_diff != self.current_difficulty {
                self.old_difficulty = self.current_difficulty;
                self.current_difficulty = new_diff;
                self.share_submission_difficulty_counter = 0; // Reset the share counter
                self.last_difficulty_change_timestamp = Some(now); // Update last difficulty change time
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

    fn calculate_new_difficulty(&self) -> u128 {
        // Calculate the bias factor, which increases as time since first share increases
        let time_since_first_share = SystemTime::now()
            .duration_since(self.first_share_timestamp.unwrap())
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();

        let bias = 1.0 - (1.0 / (time_since_first_share / BIAS_TIME_CONSTANT).exp());

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

        // Apply constraints to the calculated difficulty
        let constrained_diff = self.apply_difficulty_constraints(optimal_diff);

        info!(
            "Difficulty adjustment: dsps5={}, bias={}, adjusted_dsps={}, drr={}, optimal={}, constrained={}",
            self.difficulty_shares_per_second_5min_window, bias, difficulty_shares_per_second, difficulty_rate_ratio, optimal_diff, constrained_diff
        );

        constrained_diff
    }

    fn apply_difficulty_constraints(&self, calculated_diff: u128) -> u128 {
        // 1. Maximum of pool minimum difficulty and calculated optimal
        let mut diff = calculated_diff.max(self.pool_minimum_difficulty);

        // 3. Minimum of calculated optimal and pool maximum difficulty
        if self.pool_maximum_difficulty.is_some() {
            diff = diff.min(self.pool_maximum_difficulty.unwrap());
        }

        // 4. Minimum of calculated optimal and network difficulty
        diff.min(self.network_difficulty)
    }

    fn update_difficulty_shares_per_second_metric(
        &mut self,
        diff_share: u128,
        which_dsps: f64,
        interval: f64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs_f64();

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
            now - self
                .last_difficulty_change_timestamp
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs_f64()
        } else {
            1.0 // Default to 1 second if no last difficulty change time
        };

        // Calculate fprop = 1 - (1 / e^(elapsed_time/interval))
        let fprop = 1.0 - (1.0 / (elapsed_time / interval).exp());

        // Update dsps using the formula:
        // f_new = (f_old + (diff_share * fprop / elapsed_time)) / (1 + fprop)
        *dsps = (*dsps + (diff_share as f64 * fprop / elapsed_time)) / (1.0 + fprop);
    }

    #[inline]
    fn current_difficulty(&self) -> u128 {
        self.current_difficulty
    }

    fn reset(&mut self, pool_minimum_difficulty: u128) {
        self.share_submission_difficulty_counter = 0;
        self.current_difficulty = pool_minimum_difficulty;
        self.old_difficulty = pool_minimum_difficulty;
        self.first_share_timestamp = None;
        self.last_difficulty_change_timestamp = None;
        self.difficulty_shares_per_second_1min_window = 0.0;
        self.difficulty_shares_per_second_5min_window = 0.0;
        self.difficulty_shares_per_second_1hour_window = 0.0;
        self.difficulty_shares_per_second_24hour_window = 0.0;
        self.difficulty_shares_per_second_7day_window = 0.0;
        self.last_diff_change_job_id = None;
    }

    fn set_network_difficulty(&mut self, network_difficulty: u128) {
        self.network_difficulty = network_difficulty;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_difficulty_adjuster() {
        let min_diff = 1000;
        let pool_max_diff = 100000;
        let network_diff = 200000;
        let adjuster = DifficultyAdjuster::new(min_diff, Some(pool_max_diff), network_diff);

        assert_eq!(adjuster.current_difficulty, min_diff);
        assert_eq!(adjuster.old_difficulty, min_diff);
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
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        let (new_diff, is_first) = adjuster.record_share_submission(min_diff, 1);

        assert!(is_first);
        assert!(new_diff.is_none());
        assert_eq!(adjuster.share_submission_difficulty_counter, 0);
        assert!(adjuster.first_share_timestamp.is_some());
        assert!(adjuster.last_difficulty_change_timestamp.is_some());
    }

    #[test]
    fn test_difficulty_not_changed_before_minimum_shares() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Submit several shares but less than MIN_SHARES_BEFORE_ADJUST
        for i in 0..(MIN_SHARES_BEFORE_ADJUST - 1) {
            let (new_diff, is_first) = adjuster.record_share_submission(min_diff, (i + 2) as u64);
            assert!(!is_first);
            assert!(new_diff.is_none());
        }

        assert_eq!(
            adjuster.share_submission_difficulty_counter,
            MIN_SHARES_BEFORE_ADJUST - 1
        );
        assert_eq!(adjuster.current_difficulty, min_diff);
    }

    #[test_log::test]
    fn test_difficulty_adjustment_after_minimum_time() {
        let min_diff = 1;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Force the timestamps to be old enough to trigger adjustment
        let past_time = SystemTime::now() - Duration::from_secs(MIN_SECONDS_BEFORE_ADJUST + 10);
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Simulate a miner with high performance by setting dsps5 directly
        adjuster.difficulty_shares_per_second_5min_window = 0.5; // This should increase the difficulty

        // Submit a share that should trigger adjustment
        let (new_diff, _) = adjuster.record_share_submission(min_diff, 2);

        // We expect difficulty to increase because dsps5/bias is higher than the target DRR
        assert!(new_diff.is_some());
        assert!(new_diff.unwrap() > min_diff);
        assert_eq!(adjuster.current_difficulty, new_diff.unwrap());
        assert_eq!(adjuster.old_difficulty, min_diff);
        assert_eq!(adjuster.share_submission_difficulty_counter, 0); // Counter should be reset
    }

    #[test_log::test]
    fn test_difficulty_adjustment_after_enough_shares() {
        let min_diff = 1;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Force the timestamps to be old enough
        let past_time = SystemTime::now() - Duration::from_secs(31); // Just over 30 seconds
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Simulate a miner with low performance
        adjuster.difficulty_shares_per_second_5min_window = 100.0; // This should increase the difficulty

        // Submit enough shares to trigger adjustment
        for i in 0..MIN_SHARES_BEFORE_ADJUST {
            if i < MIN_SHARES_BEFORE_ADJUST - 1 {
                let (new_diff, _) = adjuster.record_share_submission(min_diff, (i + 2) as u64);
                assert!(new_diff.is_none());
            } else {
                // The last share should trigger adjustment
                let (new_diff, _) = adjuster.record_share_submission(min_diff, (i + 2) as u64);
                assert!(new_diff.is_some());
                assert_eq!(new_diff.unwrap(), 5);
            }
        }
    }

    #[test]
    fn test_difficulty_constraints() {
        let min_diff = 1000;
        let pool_max_diff = 100_000;
        let network_diff = 500_000; // Higher than pool_max_diff to test constraints
        let adjuster = DifficultyAdjuster::new(min_diff, Some(pool_max_diff), network_diff);

        // Test minimum constraint
        let calculated = 500; // Below pool minimum
        let constrained = adjuster.apply_difficulty_constraints(calculated);
        assert_eq!(constrained, min_diff);

        // Test maximum pool constraint
        let calculated = 150_000; // Above pool maximum
        let constrained = adjuster.apply_difficulty_constraints(calculated);
        assert_eq!(constrained, pool_max_diff);

        let network_diff = 50_000; // Lower than pool_max to test constraint
        let adjuster = DifficultyAdjuster::new(min_diff, Some(pool_max_diff), network_diff);

        // Test network constraint
        let calculated = 75_000; // Above network but below pool max
        let constrained = adjuster.apply_difficulty_constraints(calculated);
        assert_eq!(constrained, network_diff);
    }

    #[test]
    fn test_adjust_dsps_bias_and_drr() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100_000), 200_000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Set a 30-minute-old first share time to get bias close to 1.0
        let past_time = SystemTime::now() - Duration::from_secs(1800);
        adjuster.first_share_timestamp = Some(past_time);

        // Set dsps5 to a value that should result in diff change
        // For a current diff of 1000 and TARGET_DRR of 0.3,
        // a dsps5 of 600 should give us a DRR of 0.6, which is > MAX_DRR_THRESHOLD
        adjuster.difficulty_shares_per_second_5min_window = 600.0;

        // Calculate new difficulty
        let new_diff = adjuster.calculate_new_difficulty();

        // Expected optimal diff with dsps=600 and TARGET_DRR=0.3 is about 2000
        assert!(new_diff > min_diff);
        // With bias close to 1.0, should be close to dsps/TARGET_DRR = 600/0.3 = 2000
        assert!(new_diff >= 1900 && new_diff <= 2100);
    }

    #[test]
    fn test_no_change_within_drr_threshold() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Set bias close to 1.0 with an old first share time
        let past_time = SystemTime::now() - Duration::from_secs(1800);
        adjuster.first_share_timestamp = Some(past_time);

        // Set dsps5 to result in a DRR within thresholds
        // For diff=1000, a dsps of 200 gives DRR=0.2, which is within [0.15, 0.4]
        adjuster.difficulty_shares_per_second_5min_window = 200.0;

        // Calculate new difficulty
        let new_diff = adjuster.calculate_new_difficulty();

        // Should not change as DRR is within acceptable range
        assert_eq!(new_diff, min_diff);
    }

    #[test_log::test]
    fn test_time_bias_effect() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Submit first share to initialize
        let _ = adjuster.record_share_submission(min_diff, 1);

        // Set a first share time that's recent (1 minute ago)
        // This should result in a significant bias effect
        let past_time = SystemTime::now() - Duration::from_secs(60);
        adjuster.first_share_timestamp = Some(past_time);
        adjuster.last_difficulty_change_timestamp = Some(past_time);

        // Set dsps5 to a high value
        adjuster.difficulty_shares_per_second_5min_window = 600.0;

        // Calculate new difficulty with 1-minute bias
        let new_diff_with_bias = adjuster.calculate_new_difficulty();

        // Now simulate the same miner after 30 minutes (bias close to 1.0)
        adjuster.first_share_timestamp = Some(SystemTime::now() - Duration::from_secs(1800));

        // Calculate difficulty again with reduced bias
        let new_diff_no_bias = adjuster.calculate_new_difficulty();

        // With bias closer to 1.0, the adjusted rate is lower, resulting in lower difficulty
        assert!(new_diff_no_bias < new_diff_with_bias);
    }

    #[test]
    fn test_reset_adjuster() {
        let min_diff = 1000;
        let mut adjuster = DifficultyAdjuster::new(min_diff, Some(100000), 200000);

        // Make some changes to the adjuster state
        adjuster.record_share_submission(min_diff, 1);
        adjuster.difficulty_shares_per_second_5min_window = 500.0;
        adjuster.current_difficulty = 2000;
        adjuster.old_difficulty = 1500;

        // Reset the adjuster
        adjuster.reset(min_diff);

        // Verify reset state
        assert_eq!(adjuster.current_difficulty, min_diff);
        assert_eq!(adjuster.old_difficulty, min_diff);
        assert_eq!(adjuster.share_submission_difficulty_counter, 0);
        assert_eq!(adjuster.difficulty_shares_per_second_1min_window, 0.0);
        assert_eq!(adjuster.difficulty_shares_per_second_5min_window, 0.0);
        assert!(adjuster.first_share_timestamp.is_none());
        assert!(adjuster.last_difficulty_change_timestamp.is_none());
    }
}
