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

use std::time::{Duration, SystemTime};

/// Calculate the time difference since the first share submission.
/// Set floor to 0.001 as used by CKPool.
pub fn sane_time_diff(current_timestamp: SystemTime, other: Option<SystemTime>) -> f64 {
    if other.is_none() {
        return 0.0;
    }
    current_timestamp
        .duration_since(other.unwrap())
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
        .max(0.001)
}

/// Calculate time bias based on CKPool's algorithm.
/// Returns a value between 0 and 1, using an exponential decay.
pub fn time_bias(time_difference: f64, period: f64) -> f64 {
    let exp_power = (time_difference / period).min(36.0);
    1.0 - 1.0 / exp_power.exp()
}

/// Apply time decay to difficulty per share based elapsed time since last change,
/// the interval we are decaying for and the incoming new difficulty value
pub fn decay_time(dsps: f64, difficulty: u64, elapsed_time: f64, interval: u64) -> f64 {
    // Calculate fprop = 1 - (1 / e^(elapsed_time/interval))
    let mut dexp = elapsed_time / interval as f64;
    dexp = dexp.min(36.0); // Cap at 36.0 to prevent overflow

    let fprop = 1.0 - (1.0 / dexp.exp());
    let ftotal = 1.0 + fprop;

    let mut new_dsps = dsps + (difficulty as f64 / elapsed_time * fprop);
    new_dsps /= ftotal;
    new_dsps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_sane_time_diff_with_valid_time() {
        let first_share_timestamp = SystemTime::now();
        sleep(Duration::from_millis(10)); // Sleep for 10ms
        let diff = sane_time_diff(SystemTime::now(), Some(first_share_timestamp));
        assert!(diff > 0.0);
        assert!(diff < 1.0); // Should be a small value around 0.01 seconds
    }

    #[test]
    fn test_sane_time_diff_returns_minimum() {
        // Test with a future time which would result in negative duration
        let future_time = SystemTime::now() + Duration::from_secs(10);
        let diff = sane_time_diff(SystemTime::now(), Some(future_time));
        assert_eq!(diff, 0.001); // Should return the minimum floor value
    }

    #[test]
    fn test_sane_time_diff_with_none() {
        // This should panic if called with None, but we're testing the behavior
        // This test might need to be updated based on intended behavior with None
        let result = std::panic::catch_unwind(|| sane_time_diff(SystemTime::now(), None));
        assert_eq!(result.unwrap(), 0.0);
    }

    #[test]
    fn test_time_bias_zero() {
        // When time_difference is 0, exp_power is 0, result should be 0
        let bias = time_bias(0.0, 1.0);
        assert_eq!(bias, 0.0);
    }

    #[test]
    fn test_time_bias_small_value() {
        // With small time_difference relative to period
        let bias = time_bias(0.1, 1.0);
        assert!(bias > 0.0 && bias < 0.1); // Small bias
    }

    #[test]
    fn test_time_bias_equal_to_period() {
        // When time_difference equals period
        let bias = time_bias(1.0, 1.0);
        assert!(bias > 0.6 && bias < 0.7); // Should be around 0.632 (1 - 1/e)
    }

    #[test]
    fn test_time_bias_large_value() {
        // With large time_difference relative to period
        let bias = time_bias(10.0, 1.0);
        assert!(bias > 0.99 && bias < 1.0); // Close to 1.0 but not exactly 1.0
    }

    #[test]
    fn test_time_bias_max_exp_power() {
        // Test the cap of exp_power at 36.0
        let bias = time_bias(100.0, 1.0); // This would make exp_power > 36
        let expected_max = 1.0 - 1.0 / 36.0_f64.exp();
        assert!((bias - expected_max).abs() < 1e-10);
    }

    #[test]
    fn test_decay_time_example_from_zero() {
        let dsps = 0.0;
        let elapsed_time = 12.687505;
        let interval = 300;
        let difficulty = 1;

        let new_dsps = decay_time(dsps, difficulty, elapsed_time, interval);
        assert!(
            (new_dsps - 0.003134).abs() < 1e-6,
            "Expected new dsps to be approximately 0.003134, got {}",
            new_dsps
        );
    }

    #[test]
    fn test_decay_time_example_from_non_zero() {
        let dsps = 9.763938;
        let elapsed_time = 2.147000;
        let interval = 300;
        let difficulty = 1000;

        let new_dsps = decay_time(dsps, difficulty, elapsed_time, interval);
        assert!(
            (new_dsps - 12.992719).abs() < 1e-6,
            "Expected new dsps to be approximately 12.992719, got {}",
            new_dsps
        );
    }
}
