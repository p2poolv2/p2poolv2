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
pub(crate) fn sane_time_diff(first_share_timestamp: Option<SystemTime>) -> f64 {
    SystemTime::now()
        .duration_since(first_share_timestamp.unwrap())
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
        .max(0.001)
}

/// Calculate time bias based on CKPool's algorithm.
/// Returns a value between 0 and 1, using an exponential decay.
pub(crate) fn time_bias(time_difference: f64, period: f64) -> f64 {
    let mut exp_power = time_difference / period;
    if exp_power > 36.0 {
        exp_power = 36.0;
    }
    1.0 - 1.0 / exp_power.exp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_sane_time_diff_with_valid_time() {
        let first_share_timestamp = SystemTime::now();
        sleep(Duration::from_millis(10)); // Sleep for 10ms
        let diff = sane_time_diff(Some(first_share_timestamp));
        assert!(diff > 0.0);
        assert!(diff < 1.0); // Should be a small value around 0.01 seconds
    }

    #[test]
    fn test_sane_time_diff_returns_minimum() {
        // Test with a future time which would result in negative duration
        let future_time = SystemTime::now() + Duration::from_secs(10);
        let diff = sane_time_diff(Some(future_time));
        assert_eq!(diff, 0.001); // Should return the minimum floor value
    }

    #[test]
    fn test_sane_time_diff_with_none() {
        // This should panic if called with None, but we're testing the behavior
        // This test might need to be updated based on intended behavior with None
        let result = std::panic::catch_unwind(|| sane_time_diff(None));
        assert!(result.is_err());
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
}
