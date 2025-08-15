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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Calculate the time difference since the first share submission.
/// Set floor to 0.001
pub(crate) fn sane_time_diff(first_share_timestamp: Option<SystemTime>) -> f64 {
    SystemTime::now()
        .duration_since(first_share_timestamp.unwrap())
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs_f64()
        .max(0.001)
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
}
