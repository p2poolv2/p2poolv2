// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use bitcoin::absolute::Time;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Trait to get current system time, allowing for mocking in tests
#[allow(dead_code)]
pub trait TimeProvider {
    fn now(&self) -> SystemTime;
    fn set_time(&mut self, time: Time);
    fn set_since_epoch(&mut self, seconds: u64);
    fn seconds_since_epoch(&self) -> u64;
}

/// Default implementation that uses actual system time
#[derive(Clone, Debug)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn set_time(&mut self, _time: Time) {
        // No-op for production provider
    }

    fn set_since_epoch(&mut self, _seconds: u64) {
        // No-op for production provider
    }

    fn seconds_since_epoch(&self) -> u64 {
        self.now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

/// Mock time provider for testing
#[derive(Clone, Debug)]
pub struct TestTimeProvider {
    time: Arc<Mutex<SystemTime>>,
}

impl TestTimeProvider {
    pub fn new(time: SystemTime) -> Self {
        Self {
            time: Arc::new(Mutex::new(time)),
        }
    }
}

impl TimeProvider for TestTimeProvider {
    fn now(&self) -> SystemTime {
        *self.time.lock().unwrap()
    }

    fn set_time(&mut self, time: Time) {
        let secs = time.to_consensus_u32() as u64;
        let mut time = self.time.lock().unwrap();
        *time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    }

    fn set_since_epoch(&mut self, seconds: u64) {
        let mut time = self.time.lock().unwrap();
        *time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
    }

    fn seconds_since_epoch(&self) -> u64 {
        let time = self.time.lock().unwrap();
        time.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

/// Formats a Unix timestamp into a human-readable string
pub fn format_timestamp(timestamp: u64) -> String {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid timestamp".to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_mock_time_provider() {
        let fixed_time = UNIX_EPOCH + Duration::from_secs(1000);
        let time_provider = TestTimeProvider::new(fixed_time);
        assert_eq!(time_provider.now(), fixed_time);
    }

    #[test]
    fn test_system_time_provider() {
        let provider = SystemTimeProvider;

        // Get current time from provider
        let provider_time = provider.now();
        // Get actual system time
        let system_time = SystemTime::now();

        // Times should be very close (within 1 second)
        let diff = system_time.duration_since(provider_time).unwrap();
        assert!(diff < Duration::from_secs(1));

        // Test seconds_since_epoch returns a reasonable value
        let seconds = provider.seconds_since_epoch();
        // Should be greater than Jan 1, 2024 (timestamp 1704067200)
        assert!(seconds > 1704067200);

        // Test set_time is no-op
        let mut provider = SystemTimeProvider;
        let before = provider.now();
        provider.set_time(Time::from_consensus(1653195600).unwrap()); // Value picked from rust-bitcoin docs
        let after = provider.now();
        // Time should still progress normally
        assert!(after >= before);
    }

    #[test]
    fn test_format_timestamp_valid() {
        // Test with a known timestamp: Jan 1, 2024 00:00:00 UTC
        let timestamp = 1704067200;
        let formatted = format_timestamp(timestamp);
        assert_eq!(formatted, "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_epoch() {
        // Test with Unix epoch (Jan 1, 1970 00:00:00 UTC)
        let timestamp = 0;
        let formatted = format_timestamp(timestamp);
        assert_eq!(formatted, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_recent() {
        // Test with a more recent timestamp: Dec 31, 2024 23:59:59 UTC
        let timestamp = 1735689599;
        let formatted = format_timestamp(timestamp);
        assert_eq!(formatted, "2024-12-31 23:59:59 UTC");
    }
}
