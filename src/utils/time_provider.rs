// Copyright (C) 2024 [Kulpreet Singh]
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

use bitcoin::absolute::Time;
use std::time::{SystemTime, UNIX_EPOCH};

/// Trait to get current system time, allowing for mocking in tests
pub trait TimeProvider {
    fn now(&self) -> SystemTime;
    fn set_time(&mut self, time: Time);
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

    fn seconds_since_epoch(&self) -> u64 {
        self.now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

/// Mock time provider for testing
#[derive(Clone, Debug)]
pub struct TestTimeProvider(pub SystemTime);

impl TimeProvider for TestTimeProvider {
    fn now(&self) -> SystemTime {
        self.0
    }

    fn set_time(&mut self, time: Time) {
        let secs = time.to_consensus_u32() as u64;
        self.0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    }

    fn seconds_since_epoch(&self) -> u64 {
        self.0.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_mock_time_provider() {
        let fixed_time = UNIX_EPOCH + Duration::from_secs(1000);
        let time_provider = TestTimeProvider(fixed_time);
        assert_eq!(time_provider.now(), fixed_time);
    }
}
