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

use std::time::SystemTime;

pub trait TimeProviderTrait: Send + Sync {
    fn current_time(&self) -> u64;
}

#[derive(Clone)]
pub struct SystemTimeProvider;

impl TimeProviderTrait for SystemTimeProvider {
    fn current_time(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl SystemTimeProvider {
    pub fn new() -> Self {
        SystemTimeProvider
    }
}

#[derive(Clone)]
pub struct TestTimeProvider {
    current_time: u64,
}

impl TimeProviderTrait for TestTimeProvider {
    fn current_time(&self) -> u64 {
        self.current_time
    }
}

impl TestTimeProvider {
    pub fn new() -> Self {
        TestTimeProvider { current_time: 1000 }
    }

    pub fn set_time(&mut self, time: u64) {
        self.current_time = time;
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_time_provider() {
        let provider = SystemTimeProvider::new();
        let time1 = provider.current_time();
        let time2 = provider.current_time();
        // Time should be monotonically increasing
        assert!(time2 >= time1);
    }

    #[test]
    fn test_test_time_provider() {
        let mut provider = TestTimeProvider::new();

        // Check default time
        assert_eq!(provider.current_time(), 1000);

        // Test setting time
        provider.set_time(2000);
        assert_eq!(provider.current_time(), 2000);

        // Test setting another time
        provider.set_time(3000);
        assert_eq!(provider.current_time(), 3000);
    }
}
