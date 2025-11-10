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

use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
use crate::stratum::error::Error;
use crate::stratum::session::Session;
use crate::utils::time_provider::TimeProvider;
use tracing::error;

/// Timeout period to wait for first share (seconds)
pub const FIRST_SHARE_TIMEOUT: u64 = 900;
/// Timeout period between two shares (seconds)
pub const INACTIVITY_TIMEOUT: u64 = 900;
/// Check for timeout ever interval period (seconds)
pub const MONITOR_INTERVAL: u64 = 1;

/// Checks for session timeouts based on initialization and inactivity periods
///
/// This function evaluates the session's state to determine if it has exceeded
/// the allowed time for completing the initialization (if not yet subscribed or
/// authorized) or for remaining inactive after submitting a share
pub fn check_session_timeouts<T: TimeProvider>(
    session: &Session<DifficultyAdjuster>,
    time_provider: &T,
) -> Result<(), Error> {
    let now = time_provider.now();
    if !session.subscribed || session.username.is_none() {
        let time_since_connected = match now.duration_since(session.connected_at) {
            Ok(since_connect) => since_connect,
            Err(_) => {
                error!("Error retrieving the duration since the connection");
                return Err(Error::TimeoutError);
            }
        };
        if time_since_connected >= tokio::time::Duration::from_secs(FIRST_SHARE_TIMEOUT) {
            error!("First share timeout");
            return Err(Error::TimeoutError);
        }
    } else {
        let last_share_received_at = match session.last_share_time {
            Some(val) => val,
            None => {
                return Ok(());
            }
        };
        let time_since_last_share = match now.duration_since(last_share_received_at) {
            Ok(since_last_share) => since_last_share,
            Err(_) => {
                error!("Error retrieving the duration since the last share sent");
                return Err(Error::TimeoutError);
            }
        };
        if time_since_last_share >= tokio::time::Duration::from_secs(INACTIVITY_TIMEOUT) {
            error!("Inactivity timeout");
            return Err(Error::TimeoutError);
        }
    }

    Ok(())
}

#[cfg(test)]
mod timeout_test {
    use super::*;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::error::Error;
    use crate::utils::time_provider::TestTimeProvider;
    use std::time::SystemTime;

    #[test]
    fn test_inactivity_timeout_not_subscribed() {
        let mut test_time_provider = TestTimeProvider::new(SystemTime::now());
        let connection_time = test_time_provider.now();

        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0);
        session.subscribed = false;
        session.username = Some("miner".to_string());
        session.connected_at = connection_time;
        session.last_share_time = None;

        test_time_provider.set_since_epoch(test_time_provider.seconds_since_epoch() + 901); // One second more than first share timeout
        let result = check_session_timeouts(&session, &test_time_provider);

        assert!(matches!(result, Err(Error::TimeoutError)));
    }

    #[test]
    fn test_inactivity_timeout_not_authorized() {
        let mut test_time_provider = TestTimeProvider::new(SystemTime::now());
        let connection_time = test_time_provider.now();

        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0);
        session.subscribed = true;
        session.username = None;
        session.connected_at = connection_time;
        session.last_share_time = None;

        test_time_provider.set_since_epoch(test_time_provider.seconds_since_epoch() + 901); // One second more than first share timeout
        let result = check_session_timeouts(&session, &test_time_provider);

        assert!(matches!(result, Err(Error::TimeoutError)));
    }

    #[test]
    fn test_first_share_timeout() {
        let mut test_time_provider = TestTimeProvider::new(SystemTime::now());
        let connection_time = test_time_provider.now();

        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0);
        session.subscribed = true;
        session.username = Some("miner".to_string());
        session.connected_at = connection_time;
        session.last_share_time = Some(connection_time);

        test_time_provider.set_since_epoch(test_time_provider.seconds_since_epoch() + 901); // One second more than inactivity timeout
        let result = check_session_timeouts(&session, &test_time_provider);

        assert!(matches!(result, Err(Error::TimeoutError)));
    }
}
