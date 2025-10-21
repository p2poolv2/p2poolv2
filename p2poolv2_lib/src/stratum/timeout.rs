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

use std::time::{Duration, Instant};
use crate::config::Config;
use crate::stratum::error::Error;
use crate::stratum::session::Session;
use crate::stratum::difficulty_adjuster::DifficultyAdjuster;

use tracing::error;


#[derive(Clone, Copy)]
pub struct SessionTimeouts {
    pub first_share_timeout: Duration,
    pub inactivity_timeout: Duration,
    pub monitor_interval: Duration,
}

impl SessionTimeouts {
    pub fn new() -> Self {
        let config_path = "../config.toml";
        let stratum_config = match Config::load(config_path) {
            Ok(config) => config.stratum,
            Err(e) => {
                error!("Failed to load the Stratum config: {e}");
                return Self::default();
            }
        };
        Self {
            first_share_timeout: Duration::from_secs(stratum_config.first_share_timeout),
            inactivity_timeout: Duration::from_secs(stratum_config.inactivity_timeout),
            monitor_interval: Duration::from_secs(stratum_config.monitor_interval),
        }
    }
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            first_share_timeout: Duration::from_secs(900),
            inactivity_timeout: Duration::from_secs(900),
            monitor_interval: Duration::from_secs(10),
        }
    }
}


/// Checks for session timeouts based on initialization and inactivity periods
/// 
/// This function evaluates the session's state to determine if it has exceeded
/// the allowed time for completing the initialization (if not yet subscribed or
/// authorized) or for remaining inactive after submitting a share
pub fn check_session_timeouts(
    session: &Session<DifficultyAdjuster>,
    timeouts: &SessionTimeouts,
) -> Result<(), Error> {
    let now = Instant::now();
    if !(session.subscribed && session.username.is_some()) {
        let since_connect = now.duration_since(session.connected_at);

        if since_connect >= timeouts.first_share_timeout {
            error!("Initialization timeout");
            return Err(Error::TimeoutError);
        }
    }

    let last_share_time = match session.last_share_time {
        Some(val) => val,
        None => {
            error!("Error retrieving the time of the last share sent");
            return Err(Error::TimeoutError)
        },
    };
    let since_last_share = now.duration_since(last_share_time);
    if session.username.is_some()
        && session.last_share_time.is_some()
        && since_last_share >= timeouts.inactivity_timeout
    {
        error!("Inactivity timeout");
        return Err(Error::TimeoutError);
    }

    Ok(())
}


#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::error::Error;
    use crate::stratum::session::Session;
    use std::time::Instant;

    #[test]
    fn test_first_share_timeout() {
        let mut session: Session<DifficultyAdjuster> = Session::new(1, 1, Some(2), 0);
        let timeouts = SessionTimeouts {
            first_share_timeout: Duration::from_secs(1),
            ..SessionTimeouts::default()
        };
        let now = Instant::now();
        session.connected_at = now - Duration::from_secs(2);
        session.last_share_time = Some(now);

        let result = check_session_timeouts(&session, &timeouts);
        
        assert!(matches!(result, Err(Error::TimeoutError))); // Connection closed due to timeout
    }

    #[test]
    fn test_inactivity_timeout() {
        let mut session: Session<DifficultyAdjuster> = Session::new(1, 1, Some(2), 0);
        session.subscribed = true;
        session.username = Some("user".to_string());
        let timeouts = SessionTimeouts {
            inactivity_timeout: Duration::from_secs(1),
            ..SessionTimeouts::default()
        };
        let now = Instant::now();
        session.last_share_time = Some(now - Duration::from_secs(2));

        let result = check_session_timeouts(&session, &timeouts);
        assert!(matches!(result, Err(Error::TimeoutError)));
    }
}