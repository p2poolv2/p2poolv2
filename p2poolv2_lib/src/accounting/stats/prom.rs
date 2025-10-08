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

use crate::accounting::stats::metrics::PoolMetrics;

impl PoolMetrics {
    pub fn get_exposition(&self) -> String {
        let mut output = String::new();

        // Counters
        output.push_str("# HELP shares_accepted_total Total number of accepted shares\n");
        output.push_str("# TYPE shares_accepted_total counter\n");
        output.push_str(&format!("shares_accepted_total {}\n", self.accepted));
        output.push('\n');

        output.push_str("# HELP shares_rejected_total Total number of rejected shares\n");
        output.push_str("# TYPE shares_rejected_total counter\n");
        output.push_str(&format!("shares_rejected_total {}\n", self.rejected));
        output.push('\n');

        // Gauges
        output.push_str("# HELP users Number of users\n");
        output.push_str("# TYPE users gauge\n");
        output.push_str(&format!("users {}\n", self.num_users));
        output.push('\n');

        output.push_str("# HELP workers Number of workers\n");
        output.push_str("# TYPE workers gauge\n");
        output.push_str(&format!("workers {}\n", self.num_workers));
        output.push('\n');

        output.push_str("# HELP idle_users Number of idle users\n");
        output.push_str("# TYPE idle_users gauge\n");
        output.push_str(&format!("idle_users {}\n", self.num_idle_users));
        output.push('\n');

        output.push_str("# HELP best_share Highest difficulty share\n");
        output.push_str("# TYPE best_share gauge\n");
        output.push_str(&format!("best_share {}\n", self.bestshare));
        output.push('\n');

        output.push_str("# HELP difficulty Current pool difficulty\n");
        output.push_str("# TYPE difficulty gauge\n");
        output.push_str(&format!("difficulty {}\n", self.difficulty));
        output.push('\n');

        output.push_str("# HELP start_time_seconds Pool start time in Unix timestamp\n");
        output.push_str("# TYPE start_time_seconds gauge\n");
        output.push_str(&format!("start_time_seconds {}\n", self.start_time));
        output.push('\n');

        output.push_str("# HELP last_update_seconds Last update time in Unix timestamp\n");
        output.push_str("# TYPE last_update_seconds gauge\n");
        output.push_str(&format!("last_update_seconds {}\n", self.lastupdate.unwrap_or(0)));
        output.push('\n');

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_exposition_format() {
        let metrics = PoolMetrics {
            accepted: 100,
            rejected: 5,
            num_users: 3,
            num_workers: 7,
            num_idle_users: 1,
            bestshare: 500,
            difficulty: 1000,
            start_time: 1234567890,
            lastupdate: Some(1234567900),
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check that it contains the expected metrics
        assert!(exposition.contains("shares_accepted_total 100"));
        assert!(exposition.contains("shares_rejected_total 5"));
        assert!(exposition.contains("users 3"));
        assert!(exposition.contains("workers 7"));
        assert!(exposition.contains("idle_users 1"));
        assert!(exposition.contains("best_share 500"));
        assert!(exposition.contains("difficulty 1000"));
        assert!(exposition.contains("start_time_seconds 1234567890"));
        assert!(exposition.contains("last_update_seconds 1234567900"));

        // Check that it contains HELP and TYPE comments
        assert!(exposition.contains("# HELP shares_accepted_total"));
        assert!(exposition.contains("# TYPE shares_accepted_total counter"));
        assert!(exposition.contains("# TYPE users gauge"));

        // Check that there's no p2pool_ prefix
        assert!(!exposition.contains("p2pool_"));
    }
}
