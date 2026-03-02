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

use crate::accounting::stats::metrics::PoolMetrics;

impl PoolMetrics {
    pub fn get_exposition(&self) -> String {
        let mut output = String::new();

        // Counters
        output.push_str("# HELP shares_accepted_total Total number of accepted shares\n");
        output.push_str("# TYPE shares_accepted_total counter\n");
        output.push_str(&format!("shares_accepted_total {}\n", self.accepted_total));
        output.push('\n');

        output.push_str("# HELP accepted_difficulty_total Total difficulty of accepted shares\n");
        output.push_str("# TYPE accepted_difficulty_total counter\n");
        output.push_str(&format!(
            "accepted_difficulty_total {}\n",
            self.accepted_difficulty_total
        ));
        output.push('\n');

        output.push_str("# HELP shares_rejected_total Total number of rejected shares\n");
        output.push_str("# TYPE shares_rejected_total counter\n");
        output.push_str(&format!("shares_rejected_total {}\n", self.rejected_total));
        output.push('\n');

        output.push_str("# HELP best_share Highest difficulty share\n");
        output.push_str("# TYPE best_share gauge\n");
        output.push_str(&format!("best_share {}\n", self.best_share));
        output.push('\n');

        output.push_str("# HELP best_share_ever Highest difficulty share across restarts\n");
        output.push_str("# TYPE best_share_ever gauge\n");
        output.push_str(&format!("best_share_ever {}\n", self.best_share_ever));
        output.push('\n');

        output.push_str("# HELP pool_difficulty Current pool difficulty\n");
        output.push_str("# TYPE pool_difficulty gauge\n");
        output.push_str(&format!("pool_difficulty {}\n", self.pool_difficulty));
        output.push('\n');

        output.push_str("# HELP start_time_seconds Pool start time in Unix timestamp\n");
        output.push_str("# TYPE start_time_seconds gauge\n");
        output.push_str(&format!("start_time_seconds {}\n", self.start_time));
        output.push('\n');

        output.push_str("# HELP last_update_seconds Last update time in Unix timestamp\n");
        output.push_str("# TYPE last_update_seconds gauge\n");
        output.push_str(&format!(
            "last_update_seconds {}\n",
            self.lastupdate.unwrap_or(0)
        ));
        output.push('\n');

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::stats::user::User;
    use crate::accounting::stats::worker::Worker;
    use std::collections::HashMap;

    #[test]
    fn test_get_exposition_format() {
        let metrics = PoolMetrics {
            accepted_total: 100,
            accepted_difficulty_total: 1,
            rejected_total: 5,
            best_share: 500,
            best_share_ever: 500,
            pool_difficulty: 1000,
            start_time: 1234567890,
            lastupdate: Some(1234567900),
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check that it contains the expected metrics
        assert!(exposition.contains(&format!("shares_accepted_total {}", 100)));
        assert!(exposition.contains(&format!("accepted_difficulty_total {}", 1)));
        assert!(exposition.contains("shares_rejected_total 5"));
        assert!(exposition.contains("best_share 500"));
        assert!(exposition.contains("best_share_ever 500"));
        assert!(exposition.contains("difficulty 1000"));
        assert!(exposition.contains("start_time_seconds 1234567890"));
        assert!(exposition.contains("last_update_seconds 1234567900"));

        // Check that it contains HELP and TYPE comments
        assert!(exposition.contains("# HELP shares_accepted_total"));
        assert!(exposition.contains("# TYPE shares_accepted_total counter"));
    }

    #[test]
    fn test_exposition_excludes_worker_metrics() {
        let mut users = HashMap::new();

        let mut user1 = User {
            last_share_at: 1234567890,
            shares_valid_total: 42,
            best_share: 1000,
            best_share_ever: 2000,
            ..Default::default()
        };

        let worker1 = Worker {
            last_share_at: 1234567891,
            shares_valid_total: 20,
            active: true,
            best_share: 800,
            best_share_ever: 1500,
        };

        let worker2 = Worker {
            last_share_at: 1234567892,
            shares_valid_total: 22,
            active: false,
            best_share: 600,
            best_share_ever: 0,
        };

        user1.workers.insert("worker1".to_string(), worker1);
        user1.workers.insert("worker2".to_string(), worker2);

        users.insert("bc1quser1".to_string(), user1);

        let metrics = PoolMetrics {
            users,
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        assert!(!exposition.contains("worker_shares_valid_total"));
        assert!(!exposition.contains("worker_best_share{"));
        assert!(!exposition.contains("worker_best_share_ever"));
        assert!(!exposition.contains("worker_last_share_at"));
        assert!(!exposition.contains("btcaddress="));
        assert!(!exposition.contains("workername="));

        // Verify no p2pool_ prefix
        assert!(!exposition.contains("p2pool_"));
    }
}
