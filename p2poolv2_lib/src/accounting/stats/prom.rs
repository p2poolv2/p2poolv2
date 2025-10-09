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
        output.push_str("# HELP users_count Number of users\n");
        output.push_str("# TYPE users_count gauge\n");
        output.push_str(&format!("users_count {}\n", self.users_count));
        output.push('\n');

        output.push_str("# HELP workers_count Number of workers\n");
        output.push_str("# TYPE workers_count gauge\n");
        output.push_str(&format!("workers_count {}\n", self.workers_count));
        output.push('\n');

        output.push_str("# HELP idle_users_count Number of idle users\n");
        output.push_str("# TYPE idle_users_count gauge\n");
        output.push_str(&format!("idle_users_count {}\n", self.idle_users_count));
        output.push('\n');

        output.push_str("# HELP best_share Highest difficulty share\n");
        output.push_str("# TYPE best_share gauge\n");
        output.push_str(&format!("best_share {}\n", self.bestshare));
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

        output.push_str(&self.get_user_expositions());
        output.push_str(&self.get_worker_expositions());

        output
    }

    fn get_user_expositions(&self) -> String {
        let mut output = String::new();

        // User metrics with btcaddress label
        output.push_str("# HELP user_shares_valid_total Total valid shares submitted by user\n");
        output.push_str("# TYPE user_shares_valid_total counter\n");
        for (btcaddress, user) in &self.users {
            output.push_str(&format!(
                "user_shares_valid_total{{btcaddress=\"{}\"}} {}\n",
                btcaddress, user.shares_valid_total
            ));
        }
        output.push('\n');

        output.push_str("# HELP user_best_share Best share difficulty for this session\n");
        output.push_str("# TYPE user_best_share gauge\n");
        for (btcaddress, user) in &self.users {
            output.push_str(&format!(
                "user_best_share{{btcaddress=\"{}\"}} {}\n",
                btcaddress, user.best_share
            ));
        }
        output.push('\n');

        output.push_str("# HELP user_best_share_ever Best share difficulty ever submitted\n");
        output.push_str("# TYPE user_best_share_ever gauge\n");
        for (btcaddress, user) in &self.users {
            output.push_str(&format!(
                "user_best_share_ever{{btcaddress=\"{}\"}} {}\n",
                btcaddress,
                user.best_share_ever.unwrap_or(0)
            ));
        }
        output.push('\n');

        output.push_str("# HELP user_last_share_at Last share submission time in Unix timestamp\n");
        output.push_str("# TYPE user_last_share_at gauge\n");
        for (btcaddress, user) in &self.users {
            output.push_str(&format!(
                "user_last_share_at{{btcaddress=\"{}\"}} {}\n",
                btcaddress, user.last_share_at
            ));
        }
        output.push('\n');

        output
    }

    fn get_worker_expositions(&self) -> String {
        let mut output = String::new();

        // Worker metrics with btcaddress and workername labels
        output
            .push_str("# HELP worker_shares_valid_total Total valid shares submitted by worker\n");
        output.push_str("# TYPE worker_shares_valid_total counter\n");
        for (btcaddress, user) in &self.users {
            for (workername, worker) in &user.workers {
                output.push_str(&format!(
                    "worker_shares_valid_total{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, workername, worker.shares_valid_total
                ));
            }
        }
        output.push('\n');

        output.push_str("# HELP worker_active Worker active status (1 = active, 0 = inactive)\n");
        output.push_str("# TYPE worker_active gauge\n");
        for (btcaddress, user) in &self.users {
            for (workername, worker) in &user.workers {
                output.push_str(&format!(
                    "worker_active{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress,
                    workername,
                    if worker.active { 1 } else { 0 }
                ));
            }
        }
        output.push('\n');

        output.push_str("# HELP worker_best_share Best share difficulty for this session\n");
        output.push_str("# TYPE worker_best_share gauge\n");
        for (btcaddress, user) in &self.users {
            for (workername, worker) in &user.workers {
                output.push_str(&format!(
                    "worker_best_share{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, workername, worker.best_share
                ));
            }
        }
        output.push('\n');

        output.push_str(
            "# HELP worker_best_share_ever Best share difficulty ever submitted by worker\n",
        );
        output.push_str("# TYPE worker_best_share_ever gauge\n");
        for (btcaddress, user) in &self.users {
            for (workername, worker) in &user.workers {
                output.push_str(&format!(
                    "worker_best_share_ever{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress,
                    workername,
                    worker.best_share_ever.unwrap_or(0)
                ));
            }
        }
        output.push('\n');

        output
            .push_str("# HELP worker_last_share_at Last share submission time in Unix timestamp\n");
        output.push_str("# TYPE worker_last_share_at gauge\n");
        for (btcaddress, user) in &self.users {
            for (workername, worker) in &user.workers {
                output.push_str(&format!(
                    "worker_last_share_at{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, workername, worker.last_share_at
                ));
            }
        }
        output.push('\n');

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::stats::user::User;
    use std::collections::HashMap;

    #[test]
    fn test_get_exposition_format() {
        let metrics = PoolMetrics {
            accepted: 100,
            rejected: 5,
            users_count: 3,
            workers_count: 7,
            idle_users_count: 1,
            bestshare: 500,
            pool_difficulty: 1000,
            start_time: 1234567890,
            lastupdate: Some(1234567900),
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check that it contains the expected metrics
        assert!(exposition.contains("shares_accepted_total 100"));
        assert!(exposition.contains("shares_rejected_total 5"));
        assert!(exposition.contains("users_count 3"));
        assert!(exposition.contains("workers_count 7"));
        assert!(exposition.contains("idle_users_count 1"));
        assert!(exposition.contains("best_share 500"));
        assert!(exposition.contains("difficulty 1000"));
        assert!(exposition.contains("start_time_seconds 1234567890"));
        assert!(exposition.contains("last_update_seconds 1234567900"));

        // Check that it contains HELP and TYPE comments
        assert!(exposition.contains("# HELP shares_accepted_total"));
        assert!(exposition.contains("# TYPE shares_accepted_total counter"));
        assert!(exposition.contains("# TYPE users_count gauge"));
    }

    #[test]
    fn test_get_user_expositions() {
        let mut users = HashMap::new();

        let user1 = User {
            last_share_at: 1234567890,
            shares_valid_total: 42,
            best_share: 1000,
            best_share_ever: Some(2000),
            ..Default::default()
        };

        let user2 = User {
            last_share_at: 1234567900,
            shares_valid_total: 100,
            best_share: 500,
            best_share_ever: None,
            ..Default::default()
        };

        users.insert("bc1quser1".to_string(), user1);
        users.insert("bc1quser2".to_string(), user2);

        let metrics = PoolMetrics {
            users,
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check user metrics are present
        assert!(exposition.contains("# HELP user_shares_valid"));
        assert!(exposition.contains("# TYPE user_shares_valid_total counter"));
        assert!(exposition.contains("user_shares_valid_total{btcaddress=\"bc1quser1\"} 42"));
        assert!(exposition.contains("user_shares_valid_total{btcaddress=\"bc1quser2\"} 100"));

        assert!(exposition.contains("# HELP user_best_share"));
        assert!(exposition.contains("# TYPE user_best_share gauge"));
        assert!(exposition.contains("user_best_share{btcaddress=\"bc1quser1\"} 1000"));
        assert!(exposition.contains("user_best_share{btcaddress=\"bc1quser2\"} 500"));

        assert!(exposition.contains("# HELP user_best_share_ever"));
        assert!(exposition.contains("# TYPE user_best_share_ever gauge"));
        assert!(exposition.contains("user_best_share_ever{btcaddress=\"bc1quser1\"} 2000"));
        assert!(exposition.contains("user_best_share_ever{btcaddress=\"bc1quser2\"} 0"));

        assert!(exposition.contains("# HELP user_last_share_at"));
        assert!(exposition.contains("# TYPE user_last_share_at gauge"));
        assert!(exposition.contains("user_last_share_at{btcaddress=\"bc1quser1\"} 1234567890"));
        assert!(exposition.contains("user_last_share_at{btcaddress=\"bc1quser2\"} 1234567900"));

        // Verify no p2pool_ prefix
        assert!(!exposition.contains("p2pool_"));
    }

    #[test]
    fn test_get_worker_expositions() {
        use crate::accounting::stats::worker::Worker;

        let mut users = HashMap::new();

        let mut user1 = User {
            last_share_at: 1234567890,
            shares_valid_total: 42,
            best_share: 1000,
            best_share_ever: Some(2000),
            ..Default::default()
        };

        let worker1 = Worker {
            last_share_at: 1234567891,
            shares_valid_total: 20,
            active: true,
            best_share: 800,
            best_share_ever: Some(1500),
            ..Default::default()
        };

        let worker2 = Worker {
            last_share_at: 1234567892,
            shares_valid_total: 22,
            active: false,
            best_share: 600,
            best_share_ever: None,
            ..Default::default()
        };

        user1.workers.insert("worker1".to_string(), worker1);
        user1.workers.insert("worker2".to_string(), worker2);

        users.insert("bc1quser1".to_string(), user1);

        let metrics = PoolMetrics {
            users,
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check worker metrics are present
        assert!(exposition.contains("# HELP worker_shares_valid"));
        assert!(exposition.contains("# TYPE worker_shares_valid_total counter"));
        assert!(exposition.contains(
            "worker_shares_valid_total{btcaddress=\"bc1quser1\",workername=\"worker1\"} 20"
        ));
        assert!(exposition.contains(
            "worker_shares_valid_total{btcaddress=\"bc1quser1\",workername=\"worker2\"} 22"
        ));

        assert!(exposition.contains("# HELP worker_active"));
        assert!(exposition.contains("# TYPE worker_active gauge"));
        assert!(
            exposition.contains("worker_active{btcaddress=\"bc1quser1\",workername=\"worker1\"} 1")
        );
        assert!(
            exposition.contains("worker_active{btcaddress=\"bc1quser1\",workername=\"worker2\"} 0")
        );

        assert!(exposition.contains("# HELP worker_best_share"));
        assert!(exposition.contains("# TYPE worker_best_share gauge"));
        assert!(
            exposition
                .contains("worker_best_share{btcaddress=\"bc1quser1\",workername=\"worker1\"} 800")
        );
        assert!(
            exposition
                .contains("worker_best_share{btcaddress=\"bc1quser1\",workername=\"worker2\"} 600")
        );

        assert!(exposition.contains("# HELP worker_best_share_ever"));
        assert!(exposition.contains("# TYPE worker_best_share_ever gauge"));
        assert!(exposition.contains(
            "worker_best_share_ever{btcaddress=\"bc1quser1\",workername=\"worker1\"} 1500"
        ));
        assert!(
            exposition.contains(
                "worker_best_share_ever{btcaddress=\"bc1quser1\",workername=\"worker2\"} 0"
            )
        );

        assert!(exposition.contains("# HELP worker_last_share_at"));
        assert!(exposition.contains("# TYPE worker_last_share_at gauge"));
        assert!(exposition.contains(
            "worker_last_share_at{btcaddress=\"bc1quser1\",workername=\"worker1\"} 1234567891"
        ));
        assert!(exposition.contains(
            "worker_last_share_at{btcaddress=\"bc1quser1\",workername=\"worker2\"} 1234567892"
        ));

        // Verify no p2pool_ prefix
        assert!(!exposition.contains("p2pool_"));
    }
}
