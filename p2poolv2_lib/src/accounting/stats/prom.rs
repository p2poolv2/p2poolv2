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
use std::time::SystemTime;

const TWO32: f64 = (1u64 << 32) as f64;

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

        output.push_str(&self.get_blocks_found_exposition());

        output.push_str(
            "# HELP work_since_last_block Accumulated accepted share difficulty since the last bitcoin block was found\n",
        );
        output.push_str("# TYPE work_since_last_block gauge\n");
        output.push_str(&format!(
            "work_since_last_block {}\n",
            self.work_since_last_block
        ));
        output.push('\n');

        output.push_str(&self.get_worker_expositions());

        output
    }

    /// Exposition for bitcoin blocks found by the pool.
    ///
    /// Emits a monotonic counter for the total and one info gauge line per
    /// recently found block, carrying blockhash and height labels set to the
    /// discovery timestamp. The bounded ring (MAX_BLOCKS_FOUND_TRACKED) keeps
    /// label cardinality low while letting Grafana build block explorer links.
    fn get_blocks_found_exposition(&self) -> String {
        let mut output = String::new();

        output.push_str("# HELP bitcoin_blocks_found_total Total number of bitcoin blocks found\n");
        output.push_str("# TYPE bitcoin_blocks_found_total counter\n");
        output.push_str(&format!(
            "bitcoin_blocks_found_total {}\n",
            self.blocks_found_total
        ));
        output.push('\n');

        output.push_str(
            "# HELP bitcoin_block_found_info Unix timestamp when a bitcoin block was found, labeled with blockhash and height\n",
        );
        output.push_str("# TYPE bitcoin_block_found_info gauge\n");
        for block in &self.blocks_found {
            output.push_str(&format!(
                "bitcoin_block_found_info{{blockhash=\"{}\",height=\"{}\"}} {}\n",
                block.blockhash, block.height, block.timestamp
            ));
        }
        output.push('\n');

        output
    }

    fn get_worker_expositions(&self) -> String {
        let mut output = String::new();

        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Collect non-expired users with non-expired active workers
        let active_users: Vec<_> = self
            .users
            .iter()
            .filter(|(_, u)| {
                !u.should_remove(current_time)
                    && u.active_workers()
                        .any(|(_, w)| !w.should_remove(current_time))
            })
            .collect();

        // Collect non-expired users with any shares
        let some_shares_users: Vec<_> = self
            .users
            .iter()
            .filter(|(_, u)| !u.should_remove(current_time) && u.shares_valid_total > 0)
            .collect();

        // User metrics with btcaddress label
        output.push_str("# HELP user_shares_valid_total Total valid shares submitted by user\n");
        output.push_str("# TYPE user_shares_valid_total counter\n");
        for (btcaddress, user) in &some_shares_users {
            output.push_str(&format!(
                "user_shares_valid_total{{btcaddress=\"{}\"}} {:.0}\n",
                btcaddress,
                (user.shares_valid_total as f64) * TWO32
            ));
        }
        output.push('\n');

        // Worker metrics with btcaddress and workername labels
        output
            .push_str("# HELP worker_shares_valid_total Total valid shares submitted by worker\n");
        output.push_str("# TYPE worker_shares_valid_total counter\n");
        for (btcaddress, user) in &active_users {
            for (workername, worker) in user
                .active_workers()
                .filter(|(_, w)| !w.should_remove(current_time))
            {
                let display_name = if workername.is_empty() {
                    "unnamed"
                } else {
                    workername
                };
                output.push_str(&format!(
                    "worker_shares_valid_total{{btcaddress=\"{}\",workername=\"{}\"}} {:.0}\n",
                    btcaddress,
                    display_name,
                    (worker.shares_valid_total as f64) * TWO32
                ));
            }
        }
        output.push('\n');

        output.push_str("# HELP worker_best_share Best share difficulty for this session\n");
        output.push_str("# TYPE worker_best_share gauge\n");
        for (btcaddress, user) in &active_users {
            for (workername, worker) in user
                .active_workers()
                .filter(|(_, w)| !w.should_remove(current_time))
            {
                let display_name = if workername.is_empty() {
                    "unnamed"
                } else {
                    workername
                };
                output.push_str(&format!(
                    "worker_best_share{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, display_name, worker.best_share
                ));
            }
        }
        output.push('\n');

        output.push_str(
            "# HELP worker_best_share_ever Best share difficulty ever submitted by worker\n",
        );
        output.push_str("# TYPE worker_best_share_ever gauge\n");
        for (btcaddress, user) in &active_users {
            for (workername, worker) in user
                .active_workers()
                .filter(|(_, w)| !w.should_remove(current_time))
            {
                let display_name = if workername.is_empty() {
                    "unnamed"
                } else {
                    workername
                };
                output.push_str(&format!(
                    "worker_best_share_ever{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, display_name, worker.best_share_ever
                ));
            }
        }
        output.push('\n');

        output
            .push_str("# HELP worker_last_share_at Last share submission time in Unix timestamp\n");
        output.push_str("# TYPE worker_last_share_at gauge\n");
        for (btcaddress, user) in &active_users {
            for (workername, worker) in user
                .active_workers()
                .filter(|(_, w)| !w.should_remove(current_time))
            {
                let display_name = if workername.is_empty() {
                    "unnamed"
                } else {
                    workername
                };
                output.push_str(&format!(
                    "worker_last_share_at{{btcaddress=\"{}\",workername=\"{}\"}} {}\n",
                    btcaddress, display_name, worker.last_share_at
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
    use crate::accounting::stats::metrics::BlockFound;
    use crate::accounting::stats::user::User;
    use std::collections::{HashMap, VecDeque};
    use std::time::SystemTime;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

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
    fn test_blocks_found_and_effort_exposition() {
        let mut blocks_found = VecDeque::new();
        blocks_found.push_back(BlockFound {
            blockhash: "00000000000000000000abcdef0123456789abcdef0123456789abcdef012345"
                .to_string(),
            height: 840000,
            timestamp: 1700000000,
        });

        let metrics = PoolMetrics {
            blocks_found_total: 3,
            blocks_found,
            work_since_last_block: 12345,
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        assert!(exposition.contains("# TYPE bitcoin_blocks_found_total counter"));
        assert!(exposition.contains("bitcoin_blocks_found_total 3"));

        assert!(exposition.contains("# TYPE bitcoin_block_found_info gauge"));
        assert!(exposition.contains(
            "bitcoin_block_found_info{blockhash=\"00000000000000000000abcdef0123456789abcdef0123456789abcdef012345\",height=\"840000\"} 1700000000"
        ));

        assert!(exposition.contains("# TYPE work_since_last_block gauge"));
        assert!(exposition.contains("work_since_last_block 12345"));
    }

    #[test]
    fn test_get_worker_expositions() {
        use crate::accounting::stats::worker::Worker;

        let recent = now();
        let mut users = HashMap::new();

        let mut user1 = User {
            last_share_at: recent,
            shares_valid_total: 42,
            best_share: 1000,
            best_share_ever: 2000,
            ..Default::default()
        };

        let worker1 = Worker {
            last_share_at: recent,
            shares_valid_total: 20,
            active: true,
            best_share: 800,
            best_share_ever: 1500,
        };

        let worker2 = Worker {
            last_share_at: recent,
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

        // Check user-level shares_valid_total metric
        assert!(exposition.contains("# HELP user_shares_valid_total"));
        assert!(exposition.contains("# TYPE user_shares_valid_total counter"));
        assert!(exposition.contains(&format!(
            r#"user_shares_valid_total{{btcaddress="bc1quser1"}} {:.0}"#,
            42.0 * TWO32
        )));

        // Check worker metrics are present for active worker1
        assert!(exposition.contains("# HELP worker_shares_valid"));
        assert!(exposition.contains("# TYPE worker_shares_valid_total counter"));
        assert!(exposition.contains(&format!(
            r#"worker_shares_valid_total{{btcaddress="bc1quser1",workername="worker1"}} {:.0}"#,
            20.0 * TWO32
        )));
        // Inactive worker2 should NOT be present
        assert!(!exposition.contains(&format!(
            r#"worker_shares_valid_total{{btcaddress="bc1quser1",workername="worker2"}} {:.0}"#,
            22.0 * TWO32
        )));

        assert!(exposition.contains("# HELP worker_best_share"));
        assert!(exposition.contains("# TYPE worker_best_share gauge"));
        assert!(
            exposition
                .contains("worker_best_share{btcaddress=\"bc1quser1\",workername=\"worker1\"} 800")
        );
        // Inactive worker2 should NOT be present
        assert!(
            !exposition
                .contains("worker_best_share{btcaddress=\"bc1quser1\",workername=\"worker2\"} 600")
        );

        assert!(exposition.contains("# HELP worker_best_share_ever"));
        assert!(exposition.contains("# TYPE worker_best_share_ever gauge"));
        assert!(exposition.contains(
            "worker_best_share_ever{btcaddress=\"bc1quser1\",workername=\"worker1\"} 1500"
        ));
        // Inactive worker2 should NOT be present
        assert!(
            !exposition.contains(
                "worker_best_share_ever{btcaddress=\"bc1quser1\",workername=\"worker2\"} 0"
            )
        );

        assert!(exposition.contains("# HELP worker_last_share_at"));
        assert!(exposition.contains("# TYPE worker_last_share_at gauge"));
        assert!(exposition.contains(&format!(
            "worker_last_share_at{{btcaddress=\"bc1quser1\",workername=\"worker1\"}} {}",
            recent
        )));
        // Inactive worker2 should NOT be present
        assert!(!exposition.contains(&format!(
            "worker_last_share_at{{btcaddress=\"bc1quser1\",workername=\"worker2\"}} {}",
            recent
        )));

        // Verify no p2pool_ prefix
        assert!(!exposition.contains("p2pool_"));
    }

    #[test]
    fn test_empty_workername_becomes_unnamed() {
        use crate::accounting::stats::worker::Worker;

        let recent = now();
        let mut users = HashMap::new();

        let mut user1 = User {
            last_share_at: recent,
            shares_valid_total: 10,
            best_share: 500,
            best_share_ever: 500,
            ..Default::default()
        };

        let worker_with_empty_name = Worker {
            last_share_at: recent,
            shares_valid_total: 10,
            active: true,
            best_share: 500,
            best_share_ever: 500,
        };

        user1.workers.insert("".to_string(), worker_with_empty_name);
        users.insert("bc1qtest".to_string(), user1);

        let metrics = PoolMetrics {
            users,
            ..Default::default()
        };

        let exposition = metrics.get_exposition();

        // Check user-level metric
        assert!(exposition.contains(&format!(
            r#"user_shares_valid_total{{btcaddress="bc1qtest"}} {:.0}"#,
            10.0 * TWO32
        )));

        // Verify that empty workername is replaced with "unnamed"
        assert!(exposition.contains(r#"workername="unnamed""#));
        assert!(exposition.contains(&format!(
            r#"worker_shares_valid_total{{btcaddress="bc1qtest",workername="unnamed"}} {:.0}"#,
            10.0 * TWO32
        )));
        assert!(
            exposition
                .contains(r#"worker_best_share{btcaddress="bc1qtest",workername="unnamed"} 500"#)
        );
        assert!(
            exposition.contains(
                r#"worker_best_share_ever{btcaddress="bc1qtest",workername="unnamed"} 500"#
            )
        );
        assert!(exposition.contains(&format!(
            r#"worker_last_share_at{{btcaddress="bc1qtest",workername="unnamed"}} {}"#,
            recent
        )));
    }
}
