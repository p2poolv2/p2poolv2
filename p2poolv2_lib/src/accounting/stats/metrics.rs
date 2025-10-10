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

use crate::accounting::stats::pool_local_stats::load_pool_local_stats;
use crate::accounting::stats::user::User;
use crate::accounting::stats::worker::Worker;
use crate::accounting::{simple_pplns::SimplePplnsShare, stats::pool_local_stats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

const METRICS_MESSAGE_BUFFER_SIZE: usize = 1000;
pub const INITIAL_USER_MAP_CAPACITY: usize = 1000;
const METRICS_SAVE_INTERVAL: u64 = 5;

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolMetrics {
    /// Start time in unix timestamp
    pub start_time: u64,
    /// Last update timestamp, time since epoch in seconds
    pub lastupdate: Option<u64>,
    /// Total accepted shares
    pub accepted_total: u64,
    /// Total rejected shares
    pub rejected_total: u64,
    /// Highest difficulty share on this start
    pub best_share: u64,
    /// Highest difficulty share across restarts
    pub best_share_ever: u64,
    /// User metrics
    pub users: HashMap<String, User>,
    /// Current pool difficulty
    pub pool_difficulty: u64,
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            lastupdate: None,
            accepted_total: 0,
            rejected_total: 0,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            best_share: 0,
            best_share_ever: 0,
            users: HashMap::with_capacity(INITIAL_USER_MAP_CAPACITY),
            pool_difficulty: 0,
        }
    }
}

impl PoolMetrics {
    /// Load existing metrics from file or build new default
    pub fn load_existing(log_dir: &str) -> Result<Self, std::io::Error> {
        let pool_stats = load_pool_local_stats(log_dir)?;
        Ok(PoolMetrics {
            accepted_total: pool_stats.accepted_total,
            rejected_total: pool_stats.rejected_total,
            users: pool_stats.users,
            ..Default::default()
        })
    }
}

/// Messages that can be sent to the MetricsActor
#[derive(Debug)]
pub enum MetricsMessage {
    RecordShareAccepted {
        btcaddress: String,
        workername: String,
        difficulty: u64,
        response: oneshot::Sender<()>,
    },
    RecordShareRejected {
        response: oneshot::Sender<()>,
    },
    IncrementWorkerCount {
        btcaddress: String,
        workername: String,
        response: oneshot::Sender<()>,
    },
    DecrementWorkerCount {
        btcaddress: Option<String>,
        workername: String,
        response: oneshot::Sender<()>,
    },
    Commit {
        response: oneshot::Sender<String>,
    },
    GetMetrics {
        response: oneshot::Sender<PoolMetrics>,
    },
    SetLastUpdate {
        lastupdate: u64,
        response: oneshot::Sender<()>,
    },
}

/// The actor that manages pool metrics state
pub struct MetricsActor {
    metrics: PoolMetrics,
    receiver: mpsc::Receiver<MetricsMessage>,
}

impl MetricsActor {
    /// Create a new metrics actor with default metrics
    pub fn new(receiver: mpsc::Receiver<MetricsMessage>) -> Self {
        Self {
            metrics: PoolMetrics::default(),
            receiver,
        }
    }

    /// Create a metrics actor with metrics loaded from the given log directory
    pub fn with_existing_metrics(
        log_dir: &str,
        receiver: mpsc::Receiver<MetricsMessage>,
    ) -> Result<Self, std::io::Error> {
        let metrics = PoolMetrics::load_existing(log_dir)?;
        Ok(Self { metrics, receiver })
    }

    /// Start the actor's message handling loop
    pub async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    async fn handle_message(&mut self, msg: MetricsMessage) {
        match msg {
            MetricsMessage::RecordShareAccepted {
                btcaddress,
                workername,
                difficulty,
                response,
            } => {
                self.record_share_accepted(btcaddress, workername, difficulty);
                let _ = response.send(());
            }
            MetricsMessage::RecordShareRejected { response } => {
                self.record_share_rejected();
                let _ = response.send(());
            }
            MetricsMessage::IncrementWorkerCount {
                btcaddress,
                workername,
                response,
            } => {
                self.worker_authorized(btcaddress, workername);
                let _ = response.send(());
            }
            MetricsMessage::DecrementWorkerCount {
                btcaddress,
                workername,
                response,
            } => {
                self.mark_worker_inactive(btcaddress, workername);
                let _ = response.send(());
            }
            MetricsMessage::Commit { response } => {
                let result = self.commit();
                let _ = response.send(result);
            }
            MetricsMessage::GetMetrics { response } => {
                let _ = response.send(self.metrics.clone());
            }
            MetricsMessage::SetLastUpdate {
                lastupdate,
                response,
            } => {
                self.set_last_update(lastupdate);
                let _ = response.send(());
            }
        }
    }

    /// Update metrics from accepted share
    fn record_share_accepted(&mut self, btcaddress: String, workername: String, difficulty: u64) {
        let current_unix_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.metrics.accepted_total += difficulty;
        self.metrics.lastupdate = Some(current_unix_timestamp);
        self.metrics.best_share = self.metrics.best_share.max(difficulty);
        self.metrics.best_share_ever = self.metrics.best_share_ever.max(difficulty);
        if let Some(user) = self.metrics.users.get_mut(&btcaddress) {
            user.record_share(&workername, difficulty, current_unix_timestamp);
        }
    }

    /// Update metrics from rejected share
    fn record_share_rejected(&mut self) {
        self.metrics.rejected_total += 1;
    }

    /// Increment worker counts - called after worker has authorised successfully.
    fn worker_authorized(&mut self, btcaddress: String, workername: String) {
        self.metrics.users
            .entry(btcaddress)
            .or_insert_with(User::default)
            .workers
            .insert(workername, Worker::default());
    }

    /// Decrement pool wide worker counts, if worker found as authorised. Unauthorised workers are not counted.
    /// Also marks Worker inactive, if found.
    fn mark_worker_inactive(&mut self, btcaddress: Option<String>, workername: String) {
        if let Some(btcaddress) = btcaddress {
            if let Some(user) = self.metrics.users.get_mut(&btcaddress) {
                if let Some(worker) = user.workers.get_mut(&workername) {
                    worker.active = false;
                }
            }
        }
    }

    /// Commit metrics
    /// Export current metrics as json, returning the serialized json
    /// Reset the metrics to start again
    fn commit(&mut self) -> String {
        serde_json::to_string(&self.metrics).unwrap()
    }

    /// Set last update time. Largely used for testing.
    fn set_last_update(&mut self, lastupdate: u64) {
        self.metrics.lastupdate = Some(lastupdate);
        for (_btcaddress, user) in self.metrics.users.iter_mut() {
            user.last_share_at = lastupdate;
            for (_workername, worker) in user.workers.iter_mut() {
                worker.last_share_at = lastupdate;
            }
        }
    }
}

/// A handle to interact with the MetricsActor
#[derive(Clone)]
pub struct MetricsHandle {
    sender: mpsc::Sender<MetricsMessage>,
}

impl MetricsHandle {
    /// Record an accepted share with the given difficulty
    pub async fn record_share_accepted(
        &self,
        share: SimplePplnsShare,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordShareAccepted {
                btcaddress: share.btcaddress.unwrap_or_default(),
                workername: share.workername.unwrap_or_default(),
                difficulty: share.difficulty,
                response: response_tx,
            })
            .await
            .expect("Error recording share");
        response_rx.await
    }

    /// Record a rejected share
    /// We don't difficulty or user info for rejected shares as the could be rejected for any reason
    pub async fn record_share_rejected(
        &self,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordShareRejected {
                response: response_tx,
            })
            .await
            .expect("Error recording share");
        response_rx.await
    }

    /// Increment worker count
    pub async fn increment_worker_count(
        &self,
        btcaddress: String,
        workername: String,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::IncrementWorkerCount {
                response: response_tx,
                btcaddress,
                workername,
            })
            .await
            .expect("Error incrementing worker count");
        response_rx.await
    }

    /// Decrement worker count
    pub async fn decrement_worker_count(
        &self,
        btcaddress: Option<String>,
        workername: String,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::DecrementWorkerCount {
                btcaddress,
                workername,
                response: response_tx,
            })
            .await
            .expect("Error decrementing worker count");
        response_rx.await
    }

    /// Commit metrics and get JSON result
    pub async fn commit(&self) -> Result<String, tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::Commit {
                response: response_tx,
            })
            .await
            .expect("Error committing metrics");
        response_rx.await
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> PoolMetrics {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::GetMetrics {
                response: response_tx,
            })
            .await
            .expect("Error getting metrics");
        response_rx.await.expect("Error getting metrics")
    }

    /// Set last update time. Largely used for testing.
    pub async fn set_last_update(
        &self,
        lastupdate: u64,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::SetLastUpdate {
                lastupdate,
                response: response_tx,
            })
            .await
            .expect("Error setting last update");
        response_rx.await
    }
}

/// Construct a new metrics actor with existing metrics and return its handle
pub async fn start_metrics(log_dir: String) -> Result<MetricsHandle, std::io::Error> {
    let (sender, receiver) = mpsc::channel(METRICS_MESSAGE_BUFFER_SIZE);
    let actor = MetricsActor::new(receiver);
    tokio::spawn(async move {
        actor.run().await;
    });
    let handle = MetricsHandle { sender };
    match pool_local_stats::start_stats_saver(
        handle.clone(),
        METRICS_SAVE_INTERVAL,
        log_dir.to_string(),
    )
    .await
    {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to start stats saver: {e}");
            return Err(std::io::Error::other("Failed to start stats saver"));
        }
    }
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use crate::accounting::stats::pool_local_stats::save_pool_local_stats;

    use super::*;

    #[test]
    fn test_pool_metrics_default() {
        let metrics = PoolMetrics::default();
        assert!(metrics.lastupdate.is_none());
        assert!(metrics.best_share == 0);
    }

    #[tokio::test]
    async fn test_record_share_accepted() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 100,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;

        let metrics = handle.get_metrics().await;
        assert!(metrics.lastupdate.is_some());
        assert_eq!(metrics.best_share, 100);

        // Test that highest difficulty is updated correctly
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 50,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.best_share, 100);

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 200,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.best_share, 200);
    }

    #[tokio::test]
    async fn test_record_share_rejected() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let _ = handle.record_share_rejected().await;

        let _ = handle.record_share_rejected().await;
    }

    #[test_log::test(tokio::test)]
    async fn test_metrics_commit() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .increment_worker_count("user1".to_string(), "worker1".to_string())
            .await;

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 1000,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 2000,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let _ = handle.record_share_rejected().await;

        let current_unix_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = handle.set_last_update(current_unix_timestamp - 60).await;

        let json_str = handle.commit().await;
        let json: serde_json::Value = serde_json::from_str(&json_str.unwrap()).unwrap();

        // Check that lastupdate exists and is a recent timestamp
        assert!(json["lastupdate"].as_u64().is_some());

        let metrics = handle.get_metrics().await;
        // After commit, the metrics should be reset
        assert_eq!(metrics.best_share, 2000);
    }

    #[test_log::test(tokio::test)]
    async fn test_get_metrics_consistency() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 123,
                btcaddress: Some("user1".to_string()),
                workername: Some("worker1".to_string()),
                n_time: 1000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let _ = handle.record_share_rejected().await;
        let _ = handle
            .increment_worker_count("user4".to_string(), "workerD".to_string())
            .await;

        let metrics = handle.get_metrics().await;
        assert!(metrics.users.contains_key("user4"));
        assert!(
            metrics
                .users
                .get("user4")
                .unwrap()
                .workers
                .contains_key("workerD")
        );
        assert_eq!(metrics.accepted_total, 123);
        assert_eq!(metrics.rejected_total, 1);

        // save and reload metrics to verify persistence
        let _ = save_pool_local_stats(&metrics, log_dir.path().to_str().unwrap());
        let reloaded = PoolMetrics::load_existing(log_dir.path().to_str().unwrap()).unwrap();
        assert_eq!(reloaded.accepted_total, metrics.accepted_total);
        assert_eq!(reloaded.rejected_total, metrics.rejected_total);
        assert_eq!(reloaded.users, metrics.users);
    }

    #[tokio::test]
    async fn test_record_share_updates_user_stats() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let btcaddress = "userY".to_string();
        let workername = "workerY".to_string();

        let _ = handle
            .increment_worker_count(btcaddress.clone(), workername.clone())
            .await;

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 77,
                btcaddress: Some(btcaddress.clone()),
                workername: Some(workername.clone()),
                n_time: 3000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;

        let metrics = handle.get_metrics().await;
        let user = metrics.users.get(&btcaddress).unwrap();
        let worker = user.workers.get(&workername).unwrap();
        // Check that worker exists and is active
        assert!(worker.active);
        // Check that user stats are updated
        assert_eq!(user.shares_valid_total, 77);
        assert_eq!(user.best_share, 77);
        assert!(user.last_share_at > 0);
    }

    #[tokio::test]
    async fn test_record_share_multiple_users_and_workers() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .increment_worker_count("userA".to_string(), "workerA1".to_string())
            .await;
        let _ = handle
            .increment_worker_count("userA".to_string(), "workerA2".to_string())
            .await;
        let _ = handle
            .increment_worker_count("userB".to_string(), "workerB1".to_string())
            .await;

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 10,
                btcaddress: Some("userA".to_string()),
                workername: Some("workerA1".to_string()),
                n_time: 4000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 20,
                btcaddress: Some("userA".to_string()),
                workername: Some("workerA2".to_string()),
                n_time: 5000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                user_id: 1,
                difficulty: 30,
                btcaddress: Some("userB".to_string()),
                workername: Some("workerB1".to_string()),
                n_time: 6000,
                job_id: "test_job".to_string(),
                extranonce2: "test_extra".to_string(),
                nonce: "test_nonce".to_string(),
            })
            .await;

        let metrics = handle.get_metrics().await;

        let user_a = metrics.users.get("userA").unwrap();
        assert_eq!(user_a.shares_valid_total, 30);
        assert_eq!(user_a.best_share, 20);
        assert!(user_a.workers.contains_key("workerA1"));
        assert!(user_a.workers.contains_key("workerA2"));

        let user_b = metrics.users.get("userB").unwrap();
        assert_eq!(user_b.shares_valid_total, 30);
        assert_eq!(user_b.best_share, 30);
        assert!(user_b.workers.contains_key("workerB1"));
    }
}
