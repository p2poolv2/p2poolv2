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

use crate::stats::computed::time_since;
use crate::stats::computed::{ComputedHashrate, ComputedShareRate};
use crate::stats::pool_local_stats::load_pool_local_stats;
use crate::stats::user::User;
use crate::stats::worker::Worker;
use crate::{simple_pplns::SimplePplnsShare, stats::pool_local_stats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

const METRICS_MESSAGE_BUFFER_SIZE: usize = 100;
pub const INITIAL_USER_MAP_CAPACITY: usize = 1000;
const METRICS_SAVE_INTERVAL: u64 = 5;

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolMetrics {
    /// Start time in unix timestamp
    pub start_time: u64,
    /// Last update timestamp, time since epoch in seconds
    pub lastupdate: Option<u64>,
    /// Number of users
    pub num_users: u32,
    /// Number of workers
    pub num_workers: u32,
    /// Number of idle users
    pub num_idle_users: u32,
    /// Tracks the number of shares since last stats update
    #[serde(skip)]
    pub unaccounted_shares: u64,
    /// Tracks the total difficulty since last stats update
    #[serde(skip)]
    pub unaccounted_difficulty: u64,
    /// Tracks the number of rejected shares since last stats update
    #[serde(skip)]
    pub unaccounted_rejected: u64,
    /// Total accepted shares
    pub accepted: u64,
    /// Total rejected shares
    pub rejected: u64,
    /// Highest difficulty share
    pub bestshare: u64,
    /// User metrics
    pub users: HashMap<String, User>,
    /// Current pool difficulty
    pub difficulty: u64,
    /// Hashrate computed from unaccounted difficulty
    pub computed_hashrate: ComputedHashrate,
    /// Shares per second computed from unaccounted shares
    pub computed_share_rate: ComputedShareRate,
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            lastupdate: None,
            unaccounted_shares: 0,
            unaccounted_difficulty: 0,
            unaccounted_rejected: 0,
            accepted: 0,
            rejected: 0,
            num_users: 0,
            num_workers: 0,
            num_idle_users: 0,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            bestshare: 0,
            users: HashMap::with_capacity(INITIAL_USER_MAP_CAPACITY),
            difficulty: 0,
            computed_hashrate: ComputedHashrate::default(),
            computed_share_rate: ComputedShareRate::default(),
        }
    }
}

impl PoolMetrics {
    /// Load existing metrics from file or build new default
    pub fn load_existing(log_dir: &str) -> Result<Self, std::io::Error> {
        let pool_stats = load_pool_local_stats(log_dir)?;
        Ok(PoolMetrics {
            accepted: pool_stats.accepted,
            rejected: pool_stats.rejected,
            users: pool_stats.users,
            ..Default::default()
        })
    }

    /// Reset metrics to their default values using default
    fn reset(&mut self) {
        self.unaccounted_shares = 0;
        self.unaccounted_rejected = 0;
        self.unaccounted_difficulty = 0;
        for (_, user) in self.users.iter_mut() {
            user.reset();
            for (_, worker) in user.workers.iter_mut() {
                worker.reset();
            }
        }
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
    MarkUserIdle {
        response: oneshot::Sender<()>,
    },
    MarkUserActive {
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
                self.increment_worker_count(btcaddress, workername);
                let _ = response.send(());
            }
            MetricsMessage::DecrementWorkerCount {
                btcaddress,
                workername,
                response,
            } => {
                self.decrement_worker_count(btcaddress, workername);
                let _ = response.send(());
            }
            MetricsMessage::MarkUserIdle { response } => {
                self.mark_user_idle();
                let _ = response.send(());
            }
            MetricsMessage::MarkUserActive { response } => {
                self.mark_user_active();
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
        self.metrics.unaccounted_shares += 1;
        self.metrics.accepted += 1;
        self.metrics.unaccounted_difficulty += difficulty;
        self.metrics.lastupdate = Some(current_unix_timestamp);
        if self.metrics.bestshare < difficulty {
            self.metrics.bestshare = difficulty;
        }
        if let Some(user) = self.metrics.users.get_mut(&btcaddress) {
            user.record_share(&workername, difficulty, current_unix_timestamp);
        }
    }

    /// Update metrics from rejected share
    fn record_share_rejected(&mut self) {
        self.metrics.unaccounted_rejected += 1;
        self.metrics.rejected += 1;
    }

    /// Increment worker counts - called after worker has authorised successfully.
    fn increment_worker_count(&mut self, btcaddress: String, workername: String) {
        self.metrics.num_workers += 1;
        self.metrics
            .users
            .entry(btcaddress.clone())
            .or_insert_with(|| {
                let mut user = User::default();
                let worker = Worker::default();
                user.workers.insert(workername, worker);
                user
            });
    }

    /// Decrement pool wide worker counts, if worker found as authorised. Unauthorised workers are not counted.
    /// Also marks Worker inactive, if found.
    fn decrement_worker_count(&mut self, btcaddress: Option<String>, workername: String) {
        if let Some(btcaddress) = btcaddress {
            if self.metrics.num_workers > 0 {
                self.metrics.num_workers -= 1;
            }
            if let Some(user) = self.metrics.users.get_mut(&btcaddress) {
                if let Some(worker) = user.workers.get_mut(&workername) {
                    worker.active = false;
                }
            }
        }
    }

    /// Mark user idle
    fn mark_user_idle(&mut self) {
        self.metrics.num_idle_users += 1;
    }

    /// Mark user not idle
    fn mark_user_active(&mut self) {
        if self.metrics.num_idle_users > 0 {
            self.metrics.num_idle_users -= 1;
        }
    }

    /// Commit metrics
    /// Export current metrics as json, returning the serialized json
    /// Reset the metrics to start again
    fn commit(&mut self) -> String {
        self.metrics.computed_hashrate.set_hashrate_metrics(
            time_since(self.metrics.lastupdate),
            self.metrics.unaccounted_difficulty,
        );

        self.metrics.computed_share_rate.set_share_rate_metrics(
            time_since(self.metrics.lastupdate),
            self.metrics.unaccounted_shares,
        );

        self.commit_users();

        let serialized = serde_json::to_string(&self.metrics).unwrap();
        self.metrics.reset();
        serialized
    }

    fn commit_users(&mut self) {
        for (_btcaddress, user) in self.metrics.users.iter_mut() {
            user.computed_hash_rate.set_hashrate_metrics(
                time_since(Some(user.last_share_at)),
                user.unaccounted_difficulty,
            );
            for (_workername, worker) in user.workers.iter_mut() {
                worker.computed_hash_rate.set_hashrate_metrics(
                    time_since(Some(worker.last_share_at)),
                    worker.unaccounted_difficulty,
                );
            }
        }
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
                btcaddress: share.btcaddress,
                workername: share.workername,
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

    /// Mark a user as idle
    pub async fn mark_user_idle(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::MarkUserIdle {
                response: response_tx,
            })
            .await
            .expect("Error marking user idle");
        response_rx.await
    }

    /// Mark a user as active
    pub async fn mark_user_active(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::MarkUserActive {
                response: response_tx,
            })
            .await
            .expect("Error marking user active");
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
    let actor = MetricsActor::with_existing_metrics(&log_dir, receiver)?;
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
    use crate::stats::pool_local_stats::save_pool_local_stats;

    use super::*;

    #[test]
    fn test_pool_metrics_default() {
        let metrics = PoolMetrics::default();
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 0);
        assert_eq!(metrics.num_idle_users, 0);
        assert_eq!(metrics.num_workers, 0);
        assert!(metrics.lastupdate.is_none());
        assert!(metrics.bestshare == 0);
    }

    #[test]
    fn test_pool_metrics_reset() {
        let mut metrics = PoolMetrics::default();
        metrics.unaccounted_shares = 10;
        metrics.unaccounted_difficulty = 1000;
        metrics.unaccounted_rejected = 5;
        metrics.num_users = 3;
        metrics.num_idle_users = 1;
        metrics.num_workers = 5;
        metrics.lastupdate = None;
        metrics.bestshare = 500;

        metrics.reset();

        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 3);
        assert_eq!(metrics.num_idle_users, 1);
        assert_eq!(metrics.num_workers, 5);
        assert!(metrics.lastupdate.is_none());
        assert_eq!(metrics.bestshare, 500);
    }

    #[tokio::test]
    async fn test_record_share_accepted() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 100,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
            })
            .await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 1);
        assert_eq!(metrics.unaccounted_difficulty, 100);
        assert!(metrics.lastupdate.is_some());
        assert_eq!(metrics.bestshare, 100);

        // Test that highest difficulty is updated correctly
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 50,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
            })
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 2);
        assert_eq!(metrics.unaccounted_difficulty, 150);
        assert_eq!(metrics.bestshare, 100);

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 200,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
            })
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 3);
        assert_eq!(metrics.unaccounted_difficulty, 350);
        assert_eq!(metrics.bestshare, 200);
    }

    #[tokio::test]
    async fn test_record_share_rejected() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let _ = handle.record_share_rejected().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_rejected, 1);

        let _ = handle.record_share_rejected().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_rejected, 2);
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
                difficulty: 1000,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 2000,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
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

        let mut metrics = handle.get_metrics().await;
        // After commit, the metrics should be reset
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.bestshare, 2000);
        assert_eq!(metrics.computed_hashrate.hashrate_1m, 19);

        let user1_metrics = metrics.users.get_mut("user1").unwrap();
        assert_eq!(user1_metrics.unaccounted_difficulty, 0);
        assert_eq!(user1_metrics.computed_hash_rate.hashrate_1m, 19);

        let worker1_metrics = user1_metrics.get_worker_mut("worker1").unwrap();
        assert_eq!(worker1_metrics.unaccounted_difficulty, 0);
        assert_eq!(worker1_metrics.computed_hash_rate.hashrate_1m, 19);
    }

    #[tokio::test]
    async fn test_increment_worker_count() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let btcaddress = "user1";
        let workername = "workerA".to_string();

        let _ = handle
            .increment_worker_count(btcaddress.to_string(), workername.clone())
            .await;
        let metrics = handle.get_metrics().await;

        assert_eq!(metrics.num_workers, 1);
        assert!(metrics.users.contains_key(btcaddress));
        let user = metrics.users.get(btcaddress).unwrap();
        assert!(user.workers.contains_key(&workername));
        assert!(user.workers.get(&workername).unwrap().active);
    }

    #[tokio::test]
    async fn test_decrement_worker_count() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let btcaddress = "user2";
        let workername = "workerB".to_string();

        // Increment first
        let _ = handle
            .increment_worker_count(btcaddress.to_string(), workername.clone())
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_workers, 1);

        // Decrement
        let _ = handle
            .decrement_worker_count(Some(btcaddress.to_string()), workername.clone())
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_workers, 0);

        // Worker should be marked inactive
        let user = metrics.users.get(btcaddress).unwrap();
        assert!(!user.workers.get(&workername).unwrap().active);

        // Decrement again, num_workers should not go below zero
        let _ = handle
            .decrement_worker_count(Some(btcaddress.to_string()), workername.clone())
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_workers, 0);
    }

    #[tokio::test]
    async fn test_decrement_worker_count_none_btcaddress() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let btcaddress = "user3";
        let workername = "workerC".to_string();

        // Increment first
        let _ = handle
            .increment_worker_count(btcaddress.to_string(), workername.clone())
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_workers, 1);

        // Decrement with None btcaddress, should not change num_workers or worker state
        let _ = handle
            .decrement_worker_count(None, workername.clone())
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_workers, 1);

        // Worker should still be active
        let user = metrics.users.get(btcaddress).unwrap();
        assert!(user.workers.get(&workername).unwrap().active);
    }

    #[tokio::test]
    async fn test_mark_user_idle_and_active() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        // Initially idle users should be 0
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_idle_users, 0);

        // Mark user idle
        let _ = handle.mark_user_idle().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_idle_users, 1);

        // Mark user active (should decrement inc and then dec idle count)
        let _ = handle.mark_user_idle().await;
        let _ = handle.mark_user_active().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_idle_users, 1);

        // Mark user active again (should increment to 2)
        let _ = handle.mark_user_idle().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.num_idle_users, 2);
    }

    #[test_log::test(tokio::test)]
    async fn test_get_metrics_consistency() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 123,
                btcaddress: "user1".to_string(),
                workername: "worker1".to_string(),
            })
            .await;
        let _ = handle.record_share_rejected().await;
        let _ = handle
            .increment_worker_count("user4".to_string(), "workerD".to_string())
            .await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 1);
        assert_eq!(metrics.unaccounted_difficulty, 123);
        assert_eq!(metrics.unaccounted_rejected, 1);
        assert_eq!(metrics.num_workers, 1);
        assert!(metrics.users.contains_key("user4"));
        assert!(
            metrics
                .users
                .get("user4")
                .unwrap()
                .workers
                .contains_key("workerD")
        );
        assert_eq!(metrics.accepted, 1);
        assert_eq!(metrics.rejected, 1);

        // save and reload metrics to verify persistence
        println!("Saving metrics: {:?}", metrics);
        let _ = save_pool_local_stats(&metrics, log_dir.path().to_str().unwrap());
        let reloaded = PoolMetrics::load_existing(log_dir.path().to_str().unwrap()).unwrap();
        println!("Reloaded metrics: {:?}", reloaded);
        assert_eq!(reloaded.accepted, metrics.accepted);
        assert_eq!(reloaded.rejected, metrics.rejected);
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
                difficulty: 77,
                btcaddress: btcaddress.clone(),
                workername: workername.clone(),
            })
            .await;

        let metrics = handle.get_metrics().await;
        let user = metrics.users.get(&btcaddress).unwrap();
        let worker = user.workers.get(&workername).unwrap();
        // Check that worker exists and is active
        assert!(worker.active);
        // Check that user stats are updated
        assert_eq!(user.shares_valid, 1);
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
                difficulty: 10,
                btcaddress: "userA".to_string(),
                workername: "workerA1".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 20,
                btcaddress: "userA".to_string(),
                workername: "workerA2".to_string(),
            })
            .await;
        let _ = handle
            .record_share_accepted(SimplePplnsShare {
                difficulty: 30,
                btcaddress: "userB".to_string(),
                workername: "workerB1".to_string(),
            })
            .await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 3);
        assert_eq!(metrics.unaccounted_difficulty, 60);

        let user_a = metrics.users.get("userA").unwrap();
        assert_eq!(user_a.shares_valid, 2);
        assert_eq!(user_a.best_share, 20);
        assert!(user_a.workers.contains_key("workerA1"));
        assert!(user_a.workers.contains_key("workerA2"));

        let user_b = metrics.users.get("userB").unwrap();
        assert_eq!(user_b.shares_valid, 1);
        assert_eq!(user_b.best_share, 30);
        assert!(user_b.workers.contains_key("workerB1"));
    }
}
