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

use crate::stats::pool_local_stats::{load_pool_local_stats, PoolLocalStats};
use crate::stats::user::User;
use crate::stats::worker::Worker;
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};

const METRICS_MESSAGE_BUFFER_SIZE: usize = 100;
const INITIAL_USER_MAP_CAPACITY: usize = 1000;

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug, Clone)]
pub struct PoolMetrics {
    /// Username to worker mapping
    pub user_workers: HashMap<String, u32>,
    /// Number of users
    pub num_users: u32,
    /// Number of workers
    pub num_workers: u32,
    /// Number of idle users
    pub num_idle_users: u32,
    /// Tracks the number of shares since last stats update
    pub unaccounted_shares: u64,
    /// Tracks the total difficulty since last stats update
    pub unaccounted_difficulty: u64,
    /// Tracks the number of rejected shares since last stats update
    pub unaccounted_rejected: u64,
    /// Total accepted shares
    pub total_accepted: u64,
    /// Total rejected shares
    pub total_rejected: u64,
    /// Timestamp for last share received
    pub last_share_at: Option<std::time::SystemTime>,
    /// Start time
    pub start_time: std::time::Instant,
    /// Highest difficulty share
    pub highest_share_difficulty: u64,
    /// Users in the pool
    pub users: HashMap<String, User>,
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            user_workers: HashMap::with_capacity(INITIAL_USER_MAP_CAPACITY),
            unaccounted_shares: 0,
            unaccounted_difficulty: 0,
            unaccounted_rejected: 0,
            total_accepted: 0,
            total_rejected: 0,
            num_users: 0,
            num_workers: 0,
            num_idle_users: 0,
            last_share_at: None,
            start_time: std::time::Instant::now(),
            highest_share_difficulty: 0,
            users: HashMap::with_capacity(INITIAL_USER_MAP_CAPACITY),
        }
    }
}

impl PoolMetrics {
    /// Load existing metrics from file or build new default
    pub fn load_existing(log_dir: String) -> Self {
        let pool_stats = load_pool_local_stats(&log_dir).unwrap_or_default();
        PoolMetrics {
            total_accepted: pool_stats.accepted_shares,
            total_rejected: pool_stats.rejected_shares,
            ..Default::default()
        }
    }

    /// Reset metrics to their default values using default
    fn reset(&mut self) {
        self.unaccounted_shares = 0;
        self.unaccounted_rejected = 0;
        self.unaccounted_difficulty = 0;
    }

    /// Compute share per seconds for the various windows
    /// Decay the share per seconds using the exponential decay from calc::decay_time
    fn compute_share_per_second_metrics(&self) -> (u32, u32, u32, u32) {
        let sps1m = self.unaccounted_shares as f64 / 60.0;
        let sps5m = self.unaccounted_shares as f64 / 300.0;
        let sps15m = self.unaccounted_shares as f64 / 900.0;
        let sps1h = self.unaccounted_shares as f64 / 3600.0;
        // TODO - apply decay_time
        (sps1m as u32, sps5m as u32, sps15m as u32, sps1h as u32)
    }

    /// Compute hashrate for various windows based on the shares received
    /// Decay the hashrate using the exponential decay from calc::decay_time
    fn compute_hashrate_metrics(&self) -> (u32, u32, u32, u32, u32, u32, u32) {
        let hashrate_1m = (self.unaccounted_difficulty as f64 / 60.0) as u32;
        let hashrate_5m = (self.unaccounted_difficulty as f64 / 300.0) as u32;
        let hashrate_15m = (self.unaccounted_difficulty as f64 / 900.0) as u32;
        let hashrate_1hr = (self.unaccounted_difficulty as f64 / 3600.0) as u32;
        let hashrate_6hr = (self.unaccounted_difficulty as f64 / 21600.0) as u32;
        let hashrate_1d = (self.unaccounted_difficulty as f64 / 86400.0) as u32;
        let hashrate_7d = (self.unaccounted_difficulty as f64 / 604800.0) as u32;
        // TODO - apply decay_time
        (
            hashrate_1m,
            hashrate_5m,
            hashrate_15m,
            hashrate_1hr,
            hashrate_6hr,
            hashrate_1d,
            hashrate_7d,
        )
    }
}

/// Messages that can be sent to the MetricsActor
#[derive(Debug)]
pub enum MetricsMessage {
    RecordShareAccepted {
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
        log_dir: String,
        receiver: mpsc::Receiver<MetricsMessage>,
    ) -> Self {
        Self {
            metrics: PoolMetrics::load_existing(log_dir),
            receiver,
        }
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
                difficulty,
                response,
            } => {
                self.record_share_accepted(difficulty);
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
            MetricsMessage::DecrementWorkerCount { response } => {
                self.decrement_worker_count();
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
        }
    }

    /// Update metrics from accepted share
    fn record_share_accepted(&mut self, difficulty: u64) {
        self.metrics.unaccounted_shares += 1;
        self.metrics.total_accepted += 1;
        self.metrics.unaccounted_difficulty += difficulty;
        self.metrics.last_share_at = Some(SystemTime::now());
        if self.metrics.highest_share_difficulty < difficulty {
            self.metrics.highest_share_difficulty = difficulty;
        }
    }

    /// Update metrics from rejected share
    fn record_share_rejected(&mut self) {
        self.metrics.unaccounted_rejected += 1;
        self.metrics.total_rejected += 1;
    }

    /// Increment worker counts
    fn increment_worker_count(&mut self, btcaddress: String, workername: String) {
        self.metrics.num_workers += 1;
        self.metrics
            .users
            .entry(btcaddress.clone())
            .or_insert_with(|| {
                let mut user = User::new(&btcaddress);
                let worker = Worker::new(&btcaddress, &workername);
                user.workers.insert(workername, worker);
                user
            });
    }

    /// Decrement worker counts
    fn decrement_worker_count(&mut self) {
        if self.metrics.num_workers > 0 {
            self.metrics.num_workers -= 1;
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
        let lastupdate = match self.metrics.last_share_at {
            Some(time) => time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            None => 0,
        };
        let (sps1m, sps5m, sps15m, sps1h) = self.metrics.compute_share_per_second_metrics();
        let (
            hashrate_1m,
            hashrate_5m,
            hashrate_15m,
            hashrate_1hr,
            hashrate_6hr,
            hashrate_1d,
            hashrate_7d,
        ) = self.metrics.compute_hashrate_metrics();
        let pool_local_stats = PoolLocalStats {
            runtime: self.metrics.start_time.elapsed().as_secs(),
            lastupdate,
            users: self.metrics.num_users,
            workers: self.metrics.num_workers,
            idle: self.metrics.num_idle_users,
            hashrate_1m,
            hashrate_5m,
            hashrate_15m,
            hashrate_1hr,
            hashrate_6hr,
            hashrate_1d,
            hashrate_7d,
            difficulty: 0,
            accepted_shares: self.metrics.total_accepted,
            rejected_shares: self.metrics.total_rejected,
            best_share: self.metrics.highest_share_difficulty,
            shares_per_second_1m: sps1m,
            shares_per_second_5m: sps5m,
            shares_per_second_15m: sps15m,
            shares_per_second_1h: sps1h,
        };

        self.metrics.reset();
        serde_json::to_string(&pool_local_stats).unwrap()
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
        difficulty: u64,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordShareAccepted {
                difficulty,
                response: response_tx,
            })
            .await
            .expect("Error recording share");
        response_rx.await
    }

    /// Record a rejected share
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
        btcaddress: &str,
        workername: &str,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::IncrementWorkerCount {
                response: response_tx,
                btcaddress: btcaddress.to_string(),
                workername: workername.to_string(),
            })
            .await
            .expect("Error incrementing worker count");
        response_rx.await
    }

    /// Decrement worker count
    pub async fn decrement_worker_count(
        &self,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::DecrementWorkerCount {
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
}

/// Construct a new metrics actor with existing metrics and return its handle
pub async fn build_metrics(log_dir: String) -> MetricsHandle {
    let (sender, receiver) = mpsc::channel(METRICS_MESSAGE_BUFFER_SIZE);
    let actor = MetricsActor::with_existing_metrics(log_dir, receiver);
    tokio::spawn(async move {
        actor.run().await;
    });
    MetricsHandle { sender }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_pool_metrics_default() {
        let metrics = PoolMetrics::default();
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 0);
        assert_eq!(metrics.num_idle_users, 0);
        assert_eq!(metrics.num_workers, 0);
        assert!(metrics.last_share_at.is_none());
        assert!(metrics.highest_share_difficulty == 0);
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
        metrics.last_share_at = Some(SystemTime::now());
        metrics.highest_share_difficulty = 500;

        metrics.reset();

        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.num_users, 3);
        assert_eq!(metrics.num_idle_users, 1);
        assert_eq!(metrics.num_workers, 5);
        assert!(metrics.last_share_at.is_some());
        assert_eq!(metrics.highest_share_difficulty, 500);
    }

    #[tokio::test]
    async fn test_record_share_accepted() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = build_metrics(log_dir.path().to_str().unwrap().to_string()).await;
        let _ = handle.record_share_accepted(100).await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 1);
        assert_eq!(metrics.unaccounted_difficulty, 100);
        assert!(metrics.last_share_at.is_some());
        assert_eq!(metrics.highest_share_difficulty, 100);

        // Test that highest difficulty is updated correctly
        let _ = handle.record_share_accepted(50).await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 2);
        assert_eq!(metrics.unaccounted_difficulty, 150);
        assert_eq!(metrics.highest_share_difficulty, 100);

        let _ = handle.record_share_accepted(200).await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_shares, 3);
        assert_eq!(metrics.unaccounted_difficulty, 350);
        assert_eq!(metrics.highest_share_difficulty, 200);
    }

    #[tokio::test]
    async fn test_record_share_rejected() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = build_metrics(log_dir.path().to_str().unwrap().to_string()).await;
        let _ = handle.record_share_rejected().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_rejected, 1);

        let _ = handle.record_share_rejected().await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.unaccounted_rejected, 2);
    }

    #[tokio::test]
    async fn test_metrics_commit() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = build_metrics(log_dir.path().to_str().unwrap().to_string()).await;

        let _ = handle.record_share_accepted(100).await;
        let _ = handle.record_share_accepted(200).await;
        let _ = handle.record_share_rejected().await;

        let json_str = handle.commit().await;
        let json: serde_json::Value = serde_json::from_str(&json_str.unwrap()).unwrap();

        // Check that lastupdate exists and is a recent timestamp
        assert!(json["lastupdate"].as_u64().is_some());

        let metrics = handle.get_metrics().await;
        // After commit, the metrics should be reset
        assert_eq!(metrics.unaccounted_shares, 0);
        assert_eq!(metrics.unaccounted_difficulty, 0);
        assert_eq!(metrics.unaccounted_rejected, 0);
        assert_eq!(metrics.highest_share_difficulty, 200);
    }
}
