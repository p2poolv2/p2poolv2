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

use crate::accounting::stats::pool_local_stats::load_pool_local_stats;
use crate::accounting::stats::user::User;
use crate::accounting::stats::worker::Worker;
use crate::accounting::{payout::simple_pplns::SimplePplnsShare, stats::pool_local_stats};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::SystemTime;
use tokio::sync::{mpsc, oneshot};
use tracing::error;

const METRICS_MESSAGE_BUFFER_SIZE: usize = 1000;
pub const INITIAL_USER_MAP_CAPACITY: usize = 1000;
const METRICS_SAVE_INTERVAL: u64 = 5;
/// Maximum number of recently found blocks retained for the block-found
/// metric. Bounds the label cardinality of `bitcoin_block_found_time_seconds`.
pub const MAX_BLOCKS_FOUND_TRACKED: usize = 20;

/// A bitcoin block found by the pool, retained for the block-found metric.
///
/// blockhash and height are exposed as Prometheus labels so Grafana can
/// build block explorer links. The retained set is bounded by
/// MAX_BLOCKS_FOUND_TRACKED so label cardinality stays low.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockFound {
    /// Block hash as a hex string, used as a Grafana data-link label
    pub blockhash: String,
    /// Bitcoin block height
    pub height: u32,
    /// Unix timestamp in seconds when the block was found
    pub timestamp: u64,
}

/// Represents the metrics for the P2Poolv2 pool, we derive the stats every five minutes from this
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolMetrics {
    /// Start time in unix timestamp
    pub start_time: u64,
    /// Last update timestamp, time since epoch in seconds
    pub lastupdate: Option<u64>,
    /// Total number of shares accepted
    pub accepted_total: u64,
    /// Total difficulty of shares accepted
    pub accepted_difficulty_total: u64,
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
    /// Total number of bitcoin blocks found by the pool (monotonic counter)
    #[serde(default)]
    pub blocks_found_total: u64,
    /// Ring of the most recently found blocks, capped at
    /// MAX_BLOCKS_FOUND_TRACKED. Exposed with blockhash/height labels for
    /// Grafana block explorer links.
    #[serde(default)]
    pub blocks_found: VecDeque<BlockFound>,
    /// Confirmed sharechain pool difficulty since the last bitcoin block was
    /// found; reset to zero on each block find. Numerator of the block effort
    /// metric (`work_since_last_block / network_difficulty`). Runtime-only (not
    /// persisted), mainnet-relative units matching network_difficulty. Pool
    /// hashrate is derived separately from confirmed-chain total work.
    #[serde(default)]
    pub work_since_last_block: f64,
}

impl Default for PoolMetrics {
    fn default() -> Self {
        Self {
            lastupdate: None,
            accepted_total: 0,
            accepted_difficulty_total: 0,
            rejected_total: 0,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            best_share: 0,
            best_share_ever: 0,
            users: HashMap::with_capacity(INITIAL_USER_MAP_CAPACITY),
            pool_difficulty: 0,
            blocks_found_total: 0,
            blocks_found: VecDeque::with_capacity(MAX_BLOCKS_FOUND_TRACKED),
            work_since_last_block: 0.0,
        }
    }
}

impl PoolMetrics {
    /// Load existing metrics from file or build new default
    pub fn load_existing(log_dir: &str) -> Result<Self, std::io::Error> {
        let pool_stats = load_pool_local_stats(log_dir)?;
        Ok(PoolMetrics {
            accepted_total: pool_stats.accepted_total,
            accepted_difficulty_total: pool_stats.accepted_difficulty_total,
            rejected_total: pool_stats.rejected_total,
            users: pool_stats.users,
            blocks_found_total: pool_stats.blocks_found_total,
            blocks_found: pool_stats.blocks_found,
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
        truediff: u64,
        response: oneshot::Sender<()>,
    },
    RecordShareRejected {
        response: oneshot::Sender<()>,
    },
    RecordBlockFound {
        blockhash: String,
        height: u32,
        response: oneshot::Sender<()>,
    },
    RecordConfirmedShare {
        difficulty: f64,
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
                truediff,
                response,
            } => {
                self.record_share_accepted(btcaddress, workername, difficulty, truediff);
                let _ = response.send(());
            }
            MetricsMessage::RecordShareRejected { response } => {
                self.record_share_rejected();
                let _ = response.send(());
            }
            MetricsMessage::RecordBlockFound {
                blockhash,
                height,
                response,
            } => {
                self.record_block_found(blockhash, height);
                let _ = response.send(());
            }
            MetricsMessage::RecordConfirmedShare {
                difficulty,
                response,
            } => {
                self.record_confirmed_share(difficulty);
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
    fn record_share_accepted(
        &mut self,
        btcaddress: String,
        workername: String,
        difficulty: u64,
        truediff: u64,
    ) {
        let current_unix_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.metrics.accepted_total += 1;
        self.metrics.accepted_difficulty_total += difficulty;
        self.metrics.lastupdate = Some(current_unix_timestamp);
        self.metrics.best_share = self.metrics.best_share.max(truediff);
        self.metrics.best_share_ever = self.metrics.best_share_ever.max(truediff);
        if let Some(user) = self.metrics.users.get_mut(&btcaddress) {
            user.record_share(&workername, difficulty, truediff, current_unix_timestamp);
        }
    }

    /// Update metrics from rejected share
    fn record_share_rejected(&mut self) {
        self.metrics.rejected_total += 1;
    }

    /// Record a bitcoin block found by the pool.
    ///
    /// Increments the monotonic counter, appends to the bounded ring of
    /// recently found blocks (evicting the oldest past MAX_BLOCKS_FOUND_TRACKED).
    /// Also resets the block effort accumulator since work now targets the
    /// next block.
    fn record_block_found(&mut self, blockhash: String, height: u32) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.metrics.blocks_found_total += 1;
        self.metrics.blocks_found.push_back(BlockFound {
            blockhash,
            height,
            timestamp,
        });
        while self.metrics.blocks_found.len() > MAX_BLOCKS_FOUND_TRACKED {
            self.metrics.blocks_found.pop_front();
        }
        self.metrics.work_since_last_block = 0.0;
    }

    /// Record the pool difficulty of a confirmed sharechain share for the
    /// per-block effort accumulator. Hashrate is derived separately from
    /// confirmed-chain total work.
    fn record_confirmed_share(&mut self, difficulty: f64) {
        self.metrics.work_since_last_block += difficulty;
    }

    /// Increment worker counts - called after worker has authorised successfully.
    /// Uses entry().or_default() to preserve existing worker stats on reconnect.
    fn worker_authorized(&mut self, btcaddress: String, workername: String) {
        let worker = self
            .metrics
            .users
            .entry(btcaddress)
            .or_default()
            .workers
            .entry(workername)
            .or_default();
        worker.active = true;
        worker.best_share = 0;
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
        truediff: u64,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordShareAccepted {
                btcaddress: share.btcaddress.unwrap_or_default(),
                workername: share.workername.unwrap_or_default(),
                difficulty: share.difficulty,
                truediff,
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

    /// Record a bitcoin block found by the pool
    pub async fn record_block_found(
        &self,
        blockhash: String,
        height: u32,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordBlockFound {
                blockhash,
                height,
                response: response_tx,
            })
            .await
            .expect("Error recording block found");
        response_rx.await
    }

    /// Record the pool difficulty of a confirmed sharechain share for the
    /// block effort metric.
    pub async fn record_confirmed_share(
        &self,
        difficulty: f64,
    ) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(MetricsMessage::RecordConfirmedShare {
                difficulty,
                response: response_tx,
            })
            .await
            .expect("Error recording confirmed share");
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

/// Spawn a metrics actor with default metrics and return its handle.
///
/// Test-only helper for wiring components that require a `MetricsHandle`
/// without touching disk or the stats saver.
#[cfg(test)]
pub(crate) fn spawn_test_metrics_handle() -> MetricsHandle {
    let (sender, receiver) = mpsc::channel(METRICS_MESSAGE_BUFFER_SIZE);
    tokio::spawn(async move {
        MetricsActor::new(receiver).run().await;
    });
    MetricsHandle { sender }
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
    use super::*;
    use crate::accounting::stats::pool_local_stats::save_pool_local_stats;

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
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 100,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                110,
            )
            .await;

        let metrics = handle.get_metrics().await;
        assert!(metrics.lastupdate.is_some());
        assert_eq!(metrics.best_share, 110);

        // Test that highest difficulty is updated correctly
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 50,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                55,
            )
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.best_share, 110);

        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 200,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                220,
            )
            .await;
        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.best_share, 220);
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

    #[tokio::test]
    async fn test_confirmed_share_and_block_found_reset() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        // Confirmed sharechain work accumulates into the effort numerator.
        let _ = handle.record_confirmed_share(500.0).await;
        let _ = handle.record_confirmed_share(250.0).await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.work_since_last_block, 750.0);

        let _ = handle
            .record_block_found(
                "00000000000000000000abcdef0123456789abcdef0123456789abcdef012345".to_string(),
                840000,
            )
            .await;

        let metrics = handle.get_metrics().await;
        assert_eq!(metrics.blocks_found_total, 1);
        assert_eq!(metrics.blocks_found.len(), 1);
        let found = metrics.blocks_found.front().unwrap();
        assert_eq!(
            found.blockhash,
            "00000000000000000000abcdef0123456789abcdef0123456789abcdef012345"
        );
        assert_eq!(found.height, 840000);
        assert!(found.timestamp > 0);
        // Finding a block resets effort toward the next block.
        assert_eq!(metrics.work_since_last_block, 0.0);
    }

    #[tokio::test]
    async fn test_blocks_found_ring_evicts_oldest() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let overflow = MAX_BLOCKS_FOUND_TRACKED as u32 + 5;
        for height in 0..overflow {
            let _ = handle
                .record_block_found(format!("hash{height:064x}"), height)
                .await;
        }

        let metrics = handle.get_metrics().await;
        // Counter is monotonic and counts every find
        assert_eq!(metrics.blocks_found_total, overflow as u64);
        // Ring is capped and holds only the most recent finds
        assert_eq!(metrics.blocks_found.len(), MAX_BLOCKS_FOUND_TRACKED);
        assert_eq!(metrics.blocks_found.front().unwrap().height, 5);
        assert_eq!(metrics.blocks_found.back().unwrap().height, overflow - 1);
    }

    #[tokio::test]
    async fn test_metrics_commit() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .increment_worker_count("user1".to_string(), "worker1".to_string())
            .await;

        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 1000,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                1100,
            )
            .await;
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 2000,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                2200,
            )
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
        assert_eq!(metrics.best_share, 2200);
    }

    #[tokio::test]
    async fn test_get_metrics_consistency() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        // Create user1/worker1 before recording shares (as would happen in real flow)
        let _ = handle
            .increment_worker_count("user1".to_string(), "worker1".to_string())
            .await;
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 123,
                    btcaddress: Some("user1".to_string()),
                    workername: Some("worker1".to_string()),
                    n_time: 1000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                134,
            )
            .await;
        let _ = handle.record_share_rejected().await;
        // Create an inactive worker (no shares submitted)
        let _ = handle
            .increment_worker_count("user4".to_string(), "workerD".to_string())
            .await;

        let metrics = handle.get_metrics().await;
        // Inactive worker exists in memory
        assert!(metrics.users.contains_key("user4"));
        assert!(
            metrics
                .users
                .get("user4")
                .unwrap()
                .workers
                .contains_key("workerD")
        );
        assert_eq!(metrics.accepted_total, 1);
        assert_eq!(metrics.accepted_difficulty_total, 123);
        assert_eq!(metrics.rejected_total, 1);

        // save and reload metrics to verify persistence
        let _ = save_pool_local_stats(&metrics, log_dir.path().to_str().unwrap());
        let reloaded = PoolMetrics::load_existing(log_dir.path().to_str().unwrap()).unwrap();
        assert_eq!(
            reloaded.accepted_difficulty_total,
            metrics.accepted_difficulty_total
        );
        assert_eq!(reloaded.accepted_total, metrics.accepted_total);
        assert_eq!(reloaded.rejected_total, metrics.rejected_total);
        // Users that never submitted a share are filtered out when saving to JSON
        assert!(!reloaded.users.contains_key("user4"));
        // Active user1 with worker1 should be present
        assert!(reloaded.users.contains_key("user1"));
        assert!(
            reloaded
                .users
                .get("user1")
                .unwrap()
                .workers
                .contains_key("worker1")
        );
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
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 77,
                    btcaddress: Some(btcaddress.clone()),
                    workername: Some(workername.clone()),
                    n_time: 3000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                84,
            )
            .await;

        let metrics = handle.get_metrics().await;
        let user = metrics.users.get(&btcaddress).unwrap();
        let worker = user.workers.get(&workername).unwrap();
        // Check that worker exists and is active
        assert!(worker.active);
        // Check that user stats are updated
        assert_eq!(user.shares_valid_total, 77);
        assert_eq!(user.best_share, 84);
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
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 10,
                    btcaddress: Some("userA".to_string()),
                    workername: Some("workerA1".to_string()),
                    n_time: 4000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                11,
            )
            .await;
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 20,
                    btcaddress: Some("userA".to_string()),
                    workername: Some("workerA2".to_string()),
                    n_time: 5000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                22,
            )
            .await;
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 30,
                    btcaddress: Some("userB".to_string()),
                    workername: Some("workerB1".to_string()),
                    n_time: 6000,
                    job_id: "test_job".to_string(),
                    extranonce2: "test_extra".to_string(),
                    nonce: "test_nonce".to_string(),
                },
                33,
            )
            .await;

        let metrics = handle.get_metrics().await;

        let user_a = metrics.users.get("userA").unwrap();
        assert_eq!(user_a.shares_valid_total, 30);
        assert_eq!(user_a.best_share, 22);
        assert!(user_a.workers.contains_key("workerA1"));
        assert!(user_a.workers.contains_key("workerA2"));

        let user_b = metrics.users.get("userB").unwrap();
        assert_eq!(user_b.shares_valid_total, 30);
        assert_eq!(user_b.best_share, 33);
        assert!(user_b.workers.contains_key("workerB1"));
    }

    #[tokio::test]
    async fn test_worker_reauthorize_preserves_stats() {
        let log_dir = tempfile::tempdir().unwrap();
        let handle = start_metrics(log_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let _ = handle
            .increment_worker_count("miner1".to_string(), "rig1".to_string())
            .await;

        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 1000,
                    btcaddress: Some("miner1".to_string()),
                    workername: Some("rig1".to_string()),
                    n_time: 1000,
                    job_id: "job1".to_string(),
                    extranonce2: "extra1".to_string(),
                    nonce: "nonce1".to_string(),
                },
                5500,
            )
            .await;

        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 1000,
                    btcaddress: Some("miner1".to_string()),
                    workername: Some("rig1".to_string()),
                    n_time: 1001,
                    job_id: "job2".to_string(),
                    extranonce2: "extra2".to_string(),
                    nonce: "nonce2".to_string(),
                },
                3200,
            )
            .await;

        let metrics = handle.get_metrics().await;
        let worker = metrics
            .users
            .get("miner1")
            .unwrap()
            .workers
            .get("rig1")
            .unwrap();
        assert_eq!(worker.shares_valid_total, 2000);
        assert_eq!(worker.best_share, 5500);
        assert_eq!(worker.best_share_ever, 5500);

        // Worker disconnects
        let _ = handle
            .decrement_worker_count(Some("miner1".to_string()), "rig1".to_string())
            .await;

        // Worker reconnects - re-authorizes with same name
        let _ = handle
            .increment_worker_count("miner1".to_string(), "rig1".to_string())
            .await;

        // Stats should be preserved, best_share reset for new session
        let metrics = handle.get_metrics().await;
        let user = metrics.users.get("miner1").unwrap();
        let worker = user.workers.get("rig1").unwrap();
        assert_eq!(worker.shares_valid_total, 2000);
        assert_eq!(worker.best_share, 0);
        assert_eq!(worker.best_share_ever, 5500);
        assert!(worker.active);

        // New shares accumulate on top of existing stats
        let _ = handle
            .record_share_accepted(
                SimplePplnsShare {
                    user_id: 1,
                    difficulty: 1000,
                    btcaddress: Some("miner1".to_string()),
                    workername: Some("rig1".to_string()),
                    n_time: 2000,
                    job_id: "job3".to_string(),
                    extranonce2: "extra3".to_string(),
                    nonce: "nonce3".to_string(),
                },
                4100,
            )
            .await;

        let metrics = handle.get_metrics().await;
        let user = metrics.users.get("miner1").unwrap();
        let worker = user.workers.get("rig1").unwrap();
        assert_eq!(worker.shares_valid_total, 3000);
        assert_eq!(user.shares_valid_total, 3000);
        assert_eq!(worker.best_share, 4100);
        assert_eq!(worker.best_share_ever, 5500);
    }
}
