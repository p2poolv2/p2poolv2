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

use super::{coinbase, gbt::BlockTemplate};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// The job id sent to miners.
/// A job id matches a block template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct JobId(pub u64);

/// Delegate to u64's lower hex
impl std::fmt::LowerHex for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, f)
    }
}

/// Implement Add for JobId
impl std::ops::Add<u64> for JobId {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// Capture job details to be used when reconstructing the block from a submitted job.
#[derive(Debug, Clone)]
pub struct JobDetails {
    pub blocktemplate: Arc<BlockTemplate>,
    pub coinbase1: String,
    pub coinbase2: String,
}

/// A map that associates templates with job id
///
/// We use this to build blocks from submitted jobs and their matching block templates.
#[derive(Debug, Clone)]
pub struct Tracker {
    job_details: HashMap<JobId, JobDetails>,
    latest_job_id: JobId,
}

impl Tracker {
    /// Insert a block template with the specified job id
    pub fn insert_job(
        &mut self,
        block_template: Arc<BlockTemplate>,
        coinbase1: String,
        coinbase2: String,
        job_id: JobId,
    ) -> JobId {
        self.job_details.insert(
            job_id,
            JobDetails {
                blocktemplate: block_template,
                coinbase1,
                coinbase2,
            },
        );
        job_id
    }

    /// Get the next job id, incrementing it atomically
    pub fn get_next_job_id(&mut self) -> JobId {
        self.latest_job_id = self.latest_job_id + 1;
        self.latest_job_id
    }
}

impl Default for Tracker {
    /// Create a default empty Map
    fn default() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            job_details: HashMap::new(),
            latest_job_id: JobId(timestamp),
        }
    }
}

/// Commands that can be sent to the MapActor
#[derive(Debug)]
pub enum Command {
    /// Insert a block template under the specified job id
    InsertJob {
        block_template: Arc<BlockTemplate>,
        coinbase1: String,
        coinbase2: String,
        job_id: JobId,
        resp: oneshot::Sender<JobId>,
    },
    /// Get job details by job id
    GetJob {
        job_id: JobId,
        resp: oneshot::Sender<Option<JobDetails>>,
    },
    /// Get the next job id, incrementing it atomically
    GetNextJobId { resp: oneshot::Sender<JobId> },
    /// Get the latest job id using the atomic counter
    GetLatestJobId { resp: oneshot::Sender<JobId> },
}

/// A handle to the TrackerActor
#[derive(Debug, Clone)]
pub struct TrackerHandle {
    tx: mpsc::Sender<Command>,
}

impl TrackerHandle {
    /// Insert a block template under the specified job id
    pub async fn insert_job(
        &self,
        block_template: Arc<BlockTemplate>,
        coinbase1: String,
        coinbase2: String,
        job_id: JobId,
    ) -> Result<JobId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::InsertJob {
                block_template,
                coinbase1,
                coinbase2,
                job_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send insert_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive insert_block_template response".to_string())
    }

    /// Find a block template by job id
    pub async fn get_job(&self, job_id: JobId) -> Result<Option<JobDetails>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetJob {
                job_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send find_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive find_block_template response".to_string())
    }

    /// Get the next job id, incrementing it atomically
    pub async fn get_next_job_id(&self) -> Result<JobId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetNextJobId { resp: resp_tx })
            .await
            .map_err(|_| "Failed to send get_next_job_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive get_next_job_id response".to_string())
    }

    /// Get the latest job id using the atomic counter
    pub async fn get_latest_job_id(&self) -> Result<JobId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetLatestJobId { resp: resp_tx })
            .await
            .map_err(|_| "Failed to send get_latest_job_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive get_latest_job_id response".to_string())
    }
}

/// The actor that manages access to the Tracker
pub struct TrackerActor {
    map: Tracker,
    rx: mpsc::Receiver<Command>,
}

impl TrackerActor {
    /// Create a new TrackerActor and return a handle to it
    pub fn new() -> (Self, TrackerHandle) {
        let (tx, rx) = mpsc::channel(100); // Buffer size of 100

        let actor = Self {
            map: Tracker::default(),
            rx,
        };

        let handle = TrackerHandle { tx };

        (actor, handle)
    }

    /// Start the actor's processing loop
    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                Command::InsertJob {
                    block_template,
                    coinbase1,
                    coinbase2,
                    job_id,
                    resp,
                } => {
                    let job_id = self
                        .map
                        .insert_job(block_template, coinbase1, coinbase2, job_id);
                    let _ = resp.send(job_id);
                }
                Command::GetJob { job_id, resp } => {
                    let details = self.map.job_details.get(&job_id).cloned();
                    let _ = resp.send(details);
                }
                Command::GetNextJobId { resp } => {
                    let next_job_id = self.map.get_next_job_id();
                    let _ = resp.send(next_job_id);
                }
                Command::GetLatestJobId { resp } => {
                    let latest_job_id = self.map.latest_job_id;
                    let _ = resp.send(latest_job_id);
                }
            }
        }
    }
}

/// Start a new TrackerActor in a separate task and return a handle to it
pub fn start_tracker_actor() -> TrackerHandle {
    let (actor, handle) = TrackerActor::new();

    // Spawn the actor in a new task
    tokio::spawn(async move {
        actor.run().await;
    });

    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_job_id_generation() {
        // Test with tracker directly
        let mut map = Tracker::default();
        let initial_job_id = map.latest_job_id;

        // Get next job id should increment
        let next_job_id = map.get_next_job_id();
        assert_eq!(next_job_id.0, initial_job_id.0 + 1);

        // Latest job id should reflect the increment
        let latest_job_id = map.latest_job_id;
        assert_eq!(latest_job_id.0, next_job_id.0);

        // Multiple calls should continue incrementing
        let next_job_id2 = map.get_next_job_id();
        assert_eq!(next_job_id2.0, next_job_id.0 + 1);
    }

    #[tokio::test]
    async fn test_job_id_generation_actor() {
        let handle = start_tracker_actor();

        // Get the initial latest job id
        let initial_job_id = handle.get_latest_job_id().await.unwrap();

        // Get next job id should increment
        let next_job_id = handle.get_next_job_id().await.unwrap();
        assert_eq!(next_job_id.0, initial_job_id.0 + 1);

        // Latest job id should reflect the increment
        let latest_job_id = handle.get_latest_job_id().await.unwrap();
        assert_eq!(latest_job_id.0, next_job_id.0);

        // Multiple calls should continue incrementing
        let next_job_id2 = handle.get_next_job_id().await.unwrap();
        assert_eq!(next_job_id2.0, next_job_id.0 + 1);
    }

    #[tokio::test]
    async fn test_block_template_operations() {
        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .unwrap();

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();
        let cloned_template = template.clone();

        let handle = start_tracker_actor();

        let job_id = handle
            .insert_job(
                Arc::new(template),
                "cb1".to_string(),
                "cb2".to_string(),
                JobId(1),
            )
            .await;
        // Test inserting a block template
        assert!(job_id.is_ok());

        // Test finding the job
        let retrieved_job = &handle.get_job(job_id.unwrap()).await.unwrap().unwrap();
        assert_eq!(
            cloned_template.previousblockhash,
            retrieved_job.blocktemplate.previousblockhash
        );
        assert_eq!(retrieved_job.coinbase1, "cb1".to_string());
        assert_eq!(retrieved_job.coinbase2, "cb2".to_string());

        // Test with non-existent job id
        let retrieved_job = handle.get_job(JobId(9997)).await.unwrap();
        assert!(retrieved_job.is_none());
    }
}
