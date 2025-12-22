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

use super::block_template::BlockTemplate;
use crate::shares::share_commitment::ShareCommitment;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};
pub mod parse_coinbase;

const MAX_JOB_AGE_SECS: u64 = 15 * 60; // 15 minutes

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
    pub generation_timestamp: u64,
    pub share_commitment: Option<ShareCommitment>,
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
        share_commitment: Option<ShareCommitment>,
        job_id: JobId,
    ) -> JobId {
        self.job_details.insert(
            job_id,
            JobDetails {
                blocktemplate: block_template,
                coinbase1,
                coinbase2,
                generation_timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                share_commitment,
            },
        );
        job_id
    }

    /// Get the next job id, incrementing it atomically
    pub fn get_next_job_id(&mut self) -> JobId {
        self.latest_job_id = self.latest_job_id + 1;
        self.latest_job_id
    }

    /// Remove job details that are older than the specified duration in seconds
    /// Returns the number of jobs that were removed
    pub fn cleanup_old_jobs(&mut self, max_age_secs: u64) -> usize {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before_count = self.job_details.len();

        // Remove jobs older than max_age_secs
        self.job_details.retain(|_, details| {
            current_time.saturating_sub(details.generation_timestamp) < max_age_secs
        });

        before_count - self.job_details.len()
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
        share_commitment: Option<ShareCommitment>,
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
    /// Clean up old job ids that are older than the specified duration
    CleanupOldJobs {
        max_age_secs: u64,
        resp: oneshot::Sender<usize>,
    },
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
        share_commitment: Option<ShareCommitment>,
        job_id: JobId,
    ) -> Result<JobId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::InsertJob {
                block_template,
                coinbase1,
                coinbase2,
                job_id,
                share_commitment,
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

    /// Clean up old job ids that are older than the specified duration in seconds
    /// Returns the number of jobs that were removed
    pub async fn cleanup_old_jobs(&self, max_age_secs: u64) -> Result<usize, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::CleanupOldJobs {
                max_age_secs,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send cleanup_old_jobs command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive cleanup_old_jobs response".to_string())
    }
}

/// The actor that manages access to the Tracker
pub struct TrackerActor {
    tracker: Tracker,
    rx: mpsc::Receiver<Command>,
}

impl TrackerActor {
    /// Create a new TrackerActor and return a handle to it
    pub fn new() -> (Self, TrackerHandle) {
        let (tx, rx) = mpsc::channel(100); // Buffer size of 100

        let actor = Self {
            tracker: Tracker::default(),
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
                    share_commitment,
                    resp,
                } => {
                    let job_id = self.tracker.insert_job(
                        block_template,
                        coinbase1,
                        coinbase2,
                        share_commitment,
                        job_id,
                    );
                    let _ = resp.send(job_id);
                }
                Command::GetJob { job_id, resp } => {
                    let details = self.tracker.job_details.get(&job_id).cloned();
                    let _ = resp.send(details);
                }
                Command::GetNextJobId { resp } => {
                    let next_job_id = self.tracker.get_next_job_id();
                    let _ = resp.send(next_job_id);
                }
                Command::GetLatestJobId { resp } => {
                    let latest_job_id = self.tracker.latest_job_id;
                    let _ = resp.send(latest_job_id);
                }
                Command::CleanupOldJobs { max_age_secs, resp } => {
                    let removed_count = self.tracker.cleanup_old_jobs(max_age_secs);
                    let _ = resp.send(removed_count);
                }
            }
        }
    }
}

/// Start a new TrackerActor in a separate task and return a handle to it
pub fn start_tracker_actor() -> TrackerHandle {
    let (actor, handle) = TrackerActor::new();
    let cleanup_handle = handle.clone();

    // Spawn the actor in a new task
    tokio::spawn(async move {
        actor.run().await;
    });

    // Spawn a task for periodic cleanup
    tokio::spawn(async move {
        let cleanup_interval = tokio::time::Duration::from_secs(MAX_JOB_AGE_SECS);
        loop {
            tokio::time::sleep(cleanup_interval).await;
            match cleanup_handle.cleanup_old_jobs(MAX_JOB_AGE_SECS).await {
                Ok(count) => {
                    if count > 0 {
                        debug!("Cleaned up {} old job IDs", count);
                    }
                }
                Err(err) => {
                    warn!("Failed to clean up old job IDs: {}", err);
                }
            }
        }
    });

    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_commitment;

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
                Some(create_test_commitment()),
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
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(current_timestamp >= retrieved_job.generation_timestamp);
        assert!(current_timestamp - retrieved_job.generation_timestamp <= 5); // Allow a small margin for time difference

        // Test with non-existent job id
        let retrieved_job = handle.get_job(JobId(9997)).await.unwrap();
        assert!(retrieved_job.is_none());
    }

    #[tokio::test]
    async fn test_job_cleanup() {
        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .unwrap();

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        // Create tracker with direct access
        let mut tracker = Tracker::default();

        // Insert jobs with different timestamps
        let old_job_id = JobId(1);
        tracker.insert_job(
            Arc::new(template.clone()),
            "old_cb1".to_string(),
            "old_cb2".to_string(),
            Some(create_test_commitment()),
            old_job_id,
        );

        // Manually set an old timestamp (20 minutes ago)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(job) = tracker.job_details.get_mut(&old_job_id) {
            job.generation_timestamp = current_time - (20 * 60);
        }

        // Insert a new job
        let new_job_id = JobId(2);
        tracker.insert_job(
            Arc::new(template.clone()),
            "new_cb1".to_string(),
            "new_cb2".to_string(),
            None,
            new_job_id,
        );

        // Verify both jobs exist
        assert!(tracker.job_details.contains_key(&old_job_id));
        assert!(tracker.job_details.contains_key(&new_job_id));

        // Run cleanup (15 minutes max age)
        let removed = tracker.cleanup_old_jobs(15 * 60);
        assert_eq!(removed, 1);

        // Verify only the new job remains
        assert!(!tracker.job_details.contains_key(&old_job_id));
        assert!(tracker.job_details.contains_key(&new_job_id));

        // Now test with the actor
        let handle = start_tracker_actor();

        // Insert jobs
        let old_actor_job = handle
            .insert_job(
                Arc::new(template.clone()),
                "old_actor_cb1".to_string(),
                "old_actor_cb2".to_string(),
                None,
                JobId(3),
            )
            .await
            .unwrap();

        // We can't modify timestamps directly with the actor, so we'll test cleanup command
        // by just verifying it executes successfully
        let removed = handle.cleanup_old_jobs(0).await.unwrap(); // All jobs should be cleaned
        assert_eq!(removed, 1);

        // Verify job was removed
        let result = handle.get_job(old_actor_job).await.unwrap();
        assert!(result.is_none());
    }
}
