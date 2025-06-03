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

use super::gbt::BlockTemplate;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// The job id sent to miners.
/// A job id matches a block template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub u32);

/// Delegate to u32's lower hex
impl std::fmt::LowerHex for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, f)
    }
}

/// A map that associates templates with job id
///
/// We use this to build blocks from submitted jobs and their matching block templates.
#[derive(Debug, Default)]
pub struct Tracker {
    blocktemplates: HashMap<JobId, Arc<BlockTemplate>>,
    latest_job_id: u32,
}

impl Tracker {
    /// Create a new empty Map
    pub fn new() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        Self {
            blocktemplates: HashMap::new(),
            latest_job_id: timestamp,
        }
    }

    /// Insert a block template with the specified job id
    pub fn insert_block_template(&mut self, block_template: Arc<BlockTemplate>) -> JobId {
        let job_id = self.get_next_job_id();
        self.blocktemplates.insert(job_id, block_template);
        job_id
    }

    /// Get the next job id, incrementing it atomically
    pub fn get_next_job_id(&mut self) -> JobId {
        self.latest_job_id += 1;
        JobId(self.latest_job_id)
    }

    /// Get the latest job id using the atomic counter
    pub fn get_latest_job_id(&self) -> JobId {
        JobId(self.latest_job_id)
    }
}

/// Commands that can be sent to the MapActor
#[derive(Debug)]
pub enum Command {
    /// Insert a block template under the specified job id
    InsertBlockTemplate {
        block_template: Arc<BlockTemplate>,
        resp: oneshot::Sender<JobId>,
    },
    /// Find block template by job id
    FindBlockTemplate {
        job_id: JobId,
        resp: oneshot::Sender<Option<Arc<BlockTemplate>>>,
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
    pub async fn insert_block_template(
        &self,
        block_template: Arc<BlockTemplate>,
    ) -> Result<JobId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::InsertBlockTemplate {
                block_template,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send insert_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive insert_block_template response".to_string())
    }

    /// Find a block template by job id
    pub async fn find_block_template(
        &self,
        job_id: JobId,
    ) -> Result<Option<Arc<BlockTemplate>>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::FindBlockTemplate {
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
            map: Tracker::new(),
            rx,
        };

        let handle = TrackerHandle { tx };

        (actor, handle)
    }

    /// Start the actor's processing loop
    pub async fn run(mut self) {
        while let Some(cmd) = self.rx.recv().await {
            match cmd {
                Command::InsertBlockTemplate {
                    block_template,
                    resp,
                } => {
                    let job_id = self.map.insert_block_template(block_template);
                    let _ = resp.send(job_id);
                }
                Command::FindBlockTemplate { job_id, resp } => {
                    let template = self.map.blocktemplates.get(&job_id).cloned();
                    let _ = resp.send(template);
                }
                Command::GetNextJobId { resp } => {
                    let next_job_id = self.map.get_next_job_id();
                    let _ = resp.send(next_job_id);
                }
                Command::GetLatestJobId { resp } => {
                    let latest_job_id = self.map.get_latest_job_id();
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
        let mut map = Tracker::new();
        let initial_job_id = map.get_latest_job_id();

        // Get next job id should increment
        let next_job_id = map.get_next_job_id();
        assert_eq!(next_job_id.0, initial_job_id.0 + 1);

        // Latest job id should reflect the increment
        let latest_job_id = map.get_latest_job_id();
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

        let job_id = handle.insert_block_template(Arc::new(template)).await;
        // Test inserting a block template
        assert!(job_id.is_ok());

        // Test finding the block template
        let retrieved_template = handle.find_block_template(job_id.unwrap()).await.unwrap();
        assert!(retrieved_template.is_some());
        assert_eq!(
            cloned_template.previousblockhash,
            retrieved_template.unwrap().previousblockhash
        );

        // Test with non-existent job id
        let retrieved_template = handle.find_block_template(JobId(9997)).await.unwrap();
        assert!(retrieved_template.is_none());
    }
}
