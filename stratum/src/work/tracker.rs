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

/// The work id used uniquely tracks block templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkId(pub u32);

/// The work id used uniquely tracks jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub u32);

/// A map that associates work ids with job ids
///
/// We use this to build blocks from submitted jobs and their matching block templates.
#[derive(Debug, Default)]
pub struct Tracker {
    jobs: HashMap<WorkId, Vec<JobId>>,
    blocktemplates: HashMap<WorkId, Arc<BlockTemplate>>,
    latest_work_id: u32,
}

impl Tracker {
    /// Create a new empty Map
    pub fn new() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        Self {
            jobs: HashMap::new(),
            blocktemplates: HashMap::new(),
            latest_work_id: timestamp,
        }
    }

    /// Insert a job id under the specified work id
    pub fn insert_job_id(&mut self, work_id: WorkId, job_id: JobId) {
        self.jobs.entry(work_id).or_default().push(job_id);
    }

    /// Get all job ids for a work id
    pub fn get_job_id(&self, work_id: &WorkId) -> Option<&Vec<JobId>> {
        self.jobs.get(work_id)
    }

    /// Check if a work id exists in the map
    pub fn contains_work_id(&self, work_id: &WorkId) -> bool {
        self.jobs.contains_key(work_id)
    }

    /// Check if a job id exists under the specified work id
    pub fn contains_job_id(&self, work_id: &WorkId, job_id: &JobId) -> bool {
        self.jobs
            .get(work_id)
            .map_or(false, |jobs| jobs.contains(job_id))
    }

    /// Find the work id for a given job id
    pub fn find_work_id_for_job(&self, job_id: &JobId) -> Option<WorkId> {
        for (work_id, jobs) in &self.jobs {
            if jobs.contains(job_id) {
                return Some(*work_id);
            }
        }
        None
    }

    /// Find the block template for a given work id
    pub fn find_block_template(&self, work_id: &WorkId) -> Option<Arc<BlockTemplate>> {
        self.blocktemplates.get(work_id).cloned()
    }

    /// Insert a block template with the specified work id
    pub fn insert_block_template(&mut self, work_id: WorkId, block_template: Arc<BlockTemplate>) {
        self.blocktemplates.insert(work_id, block_template);
    }

    /// Add a job ID for a template, creating and inserting the template if it doesn't exist
    pub fn add_job_for_template(
        &mut self,
        job_id: JobId,
        template: Arc<BlockTemplate>,
        work_id: WorkId,
    ) -> WorkId {
        // Insert the block template if it doesn't exist
        self.blocktemplates.entry(work_id).or_insert(template);

        // Add the job ID to the work ID
        self.insert_job_id(work_id, job_id);

        work_id
    }

    /// Get the next work id, incrementing it atomically
    pub fn get_next_work_id(&mut self) -> WorkId {
        self.latest_work_id += 1;
        WorkId(self.latest_work_id)
    }

    /// Get the latest work id using the atomic counter
    pub fn get_latest_work_id(&self) -> WorkId {
        WorkId(self.latest_work_id)
    }
}

/// Commands that can be sent to the MapActor
#[derive(Debug)]
pub enum Command {
    /// Insert a job id under the specified work id
    InsertJob {
        work_id: WorkId,
        job_id: JobId,
        resp: oneshot::Sender<()>,
    },
    /// Get all job ids for a work id
    GetJob {
        work_id: WorkId,
        resp: oneshot::Sender<Option<Vec<JobId>>>,
    },
    /// Check if a work id exists in the map
    ContainsWorkId {
        work_id: WorkId,
        resp: oneshot::Sender<bool>,
    },
    /// Check if a job id exists under the specified work id
    ContainsJobId {
        work_id: WorkId,
        job_id: JobId,
        resp: oneshot::Sender<bool>,
    },
    /// Find the work id for a given job id
    FindWorkIdForJob {
        job_id: JobId,
        resp: oneshot::Sender<Option<WorkId>>,
    },
    /// Find the block template for a given work id
    FindBlockTemplate {
        work_id: WorkId,
        resp: oneshot::Sender<Option<Arc<BlockTemplate>>>,
    },
    /// Insert a block template under the specified work id
    InsertBlockTemplate {
        work_id: WorkId,
        block_template: Arc<BlockTemplate>,
        resp: oneshot::Sender<()>,
    },
    /// Add a job ID for a template, creating and inserting the template if it doesn't exist
    AddJobForTemplate {
        job_id: JobId,
        template: Arc<BlockTemplate>,
        work_id: WorkId,
        resp: oneshot::Sender<()>,
    },
    /// Get the next work id, incrementing it atomically
    GetNextWorkId { resp: oneshot::Sender<WorkId> },
    /// Get the latest work id using the atomic counter
    GetLatestWorkId { resp: oneshot::Sender<WorkId> },
}

/// A handle to the TrackerActor
#[derive(Debug, Clone)]
pub struct TrackerHandle {
    tx: mpsc::Sender<Command>,
}

impl TrackerHandle {
    /// Insert a job id under the specified work id
    pub async fn insert_job_id(&self, work_id: WorkId, job_id: JobId) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::InsertJob {
                work_id,
                job_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send insert command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive insert response".to_string())
    }

    /// Get all job ids for a work id
    pub async fn get_job_ids(&self, work_id: WorkId) -> Result<Option<Vec<JobId>>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetJob {
                work_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send get command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive get response".to_string())
    }

    /// Check if a work id exists in the map
    pub async fn contains_work_id(&self, work_id: WorkId) -> Result<bool, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::ContainsWorkId {
                work_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send contains_work_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive contains_work_id response".to_string())
    }

    /// Check if a job id exists under the specified work id
    pub async fn contains_job_id(&self, work_id: WorkId, job_id: JobId) -> Result<bool, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::ContainsJobId {
                work_id,
                job_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send contains_job_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive contains_job_id response".to_string())
    }

    /// Find the work id for a given job id
    pub async fn find_work_id_for_job(&self, job_id: JobId) -> Result<Option<WorkId>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::FindWorkIdForJob {
                job_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send find_work_id_for_job command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive find_work_id_for_job response".to_string())
    }

    /// Find the block template for a given work id
    pub async fn find_block_template(
        &self,
        work_id: WorkId,
    ) -> Result<Option<Arc<BlockTemplate>>, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::FindBlockTemplate {
                work_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send find_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive find_block_template response".to_string())
    }

    /// Insert a block template under the specified work id
    pub async fn insert_block_template(
        &self,
        work_id: WorkId,
        block_template: BlockTemplate,
    ) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        // Create the Arc here, before sending the command
        let arc_template = Arc::new(block_template);

        self.tx
            .send(Command::InsertBlockTemplate {
                work_id,
                block_template: arc_template,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send insert_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive insert_block_template response".to_string())
    }

    /// Add a job ID for a template, creating and inserting the template if it doesn't exist
    pub async fn add_job_for_template(
        &self,
        job_id: JobId,
        template: BlockTemplate,
        work_id: WorkId,
    ) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        // Create Arc here
        let arc_template = Arc::new(template);

        self.tx
            .send(Command::AddJobForTemplate {
                job_id,
                template: arc_template,
                work_id,
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send add_job_for_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive add_job_for_template response".to_string())
    }

    /// Get the next work id, incrementing it atomically
    pub async fn get_next_work_id(&self) -> Result<WorkId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetNextWorkId { resp: resp_tx })
            .await
            .map_err(|_| "Failed to send get_next_work_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive get_next_work_id response".to_string())
    }

    /// Get the latest work id using the atomic counter
    pub async fn get_latest_work_id(&self) -> Result<WorkId, String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.tx
            .send(Command::GetLatestWorkId { resp: resp_tx })
            .await
            .map_err(|_| "Failed to send get_latest_work_id command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive get_latest_work_id response".to_string())
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
                Command::InsertJob {
                    work_id,
                    job_id,
                    resp,
                } => {
                    self.map.insert_job_id(work_id, job_id);
                    let _ = resp.send(());
                }
                Command::GetJob { work_id, resp } => {
                    let result = self.map.get_job_id(&work_id).cloned();
                    let _ = resp.send(result);
                }
                Command::ContainsWorkId { work_id, resp } => {
                    let result = self.map.contains_work_id(&work_id);
                    let _ = resp.send(result);
                }
                Command::ContainsJobId {
                    work_id,
                    job_id,
                    resp,
                } => {
                    let result = self.map.contains_job_id(&work_id, &job_id);
                    let _ = resp.send(result);
                }
                Command::FindWorkIdForJob { job_id, resp } => {
                    let result = self.map.find_work_id_for_job(&job_id);
                    let _ = resp.send(result);
                }
                Command::FindBlockTemplate { work_id, resp } => {
                    let result = self.map.find_block_template(&work_id);
                    let _ = resp.send(result);
                }
                Command::InsertBlockTemplate {
                    work_id,
                    block_template,
                    resp,
                } => {
                    self.map.insert_block_template(work_id, block_template);
                    let _ = resp.send(());
                }
                Command::AddJobForTemplate {
                    job_id,
                    template,
                    work_id,
                    resp,
                } => {
                    let _work_id = self.map.add_job_for_template(job_id, template, work_id);
                    let _ = resp.send(());
                }
                Command::GetNextWorkId { resp } => {
                    let next_work_id = self.map.get_next_work_id();
                    let _ = resp.send(next_work_id);
                }
                Command::GetLatestWorkId { resp } => {
                    let latest_work_id = self.map.get_latest_work_id();
                    let _ = resp.send(latest_work_id);
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
    async fn test_work_id_generation() {
        // Test with tracker directly
        let mut map = Tracker::new();
        let initial_work_id = map.get_latest_work_id();

        // Get next work id should increment
        let next_work_id = map.get_next_work_id();
        assert_eq!(next_work_id.0, initial_work_id.0 + 1);

        // Latest work id should reflect the increment
        let latest_work_id = map.get_latest_work_id();
        assert_eq!(latest_work_id.0, next_work_id.0);

        // Multiple calls should continue incrementing
        let next_work_id2 = map.get_next_work_id();
        assert_eq!(next_work_id2.0, next_work_id.0 + 1);
    }

    #[tokio::test]
    async fn test_work_id_generation_actor() {
        let handle = start_tracker_actor();

        // Get the initial latest work id
        let initial_work_id = handle.get_latest_work_id().await.unwrap();

        // Get next work id should increment
        let next_work_id = handle.get_next_work_id().await.unwrap();
        assert_eq!(next_work_id.0, initial_work_id.0 + 1);

        // Latest work id should reflect the increment
        let latest_work_id = handle.get_latest_work_id().await.unwrap();
        assert_eq!(latest_work_id.0, next_work_id.0);

        // Multiple calls should continue incrementing
        let next_work_id2 = handle.get_next_work_id().await.unwrap();
        assert_eq!(next_work_id2.0, next_work_id.0 + 1);
    }

    #[tokio::test]
    async fn test_tracker_operations() {
        let mut map = Tracker::new();
        let work_id = WorkId(1001);
        let job_id = JobId(2001);

        // Test insert and contains
        map.insert_job_id(work_id, job_id);
        assert!(map.contains_work_id(&work_id));
        assert!(map.contains_job_id(&work_id, &job_id));

        // Test get
        let jobs = map.get_job_id(&work_id).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0], job_id);

        // Test find work id for job
        let found_work_id = map.find_work_id_for_job(&job_id).unwrap();
        assert_eq!(found_work_id, work_id);

        // Test with non-existent ids
        let non_existent_work_id = WorkId(9999);
        let non_existent_job_id = JobId(9999);
        assert!(!map.contains_work_id(&non_existent_work_id));
        assert!(!map.contains_job_id(&work_id, &non_existent_job_id));
        assert!(map.find_work_id_for_job(&non_existent_job_id).is_none());
    }

    #[tokio::test]
    async fn test_map_actor() {
        let handle = start_tracker_actor();
        let work_id = WorkId(1002);
        let job_id = JobId(2002);

        // Test insert job and contains
        assert!(handle.insert_job_id(work_id, job_id).await.is_ok());
        assert_eq!(handle.contains_work_id(work_id).await.unwrap(), true);
        assert_eq!(handle.contains_job_id(work_id, job_id).await.unwrap(), true);

        // Test get
        let jobs = handle.get_job_ids(work_id).await.unwrap().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0], job_id);

        // Test find work id for job
        let found_work_id = handle.find_work_id_for_job(job_id).await.unwrap().unwrap();
        assert_eq!(found_work_id, work_id);

        // Test with non-existent ids
        let non_existent_work_id = WorkId(9998);
        let non_existent_job_id = JobId(9998);
        assert_eq!(
            handle.contains_work_id(non_existent_work_id).await.unwrap(),
            false
        );
        assert_eq!(
            handle
                .contains_job_id(work_id, non_existent_job_id)
                .await
                .unwrap(),
            false
        );
        assert!(handle
            .find_work_id_for_job(non_existent_job_id)
            .await
            .unwrap()
            .is_none());
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
        let work_id = WorkId(1003);

        // Test inserting a block template
        assert!(handle
            .insert_block_template(work_id, template)
            .await
            .is_ok());

        // Test finding the block template
        let retrieved_template = handle.find_block_template(work_id).await.unwrap();
        assert!(retrieved_template.is_some());
        assert_eq!(
            cloned_template.previousblockhash,
            retrieved_template.unwrap().previousblockhash
        );

        // Test with non-existent work id
        let retrieved_template = handle.find_block_template(WorkId(9997)).await.unwrap();
        assert!(retrieved_template.is_none());
    }

    #[tokio::test]
    async fn test_multiple_jobs_per_work() {
        let mut map = Tracker::new();
        let work_id = WorkId(1004);
        let job_id1 = JobId(2003);
        let job_id2 = JobId(2004);

        // Insert multiple jobs for the same work
        map.insert_job_id(work_id, job_id1);
        map.insert_job_id(work_id, job_id2);

        // Verify all jobs are stored
        let jobs = map.get_job_id(&work_id).unwrap();
        assert_eq!(jobs.len(), 2);
        assert!(jobs.contains(&job_id1));
        assert!(jobs.contains(&job_id2));

        // Check find_work_id_for_job for both jobs
        assert_eq!(map.find_work_id_for_job(&job_id1).unwrap(), work_id);
        assert_eq!(map.find_work_id_for_job(&job_id2).unwrap(), work_id);
    }

    #[tokio::test]
    async fn test_add_job_for_template() {
        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .unwrap();

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();
        let job_id = JobId(2005);
        let work_id = WorkId(1004);

        // Test with tracker directly
        let mut map = Tracker::new();
        map.add_job_for_template(job_id, Arc::new(template.clone()), work_id);

        // Verify job was added
        assert!(map.contains_job_id(&work_id, &job_id));
        assert!(map.find_block_template(&work_id).is_some());

        // Test with actor
        let handle = start_tracker_actor();
        let job_id2 = JobId(2006);
        let work_id2 = WorkId(1005);
        handle
            .add_job_for_template(job_id2, template.clone(), work_id2)
            .await
            .unwrap();

        // Verify results
        assert_eq!(
            handle.contains_job_id(work_id2, job_id2).await.unwrap(),
            true
        );
        assert!(handle
            .find_block_template(work_id2)
            .await
            .unwrap()
            .is_some());

        // Test adding another job for the same template
        let job_id3 = JobId(2007);
        handle
            .add_job_for_template(job_id3, template, work_id2)
            .await
            .unwrap();

        // Both jobs should be present
        let jobs = handle.get_job_ids(work_id2).await.unwrap().unwrap();
        assert!(jobs.contains(&job_id2));
        assert!(jobs.contains(&job_id3));
    }
}
