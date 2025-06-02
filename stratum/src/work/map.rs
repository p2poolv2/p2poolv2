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

/// The work id used uniquely track block templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkId(pub &'static str);

/// The work id used uniquely track jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub &'static str);

/// A map that associates work ids with job ids
#[derive(Debug, Default)]
pub struct WorkMap {
    jobs: HashMap<WorkId, Vec<JobId>>,
    blocktemplates: HashMap<WorkId, Arc<BlockTemplate>>,
}

impl WorkMap {
    /// Create a new empty Map
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            blocktemplates: HashMap::new(),
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

    /// Insert a block template under the specified work id
    pub fn insert_block_template(&mut self, work_id: WorkId, block_template: Arc<BlockTemplate>) {
        self.blocktemplates.insert(work_id, block_template);
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
        block_template: Arc<BlockTemplate>, // Change from BlockTemplate to Arc<BlockTemplate>
        resp: oneshot::Sender<()>,
    },
}

/// A handle to the WorkMapActor
#[derive(Debug, Clone)]
pub struct WorkMapActorHandle {
    tx: mpsc::Sender<Command>,
}

impl WorkMapActorHandle {
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
    pub async fn get_job_id(&self, work_id: WorkId) -> Result<Option<Vec<JobId>>, String> {
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
        block_template: BlockTemplate, // Accept a BlockTemplate directly from caller
    ) -> Result<(), String> {
        let (resp_tx, resp_rx) = oneshot::channel();

        // Create the Arc here, before sending the command
        let arc_template = Arc::new(block_template);

        self.tx
            .send(Command::InsertBlockTemplate {
                work_id,
                block_template: arc_template, // Send the Arc<BlockTemplate>
                resp: resp_tx,
            })
            .await
            .map_err(|_| "Failed to send insert_block_template command".to_string())?;

        resp_rx
            .await
            .map_err(|_| "Failed to receive insert_block_template response".to_string())
    }
}

/// The actor that manages access to the WorkMap
pub struct WorkMapActor {
    map: WorkMap,
    rx: mpsc::Receiver<Command>,
}

impl WorkMapActor {
    /// Create a new WorkMapActor and return a handle to it
    pub fn new() -> (Self, WorkMapActorHandle) {
        let (tx, rx) = mpsc::channel(100); // Buffer size of 100

        let actor = Self {
            map: WorkMap::new(),
            rx,
        };

        let handle = WorkMapActorHandle { tx };

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
            }
        }
    }
}

/// Start a new MapActor in a separate task and return a handle to it
pub fn start_map_actor() -> WorkMapActorHandle {
    let (actor, handle) = WorkMapActor::new();

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
    async fn test_workmap_operations() {
        let mut map = WorkMap::new();
        let work_id = WorkId("test_work");
        let job_id = JobId("test_job");

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
        let non_existent_work_id = WorkId("non_existent");
        let non_existent_job_id = JobId("non_existent");
        assert!(!map.contains_work_id(&non_existent_work_id));
        assert!(!map.contains_job_id(&work_id, &non_existent_job_id));
        assert!(map.find_work_id_for_job(&non_existent_job_id).is_none());
    }

    #[tokio::test]
    async fn test_map_actor() {
        let handle = start_map_actor();
        let work_id = WorkId("test_work");
        let job_id = JobId("test_job");

        // Test insert job and contains
        assert!(handle.insert_job_id(work_id, job_id).await.is_ok());
        assert_eq!(handle.contains_work_id(work_id).await.unwrap(), true);
        assert_eq!(handle.contains_job_id(work_id, job_id).await.unwrap(), true);

        // Test get
        let jobs = handle.get_job_id(work_id).await.unwrap().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0], job_id);

        // Test find work id for job
        let found_work_id = handle.find_work_id_for_job(job_id).await.unwrap().unwrap();
        assert_eq!(found_work_id, work_id);

        // Test with non-existent ids
        let non_existent_work_id = WorkId("non_existent");
        let non_existent_job_id = JobId("non_existent");
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

        let handle = start_map_actor();
        let work_id = WorkId("test_work");

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
        let retrieved_template = handle
            .find_block_template(WorkId("non_existent"))
            .await
            .unwrap();
        assert!(retrieved_template.is_none());
    }

    #[tokio::test]
    async fn test_multiple_jobs_per_work() {
        let mut map = WorkMap::new();
        let work_id = WorkId("multi_job_work");
        let job_id1 = JobId("job1");
        let job_id2 = JobId("job2");

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
}
