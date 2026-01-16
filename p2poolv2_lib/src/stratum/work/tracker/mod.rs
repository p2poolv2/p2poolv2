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
use bitcoin::BlockHash;
use dashmap::{DashMap, DashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;
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

/// Lock-free job tracker using DashMap for concurrent access.
#[derive(Debug)]
pub struct JobTracker {
    job_details: DashMap<JobId, JobDetails>,
    /// Tracks submitted shares per job for duplicate detection (internal only)
    job_shares: DashMap<JobId, DashSet<BlockHash>>,
    latest_job_id: AtomicU64,
}

impl JobTracker {
    /// Create a new Tracker with timestamp-based initial job ID
    pub fn new() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            job_details: DashMap::new(),
            job_shares: DashMap::new(),
            latest_job_id: AtomicU64::new(timestamp),
        }
    }

    /// Insert a block template with the specified job id
    pub fn insert_job(
        &self,
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
        self.job_shares.insert(job_id, DashSet::new());
        job_id
    }

    /// Get the next job id, incrementing it atomically
    pub fn get_next_job_id(&self) -> JobId {
        JobId(self.latest_job_id.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// Get the latest job id without incrementing
    pub fn get_latest_job_id(&self) -> JobId {
        JobId(self.latest_job_id.load(Ordering::SeqCst))
    }

    /// Get job details by job id
    pub fn get_job(&self, job_id: JobId) -> Option<JobDetails> {
        self.job_details.get(&job_id).map(|r| r.clone())
    }

    /// Remove job details that are older than the specified duration in seconds
    /// Returns the number of jobs that were removed
    pub fn cleanup_old_jobs(&self, max_age_secs: u64) -> usize {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before_count = self.job_details.len();

        self.job_details.retain(|job_id, details| {
            let keep = current_time.saturating_sub(details.generation_timestamp) < max_age_secs;
            if !keep {
                // Also remove shares for this job
                self.job_shares.remove(job_id);
            }
            keep
        });

        before_count - self.job_details.len()
    }

    /// Add a share to shares tracker for duplicate detection
    /// Returns true if share is newly inserted, false if job not found or share already exists
    pub fn add_share(&self, job_id: JobId, blockhash: BlockHash) -> bool {
        if let Some(shares) = self.job_shares.get(&job_id) {
            shares.insert(blockhash)
        } else {
            false
        }
    }
}

impl Default for JobTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Start a new JobTracker and return an Arc to it.
///
/// Also spawns a background cleanup task that periodically removes old jobs.
pub fn start_tracker_actor() -> Arc<JobTracker> {
    let tracker = Arc::new(JobTracker::new());

    // Spawn a task for periodic cleanup
    let cleanup_tracker = tracker.clone();
    tokio::spawn(async move {
        let cleanup_interval = tokio::time::Duration::from_secs(MAX_JOB_AGE_SECS);
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let count = cleanup_tracker.cleanup_old_jobs(MAX_JOB_AGE_SECS);
            if count > 0 {
                debug!("Cleaned up {} old job IDs", count);
            }
        }
    });

    tracker
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_commitment;

    #[test]
    fn test_job_id_generation() {
        let tracker = JobTracker::new();
        let initial_job_id = tracker.get_latest_job_id();

        // Get next job id should increment
        let next_job_id = tracker.get_next_job_id();
        assert_eq!(next_job_id.0, initial_job_id.0 + 1);

        // Latest job id should reflect the increment
        let latest_job_id = tracker.get_latest_job_id();
        assert_eq!(latest_job_id.0, next_job_id.0);

        // Multiple calls should continue incrementing
        let next_job_id2 = tracker.get_next_job_id();
        assert_eq!(next_job_id2.0, next_job_id.0 + 1);
    }

    #[tokio::test]
    async fn test_job_id_generation_tracker() {
        let tracker = start_tracker_actor();

        // Get the initial latest job id
        let initial_job_id = tracker.get_latest_job_id();

        // Get next job id should increment
        let next_job_id = tracker.get_next_job_id();
        assert_eq!(next_job_id.0, initial_job_id.0 + 1);

        // Latest job id should reflect the increment
        let latest_job_id = tracker.get_latest_job_id();
        assert_eq!(latest_job_id.0, next_job_id.0);

        // Multiple calls should continue incrementing
        let next_job_id2 = tracker.get_next_job_id();
        assert_eq!(next_job_id2.0, next_job_id.0 + 1);
    }

    #[tokio::test]
    async fn test_block_template_operations() {
        let template_str = include_str!(
            "../../../../../p2poolv2_tests/test_data/gbt/signet/gbt-no-transactions.json"
        );

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();
        let cloned_template = template.clone();

        let tracker = start_tracker_actor();

        let job_id = tracker.insert_job(
            Arc::new(template),
            "cb1".to_string(),
            "cb2".to_string(),
            Some(create_test_commitment()),
            JobId(1),
        );

        // Test inserting a block template
        assert_eq!(job_id, JobId(1));

        // Test finding the job
        let retrieved_job = tracker.get_job(job_id).unwrap();
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
        assert!(current_timestamp - retrieved_job.generation_timestamp <= 5);

        // Test with non-existent job id
        let retrieved_job = tracker.get_job(JobId(9997));
        assert!(retrieved_job.is_none());
    }

    #[tokio::test]
    async fn test_job_cleanup() {
        let template_str = include_str!(
            "../../../../../p2poolv2_tests/test_data/gbt/signet/gbt-no-transactions.json"
        );

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        // Create tracker directly
        let tracker = JobTracker::new();

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
        if let Some(mut job) = tracker.job_details.get_mut(&old_job_id) {
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

        // Test with tracker
        let tracker = start_tracker_actor();

        // Insert a job
        let job_id = tracker.insert_job(
            Arc::new(template.clone()),
            "actor_cb1".to_string(),
            "actor_cb2".to_string(),
            None,
            JobId(3),
        );

        // Cleanup with 0 max age should remove all jobs
        let removed = tracker.cleanup_old_jobs(0);
        assert_eq!(removed, 1);

        // Verify job was removed
        let result = tracker.get_job(job_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_add_share_rejects_duplicates() {
        let template_str = include_str!(
            "../../../../../p2poolv2_tests/test_data/gbt/signet/gbt-no-transactions.json"
        );
        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        let tracker = JobTracker::new();
        let job_id = JobId(1);

        // Insert a job
        tracker.insert_job(
            Arc::new(template),
            "cb1".to_string(),
            "cb2".to_string(),
            None,
            job_id,
        );

        // Create a test blockhash
        let blockhash: BlockHash =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();

        // First add should succeed (returns true for newly inserted)
        assert!(tracker.add_share(job_id, blockhash));

        // Second add of same blockhash should fail (returns false for duplicate)
        assert!(!tracker.add_share(job_id, blockhash));

        // Third add should still fail
        assert!(!tracker.add_share(job_id, blockhash));

        // Adding a different blockhash should succeed
        let blockhash2: BlockHash =
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse()
                .unwrap();
        assert!(tracker.add_share(job_id, blockhash2));

        // But adding blockhash2 again should fail
        assert!(!tracker.add_share(job_id, blockhash2));

        // Adding to non-existent job should return false
        let non_existent_job = JobId(999);
        assert!(!tracker.add_share(non_existent_job, blockhash));
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let tracker = Arc::new(JobTracker::new());

        // Get the initial job ID before spawning threads
        let initial_id = tracker.get_latest_job_id();

        // Spawn multiple threads doing concurrent operations
        let mut trackers = vec![];

        for _ in 0..10 {
            let tracker_clone = tracker.clone();
            let tracker = thread::spawn(move || {
                // Each thread gets job IDs
                for _ in 0..100 {
                    let _job_id = tracker_clone.get_next_job_id();
                }
            });
            trackers.push(tracker);
        }

        // Wait for all threads
        for tracker in trackers {
            tracker.join().unwrap();
        }

        // Should have incremented 1000 times total (10 threads * 100 iterations)
        let final_id = tracker.get_latest_job_id();
        assert_eq!(final_id.0, initial_id.0 + 1000);
    }
}
