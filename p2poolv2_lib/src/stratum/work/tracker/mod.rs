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
use crate::utils::snowflake_simplified::{CUSTOM_EPOCH, get_next_id};
use bitcoin::BlockHash;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;
pub mod parse_coinbase;

const MAX_JOB_AGE_SECS: u64 = 10 * 60; // 10 minutes

/// The job id sent to miners.
/// A job id matches a block template.
/// Uses snowflake IDs which encode timestamp and sequence, making them chronologically ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct JobId(pub u64);

impl JobId {
    /// Extract creation timestamp in milliseconds since Unix epoch from the snowflake ID.
    pub fn timestamp_ms(&self) -> u64 {
        (self.0 >> 22) + CUSTOM_EPOCH
    }

    /// Extract creation timestamp in seconds since Unix epoch from the snowflake ID.
    pub fn timestamp_secs(&self) -> u64 {
        self.timestamp_ms() / 1000
    }
}

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
    pub share_commitment: Option<ShareCommitment>,
}

/// Job tracker using RwLock<HashMap> for concurrent access.
#[derive(Debug)]
pub struct JobTracker {
    /// Job details indexed by job ID
    job_details: RwLock<HashMap<JobId, JobDetails>>,
    /// Tracks submitted shares per job for duplicate detection
    job_shares: RwLock<HashMap<JobId, HashSet<BlockHash>>>,
}

impl JobTracker {
    /// Create a new Tracker
    pub fn new() -> Self {
        Self {
            job_details: RwLock::new(HashMap::new()),
            job_shares: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a block template with the specified job id.
    /// The job's creation time is encoded in the job_id itself (snowflake ID).
    pub fn insert_job(
        &self,
        block_template: Arc<BlockTemplate>,
        coinbase1: String,
        coinbase2: String,
        share_commitment: Option<ShareCommitment>,
        job_id: JobId,
    ) -> JobId {
        self.job_details.write().insert(
            job_id,
            JobDetails {
                blocktemplate: block_template,
                coinbase1,
                coinbase2,
                share_commitment,
            },
        );
        self.job_shares.write().insert(job_id, HashSet::new());
        job_id
    }

    /// Get the next job id using snowflake ID generator.
    /// The ID encodes the current timestamp (42 bits) and a sequence number (22 bits).
    pub fn get_next_job_id(&self) -> JobId {
        JobId(get_next_id())
    }

    /// Get job details by job id
    pub fn get_job(&self, job_id: JobId) -> Option<JobDetails> {
        self.job_details.read().get(&job_id).cloned()
    }

    /// Get any recent job ID from the tracker.
    /// Returns the first key found without iterating all keys (O(1)).
    /// All jobs are recent (within 10 min max age), so coinbase is essentially the same.
    /// Returns None if no jobs exist.
    pub fn get_recent_job_id(&self) -> Option<JobId> {
        self.job_details.read().keys().next().copied()
    }

    /// Remove job details that are older than the specified duration in seconds.
    /// Uses the timestamp encoded in the snowflake job ID for age determination.
    /// Returns the number of jobs that were removed.
    pub fn cleanup_old_jobs(&self, max_age_secs: u64) -> usize {
        let current_time_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut removed_count = 0;

        // Clean job_shares using job_id timestamps
        self.job_shares.write().retain(|job_id, _| {
            let keep = current_time_secs.saturating_sub(job_id.timestamp_secs()) < max_age_secs;
            if !keep {
                removed_count += 1;
            }
            keep
        });

        // Clean job_details using job_id timestamps
        self.job_details.write().retain(|job_id, _| {
            current_time_secs.saturating_sub(job_id.timestamp_secs()) < max_age_secs
        });

        removed_count
    }

    /// Add a share to shares tracker for duplicate detection.
    /// Returns true if share is newly inserted, false if job not found or share already exists.
    pub fn add_share(&self, job_id: JobId, blockhash: BlockHash) -> bool {
        let mut shares_map = self.job_shares.write();
        if let Some(shares) = shares_map.get_mut(&job_id) {
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
    fn test_job_id_timestamp_extraction() {
        // Test with a known timestamp to verify extraction logic
        // Snowflake ID structure: (timestamp_ms - CUSTOM_EPOCH) << 22 | sequence
        let known_timestamp_ms: u64 = 1750000000000; // A known timestamp in ms
        let sequence: u64 = 42;
        let snowflake_id = ((known_timestamp_ms - CUSTOM_EPOCH) << 22) | sequence;
        let job_id = JobId(snowflake_id);

        // Verify timestamp_ms extracts the correct timestamp
        assert_eq!(
            job_id.timestamp_ms(),
            known_timestamp_ms,
            "timestamp_ms should extract the encoded timestamp"
        );

        // Verify timestamp_secs is timestamp_ms / 1000
        assert_eq!(
            job_id.timestamp_secs(),
            known_timestamp_ms / 1000,
            "timestamp_secs should be timestamp_ms / 1000"
        );

        // Test with sequence bits at maximum (all 22 bits set)
        let max_sequence: u64 = (1 << 22) - 1;
        let snowflake_id_max_seq = ((known_timestamp_ms - CUSTOM_EPOCH) << 22) | max_sequence;
        let job_id_max_seq = JobId(snowflake_id_max_seq);

        assert_eq!(
            job_id_max_seq.timestamp_ms(),
            known_timestamp_ms,
            "timestamp should be unaffected by sequence bits"
        );

        // Test with a freshly generated ID
        let tracker = JobTracker::new();
        let fresh_job_id = tracker.get_next_job_id();
        let current_time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Fresh ID timestamp should be within 1 second of current time
        let extracted_ms = fresh_job_id.timestamp_ms();
        assert!(
            current_time_ms.saturating_sub(extracted_ms) < 1000,
            "Fresh ID timestamp_ms should be within 1 second of current time"
        );

        let extracted_secs = fresh_job_id.timestamp_secs();
        let current_time_secs = current_time_ms / 1000;
        assert!(
            current_time_secs.saturating_sub(extracted_secs) <= 1,
            "Fresh ID timestamp_secs should be within 1 second of current time"
        );
    }

    #[test]
    fn test_job_id_generation() {
        let tracker = JobTracker::new();

        // No jobs initially
        assert!(tracker.get_recent_job_id().is_none());

        // Snowflake IDs should be unique and increasing
        let job_id1 = tracker.get_next_job_id();
        let job_id2 = tracker.get_next_job_id();
        let job_id3 = tracker.get_next_job_id();

        assert!(job_id2.0 > job_id1.0, "IDs should be increasing");
        assert!(job_id3.0 > job_id2.0, "IDs should be increasing");

        // IDs should encode a reasonable timestamp (close to current time)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let id_timestamp = job_id1.timestamp_secs();
        assert!(
            current_time.saturating_sub(id_timestamp) < 5,
            "ID timestamp should be recent"
        );
    }

    #[tokio::test]
    async fn test_job_id_generation_tracker() {
        let tracker = start_tracker_actor();

        // Snowflake IDs should be unique and increasing
        let job_id1 = tracker.get_next_job_id();
        let job_id2 = tracker.get_next_job_id();
        let job_id3 = tracker.get_next_job_id();

        assert!(job_id2.0 > job_id1.0, "IDs should be increasing");
        assert!(job_id3.0 > job_id2.0, "IDs should be increasing");

        // IDs should encode a reasonable timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let id_timestamp = job_id1.timestamp_secs();
        assert!(
            current_time.saturating_sub(id_timestamp) < 5,
            "ID timestamp should be recent"
        );
    }

    #[tokio::test]
    async fn test_block_template_operations() {
        let template_str = include_str!(
            "../../../../../p2poolv2_tests/test_data/gbt/signet/gbt-no-transactions.json"
        );

        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();
        let cloned_template = template.clone();

        let tracker = start_tracker_actor();

        // Use a snowflake ID for the job
        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(template),
            "cb1".to_string(),
            "cb2".to_string(),
            Some(create_test_commitment()),
            job_id,
        );

        // Test finding the job
        let retrieved_job = tracker.get_job(job_id).unwrap();
        assert_eq!(
            cloned_template.previousblockhash,
            retrieved_job.blocktemplate.previousblockhash
        );
        assert_eq!(retrieved_job.coinbase1, "cb1".to_string());
        assert_eq!(retrieved_job.coinbase2, "cb2".to_string());

        // Verify job_id encodes a recent timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(current_timestamp >= job_id.timestamp_secs());
        assert!(current_timestamp - job_id.timestamp_secs() <= 5);

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

        // Create a snowflake ID representing a job from 20 minutes ago
        let current_time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let old_timestamp_ms = current_time_ms - (20 * 60 * 1000); // 20 minutes ago
        let old_job_id = JobId((old_timestamp_ms - CUSTOM_EPOCH) << 22);

        tracker.insert_job(
            Arc::new(template.clone()),
            "old_cb1".to_string(),
            "old_cb2".to_string(),
            Some(create_test_commitment()),
            old_job_id,
        );

        // Insert a new job with current timestamp
        let new_job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(template.clone()),
            "new_cb1".to_string(),
            "new_cb2".to_string(),
            None,
            new_job_id,
        );

        // Verify both jobs exist
        assert!(tracker.job_details.read().contains_key(&old_job_id));
        assert!(tracker.job_details.read().contains_key(&new_job_id));

        // Run cleanup (15 minutes max age)
        let removed = tracker.cleanup_old_jobs(15 * 60);
        assert_eq!(removed, 1);

        // Verify only the new job remains
        assert!(!tracker.job_details.read().contains_key(&old_job_id));
        assert!(tracker.job_details.read().contains_key(&new_job_id));

        // Test with tracker: cleanup with 0 max age should remove all jobs
        let tracker = start_tracker_actor();

        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(template.clone()),
            "actor_cb1".to_string(),
            "actor_cb2".to_string(),
            None,
            job_id,
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
        use std::collections::HashSet;
        use std::sync::Mutex;
        use std::thread;

        let tracker = Arc::new(JobTracker::new());
        let collected_ids = Arc::new(Mutex::new(HashSet::new()));

        // Spawn multiple threads doing concurrent operations
        let mut handles = vec![];

        for _ in 0..10 {
            let tracker_clone = tracker.clone();
            let ids_clone = collected_ids.clone();
            let handle = thread::spawn(move || {
                let mut local_ids = Vec::new();
                // Each thread gets job IDs
                for _ in 0..100 {
                    let job_id = tracker_clone.get_next_job_id();
                    local_ids.push(job_id);
                }
                // Add to shared collection
                let mut ids = ids_clone.lock().unwrap();
                for id in local_ids {
                    ids.insert(id);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All 1000 IDs should be unique
        let ids = collected_ids.lock().unwrap();
        assert_eq!(ids.len(), 1000, "All generated IDs should be unique");
    }
}
