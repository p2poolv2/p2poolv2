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

use crate::store::{ColumnFamily, Store};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

impl Store {
    /// Save a job with the given timestamp key to the Job column family
    pub fn add_job(
        &self,
        timestamp: u64,
        serialized_notify: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Saving job to store with key: {:?}", timestamp);
        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();
        self.db.put_cf(
            &job_cf,
            timestamp.to_be_bytes(),
            serialized_notify.as_bytes(),
        )?;
        Ok(())
    }

    /// Get jobs within a time range from the Job column family
    /// Returns jobs ordered by timestamp (newest first)
    pub fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        debug!(
            "Getting jobs from store with start_time: {:?}, end_time: {:?}, limit: {}",
            start_time, end_time, limit
        );

        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();

        // If end_time is None, use current time
        let effective_end_time = end_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        });

        // Create a read options object to set iteration bounds
        let mut read_opts = rocksdb::ReadOptions::default();

        if let Some(start) = start_time {
            // Set the lower bound (start_time) for reverse iteration
            read_opts.set_iterate_lower_bound(start.to_be_bytes().to_vec());
        }

        // Start iterating from end_time in reverse order to get newest first
        let iter = self.db.iterator_cf_opt(
            &job_cf,
            read_opts,
            rocksdb::IteratorMode::From(
                &effective_end_time.to_be_bytes(),
                rocksdb::Direction::Reverse,
            ),
        );

        // Collect results
        let mut results = Vec::with_capacity(limit);

        for (i, item) in iter.enumerate() {
            if i >= limit {
                break;
            }

            let (key, value) = item?;

            // Convert key bytes to u64 timestamp
            let timestamp = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| "Invalid timestamp key")?,
            );

            // Convert value bytes to string
            let job_data =
                String::from_utf8(value.to_vec()).map_err(|e| format!("Invalid job data: {e}"))?;

            results.push((timestamp, job_data));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_add_job() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add a job with timestamp
        let timestamp = 1000000u64;
        let job_data = "test_job_data".to_string();

        let result = store.add_job(timestamp, job_data.clone());
        assert!(result.is_ok());

        // Verify job was stored by reading it back
        let jobs = store.get_jobs(None, Some(timestamp + 1000), 10).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, timestamp);
        assert_eq!(jobs[0].1, job_data);
    }

    #[test]
    fn test_get_jobs_with_no_jobs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let jobs = store.get_jobs(None, None, 10).unwrap();
        assert_eq!(jobs.len(), 0);
    }

    #[test]
    fn test_get_jobs_ordered_by_timestamp() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs with different timestamps
        let job1_time = 1000000u64;
        let job2_time = 2000000u64;
        let job3_time = 3000000u64;

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();

        // Get all jobs - should be ordered newest first
        let jobs = store.get_jobs(None, Some(job3_time + 1000), 10).unwrap();
        assert_eq!(jobs.len(), 3);

        // Verify newest first ordering
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[0].1, "job3");
        assert_eq!(jobs[1].0, job2_time);
        assert_eq!(jobs[1].1, "job2");
        assert_eq!(jobs[2].0, job1_time);
        assert_eq!(jobs[2].1, "job1");
    }

    #[test]
    fn test_get_jobs_with_limit() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add 5 jobs
        for i in 1..=5 {
            store.add_job(i * 1000000, format!("job{i}")).unwrap();
        }

        // Request only 3 jobs
        let jobs = store.get_jobs(None, Some(6000000), 3).unwrap();
        assert_eq!(jobs.len(), 3);

        // Should get the 3 newest
        assert_eq!(jobs[0].1, "job5");
        assert_eq!(jobs[1].1, "job4");
        assert_eq!(jobs[2].1, "job3");
    }

    #[test]
    fn test_get_jobs_with_time_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs with different timestamps
        let job1_time = 1000000u64;
        let job2_time = 2000000u64;
        let job3_time = 3000000u64;
        let job4_time = 4000000u64;

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();
        store.add_job(job4_time, "job4".to_string()).unwrap();

        // Get jobs between start_time=1.5M and end_time=3.5M
        // Should return job3 and job2 (newest first)
        let jobs = store.get_jobs(Some(1500000), Some(3500000), 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[0].1, "job3");
        assert_eq!(jobs[1].0, job2_time);
        assert_eq!(jobs[1].1, "job2");
    }

    #[test]
    fn test_get_jobs_with_end_time_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add jobs
        store.add_job(1000000, "job1".to_string()).unwrap();
        store.add_job(2000000, "job2".to_string()).unwrap();
        store.add_job(3000000, "job3".to_string()).unwrap();

        // Get all jobs up to 2.5M
        let jobs = store.get_jobs(None, Some(2500000), 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].1, "job2");
        assert_eq!(jobs[1].1, "job1");
    }

    #[test]
    fn test_get_jobs_with_start_time_only() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Get current time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        // Add jobs in the past
        let job1_time = now - 3000000; // ~3 seconds ago
        let job2_time = now - 2000000; // ~2 seconds ago
        let job3_time = now - 1000000; // ~1 second ago

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();

        // Get jobs from 2.5 seconds ago to now (should return job3 and job2)
        let jobs = store.get_jobs(Some(now - 2500000), None, 10).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].0, job3_time);
        assert_eq!(jobs[1].0, job2_time);
    }
}
