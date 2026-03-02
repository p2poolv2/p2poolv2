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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::store::Store;
use crate::store::column_families::ColumnFamily;
use crate::store::writer::StoreError;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

const MIN_TIMESTAMP: u64 = 0;

/// Start any background tasks required
///
/// Start a tokio task that runs every frequency period and
/// deletes all shares older than pplns_share_ttl older than now.
pub fn start_background_tasks(
    store: Arc<Store>,
    frequency: Duration,
    pplns_ttl: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(frequency);
        loop {
            interval.tick().await;
            debug!("Running background cleanup tasks");

            if let Err(e) = store.prune_shares(pplns_ttl) {
                error!("Error running shares cleanup: {:?}", e);
            }

            if let Err(e) = store.prune_jobs(pplns_ttl) {
                error!("Error running jobs cleanup: {:?}", e);
            }
        }
    })
}

impl Store {
    /// Delete all PPLNS shares older than the given TTL
    ///
    /// Uses RocksDB range delete for efficient bulk deletion
    /// Keys are in format: n_time(8 bytes) + user_id(8 bytes) + seq(8 bytes)
    fn prune_shares(&self, pplns_ttl: Duration) -> Result<(), StoreError> {
        let pplns_share_cf = self.db.cf_handle(&ColumnFamily::Share).unwrap();

        // Calculate cutoff time in microseconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let cutoff_micros = now.saturating_sub(pplns_ttl.as_micros() as u64);

        info!(
            "Cleaning up PPLNS shares older than {} seconds (cutoff: {})",
            pplns_ttl.as_secs(),
            cutoff_micros
        );

        // Create range: from beginning (min key) to cutoff (exclusive)
        // We want to delete all shares with timestamp < cutoff_micros
        // Since delete_range_cf uses [start, end), we set end to cutoff + 1 to include cutoff
        let start_key = SimplePplnsShare::make_key(0, 0, 0);
        let end_key = SimplePplnsShare::make_key(cutoff_micros.saturating_add(1), 0, 0);

        // Use RocksDB range delete for efficient bulk deletion
        // delete_range_cf deletes all keys in [start_key, end_key)
        self.db
            .delete_range_cf(&pplns_share_cf, &start_key, &end_key)?;

        info!("Deleted PPLNS shares older than cutoff time");

        Ok(())
    }

    /// Delete all jobs older than the given TTL
    ///
    /// Uses RocksDB range delete for efficient bulk deletion
    /// Keys are in format: timestamp(8 bytes) in big-endian
    fn prune_jobs(&self, job_ttl: Duration) -> Result<(), StoreError> {
        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();

        // Calculate cutoff time in microseconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let cutoff_micros = now.saturating_sub(job_ttl.as_micros() as u64);

        info!(
            "Cleaning up jobs older than {} seconds (cutoff: {})",
            job_ttl.as_secs(),
            cutoff_micros
        );

        // Create range: from beginning (min timestamp) to cutoff (exclusive)
        // Jobs use simple u64 timestamp keys in big-endian format
        let start_key = MIN_TIMESTAMP.to_be_bytes();
        let end_key = cutoff_micros.saturating_add(1).to_be_bytes();

        // Use RocksDB range delete for efficient bulk deletion
        // delete_range_cf deletes all keys in [start_key, end_key)
        self.db.delete_range_cf(&job_cf, &start_key, &end_key)?;

        info!("Deleted jobs older than cutoff time");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use tempfile::tempdir;

    #[test]
    fn test_run_shares_cleanup_removes_old_shares() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_id = store.add_user("addr1".to_string()).unwrap();

        // Get current time in seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add shares with different timestamps relative to now
        let shares = vec![
            SimplePplnsShare::new(
                user_id,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                now - 3600, // 1 hour ago
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id,
                200,
                "addr1".to_string(),
                "worker1".to_string(),
                now - 1800, // 30 minutes ago
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id,
                300,
                "addr1".to_string(),
                "worker1".to_string(),
                now - 300, // 5 minutes ago
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        // Verify all shares are stored
        let all_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(all_shares.len(), 3);

        // Run cleanup with TTL of 1500 seconds (25 minutes)
        // This should delete shares older than 25 minutes: the 1 hour and 30 minute old shares
        // The 5 minute old share should remain
        let ttl = Duration::from_secs(1500);
        store.prune_shares(ttl).unwrap();

        // Verify only the newest share remains
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 1);
        assert_eq!(remaining_shares[0].n_time, now - 300);
    }

    #[test]
    fn test_run_shares_cleanup_no_shares_to_delete() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_id = store.add_user("addr1".to_string()).unwrap();

        // Get current time in seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add a recent share (30 seconds ago)
        let share = SimplePplnsShare::new(
            user_id,
            100,
            "addr1".to_string(),
            "worker1".to_string(),
            now - 30,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );
        store.add_pplns_share(share).unwrap();

        // Run cleanup with TTL of 100 seconds - should not delete the 30 second old share
        let ttl = Duration::from_secs(100);
        let result = store.prune_shares(ttl);
        assert!(result.is_ok());

        // Verify share still exists
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 1);
    }

    #[test]
    fn test_run_shares_cleanup_empty_store() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Run cleanup on empty store - should not error
        let ttl = Duration::from_secs(3600);
        let result = store.prune_shares(ttl);
        assert!(result.is_ok());

        // Verify still empty
        let shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(shares.len(), 0);
    }

    #[tokio::test]
    async fn test_start_background_tasks() {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());

        let user_id = store.add_user("addr1".to_string()).unwrap();

        // Get current time in seconds and microseconds
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let now_secs = now.as_secs();
        let now_micros = now.as_micros() as u64;

        // Add an old share (1 hour ago)
        let old_share = SimplePplnsShare::new(
            user_id,
            100,
            "addr1".to_string(),
            "worker1".to_string(),
            now_secs - 3600,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );
        store.add_pplns_share(old_share).unwrap();

        // Add an old job (1 hour ago in microseconds)
        let old_job_timestamp = now_micros - 3_600_000_000; // 1 hour in microseconds
        store
            .add_job(old_job_timestamp, "old_job_data".to_string())
            .unwrap();

        // Start background task with short frequency and TTL of 30 minutes
        let frequency = Duration::from_millis(100);
        let ttl = Duration::from_secs(1800);
        let handle = start_background_tasks(store.clone(), frequency, ttl);

        // Wait for at least one cleanup cycle
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify share was deleted (it's 1 hour old, TTL is 30 minutes)
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 0);

        // Verify job was deleted (use a future end_time to capture all jobs)
        let future_time = now_micros + 1_000_000_000; // 1000 seconds in the future
        let remaining_jobs = store.get_jobs(None, Some(future_time), 10).unwrap();
        assert_eq!(remaining_jobs.len(), 0);

        // Cancel background task
        handle.abort();
    }

    #[test]
    fn test_prune_jobs_removes_old_jobs() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Get current time in microseconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        // Add jobs with different timestamps (in microseconds)
        let job1_time = now - 3_600_000_000; // 1 hour ago
        let job2_time = now - 1_800_000_000; // 30 minutes ago
        let job3_time = now - 300_000_000; // 5 minutes ago

        store.add_job(job1_time, "job1".to_string()).unwrap();
        store.add_job(job2_time, "job2".to_string()).unwrap();
        store.add_job(job3_time, "job3".to_string()).unwrap();

        // Verify all jobs are stored (use a future end_time to capture all jobs)
        let future_time = now + 1_000_000_000; // 1000 seconds in the future
        let all_jobs = store.get_jobs(None, Some(future_time), 10).unwrap();
        assert_eq!(all_jobs.len(), 3);

        // Run cleanup with TTL of 1500 seconds (25 minutes)
        // This should delete jobs older than 25 minutes: 1 hour and 30 minute old jobs
        let ttl = Duration::from_secs(1500);
        store.prune_jobs(ttl).unwrap();

        // Verify only the newest job remains (use a future end_time to capture all jobs)
        let future_time = now + 1_000_000_000; // 1000 seconds in the future
        let remaining_jobs = store.get_jobs(None, Some(future_time), 10).unwrap();
        assert_eq!(remaining_jobs.len(), 1);
        assert_eq!(remaining_jobs[0].0, job3_time);
    }

    #[test]
    fn test_prune_jobs_no_jobs_to_delete() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Get current time in microseconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        // Add a recent job (30 seconds ago)
        let recent_job_time = now - 30_000_000; // 30 seconds in microseconds
        store
            .add_job(recent_job_time, "recent_job".to_string())
            .unwrap();

        // Run cleanup with TTL of 100 seconds - should not delete the 30 second old job
        let ttl = Duration::from_secs(100);
        let result = store.prune_jobs(ttl);
        assert!(result.is_ok());

        // Verify job still exists (use a future end_time to capture all jobs)
        let future_time = now + 1_000_000_000; // 1000 seconds in the future
        let remaining_jobs = store.get_jobs(None, Some(future_time), 10).unwrap();
        assert_eq!(remaining_jobs.len(), 1);
    }

    #[test]
    fn test_prune_jobs_empty_store() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Run cleanup on empty store - should not error
        let ttl = Duration::from_secs(3600);
        let result = store.prune_jobs(ttl);
        assert!(result.is_ok());

        // Verify still empty (use a future end_time to capture all jobs)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        let future_time = now + 1_000_000_000; // 1000 seconds in the future
        let jobs = store.get_jobs(None, Some(future_time), 10).unwrap();
        assert_eq!(jobs.len(), 0);
    }
}
