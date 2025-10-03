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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::store::Store;
use crate::store::column_families::ColumnFamily;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

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
        }
    })
}

impl Store {
    /// Delete all PPLNS shares older than the given TTL
    ///
    /// Uses RocksDB range delete for efficient bulk deletion
    /// Keys are in format: n_time(8 bytes) + user_id(8 bytes) + seq(8 bytes)
    fn prune_shares(&self, pplns_ttl: Duration) -> Result<(), Box<dyn Error>> {
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
            .delete_range_cf(pplns_share_cf, &start_key, &end_key)?;

        info!("Deleted PPLNS shares older than cutoff time");

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

        // Get current time in seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add an old share (1 hour ago)
        let old_share = SimplePplnsShare::new(
            user_id,
            100,
            "addr1".to_string(),
            "worker1".to_string(),
            now - 3600,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );
        store.add_pplns_share(old_share).unwrap();

        // Start background task with short frequency and TTL of 30 minutes
        let frequency = Duration::from_millis(100);
        let ttl = Duration::from_secs(1800);
        let handle = start_background_tasks(store.clone(), frequency, ttl);

        // Wait for at least one cleanup cycle
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify share was deleted (it's 1 hour old, TTL is 30 minutes)
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 0);

        // Cancel background task
        handle.abort();
    }
}
