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

//! Save and load pool metrics.
//!
//! We introduce Filtered.* strucs to serialize PoolMetric without
//! cloning and collecting vectore of user and workers.
//!
//! The Filtered structs let us serialize PoolMetrics without cloning
//! and in a single iteration over users and workers.

use crate::accounting::stats::metrics::MetricsHandle;
use crate::accounting::stats::metrics::PoolMetrics;
use crate::accounting::stats::user::User;
use crate::accounting::stats::worker::Worker;
use serde::Serialize;
use serde::ser::{SerializeMap, SerializeStruct};
use std::collections::HashMap;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;
use tracing::error;

const POOL_STATS_DIR: &str = "pool";

/// Returns true if a worker should be included in filtered output.
fn is_active_worker(worker: &Worker) -> bool {
    worker.active && worker.shares_valid_total > 0
}

/// Wrapper for `&HashMap<String, Worker>` that serializes only active workers with shares.
/// Avoids allocating a filtered copy by filtering during serialization.
struct FilteredWorkers<'a>(&'a HashMap<String, Worker>);

impl Serialize for FilteredWorkers<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self.0.values().filter(|w| is_active_worker(w)).count();
        let mut map = serializer.serialize_map(Some(count))?;
        for (name, worker) in self.0.iter().filter(|(_, w)| is_active_worker(w)) {
            map.serialize_entry(name, worker)?;
        }
        map.end()
    }
}

/// Wrapper for `&User` that uses `FilteredWorkers` for the workers field.
struct FilteredUser<'a>(&'a User);

impl Serialize for FilteredUser<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("User", 5)?;
        state.serialize_field("last_share_at", &self.0.last_share_at)?;
        state.serialize_field("shares_valid_total", &self.0.shares_valid_total)?;
        state.serialize_field("workers", &FilteredWorkers(&self.0.workers))?;
        state.serialize_field("best_share", &self.0.best_share)?;
        state.serialize_field("best_share_ever", &self.0.best_share_ever)?;
        state.end()
    }
}

/// Wrapper for `&HashMap<String, User>` that serializes only users with active workers.
/// Uses `FilteredUser` for each user to filter workers during serialization.
struct FilteredUsers<'a>(&'a HashMap<String, User>);

impl Serialize for FilteredUsers<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let active_users: Vec<_> = self
            .0
            .iter()
            .filter(|(_, u)| u.workers.values().any(is_active_worker))
            .collect();
        let mut map = serializer.serialize_map(Some(active_users.len()))?;
        for (name, user) in active_users {
            map.serialize_entry(name, &FilteredUser(user))?;
        }
        map.end()
    }
}

/// Wrapper for `&PoolMetrics` that filters inactive users/workers during serialization.
/// Zero intermediate allocations - iterates once and writes directly to serializer.
struct FilteredPoolMetrics<'a>(&'a PoolMetrics);

impl Serialize for FilteredPoolMetrics<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("PoolMetrics", 9)?;
        state.serialize_field("start_time", &self.0.start_time)?;
        state.serialize_field("lastupdate", &self.0.lastupdate)?;
        state.serialize_field("accepted_total", &self.0.accepted_total)?;
        state.serialize_field(
            "accepted_difficulty_total",
            &self.0.accepted_difficulty_total,
        )?;
        state.serialize_field("rejected_total", &self.0.rejected_total)?;
        state.serialize_field("best_share", &self.0.best_share)?;
        state.serialize_field("best_share_ever", &self.0.best_share_ever)?;
        state.serialize_field("users", &FilteredUsers(&self.0.users))?;
        state.serialize_field("pool_difficulty", &self.0.pool_difficulty)?;
        state.end()
    }
}

/// Save pool stats to log dir
/// Use fs::rename to ensure atomic write
/// Only saves active workers with shares and users with at least one such worker.
///
/// Uses custom serialization wrappers to filter during the serialize pass,
/// avoiding intermediate allocations. With thousands of workers, this writes
/// directly to the serializer without cloning any data structures.
pub fn save_pool_local_stats(pool_metrics: &PoolMetrics, log_dir: &str) -> std::io::Result<()> {
    let stats_dir = Path::new(log_dir).join(POOL_STATS_DIR);
    if let Err(e) = create_dir_all(&stats_dir) {
        error!("Error creating directory {e}");
        return Err(std::io::Error::other("Error creating directory"));
    }
    let path = stats_dir.join("pool_stats.json");
    let tmp_path = stats_dir.join("pool_stats.json.tmp");

    let serialized = serde_json::to_string_pretty(&FilteredPoolMetrics(pool_metrics))
        .map_err(|_| std::io::Error::other("JSON serialization failed"))?;

    if !serialized.is_empty() {
        let mut file = File::create(&tmp_path)?;
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp_path, &path)?;
    }

    Ok(())
}

/// Load pool stats from log dir
/// Returns default PoolMetrics if the file doesn't exist
/// or returns error for other failure cases
pub fn load_pool_local_stats(log_dir: &str) -> Result<PoolMetrics, std::io::Error> {
    let path = Path::new(log_dir)
        .join(POOL_STATS_DIR)
        .join("pool_stats.json");

    if !path.exists() {
        return Ok(PoolMetrics::default());
    }

    let file_content =
        std::fs::read_to_string(&path).map_err(|_| std::io::Error::other("File read failed"))?;

    match serde_json::from_str(&file_content) {
        Ok(pool_metrics) => Ok(pool_metrics),
        Err(e) => {
            tracing::error!("Error deserializing pool stats: {e}");
            Err(std::io::Error::other("JSON deserialization failed"))
        }
    }
}

/// Start a background task to periodically save pool local stats
/// to the specified log directory.
/// The stats are saved every `save_interval_secs` seconds.
pub async fn start_stats_saver(
    metrics_handle: MetricsHandle,
    save_interval_secs: u64,
    log_dir: String,
) -> Result<(), std::io::Error> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(save_interval_secs));
        loop {
            interval.tick().await;
            match metrics_handle.commit().await {
                Ok(_) => {
                    let metrics = metrics_handle.get_metrics().await;
                    if let Err(e) = save_pool_local_stats(&metrics, &log_dir) {
                        error!("Failed to save pool local stats: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to commit metrics before saving: {}", e);
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test_log::test]
    fn test_pool_local_stats_save_load() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();

        // Create stats directory
        let stats_dir = Path::new(log_dir).join(POOL_STATS_DIR);
        fs::create_dir_all(&stats_dir).unwrap();

        // Create test stats
        let pool_stats = PoolMetrics {
            start_time: 1234567890,
            lastupdate: Some(1234567890),
            accepted_total: 0,
            accepted_difficulty_total: 0,
            rejected_total: 0,
            best_share: 0,
            best_share_ever: 0,
            users: HashMap::with_capacity(100),
            pool_difficulty: 500000,
        };

        // Save stats
        let save_result = save_pool_local_stats(&pool_stats, log_dir);
        assert!(save_result.is_ok());

        // Load stats
        let loaded_stats = load_pool_local_stats(log_dir);
        assert!(loaded_stats.is_ok());

        let loaded_stats = loaded_stats.unwrap();
        assert_eq!(pool_stats, loaded_stats);
    }

    #[test]
    fn test_load_nonexistent_stats() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();

        // Try to load without creating file
        let result = load_pool_local_stats(log_dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PoolMetrics::default());
    }

    #[test]
    fn test_save_to_nonexistent_directory_should_create_directory_and_proceed() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir
            .path()
            .join("nonexistent")
            .to_str()
            .unwrap()
            .to_string();

        let pool_stats = PoolMetrics {
            start_time: 1234567890,
            lastupdate: Some(1234567890),
            accepted_total: 0,
            accepted_difficulty_total: 0,
            rejected_total: 0,
            best_share: 0,
            best_share_ever: 0,
            users: HashMap::with_capacity(100),
            pool_difficulty: 500000,
        };

        // Save should fail because directory doesn't exist
        let save_result = save_pool_local_stats(&pool_stats, &log_dir);
        assert!(save_result.is_ok());
    }
}
