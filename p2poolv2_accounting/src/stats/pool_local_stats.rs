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

use crate::stats::metrics::MetricsHandle;
use crate::stats::metrics::PoolMetrics;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;
use tracing::error;

const POOL_STATS_DIR: &str = "pool";

/// Save pool stats to log dir
/// Use fs::rename to ensure atomic write
pub fn save_pool_local_stats(pool_metrics: &PoolMetrics, log_dir: &str) -> std::io::Result<()> {
    let stats_dir = Path::new(log_dir).join(POOL_STATS_DIR);
    if let Err(e) = create_dir_all(&stats_dir) {
        error!("Error creating directory {e}");
        return Err(std::io::Error::other("Error creating directory"));
    }
    let path = stats_dir.join("pool_stats.json");
    let tmp_path = stats_dir.join("pool_stats.json.tmp");

    let serialized = serde_json::to_string_pretty(pool_metrics)
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
    use crate::stats::computed::{ComputedHashrate, ComputedShareRate};
    use std::collections::HashMap;
    use std::fs;
    use tempfile::tempdir;

    #[test_log::test]
    fn test_pool_local_stats_save_load() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();
        println!("Temporary log directory: {}", log_dir);

        // Create stats directory
        let stats_dir = Path::new(log_dir).join(POOL_STATS_DIR);
        fs::create_dir_all(&stats_dir).unwrap();

        // Create test stats
        let pool_stats = PoolMetrics {
            start_time: 1234567890,
            lastupdate: Some(1234567890),
            num_users: 10,
            num_workers: 15,
            num_idle_users: 2,
            unaccounted_shares: 0,
            unaccounted_difficulty: 0,
            unaccounted_rejected: 0,
            accepted: 0,
            rejected: 0,
            bestshare: 0,
            users: HashMap::with_capacity(100),
            difficulty: 500000,
            computed_hashrate: ComputedHashrate {
                hashrate_1m: 1000,
                hashrate_5m: 1200,
                hashrate_15m: 1100,
                hashrate_1hr: 1050,
                hashrate_6hr: 1020,
                hashrate_1d: 980,
                hashrate_7d: 950,
            },
            computed_share_rate: ComputedShareRate::default(),
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
            num_users: 10,
            num_workers: 15,
            num_idle_users: 2,
            unaccounted_shares: 0,
            unaccounted_difficulty: 0,
            unaccounted_rejected: 0,
            accepted: 0,
            rejected: 0,
            bestshare: 0,
            users: HashMap::with_capacity(100),
            difficulty: 500000,
            computed_hashrate: ComputedHashrate {
                hashrate_1m: 1000,
                hashrate_5m: 1200,
                hashrate_15m: 1100,
                hashrate_1hr: 1050,
                hashrate_6hr: 1020,
                hashrate_1d: 980,
                hashrate_7d: 950,
            },
            computed_share_rate: ComputedShareRate::default(),
        };

        // Save should fail because directory doesn't exist
        let save_result = save_pool_local_stats(&pool_stats, &log_dir);
        assert!(save_result.is_ok());
    }
}
