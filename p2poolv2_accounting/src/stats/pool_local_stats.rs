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

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

const POOL_STATS_DIR: &str = "pool";

/// Pool's local node stats, used by node operator and users to monitor their mining performance
/// The serde format conforms to the ckpool/solostats
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PoolLocalStats {
    // Runtime statistics
    pub runtime: u64,
    pub lastupdate: u64,
    #[serde(rename = "Users")]
    pub users: u32,
    #[serde(rename = "Workers")]
    pub workers: u32,
    #[serde(rename = "Idle")]
    pub idle: u32,

    // Hashrate statistics
    #[serde(rename = "Hashrate1m")]
    pub hashrate_1m: u32,
    #[serde(rename = "Hashrate5m")]
    pub hashrate_5m: u32,
    #[serde(rename = "Hashrate15m")]
    pub hashrate_15m: u32,
    #[serde(rename = "Hashrate1hr")]
    pub hashrate_1hr: u32,
    #[serde(rename = "Hashrate6hr")]
    pub hashrate_6hr: u32,
    #[serde(rename = "Hashrate1d")]
    pub hashrate_1d: u32,
    #[serde(rename = "Hashrate7d")]
    pub hashrate_7d: u32,

    // Share statistics
    #[serde(rename = "diff")]
    pub difficulty: u64,
    #[serde(rename = "accepted")]
    pub accepted_shares: u64,
    #[serde(rename = "rejected")]
    pub rejected_shares: u64,
    #[serde(rename = "bestshare")]
    pub best_share: u64,
    #[serde(rename = "SPS1m")]
    pub shares_per_second_1m: u32,
    #[serde(rename = "SPS5m")]
    pub shares_per_second_5m: u32,
    #[serde(rename = "SPS15m")]
    pub shares_per_second_15m: u32,
    #[serde(rename = "SPS1h")]
    pub shares_per_second_1h: u32,
}

/// Save pool stats to log dir
pub fn save_pool_local_stats(pool_stats: &PoolLocalStats, log_dir: &str) -> std::io::Result<()> {
    let path = Path::new(log_dir)
        .join(POOL_STATS_DIR)
        .join("pool_stats.json");
    let serialized = serde_json::to_string_pretty(pool_stats)
        .map_err(|_| std::io::Error::other("JSON serialization failed"))?;

    if !serialized.is_empty() {
        let mut file = File::create(&path)?;
        file.write_all(serialized.as_bytes())?;
    }

    Ok(())
}

/// Load pool stats from log dir
pub fn load_pool_local_stats(log_dir: &str) -> Result<PoolLocalStats, std::io::Error> {
    let path = Path::new(log_dir)
        .join(POOL_STATS_DIR)
        .join("pool_stats.json");
    let file = File::open(&path).map_err(|_| std::io::Error::other("File open failed"))?;
    let pool_stats: PoolLocalStats = serde_json::from_reader(file)
        .map_err(|_| std::io::Error::other("JSON deserialization failed"))?;
    Ok(pool_stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_pool_local_stats_save_load() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();

        // Create stats directory
        let stats_dir = Path::new(log_dir).join(POOL_STATS_DIR);
        fs::create_dir_all(&stats_dir).unwrap();

        // Create test stats
        let pool_stats = PoolLocalStats {
            runtime: 3600,
            lastupdate: 1234567890,
            users: 10,
            workers: 15,
            idle: 2,
            hashrate_1m: 1000,
            hashrate_5m: 1200,
            hashrate_15m: 1100,
            hashrate_1hr: 1050,
            hashrate_6hr: 1020,
            hashrate_1d: 980,
            hashrate_7d: 950,
            difficulty: 500000,
            accepted_shares: 120,
            rejected_shares: 5,
            best_share: 400000,
            shares_per_second_1m: 2,
            shares_per_second_5m: 2,
            shares_per_second_15m: 2,
            shares_per_second_1h: 1,
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
        assert!(result.is_err());
    }

    #[test]
    fn test_save_to_nonexistent_directory() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir
            .path()
            .join("nonexistent")
            .to_str()
            .unwrap()
            .to_string();

        let pool_stats = PoolLocalStats {
            runtime: 3600,
            lastupdate: 1234567890,
            users: 10,
            workers: 15,
            idle: 2,
            hashrate_1m: 1000,
            hashrate_5m: 1200,
            hashrate_15m: 1100,
            hashrate_1hr: 1050,
            hashrate_6hr: 1020,
            hashrate_1d: 980,
            hashrate_7d: 950,
            difficulty: 500000,
            accepted_shares: 120,
            rejected_shares: 5,
            best_share: 400000,
            shares_per_second_1m: 2,
            shares_per_second_5m: 2,
            shares_per_second_15m: 2,
            shares_per_second_1h: 1,
        };

        // Save should fail because directory doesn't exist
        let save_result = save_pool_local_stats(&pool_stats, &log_dir);
        assert!(save_result.is_err());
    }
}
