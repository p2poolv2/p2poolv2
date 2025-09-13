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

use crate::stats::user::User;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const USER_STATS_DIR: &str = "user_stats";

/// Save user stats to log dir
pub fn save_user_stats(btcaddress: &str, user: &User, log_dir: String) -> std::io::Result<()> {
    let path = Path::new(&log_dir)
        .join(USER_STATS_DIR)
        .join(format!("{btcaddress}.json"));
    let serialized = serde_json::to_string_pretty(user)
        .map_err(|_| std::io::Error::other("JSON serialization failed"))?;

    if !serialized.is_empty() {
        let mut file = File::create(&path)?;
        file.write_all(serialized.as_bytes())?;
    }

    Ok(())
}

/// Load user stats from log dir
pub fn load_user_stats(btcaddress: &str, log_dir: &str) -> std::io::Result<User> {
    let path = Path::new(log_dir)
        .join(USER_STATS_DIR)
        .join(format!("{btcaddress}.json"));
    let file = File::open(&path).map_err(|_| std::io::Error::other("File open failed"))?;
    let user_stats: User = serde_json::from_reader(file)
        .map_err(|_| std::io::Error::other("JSON deserialization failed"))?;
    Ok(user_stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_save_and_load_user_stats() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();

        // Create the user_stats directory
        let stats_dir = Path::new(log_dir).join(USER_STATS_DIR);
        fs::create_dir_all(&stats_dir).unwrap();

        // Create a test user
        let mut user = User::default();
        user.shares_valid = 10;

        // Save the user stats
        save_user_stats("test_address", &user, log_dir.to_string()).unwrap();

        // Load the user stats
        let loaded_user = load_user_stats("test_address", log_dir).unwrap();

        // Verify that the loaded user matches the original
        assert_eq!(loaded_user.shares_valid, user.shares_valid);
    }

    #[test]
    fn test_load_nonexistent_user_stats() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_str().unwrap();

        // Create the user_stats directory
        let stats_dir = Path::new(log_dir).join(USER_STATS_DIR);
        fs::create_dir_all(&stats_dir).unwrap();

        // Try to load stats for a user that doesn't exist
        let result = load_user_stats("nonexistent_address", log_dir);

        // Verify that the operation failed
        assert!(result.is_err());
    }
}
