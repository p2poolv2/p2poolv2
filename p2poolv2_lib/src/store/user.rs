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

use super::stored_user::StoredUser;
use super::{ColumnFamily, Store};
use crate::utils::snowflake_simplified::get_next_id;
use bitcoin::consensus::{Encodable, encode};
use std::error::Error;

impl Store {
    /// Store a user by btcaddress, returns the user ID
    pub fn add_user(&self, btcaddress: String) -> Result<u64, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        // Check if user already exists via index
        if let Some(existing_id_bytes) = self.db.get_cf(&user_index_cf, &btcaddress)? {
            let user_id = u64::from_be_bytes(
                existing_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid user ID format in index")?,
            );
            return Ok(user_id);
        }

        // Generate new user ID
        let user_id = get_next_id();
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create stored user
        let stored_user = StoredUser {
            user_id,
            btcaddress: btcaddress.clone(),
            created_at: current_timestamp,
        };

        // Create write batch for atomic operation
        let mut batch = Self::get_write_batch();

        // Store user data (key: user_id, value: serialized StoredUser)
        let mut serialized_user = Vec::new();
        stored_user.consensus_encode(&mut serialized_user)?;
        batch.put_cf(&user_cf, user_id.to_be_bytes(), serialized_user);

        // Store index mapping (key: btcaddress, value: user_id)
        batch.put_cf(&user_index_cf, btcaddress, user_id.to_be_bytes());

        // Write batch atomically
        self.db.write(batch)?;

        Ok(user_id)
    }

    /// Get user by user ID
    pub fn get_user_by_id(
        &self,
        user_id: u64,
    ) -> Result<Option<StoredUser>, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();

        if let Some(serialized_user) = self.db.get_cf(&user_cf, user_id.to_be_bytes())? {
            if let Ok(stored_user) = encode::deserialize(&serialized_user) {
                Ok(Some(stored_user))
            } else {
                tracing::warn!("Error deserializing stored user. Database corrupted?");
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get user by btcaddress
    pub fn get_user_by_btcaddress(
        &self,
        btcaddress: &str,
    ) -> Result<Option<StoredUser>, Box<dyn Error + Send + Sync>> {
        let user_index_cf = self.db.cf_handle(&ColumnFamily::UserIndex).unwrap();

        if let Some(user_id_bytes) = self.db.get_cf(&user_index_cf, btcaddress)? {
            let user_id = u64::from_be_bytes(
                user_id_bytes
                    .try_into()
                    .map_err(|_| "Invalid user ID format in index")?,
            );
            self.get_user_by_id(user_id)
        } else {
            Ok(None)
        }
    }

    /// Get bitcoin addresses for multiple user IDs
    /// Returns a vector of tuples (user_id, btcaddress) for users that exist
    /// Accepts any iterable of user IDs for flexibility (HashSet, Vec, slice, etc.)
    /// Uses RocksDB multi_get_cf for efficient batch querying
    pub fn get_btcaddresses_for_user_ids(
        &self,
        user_ids: &[u64],
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        let user_cf = self.db.cf_handle(&ColumnFamily::User).unwrap();

        // Build keys for multi_get_cf: (column_family, key_bytes)
        let keys: Vec<_> = user_ids
            .iter()
            .map(|user_id| (&user_cf, user_id.to_be_bytes()))
            .collect();

        // Batch fetch all users in a single multi_get_cf call
        let users = self.db.multi_get_cf(keys);

        // Zip user_ids with results, filter successful ones, and extract btcaddresses
        let results: Vec<(u64, String)> = user_ids
            .iter()
            .zip(users)
            .filter_map(|(user_id, result)| {
                if let Ok(Some(serialized_user)) = result {
                    if let Ok(stored_user) = encode::deserialize::<StoredUser>(&serialized_user) {
                        Some((*user_id, stored_user.btcaddress))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_and_get_user() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();

        // Store a new user
        let user_id = store.add_user(btcaddress.clone()).unwrap();

        // Get user by ID
        let stored_user = store.get_user_by_id(user_id).unwrap().unwrap();
        assert_eq!(stored_user.user_id, user_id);
        assert_eq!(stored_user.btcaddress, btcaddress);
        assert!(stored_user.created_at > 0);

        // Get user by btcaddress
        let user_by_address = store.get_user_by_btcaddress(&btcaddress).unwrap().unwrap();
        assert_eq!(user_by_address.user_id, user_id);
        assert_eq!(user_by_address.btcaddress, btcaddress);

        // Store same user again - should return same ID
        let same_user_id = store.add_user(btcaddress.clone()).unwrap();
        assert_eq!(same_user_id, user_id);

        // Store different user - should get new ID
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let _user_id2 = store.add_user(btcaddress2.clone()).unwrap();

        // Verify both users exist
        let user1 = store.get_user_by_btcaddress(&btcaddress).unwrap().unwrap();
        let user2 = store.get_user_by_btcaddress(&btcaddress2).unwrap().unwrap();
        assert_ne!(user1.user_id, user2.user_id);
    }

    #[test]
    fn test_get_nonexistent_user() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Test getting non-existent user by ID
        let user = store.get_user_by_id(999).unwrap();
        assert!(user.is_none());

        // Test getting non-existent user by btcaddress
        let user = store.get_user_by_btcaddress("nonexistent_address").unwrap();
        assert!(user.is_none());
    }

    #[test]
    fn test_user_serialization() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let btcaddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();

        // Store user
        let user_id = store.add_user(btcaddress.clone()).unwrap();

        // Retrieve and verify data integrity
        let stored_user = store.get_user_by_id(user_id).unwrap().unwrap();

        // Verify all fields are correctly serialized/deserialized
        assert_eq!(stored_user.user_id, user_id);
        assert_eq!(stored_user.btcaddress, btcaddress);
        assert!(stored_user.created_at > 0);

        // Verify timestamps are reasonable (within last minute)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(stored_user.created_at <= now);
        assert!(stored_user.created_at > now - 60);
    }

    #[test]
    fn test_get_btcaddresses_for_user_ids() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Store multiple users
        let btcaddress1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let btcaddress2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string();
        let btcaddress3 = "1QGTJkBFhCjPHqbnwK6z7JfEHefq6Yj2jJ".to_string();

        let user_id1 = store.add_user(btcaddress1.clone()).unwrap();
        let user_id2 = store.add_user(btcaddress2.clone()).unwrap();
        let user_id3 = store.add_user(btcaddress3.clone()).unwrap();

        // Test getting btcaddresses for existing user IDs
        let user_ids = &[user_id1, user_id2, user_id3];
        let results = store.get_btcaddresses_for_user_ids(user_ids).unwrap();

        assert_eq!(results.len(), 3);

        // Convert to HashMap for easier lookup
        let result_map: std::collections::HashMap<u64, String> = results.into_iter().collect();

        assert_eq!(result_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(result_map.get(&user_id2), Some(&btcaddress2));
        assert_eq!(result_map.get(&user_id3), Some(&btcaddress3));

        // Test with subset of user IDs
        let subset_ids = &[user_id1, user_id3];
        let subset_results = store.get_btcaddresses_for_user_ids(subset_ids).unwrap();

        assert_eq!(subset_results.len(), 2);
        let subset_map: std::collections::HashMap<u64, String> =
            subset_results.into_iter().collect();

        assert_eq!(subset_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(subset_map.get(&user_id3), Some(&btcaddress3));
        assert!(!subset_map.contains_key(&user_id2));

        // Test with non-existent user IDs
        let nonexistent_ids = &[9999, 8888];
        let empty_results = store
            .get_btcaddresses_for_user_ids(nonexistent_ids)
            .unwrap();

        assert_eq!(empty_results.len(), 0);

        // Test with mixed existing and non-existent IDs
        let mixed_ids = &[user_id1, 9999, user_id2];
        let mixed_results = store.get_btcaddresses_for_user_ids(mixed_ids).unwrap();

        assert_eq!(mixed_results.len(), 2);
        let mixed_map: std::collections::HashMap<u64, String> = mixed_results.into_iter().collect();

        assert_eq!(mixed_map.get(&user_id1), Some(&btcaddress1));
        assert_eq!(mixed_map.get(&user_id2), Some(&btcaddress2));
        assert!(!mixed_map.contains_key(&9999));
    }
}
