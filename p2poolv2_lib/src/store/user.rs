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
