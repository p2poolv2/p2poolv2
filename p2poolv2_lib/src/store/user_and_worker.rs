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
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a stored user with internal ID and bitcoin address
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredUser {
    /// Internal unique ID for the user
    pub user_id: u64,
    /// Bitcoin address of the user
    pub btcaddress: String,
    /// Timestamp when the user was first stored (microseconds since epoch)
    pub created_at: u64,
}

impl StoredUser {
    /// Create a new StoredUser with current timestamp
    pub fn new(user_id: u64, btcaddress: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        Self {
            user_id,
            btcaddress,
            created_at,
        }
    }
}

/// Represents a stored worker with internal ID and worker name
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredWorker {
    /// Internal unique ID for the worker
    pub worker_id: u64,
    /// Internal user ID that this worker belongs to
    pub user_id: u64,
    /// Name of the worker
    pub workername: String,
    /// Timestamp when the worker was first stored (microseconds since epoch)
    pub created_at: u64,
}

impl StoredWorker {
    /// Create a new StoredWorker with current timestamp
    pub fn new(worker_id: u64, user_id: u64, workername: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        Self {
            worker_id,
            user_id,
            workername,
            created_at,
        }
    }
}
