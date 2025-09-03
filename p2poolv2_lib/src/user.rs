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

use bitcoin::hashes::{sha256, Hash};

/// User record, captures username, id, and hashrate stats
struct User {
    /// Unique identifier for the user, a hash of the user's username
    id: [u8; 32],
    /// Bitcoin address
    btcaddress: String,
    /// Timestamp of the last share submitted by the user, time since epoch in ms
    last_share_at: u64,
    /// Difficulty share per second 1min window
    difficulty_share_per_second_1min: f64,
    /// Difficulty share per second 5min window
    difficulty_share_per_second_5min: f64,
    /// Difficulty share per second 1h window
    difficulty_share_per_second_1h: f64,
    /// Difficulty share per second 24h window
    difficulty_share_per_second_24h: f64,
    /// Difficulty share per second 7d window
    difficulty_share_per_second_7d: f64,
}

impl User {
    /// Create a new user record for a new signing up user.
    /// To fetch an existing user see load_or_create
    pub fn new(btcaddress: String) -> Self {
        let hash: [u8; 32] = sha256::Hash::hash(btcaddress.as_bytes()).to_byte_array();
        User {
            id: hash,
            btcaddress,
            last_share_at: 0,
            difficulty_share_per_second_1min: 0.0,
            difficulty_share_per_second_5min: 0.0,
            difficulty_share_per_second_1h: 0.0,
            difficulty_share_per_second_24h: 0.0,
            difficulty_share_per_second_7d: 0.0,
        }
    }

    /// Load an existing user from store or create a new one if none found
    pub fn load_or_create(btcaddress: String) -> Self {
        let hash: [u8; 32] = sha256::Hash::hash(btcaddress.as_bytes()).to_byte_array();
        User {
            id: hash,
            btcaddress,
            last_share_at: 0,
            difficulty_share_per_second_1min: 0.0,
            difficulty_share_per_second_5min: 0.0,
            difficulty_share_per_second_1h: 0.0,
            difficulty_share_per_second_24h: 0.0,
            difficulty_share_per_second_7d: 0.0,
        }
    }
}
