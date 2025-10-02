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

pub mod payout;

/// PPLNS share representation
/// btcaddress and workername are skipped during serialization to minimize storage
/// They are restored from user_id when loading from database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePplnsShare {
    pub user_id: u64,
    pub difficulty: u64,
    #[serde(skip)]
    pub btcaddress: Option<String>,
    #[serde(skip)]
    pub workername: Option<String>,
    pub n_time: u64,
    pub job_id: String,
    pub extranonce2: String,
    pub nonce: String,
}

impl SimplePplnsShare {
    pub fn new(
        user_id: u64,
        difficulty: u64,
        btcaddress: String,
        workername: String,
        n_time: u64,
        job_id: String,
        extranonce2: String,
        nonce: String,
    ) -> Self {
        SimplePplnsShare {
            user_id,
            difficulty,
            btcaddress: Some(btcaddress),
            workername: Some(workername),
            n_time,
            job_id,
            extranonce2,
            nonce,
        }
    }

    /// Makes key for share
    ///
    /// Three 8 bytes key components: n_time, user_id, and sequence
    pub fn make_key(n_time: u64, user_id: u64, seq: u64) -> Vec<u8> {
        let mut key = Vec::<u8>::with_capacity(24);
        key.extend_from_slice(&n_time.to_be_bytes());
        key.extend_from_slice(&user_id.to_be_bytes());
        key.extend_from_slice(&seq.to_be_bytes());
        key
    }

    /// Parse key made by make_key
    ///
    /// Three 8 byte components, n_time, user_id and sequence
    /// Returns n_time and user_id
    pub fn parse_key(key: &[u8]) -> (u64, u64) {
        let n_time = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let user_id = u64::from_be_bytes(key[8..16].try_into().unwrap());
        (n_time, user_id)
    }
}
