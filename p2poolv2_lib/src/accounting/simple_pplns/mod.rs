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

use bitcoin::BlockHash;
use ciborium;
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

    /// Serialize the pplns share and take a double sha256 hash for it
    /// The result is used to identify the share uniquely and store it in store
    /// Note: btcaddress and workername are skipped during serialization (serde(skip))
    pub fn hash_and_serialize(&self) -> Result<(PplnsShareBlockHash, Vec<u8>), std::io::Error> {
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&self, &mut serialized).unwrap();
        let hash = PplnsShareBlockHash(bitcoin::hashes::Hash::hash(&serialized));
        Ok((hash, serialized))
    }
}

/// Type alias for bitcoin block hash, so we can depend on types to catch potential errors
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Hash, Copy)]
pub struct PplnsShareBlockHash(BlockHash);

impl From<&str> for PplnsShareBlockHash {
    fn from(s: &str) -> PplnsShareBlockHash {
        PplnsShareBlockHash(s.parse().expect("Invalid pplns share block hash string"))
    }
}

impl std::fmt::Display for PplnsShareBlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<PplnsShareBlockHash> for &str {
    fn eq(&self, other: &PplnsShareBlockHash) -> bool {
        self.parse::<BlockHash>().unwrap() == other.0
    }
}

impl PartialEq<&str> for PplnsShareBlockHash {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.parse().unwrap()
    }
}

impl PartialEq<PplnsShareBlockHash> for &PplnsShareBlockHash {
    fn eq(&self, other: &PplnsShareBlockHash) -> bool {
        self.0 == other.0
    }
}

impl Eq for PplnsShareBlockHash {}

impl AsRef<[u8]> for PplnsShareBlockHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
