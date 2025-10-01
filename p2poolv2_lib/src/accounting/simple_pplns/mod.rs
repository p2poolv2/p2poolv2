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

/// Stored representation of a PPLNS share - persisted to database
/// Contains only essential data to minimize storage size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPplnsShare {
    pub user_id: u64,
    pub difficulty: u64,
    pub timestamp: u64,
}

impl StoredPplnsShare {
    /// Serialize the stored pplns share and take a double sha256 hash for it
    /// The result is used to identify the share uniquely and store it in store
    pub fn hash_and_serialize(&self) -> Result<(PplnsShareBlockHash, Vec<u8>), std::io::Error> {
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&self, &mut serialized).unwrap();
        let hash = PplnsShareBlockHash(bitcoin::hashes::Hash::hash(&serialized));
        Ok((hash, serialized))
    }
}

/// In-memory representation of a PPLNS share
/// Contains additional fields (btcaddress, workername) for metrics and display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePplnsShare {
    pub user_id: u64,
    pub difficulty: u64,
    pub btcaddress: String,
    pub workername: String,
    pub timestamp: u64,
}

impl SimplePplnsShare {
    pub fn new(
        user_id: u64,
        difficulty: u64,
        btcaddress: String,
        workername: String,
        timestamp: u64,
    ) -> Self {
        SimplePplnsShare {
            user_id,
            difficulty,
            btcaddress,
            workername,
            timestamp,
        }
    }

    /// Convert to stored representation for database persistence
    pub fn to_stored(&self) -> StoredPplnsShare {
        StoredPplnsShare {
            user_id: self.user_id,
            difficulty: self.difficulty,
            timestamp: self.timestamp,
        }
    }

    /// Serialize the pplns share and take a double sha256 hash for it
    /// The result is used to identify the share uniquely and store it in store
    pub fn hash_and_serialize(&self) -> Result<(PplnsShareBlockHash, Vec<u8>), std::io::Error> {
        self.to_stored().hash_and_serialize()
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
