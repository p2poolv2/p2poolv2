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

use crate::stratum::difficulty_adjuster::DifficultyAdjusterTrait;
use bitcoin::secp256k1::rand::{self, Rng};
use std::time::Instant;

/// Use 4 byte extranonce1
pub const EXTRANONCE1_SIZE: usize = 4;
/// Use 8 byte extranonce2
pub const EXTRANONCE2_SIZE: usize = 8;

/// Manages each sessions for each miner connection.
///
/// Stores the session ID, extranonce1, and other session-related data.
pub struct Session<D: DifficultyAdjusterTrait> {
    /// Unique session ID
    pub id: String,
    /// extranonce1 in le. Sent to the miner, computed from the session ID
    pub enonce1: u32,
    /// Extranonce1 in le, as a hex string. Sent to miner.
    pub enonce1_hex: String,
    /// Did the mine subscribe already?
    pub subscribed: bool,
    /// Optional username of the miner, supplied by the miner, we just store it in session
    pub username: Option<String>,
    /// bitcoin address used as user identifier
    pub btcaddress: Option<String>,
    /// Worker name for the mining device
    pub workername: Option<String>,
    /// Optional password of the miner, supplied by the miner, we just store it in session
    pub password: Option<String>,
    /// User ID from the store
    pub user_id: Option<u64>,
    /// Worker ID from the store
    pub worker_id: Option<u64>,
    /// Difficulty adjuster for the session
    pub difficulty_adjuster: D,
    /// version_mask used in this session, defaults to one provided from config
    pub version_mask: i32,
    /// Difficulty suggested by the client
    pub suggested_difficulty: Option<u64>,
    /// Instant when the session was created
    pub connected_at: Instant,
    /// Instant when the last valid share was submitted
    pub last_share_time: Option<Instant>,
}

impl<D: DifficultyAdjusterTrait> Session<D> {
    /// Creates a new session with the given minimum difficulty.
    pub fn new(
        start_difficulty: u64,
        minimum_difficulty: u64,
        maximum_difficulty: Option<u64>,
        version_mask: i32,
    ) -> Self {
        let id = Session::<D>::generate_id();
        let enonce1 = id.to_le();
        let now = Instant::now();
        Self {
            id: hex::encode(id.to_be_bytes()),
            enonce1,
            enonce1_hex: hex::encode(enonce1.to_le_bytes()),
            subscribed: false,
            username: None,
            workername: None,
            btcaddress: None,
            password: None,
            user_id: None,
            worker_id: None,
            difficulty_adjuster: D::new(start_difficulty, minimum_difficulty, maximum_difficulty),
            version_mask,
            suggested_difficulty: None,
            connected_at: now,
            last_share_time: None,
        }
    }

    /// Generates a random session ID.
    fn generate_id() -> u32 {
        let mut rng = rand::thread_rng();
        rng.r#gen::<u32>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;

    #[test]
    fn test_new_session() {
        let min_difficulty = 1000;
        let start_difficulty = 100;
        let session = Session::<DifficultyAdjuster>::new(
            start_difficulty,
            min_difficulty,
            Some(2000),
            0x1fffe000,
        );

        assert_eq!(
            session.difficulty_adjuster.pool_minimum_difficulty,
            min_difficulty
        );
        assert_eq!(
            session.difficulty_adjuster.current_difficulty,
            start_difficulty
        );
        assert_ne!(session.id, "");

        // Verify that id and enonce1_hex are reverse encodings of each other
        let id_bytes = hex::decode(&session.id).unwrap();
        let enonce1_hex_bytes = hex::decode(&session.enonce1_hex).unwrap();
        assert_eq!(
            id_bytes,
            enonce1_hex_bytes.iter().rev().cloned().collect::<Vec<_>>()
        );

        // session.id is BE encoded
        assert_eq!(
            session.enonce1,
            u32::from_be_bytes(
                hex::decode(session.id)
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap()
            )
        );

        // session.enonce1 is LE encoded
        assert_eq!(
            session.enonce1,
            u32::from_le_bytes(
                hex::decode(&session.enonce1_hex)
                    .unwrap()
                    .try_into()
                    .unwrap()
            )
        );
        assert!(!session.subscribed);
    }

    #[test]
    fn test_get_current_difficulty() {
        let session = Session::<DifficultyAdjuster>::new(100, 2000, Some(3000), 0x1fffe000);

        assert_eq!(session.difficulty_adjuster.current_difficulty, 100);
    }
}
