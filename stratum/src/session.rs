// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use crate::difficulty_adjuster::DifficultyAdjuster;
use bitcoin::secp256k1::rand::{self, Rng};

/// Use 4 byte extranonce1
pub const EXTRANONCE1_SIZE: usize = 4;
/// Use 8 byte extranonce2
pub const EXTRANONCE2_SIZE: usize = 8;

/// Manages each sessions for each miner connection.
///
/// Stores the session ID, extranonce1, and other session-related data.
pub struct Session {
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
    /// Optional password of the miner, supplied by the miner, we just store it in session
    pub password: Option<String>,
    /// The minimum difficulty for the session
    pub minimum_difficulty: u32,
    /// The current difficulty for the session
    pub current_difficulty: u32,
    /// Difficulty adjuster for the session
    pub difficulty_adjuster: DifficultyAdjuster,
}

impl Session {
    /// Creates a new session with the given minimum difficulty.
    pub fn new(minimum_difficulty: u32) -> Self {
        let id = Session::generate_id();
        let enonce1 = id.to_le();
        Self {
            id: hex::encode(id.to_be_bytes()),
            enonce1,
            enonce1_hex: hex::encode(enonce1.to_le_bytes()),
            subscribed: false,
            username: None,
            password: None,
            minimum_difficulty,
            current_difficulty: minimum_difficulty,
            difficulty_adjuster: DifficultyAdjuster::new(minimum_difficulty, 100_000, 200_000),
        }
    }

    /// Generates a random session ID.
    fn generate_id() -> u32 {
        let mut rng = rand::thread_rng();
        rng.gen::<u32>()
    }

    /// Recalculate current difficulty, return the new difficulty.
    /// TODO(pool2win): Implement the actual difficulty adjustment algorithm.
    pub fn recalculate_difficulty(&mut self) -> u32 {
        self.current_difficulty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session() {
        let min_difficulty = 1000;
        let session = Session::new(min_difficulty);

        assert_eq!(session.minimum_difficulty, min_difficulty);
        assert_eq!(session.current_difficulty, min_difficulty);
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
        let min_difficulty = 2000;
        let session = Session::new(min_difficulty);

        assert_eq!(session.current_difficulty, min_difficulty);
    }

    #[test]
    fn test_recalculate_difficulty() {
        let min_difficulty = 3000;
        let mut session = Session::new(min_difficulty);

        // Currently it just returns the current difficulty
        let new_difficulty = session.recalculate_difficulty();
        assert_eq!(new_difficulty, min_difficulty);
        assert_eq!(session.current_difficulty, min_difficulty);
    }
}
