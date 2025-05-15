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

/// Manages each sessions for each miner connection.
pub struct Session {
    pub minimum_difficulty: u32,
    pub current_difficulty: u32,
}

impl Session {
    /// Creates a new session with the given minimum difficulty.
    pub fn new(minimum_difficulty: u32) -> Self {
        Self {
            minimum_difficulty,
            current_difficulty: minimum_difficulty,
        }
    }

    /// Gets the current difficulty for the session.
    pub fn get_current_difficulty(&self) -> u32 {
        self.current_difficulty
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
    }

    #[test]
    fn test_get_current_difficulty() {
        let min_difficulty = 2000;
        let session = Session::new(min_difficulty);
        
        assert_eq!(session.get_current_difficulty(), min_difficulty);
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
