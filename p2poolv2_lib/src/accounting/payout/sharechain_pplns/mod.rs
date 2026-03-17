// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

//! Share chain PPLNS payout distribution.
//!
//! Computes payout distributions directly from the confirmed share chain,
//! applying uncle weighting: uncles receive 90% of their work, and
//! confirmed shares that reference uncles receive a 10% bonus per uncle.

pub mod payout;

pub use payout::Payout;

use super::payout_distribution::PayoutShare;

/// A share chain entry with pre-computed weighted difficulty for payout distribution.
///
/// This is ephemeral -- created during payout computation and never stored.
/// The weighted_difficulty already accounts for uncle penalties (90%) or
/// nephew bonuses (base work + 10% of each referenced uncle's work).
pub struct ShareChainPplnsShare {
    miner_address: String,
    weighted_difficulty: u64,
}

impl ShareChainPplnsShare {
    /// Create a new share chain PPLNS share with pre-computed weighted difficulty.
    pub fn new(miner_address: String, weighted_difficulty: u64) -> Self {
        Self {
            miner_address,
            weighted_difficulty,
        }
    }
}

impl PayoutShare for ShareChainPplnsShare {
    fn get_btcaddress(&self) -> Option<&str> {
        Some(&self.miner_address)
    }

    fn get_difficulty(&self) -> u64 {
        self.weighted_difficulty
    }
}
