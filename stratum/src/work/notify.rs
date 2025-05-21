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

use serde::{Deserialize, Serialize};

/// The mining.notify message to be built
/// MAYBE WE SHOULD USE NOTIFYPARAMS FROM messages.rs instead?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notify {
    /// The job ID
    pub job_id: String,
    /// The previous block hash
    pub prev_hash: String,
    /// The coinbase1 part of the coinbase transaction
    pub coinbase1: String,
    /// The coinbase2 part of the coinbase transaction
    pub coinbase2: String,
    /// The merkle branch for the block
    pub merkle_branch: Vec<String>,
    /// The version of the block
    pub version: String,
    /// The nbits (difficulty target) for the block
    pub nbits: String,
    /// The ntime (timestamp) for the block
    pub ntime: String,
}
