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

//! No-PoW load-test simulation.
//!
//! This module is compiled only under the `sim` cargo feature and MUST NEVER be
//! enabled in a release build. It provides the synthetic share emitter and
//! supporting utilities for load-testing the share chain, P2P, and payout
//! machinery without proof-of-work.
//!
//! Compile-time behavioral overrides (pow_meets, ideal_block_time, etc.) live
//! in `crate::sim_overrides`, not here.
//!
//! See `docs/simulation/load-test-plan.md` for the full design.

pub mod blockfind;
pub mod emitter;
pub mod share;
pub mod timing;
