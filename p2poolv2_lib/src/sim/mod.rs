// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
