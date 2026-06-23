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

//! Compile-time bridge for sim vs production behavior.
//!
//! Every function in this module has two implementations selected by
//! `cfg(feature = "sim")`. In production builds the functions inline to
//! constants or no-ops -- identical codegen to hard-coded values.
//!
//! Sim-specific state is held in OnceLocks behind cfg and initialized
//! once at startup by the sim binary via `init_*()` functions. These
//! init functions do not exist in production builds.

/// Production ideal block time constant (seconds).
const IDEAL_BLOCK_TIME: u32 = 10;

/// Production ASERT half-life constant (seconds).
const HALFLIFE: u32 = 600;

// ---------------------------------------------------------------------------
// ideal_block_time / half_life
// ---------------------------------------------------------------------------

#[cfg(feature = "sim")]
static SIM_IDEAL_BLOCK_TIME: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Set the sim ideal block time. Called once at startup by the sim binary.
/// Does not exist in production builds.
#[cfg(feature = "sim")]
pub fn init_ideal_block_time(secs: u32) {
    SIM_IDEAL_BLOCK_TIME.set(secs).ok();
}

/// Effective ideal block time for the share chain.
///
/// Production: returns the constant 10.
/// Sim: returns the value set by `init_ideal_block_time`, falling back
/// to the production constant if unset.
#[inline(always)]
pub fn ideal_block_time() -> u32 {
    #[cfg(feature = "sim")]
    {
        *SIM_IDEAL_BLOCK_TIME.get().unwrap_or(&IDEAL_BLOCK_TIME)
    }
    #[cfg(not(feature = "sim"))]
    {
        IDEAL_BLOCK_TIME
    }
}

/// Effective ASERT half-life.
///
/// Production: returns the constant 600.
/// Sim: scales proportionally with `ideal_block_time` so that the ratio
/// HALFLIFE / IDEAL_BLOCK_TIME stays constant -- ASERT per-block dynamics
/// are identical under time compression.
#[inline(always)]
pub fn half_life() -> u32 {
    #[cfg(feature = "sim")]
    {
        (HALFLIFE as u64 * ideal_block_time() as u64 / IDEAL_BLOCK_TIME as u64) as u32
    }
    #[cfg(not(feature = "sim"))]
    {
        HALFLIFE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ideal_block_time_returns_production_default() {
        assert_eq!(ideal_block_time(), 10);
    }

    #[test]
    fn test_half_life_returns_production_default() {
        assert_eq!(half_life(), 600);
    }
}
