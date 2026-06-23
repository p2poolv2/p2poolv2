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

#[cfg(feature = "sim")]
use crate::accounting::payout::sharechain_pplns::pplns_window::MAX_PPLNS_WINDOW_SHARES;

use crate::shares::genesis::GenesisData;
use bitcoin::CompactTarget;
use bitcoin::{BlockHash, Target};

#[cfg(feature = "sim")]
use crate::node::SwarmSend;
#[cfg(feature = "sim")]
use crate::node::messages::Message;
#[cfg(feature = "sim")]
use crate::pool_difficulty;
#[cfg(feature = "sim")]
use crate::shares::share_block::ShareBlock;
#[cfg(feature = "sim")]
use libp2p::request_response::ResponseChannel;

// ---------------------------------------------------------------------------
// OnceLock state (sim-only, does not exist in production builds)
// ---------------------------------------------------------------------------

#[cfg(feature = "sim")]
static SIM_IDEAL_BLOCK_TIME: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

#[cfg(feature = "sim")]
static SIM_ASERT_ANCHOR_TIME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

#[cfg(feature = "sim")]
static SIM_NETWORK_HASHRATE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

#[cfg(feature = "sim")]
static SIM_PROPAGATION_DELAY_MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

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

// ---------------------------------------------------------------------------
// genesis overrides
// ---------------------------------------------------------------------------

/// Set the sim genesis overrides. Called once at startup by the sim binary.
/// Does not exist in production builds.
#[cfg(feature = "sim")]
pub fn init_genesis_overrides(asert_anchor_time: u64, network_hashrate: u64) {
    SIM_ASERT_ANCHOR_TIME.set(asert_anchor_time).ok();
    SIM_NETWORK_HASHRATE.set(network_hashrate).ok();
}

/// Return the genesis timestamp.
///
/// Production: returns `genesis_data.timestamp`.
/// Sim: returns the configured ASERT anchor time, falling back to
/// `genesis_data.timestamp` if unset or zero.
#[inline(always)]
pub fn genesis_timestamp(genesis_data: &GenesisData) -> u32 {
    #[cfg(feature = "sim")]
    {
        let anchor = *SIM_ASERT_ANCHOR_TIME.get().unwrap_or(&0);
        if anchor == 0 {
            genesis_data.timestamp
        } else {
            anchor as u32
        }
    }
    #[cfg(not(feature = "sim"))]
    {
        genesis_data.timestamp
    }
}

/// Return the genesis target (bits).
///
/// Production: returns the fixed regtest maximum target.
/// Sim: computes the steady-state target for the configured network
/// hashrate so the chain starts already regulated. Falls back to the
/// fixed target if network hashrate is unset or zero.
/// Runs once at startup so `#[inline]` (not always) is sufficient.
#[inline]
pub fn anchor_target() -> CompactTarget {
    #[cfg(feature = "sim")]
    {
        let hps = *SIM_NETWORK_HASHRATE.get().unwrap_or(&0);
        if hps == 0 {
            CompactTarget::from_consensus(0x1b4188f5)
        } else {
            pool_difficulty::anchor_target_for_network_hashrate(hps as f64)
        }
    }
    #[cfg(not(feature = "sim"))]
    {
        CompactTarget::from_consensus(0x1b4188f5)
    }
}

// ---------------------------------------------------------------------------
// pplns_total_difficulty
// ---------------------------------------------------------------------------

/// Compute the PPLNS total difficulty threshold.
///
/// Production: `bitcoin_difficulty * difficulty_multiplier` -- the standard
/// formula that sizes the payout window relative to bitcoin block difficulty.
///
/// Sim: `share_pool_difficulty * MAX_PPLNS_WINDOW_SHARES` -- on regtest the
/// bitcoin difficulty is trivially 1, which collapses the window to a single
/// share. The sim formula uses the pool target difficulty scaled by the
/// maximum window size, giving a realistic multi-miner coinbase.
#[inline(always)]
pub fn pplns_total_difficulty(
    bitcoin_difficulty: u128,
    difficulty_multiplier: u128,
    share_pool_difficulty: u128,
) -> u128 {
    #[cfg(feature = "sim")]
    {
        let _ = (bitcoin_difficulty, difficulty_multiplier);
        share_pool_difficulty.saturating_mul(MAX_PPLNS_WINDOW_SHARES as u128)
    }
    #[cfg(not(feature = "sim"))]
    {
        let _ = share_pool_difficulty;
        bitcoin_difficulty.saturating_mul(difficulty_multiplier)
    }
}

// ---------------------------------------------------------------------------
// pow_meets
// ---------------------------------------------------------------------------

/// Proof-of-work gate: does `hash` meet `target`?
///
/// Production: real PoW check via `target.is_met_by(hash)`.
/// Sim: always returns `true` -- the no-PoW load test emits structurally
/// valid shares whose nonce satisfies no target. The sim feature must
/// never be enabled in a release build.
#[inline(always)]
pub fn pow_meets(target: Target, hash: BlockHash) -> bool {
    #[cfg(feature = "sim")]
    {
        let _ = (target, hash);
        true
    }
    #[cfg(not(feature = "sim"))]
    {
        target.is_met_by(hash)
    }
}

// ---------------------------------------------------------------------------
// propagation delay
// ---------------------------------------------------------------------------

/// Set the sim propagation delay base value (milliseconds).
/// Called once at startup by the sim binary. Does not exist in production builds.
#[cfg(feature = "sim")]
pub fn init_propagation_delay(ms: u64) {
    SIM_PROPAGATION_DELAY_MS.set(ms).ok();
}

/// Spawn a delayed broadcast of a share block to peers.
///
/// Computes a jittered delay from the configured base propagation delay,
/// then spawns a task that sleeps and sends. All delay/jitter complexity
/// lives here. Does not exist in production builds.
#[cfg(feature = "sim")]
pub fn spawn_delayed_broadcast(
    swarm_tx: tokio::sync::mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    share_block: ShareBlock,
) {
    let base = *SIM_PROPAGATION_DELAY_MS.get().unwrap_or(&0);
    let delay = if base == 0 {
        std::time::Duration::ZERO
    } else {
        let jitter = (base as f64 * 0.5 * (2.0 * rand::random::<f64>() - 1.0)) as i64;
        std::time::Duration::from_millis((base as i64 + jitter).max(0) as u64)
    };
    tokio::spawn(async move {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if swarm_tx
            .send(SwarmSend::BroadcastBlock(share_block))
            .await
            .is_err()
        {
            tracing::error!("Failed to broadcast share block");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_ideal_block_time_returns_production_default() {
        assert_eq!(ideal_block_time(), 10);
    }

    #[test]
    fn test_half_life_returns_production_default() {
        assert_eq!(half_life(), 600);
    }

    #[test]
    #[cfg(not(feature = "sim"))]
    fn test_pplns_total_difficulty_uses_production_formula() {
        let result = pplns_total_difficulty(1000, 2016, 500);
        assert_eq!(result, 1000 * 2016);
    }

    #[test]
    #[cfg(feature = "sim")]
    fn test_pplns_total_difficulty_uses_sim_formula() {
        let result = pplns_total_difficulty(1000, 2016, 500);
        assert_eq!(result, 500 * MAX_PPLNS_WINDOW_SHARES as u128);
    }

    #[test]
    #[cfg(not(feature = "sim"))]
    fn test_pow_meets_rejects_hash_above_target() {
        let hard_target = Target::from_compact(CompactTarget::from_consensus(0x01010000));
        let high_hash = BlockHash::from_byte_array([0xff; 32]);
        assert!(!pow_meets(hard_target, high_hash));
    }

    #[test]
    #[cfg(feature = "sim")]
    fn test_pow_meets_always_passes_in_sim() {
        let hard_target = Target::from_compact(CompactTarget::from_consensus(0x01010000));
        let high_hash = BlockHash::from_byte_array([0xff; 32]);
        assert!(pow_meets(hard_target, high_hash));
    }

    #[test]
    fn test_pow_meets_accepts_hash_below_target() {
        use bitcoin::hashes::Hash;
        let easy_target = Target::MAX;
        let hash = BlockHash::all_zeros();
        assert!(pow_meets(easy_target, hash));
    }
}
