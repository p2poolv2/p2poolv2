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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{CompactTarget, Target};
use std::error::Error;
use std::fmt;

uint::construct_uint! {
    /// 512-bit unsigned integer used as an intermediate type for ASERT target
    /// arithmetic. Using 512 bits avoids overflow when multiplying a 256-bit
    /// anchor target by the polynomial factor and applying bit shifts.
    struct U512(8);
}

/// Ideal block time for the share chain in seconds (target: one share every 10 seconds)
const IDEAL_BLOCK_TIME: u32 = 10;

/// Half life for the ASERT algorithm in seconds.
/// Set to 60 times the ideal block time (60 * 10 = 600 seconds = 10 minutes).
/// Difficulty halves (or doubles) when blocks are consistently twice as fast
/// (or slow) as expected over this period.
const HALFLIFE: u32 = 600;

/// Maximum (easiest) target as a consensus u32. This is the regtest maximum and
/// serves as the ceiling for the share chain target. Stored as u32 because
/// `CompactTarget::from_consensus` is not a const fn.
const MAX_TARGET_CONSENSUS: u32 = 0x207fffff;

/// Fixed-point radix for the ASERT exponent representation (2^16)
const RADIX: i64 = 65536;

/// Convert a `Target` to a `U512` via its little-endian byte representation.
fn target_to_u512(target: Target) -> U512 {
    let bytes = target.to_le_bytes();
    let mut padded = [0u8; 64];
    padded[..32].copy_from_slice(&bytes);
    U512::from_little_endian(&padded)
}

/// Convert a `U512` value back to a `Target`, assuming it fits in 256 bits.
/// The caller must ensure the value has been clamped to the 256-bit range.
fn u512_to_target(value: U512) -> Target {
    let mut bytes = [0u8; 64];
    value.to_little_endian(&mut bytes);
    Target::from_le_bytes(bytes[..32].try_into().expect("slice is 32 bytes"))
}

// ---------------------------------------------------------------------------
// ASERT core algorithm
// ---------------------------------------------------------------------------

/// Calculate the next target using the ASERT (aserti3-2d, as
/// aserti3-10m) algorithm. We use 10m halflife instead of 2 day.
///
/// This is a pure function implementing the integer-only BCH ASERT specification.
/// All arithmetic uses fixed-point integers with no floating point.
///
/// The formula computes:
///   next_target = anchor_target * 2^((time_delta - ideal_block_time * (height_delta + 1)) / halflife)
///
/// using a cubic polynomial approximation for the fractional exponent part.
///
/// Parameters:
///   - `anchor_target`: the compact target of the anchor block
///   - `time_delta`: seconds elapsed from anchor parent time to current block parent time
///   - `height_delta`: block height difference from anchor to current block
///   - `halflife`: ASERT halflife parameter in seconds
///   - `ideal_block_time`: target time between blocks in seconds
///
/// Returns the computed compact target for the next block.
pub(crate) fn asert_calculate_target(
    anchor_target: CompactTarget,
    time_delta: i64,
    height_delta: i64,
    halflife: u32,
    ideal_block_time: u32,
) -> CompactTarget {
    let max_target = target_to_u512(Target::from_compact(CompactTarget::from_consensus(
        MAX_TARGET_CONSENSUS,
    )));

    // Step 1: Compute exponent in 16.16 fixed-point format.
    // Use i128 to prevent overflow on the numerator multiplication.
    let ideal_spacing = ideal_block_time as i128;
    let exponent_numerator: i128 =
        (time_delta as i128 - ideal_spacing * (height_delta as i128 + 1)) * RADIX as i128;
    let exponent: i64 = (exponent_numerator / halflife as i128) as i64;

    // Step 2: Decompose into integer shifts and fractional remainder.
    // Rust's >> on i64 is arithmetic (sign-extending), matching the spec requirement.
    let num_shifts: i32 = (exponent >> 16) as i32;
    let remainder: i64 = exponent - (num_shifts as i64) * RADIX;
    // remainder is guaranteed to be in [0, 65535] by the arithmetic right shift property.

    // Step 3: Cubic polynomial approximation of 2^(remainder/65536) in fixed-point.
    // Coefficients from the BCH specification.
    let remainder_wide = remainder as i128;
    let remainder_squared = remainder_wide * remainder_wide;
    let remainder_cubed = remainder_squared * remainder_wide;

    let polynomial: i128 = 195_766_423_245_049_i128 * remainder_wide
        + 971_821_376_i128 * remainder_squared
        + 5_127_i128 * remainder_cubed
        + (1_i128 << 47);

    let factor: u64 = ((polynomial >> 48) + RADIX as i128) as u64;

    // Step 4: Convert anchor target to U512 and multiply by factor.
    // Using U512 avoids overflow even for the maximum 256-bit target.
    let anchor_wide = target_to_u512(Target::from_compact(anchor_target));
    let mut next_target = anchor_wide * U512::from(factor);

    // Step 5: Apply integer shifts.
    // Guard against U512 overflow: anchor (~256 bits) * factor (~17 bits)
    // = ~273 bits. A left shift >= 239 would exceed 512 bits and wrap to
    // zero, bypassing the max_target clamp below. Any such shift guarantees
    // the result exceeds max_target, so clamp directly.
    const MAX_LEFT_SHIFT: i32 = 238;
    if num_shifts >= 0 {
        if num_shifts > MAX_LEFT_SHIFT {
            return CompactTarget::from_consensus(MAX_TARGET_CONSENSUS);
        }
        next_target <<= num_shifts as usize;
    } else {
        next_target >>= (-num_shifts) as usize;
    }

    // Step 6: Remove fixed-point scaling (divide by 2^16).
    next_target >>= 16;

    // Step 7: Clamp to maximum target.
    if next_target > max_target {
        next_target = max_target;
    }

    // Step 7b: Ensure target is not zero (minimum target of 1).
    if next_target.is_zero() {
        next_target = U512::one();
    }

    // Step 8: Convert back to CompactTarget via Target round-trip.
    let result_target = u512_to_target(next_target);
    result_target.to_compact_lossy()
}

// ---------------------------------------------------------------------------
// PoolDifficulty -- public API
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum PoolDifficultyError {
    /// Failed to update difficulty due to an internal error
    UpdateError(String),
    /// Anchor block data is not available
    AnchorNotFound(String),
}

impl fmt::Display for PoolDifficultyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolDifficultyError::UpdateError(message) => {
                write!(formatter, "Pool difficulty update error: {message}")
            }
            PoolDifficultyError::AnchorNotFound(message) => {
                write!(formatter, "Anchor block not found: {message}")
            }
        }
    }
}

impl Error for PoolDifficultyError {}

/// Pool difficulty tracker using the ASERT (aserti3-2d renamed as
/// aserti3-10m) algorithm. Our halflife is 10m instead of 2 days.
///
/// Stores the anchor block parameters needed to compute the difficulty
/// for any given height and timestamp. The ASERT algorithm is absolute
/// (not iterative), meaning it only needs the anchor point and the current
/// block's parameters to compute the next target.
pub struct PoolDifficulty {
    /// The anchor block's compact target (difficulty at the anchor point)
    anchor_target: CompactTarget,
    /// The timestamp of the anchor block's parent (or the anchor itself for genesis)
    anchor_parent_time: u32,
    /// The height of the anchor block
    anchor_height: u32,
}

impl PoolDifficulty {
    /// Create a new PoolDifficulty anchored at the given block.
    ///
    /// For a new chain, the anchor is the genesis block. Use the genesis block's
    /// own timestamp as `anchor_parent_time` since genesis has no parent.
    pub fn new(anchor_target: CompactTarget, anchor_parent_time: u32, anchor_height: u32) -> Self {
        Self {
            anchor_target,
            anchor_parent_time,
            anchor_height,
        }
    }

    /// Build a PoolDifficulty anchored at the genesis block from the chain store.
    ///
    /// Reads the genesis header to obtain the anchor target and timestamp.
    /// The anchor height is always 0 since the anchor is genesis.
    pub fn build(chain_store_handle: &ChainStoreHandle) -> Result<Self, PoolDifficultyError> {
        let genesis_header = chain_store_handle
            .get_genesis_header()
            .map_err(|error| PoolDifficultyError::AnchorNotFound(error.to_string()))?;
        Ok(Self {
            anchor_target: genesis_header.bits,
            anchor_parent_time: genesis_header.time,
            anchor_height: 0,
        })
    }

    /// Calculate the required target for a block at the given height and time.
    ///
    /// This is a pure computation from the anchor point.
    ///
    /// Parameters:
    ///   - `block_parent_time`: the timestamp of the current block's parent
    ///   - `block_height`: the height of the block being mined
    pub fn calculate_target(&self, block_parent_time: u32, block_height: u32) -> CompactTarget {
        let time_delta = block_parent_time as i64 - self.anchor_parent_time as i64;
        let height_delta = block_height as i64 - self.anchor_height as i64;

        asert_calculate_target(
            self.anchor_target,
            time_delta,
            height_delta,
            HALFLIFE,
            IDEAL_BLOCK_TIME,
        )
    }

    /// Calculate the target and return it as a consensus u32.
    ///
    /// Convenience wrapper for compatibility with `ChainStoreHandle::get_current_target()`.
    pub fn calculate_target_consensus(&self, block_parent_time: u32, block_height: u32) -> u32 {
        self.calculate_target(block_parent_time, block_height)
            .to_consensus()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // U512 / Target conversion tests
    // =======================================================================

    #[test]
    fn test_target_u512_roundtrip_regtest_max() {
        let original = Target::from_compact(CompactTarget::from_consensus(0x207fffff));
        let wide = target_to_u512(original);
        let recovered = u512_to_target(wide);
        assert_eq!(original.to_le_bytes(), recovered.to_le_bytes());
    }

    #[test]
    fn test_target_u512_roundtrip_mainnet_genesis() {
        let original = Target::from_compact(CompactTarget::from_consensus(0x1d00ffff));
        let wide = target_to_u512(original);
        let recovered = u512_to_target(wide);
        assert_eq!(original.to_le_bytes(), recovered.to_le_bytes());
    }

    #[test]
    fn test_u512_multiply_then_shift_recovers_original() {
        // (anchor * 65536) >> 16 should give back anchor
        let target = Target::from_compact(CompactTarget::from_consensus(0x207fffff));
        let anchor = target_to_u512(target);
        let product = anchor * U512::from(65536u64);
        let recovered = product >> 16;
        assert_eq!(anchor, recovered);
    }

    #[test]
    fn test_u512_max_target_multiply_does_not_overflow() {
        // Max target (~2^255) * 131072 (~2^17) = ~2^272, fits in U512
        let target = Target::from_compact(CompactTarget::from_consensus(0x207fffff));
        let anchor = target_to_u512(target);
        let product = anchor * U512::from(131072u64);
        // Product should be larger than anchor
        assert!(product > anchor);
        // Product should not be zero (no wrapping)
        assert!(!product.is_zero());
    }

    // =======================================================================
    // ASERT algorithm tests
    // =======================================================================

    #[test]
    fn test_asert_on_schedule_returns_anchor_target() {
        // When blocks are exactly on schedule, the exponent is zero and the
        // target should equal the anchor target.
        // For height_delta=0: on schedule means time_delta = ideal_block_time * (0 + 1) = 10
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 10, 0, 600, 10);
        assert_eq!(result.to_consensus(), anchor.to_consensus());
    }

    #[test]
    fn test_asert_on_schedule_height_1() {
        // height_delta=1, on schedule means time_delta = ideal_block_time * (1 + 1) = 20
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 20, 1, 600, 10);
        assert_eq!(result.to_consensus(), anchor.to_consensus());
    }

    #[test]
    fn test_asert_on_schedule_height_60() {
        // height_delta=60, on schedule means time_delta = 10 * 61 = 610
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 610, 60, 600, 10);
        assert_eq!(result.to_consensus(), anchor.to_consensus());
    }

    #[test]
    fn test_asert_on_schedule_mainnet_target() {
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let result = asert_calculate_target(anchor, 10, 0, 600, 10);
        assert_eq!(result.to_consensus(), anchor.to_consensus());
    }

    #[test]
    fn test_asert_fast_blocks_decrease_target() {
        // Blocks arriving faster than expected should lower the target (harder mining)
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let on_schedule = asert_calculate_target(anchor, 610, 60, 600, 10);
        let too_fast = asert_calculate_target(anchor, 305, 60, 600, 10);

        let on_schedule_wide = target_to_u512(Target::from_compact(on_schedule));
        let too_fast_wide = target_to_u512(Target::from_compact(too_fast));
        assert!(
            too_fast_wide < on_schedule_wide,
            "faster blocks should produce a lower (harder) target"
        );
    }

    #[test]
    fn test_asert_slow_blocks_increase_target() {
        // Blocks arriving slower than expected should raise the target (easier mining).
        // Use mainnet target as anchor so there's room to increase.
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let on_schedule = asert_calculate_target(anchor, 610, 60, 600, 10);
        let too_slow = asert_calculate_target(anchor, 1220, 60, 600, 10);

        let on_schedule_wide = target_to_u512(Target::from_compact(on_schedule));
        let too_slow_wide = target_to_u512(Target::from_compact(too_slow));
        assert!(
            too_slow_wide > on_schedule_wide,
            "slower blocks should produce a higher (easier) target"
        );
    }

    #[test]
    fn test_asert_slow_blocks_at_max_target_clamps() {
        // When anchor is already at max, slow blocks should clamp to max
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let too_slow = asert_calculate_target(anchor, 1220, 60, 600, 10);
        let max_target_wide = target_to_u512(Target::from_compact(CompactTarget::from_consensus(
            MAX_TARGET_CONSENSUS,
        )));
        let too_slow_wide = target_to_u512(Target::from_compact(too_slow));
        assert!(
            too_slow_wide <= max_target_wide,
            "result should be clamped to max target"
        );
    }

    #[test]
    fn test_asert_halflife_approximately_doubles_target() {
        // When blocks are behind schedule by exactly one halflife, the target
        // should approximately double.
        //
        // For height_delta=0: exponent = (time_delta - 10) * 65536 / 600
        // We want exponent = 65536 (one full unit), so:
        //   (time_delta - 10) * 65536 / 600 = 65536
        //   time_delta - 10 = 600
        //   time_delta = 610
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let anchor_wide = target_to_u512(Target::from_compact(anchor));
        let result = asert_calculate_target(anchor, 610, 0, 600, 10);
        let result_wide = target_to_u512(Target::from_compact(result));

        assert!(
            result_wide > anchor_wide,
            "target should increase when behind schedule"
        );

        // Verify it is close to 2x (sanity upper bound: less than 3x)
        let anchor_times_3 = anchor_wide * U512::from(3u64);
        assert!(
            result_wide < anchor_times_3,
            "target should not more than triple after one halflife"
        );
    }

    #[test]
    fn test_asert_halflife_approximately_halves_target() {
        // When blocks are ahead of schedule by one halflife, the target should
        // approximately halve.
        //
        // For height_delta=0: exponent = (time_delta - 10) * 65536 / 600
        // We want exponent = -65536, so:
        //   time_delta - 10 = -600
        //   time_delta = -590
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let anchor_wide = target_to_u512(Target::from_compact(anchor));
        let result = asert_calculate_target(anchor, -590, 0, 600, 10);
        let result_wide = target_to_u512(Target::from_compact(result));

        assert!(
            result_wide < anchor_wide,
            "target should decrease when ahead of schedule"
        );

        // Should not drop below anchor/4 (sanity lower bound)
        let anchor_quarter = anchor_wide >> 2;
        assert!(
            result_wide > anchor_quarter,
            "target should not drop below quarter after one halflife"
        );
    }

    #[test]
    fn test_asert_negative_time_delta() {
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let normal = asert_calculate_target(anchor, 10, 0, 600, 10);
        let negative = asert_calculate_target(anchor, -10, 0, 600, 10);

        let normal_wide = target_to_u512(Target::from_compact(normal));
        let negative_wide = target_to_u512(Target::from_compact(negative));
        assert!(
            negative_wide < normal_wide,
            "negative time delta should produce harder target"
        );
    }

    #[test]
    fn test_asert_large_height_delta_does_not_panic() {
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 100_000, 100_000, 600, 10);
        let _ = Target::from_compact(result);
    }

    #[test]
    fn test_asert_extreme_fast_mining_target_not_zero() {
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 0, 100_000, 600, 10);
        let result_wide = target_to_u512(Target::from_compact(result));
        assert!(
            !result_wide.is_zero(),
            "target should never be zero even under extreme conditions"
        );
    }

    #[test]
    fn test_asert_extreme_slow_mining_clamps_to_max() {
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let result = asert_calculate_target(anchor, 1_000_000, 0, 600, 10);
        let result_wide = target_to_u512(Target::from_compact(result));
        let max_wide = target_to_u512(Target::from_compact(CompactTarget::from_consensus(
            MAX_TARGET_CONSENSUS,
        )));
        assert!(result_wide <= max_wide, "target should be clamped to max");
    }

    #[test]
    fn test_asert_compact_target_stable_under_roundtrip() {
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 50, 3, 600, 10);
        let result_target = Target::from_compact(result);
        let roundtrip = result_target.to_compact_lossy();
        assert_eq!(result.to_consensus(), roundtrip.to_consensus());
    }

    #[test]
    fn test_asert_symmetry_of_adjustments() {
        let anchor = CompactTarget::from_consensus(0x1d00ffff);
        let anchor_wide = target_to_u512(Target::from_compact(anchor));

        // 300 seconds behind schedule at height 0
        let behind = asert_calculate_target(anchor, 310, 0, 600, 10);
        let behind_wide = target_to_u512(Target::from_compact(behind));

        // 300 seconds ahead of schedule at height 0
        let ahead = asert_calculate_target(anchor, -290, 0, 600, 10);
        let ahead_wide = target_to_u512(Target::from_compact(ahead));

        assert!(behind_wide > anchor_wide);
        assert!(ahead_wide < anchor_wide);
    }

    #[test]
    fn test_asert_monotonic_with_time() {
        // For a fixed height_delta, increasing time_delta should monotonically
        // increase the target (easier difficulty).
        let anchor = CompactTarget::from_consensus(0x1d00ffff);

        let target_at_100 = asert_calculate_target(anchor, 100, 5, 600, 10);
        let target_at_200 = asert_calculate_target(anchor, 200, 5, 600, 10);
        let target_at_300 = asert_calculate_target(anchor, 300, 5, 600, 10);

        let t100 = target_to_u512(Target::from_compact(target_at_100));
        let t200 = target_to_u512(Target::from_compact(target_at_200));
        let t300 = target_to_u512(Target::from_compact(target_at_300));

        assert!(
            t200 >= t100,
            "target should increase with increasing time delta"
        );
        assert!(
            t300 >= t200,
            "target should increase with increasing time delta"
        );
    }

    #[test]
    fn test_asert_with_high_difficulty_anchor() {
        let anchor = CompactTarget::from_consensus(0x01010000);
        let result = asert_calculate_target(anchor, 10, 0, 600, 10);
        assert_ne!(result.to_consensus(), 0);
    }

    // =======================================================================
    // PoolDifficulty struct tests
    // =======================================================================

    #[test]
    fn test_pool_difficulty_new() {
        let pool_difficulty =
            PoolDifficulty::new(CompactTarget::from_consensus(0x207fffff), 1_700_000_000, 0);
        assert_eq!(pool_difficulty.anchor_target.to_consensus(), 0x207fffff);
        assert_eq!(pool_difficulty.anchor_parent_time, 1_700_000_000);
        assert_eq!(pool_difficulty.anchor_height, 0);
    }

    #[test]
    fn test_pool_difficulty_on_schedule() {
        let pool_difficulty =
            PoolDifficulty::new(CompactTarget::from_consensus(0x207fffff), 1_700_000_000, 0);
        // Block at height 1, exactly 20 seconds after anchor (on schedule: 10 * (1+1) = 20)
        let target = pool_difficulty.calculate_target(1_700_000_020, 1);
        assert_eq!(target.to_consensus(), 0x207fffff);
    }

    #[test]
    fn test_pool_difficulty_consensus_matches_compact() {
        let pool_difficulty =
            PoolDifficulty::new(CompactTarget::from_consensus(0x207fffff), 1_700_000_000, 0);
        let compact = pool_difficulty.calculate_target(1_700_000_015, 1);
        let consensus = pool_difficulty.calculate_target_consensus(1_700_000_015, 1);
        assert_eq!(consensus, compact.to_consensus());
    }

    #[test]
    fn test_pool_difficulty_on_schedule_at_various_heights() {
        let pool_difficulty =
            PoolDifficulty::new(CompactTarget::from_consensus(0x207fffff), 1_700_000_000, 0);

        // On schedule: block_parent_time = anchor_parent_time + ideal_block_time * (height + 1)
        let on_schedule_1 = pool_difficulty.calculate_target(1_700_000_020, 1);
        let on_schedule_5 = pool_difficulty.calculate_target(1_700_000_060, 5);
        let on_schedule_100 = pool_difficulty.calculate_target(1_700_001_010, 100);

        assert_eq!(on_schedule_1.to_consensus(), 0x207fffff);
        assert_eq!(on_schedule_5.to_consensus(), 0x207fffff);
        assert_eq!(on_schedule_100.to_consensus(), 0x207fffff);
    }

    #[test]
    fn test_pool_difficulty_slightly_ahead() {
        let pool_difficulty =
            PoolDifficulty::new(CompactTarget::from_consensus(0x207fffff), 1_700_000_000, 0);
        // Block at height 1, only 10 seconds later (ahead of schedule by 10s)
        //
        // on-schedule time is ideal_block_time * (height_delta + 1) =
        //  10 * (1 + 1) = 20 seconds after the anchor.
        let target = pool_difficulty.calculate_target(1_700_000_010, 1);
        let anchor_wide = target_to_u512(Target::from_compact(CompactTarget::from_consensus(
            0x207fffff,
        )));
        let target_wide = target_to_u512(Target::from_compact(target));
        // Slightly ahead -> slightly harder -> lower target
        assert!(target_wide <= anchor_wide);
    }

    // =======================================================================
    // Error type tests
    // =======================================================================

    #[test]
    fn test_asert_large_positive_time_delta_clamps_to_max() {
        // Reproduces a live signet bug: chain started Nov 2023, now March 2026.
        // Only 3033 shares mined in ~2.3 years. Blocks are massively behind
        // schedule, so the target should clamp to max (easiest difficulty).
        //
        // Actual debug output from the node:
        //   anchor_target = CompactTarget(545259519)  = 0x207fffff
        //   time_delta    = 72393399
        //   height_delta  = 3033
        //
        // Bug: num_shifts ≈ 120,605. Left-shifting U512 by >= 512 wraps to 0,
        // then the "ensure not zero" clamp sets target to 1 (hardest).
        let anchor = CompactTarget::from_consensus(0x207fffff);
        let result = asert_calculate_target(anchor, 72_393_399, 3033, 600, 10);
        assert_eq!(
            result.to_consensus(),
            0x207fffff,
            "target should clamp to max when blocks are far behind schedule"
        );
    }

    #[test]
    fn test_pool_difficulty_error_display() {
        let update_error = PoolDifficultyError::UpdateError("test error".to_string());
        assert_eq!(
            format!("{update_error}"),
            "Pool difficulty update error: test error"
        );

        let anchor_error = PoolDifficultyError::AnchorNotFound("missing".to_string());
        assert_eq!(format!("{anchor_error}"), "Anchor block not found: missing");
    }
}
