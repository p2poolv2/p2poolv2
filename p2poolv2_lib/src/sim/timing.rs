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

//! Closed-loop emission timing and statistical block-find.
//!
//! This replaces the physical mining process. Instead of grinding hashes, a
//! modeled miner of hashrate `H` (hashes/sec) producing shares at pool
//! difficulty `D` is paced by sleeping: a share requires on average
//! `D · 2^32` hashes, so the mean inter-share interval is `D · 2^32 / H`
//! seconds, and inter-share times are exponentially distributed (a Poisson
//! process). When ASERT raises `D`, the interval grows and the emitter slows
//! on its own — the difficulty controller is genuinely under test.
//!
//! Each emitted share is independently a bitcoin block with probability
//! `1 / block_to_share_ratio` (a Bernoulli draw — NOT a header hash; see
//! `docs/simulation/load-test-plan.md` for why hashing the header would be the
//! regtest ~50% trap). All randomness is caller-supplied so runs are
//! reproducible from a per-node seed.

use rand::Rng;

/// Number of hashes, on expectation, to find one difficulty-1 share (2^32).
const HASHES_PER_DIFFICULTY_1: f64 = 4_294_967_296.0; // 2^32

/// Difficulty (diff-1 relative) implied by a compact target.
///
/// Uses the same mainnet-max-target convention as the rest of the pool
/// (see `get_true_difficulty`), so the closed-loop emission rate tracks the
/// ASERT pool target consistently across nodes.
pub fn difficulty_from_bits(bits: bitcoin::CompactTarget) -> f64 {
    bitcoin::Target::from_compact(bits).difficulty_float()
}

/// Mean interval between shares, in seconds, for a modeled miner.
///
/// `pool_difficulty` is the share's difficulty (diff-1 relative) and
/// `hashrate_hps` is the modeled miner hashrate in hashes/sec. Returns
/// `f64::INFINITY` for a non-positive hashrate (a miner that never emits),
/// which a caller can treat as "disabled".
pub fn mean_share_interval_secs(pool_difficulty: f64, hashrate_hps: f64) -> f64 {
    if hashrate_hps <= 0.0 || !hashrate_hps.is_finite() {
        return f64::INFINITY;
    }
    let difficulty = pool_difficulty.max(0.0);
    difficulty * HASHES_PER_DIFFICULTY_1 / hashrate_hps
}

/// Draw one exponentially-distributed inter-share interval (seconds).
///
/// Uses inverse-transform sampling: `-mean · ln(1 - u)` with `u ∈ [0, 1)`.
/// We use `1 - u` so the argument to `ln` is in `(0, 1]`, never zero.
/// A non-finite `mean` (e.g. from a zero hashrate) yields `f64::INFINITY`.
pub fn sample_exponential_secs<R: Rng + ?Sized>(mean_secs: f64, rng: &mut R) -> f64 {
    if !mean_secs.is_finite() {
        return f64::INFINITY;
    }
    if mean_secs <= 0.0 {
        return 0.0;
    }
    let u: f64 = rng.gen_range(0.0..1.0); // [0, 1)
    -mean_secs * (1.0 - u).ln()
}

/// Per-share probability that a share is also a bitcoin block.
///
/// `0` ratio (or 1-in-0) is treated as "never find a block".
// Small naming note: block_to_share_ratio is 10:1 if there is 1 block per 10 shares.
pub fn block_find_probability(block_to_share_ratio: u64) -> f64 {
    if block_to_share_ratio == 0 {
        0.0
    } else {
        1.0 / block_to_share_ratio as f64
    }
}

/// Bernoulli draw: is this share also a bitcoin block?
///
/// This is the only place a block-find is decided. It is a single O(1) draw,
/// deliberately NOT a header hash against the network target.
pub fn is_block_find<R: Rng + ?Sized>(probability: f64, rng: &mut R) -> bool {
    if probability <= 0.0 {
        return false;
    }
    if probability >= 1.0 {
        return true;
    }
    rng.gen_range(0.0..1.0) < probability
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn mean_interval_scales_with_difficulty_and_hashrate() {
        // 1 TH/s = 1e12 h/s; difficulty 1 -> 2^32 / 1e12 seconds.
        let h = 1.0e12;
        let d1 = mean_share_interval_secs(1.0, h);
        assert!((d1 - HASHES_PER_DIFFICULTY_1 / h).abs() < 1e-9);
        // Doubling difficulty doubles the interval.
        let d2 = mean_share_interval_secs(2.0, h);
        assert!((d2 / d1 - 2.0).abs() < 1e-9);
        // Doubling hashrate halves the interval.
        let d1_fast = mean_share_interval_secs(1.0, 2.0 * h);
        assert!((d1 / d1_fast - 2.0).abs() < 1e-9);
    }

    #[test]
    fn mean_interval_non_positive_hashrate_is_infinite() {
        assert_eq!(mean_share_interval_secs(1.0, 0.0), f64::INFINITY);
        assert_eq!(mean_share_interval_secs(1.0, -5.0), f64::INFINITY);
        assert_eq!(mean_share_interval_secs(1.0, f64::INFINITY), f64::INFINITY);
    }

    #[test]
    fn exponential_samples_are_non_negative() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..10_000 {
            let s = sample_exponential_secs(5.0, &mut rng);
            assert!(s >= 0.0 && s.is_finite());
        }
    }

    #[test]
    fn exponential_sample_mean_converges() {
        let mut rng = StdRng::seed_from_u64(42);
        let mean = 10.0;
        let n = 200_000;
        let sum: f64 = (0..n).map(|_| sample_exponential_secs(mean, &mut rng)).sum();
        let observed = sum / n as f64;
        // Exponential has mean == `mean`; allow 3% tolerance for 200k samples.
        assert!(
            (observed - mean).abs() / mean < 0.03,
            "observed mean {observed} too far from {mean}"
        );
    }

    #[test]
    fn exponential_degenerate_inputs() {
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(sample_exponential_secs(0.0, &mut rng), 0.0);
        assert_eq!(sample_exponential_secs(f64::INFINITY, &mut rng), f64::INFINITY);
    }

    #[test]
    fn block_probability_edges() {
        assert_eq!(block_find_probability(0), 0.0);
        assert_eq!(block_find_probability(1), 1.0);
        assert!((block_find_probability(10_000) - 1.0e-4).abs() < 1e-12);
    }

    #[test]
    fn block_find_frequency_matches_probability() {
        let mut rng = StdRng::seed_from_u64(123);
        let ratio = 100u64;
        let p = block_find_probability(ratio);
        let n = 500_000;
        let hits = (0..n).filter(|_| is_block_find(p, &mut rng)).count();
        let observed = hits as f64 / n as f64;
        // Expected ~1/100; allow 10% relative tolerance.
        assert!(
            (observed - p).abs() / p < 0.10,
            "observed block rate {observed} too far from {p}"
        );
    }

    #[test]
    fn block_find_probability_clamps() {
        let mut rng = StdRng::seed_from_u64(9);
        assert!(!is_block_find(0.0, &mut rng));
        assert!(!is_block_find(-1.0, &mut rng));
        assert!(is_block_find(1.0, &mut rng));
        assert!(is_block_find(2.0, &mut rng));
    }

    #[test]
    fn deterministic_with_same_seed() {
        let draw = |seed: u64| {
            let mut rng = StdRng::seed_from_u64(seed);
            (0..5)
                .map(|_| sample_exponential_secs(3.0, &mut rng))
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(555), draw(555));
        assert_ne!(draw(555), draw(556));
    }
}
