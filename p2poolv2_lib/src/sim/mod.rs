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
//! enabled in a release build. It replaces the physical mining process with a
//! timed emitter of synthetic shares so the share-chain / p2p /
//! payout machinery can be load-tested with many peers without spending CPU on
//! proof-of-work. Proof-of-work verification is stubbed elsewhere (see
//! `shares::validation::pow_meets` and the auto-submit gate in
//! `stratum::message_handlers::submit`).
//!
//! See `docs/simulation/load-test-plan.md` for the full design.

pub mod blockfind;
pub mod emitter;
pub mod share;
pub mod timing;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Artificial outbound-announcement delay, in milliseconds, shared process-wide.
///
/// Set once at startup from `[sim].propagation_delay_ms`; read on the share
/// broadcast path. A process-global avoids threading sim config through the
/// core node, and the read site is compiled out entirely in non-sim builds.
static PROPAGATION_DELAY_MS: AtomicU64 = AtomicU64::new(0);

/// Set the simulated propagation delay (milliseconds). Call once at startup.
pub fn set_propagation_delay_ms(ms: u64) {
    PROPAGATION_DELAY_MS.store(ms, Ordering::Relaxed);
}

/// The simulated propagation delay as a `Duration` (zero if unset/disabled).
pub fn propagation_delay() -> Duration {
    Duration::from_millis(PROPAGATION_DELAY_MS.load(Ordering::Relaxed))
}

/// The propagation delay for a single announcement, with per-broadcast jitter.
///
/// Applies a uniform ±50% factor around
/// the configured base (per-node base is set from `[sim].propagation_delay_ms`;
/// the harness already spreads the base across nodes). Returns zero when no base
/// delay is configured.
pub fn propagation_delay_jittered() -> Duration {
    use rand::Rng;
    let base = PROPAGATION_DELAY_MS.load(Ordering::Relaxed);
    if base == 0 {
        return Duration::ZERO;
    }
    let factor: f64 = rand::thread_rng().gen_range(0.5..1.5);
    Duration::from_millis((base as f64 * factor).round() as u64)
}

/// Number of shares the PPLNS payout window should span, process-wide.
///
/// On regtest the bitcoin block difficulty is trivially 1, so the real payout
/// window (`total_difficulty / share_difficulty`) collapses to a single share.
/// Setting this makes the payout calc pretend the network is `N ×` a share's
/// difficulty, so the window spans ~N shares — a mainnet-like, ASERT-stable
/// distribution. `0` means "unset": the original formula
/// (`bitcoin_difficulty × difficulty_multiplier`) is used. Set once at startup
/// from `[sim].pplns_window_shares` (default: `block_to_share_ratio`).
static PPLNS_WINDOW_SHARES: AtomicU64 = AtomicU64::new(0);

/// Set the simulated PPLNS window size in shares. Call once at startup.
pub fn set_pplns_window_shares(n: u64) {
    PPLNS_WINDOW_SHARES.store(n, Ordering::Relaxed);
}

/// The simulated PPLNS window size in shares (0 = unset / use original formula).
pub fn pplns_window_shares() -> u64 {
    PPLNS_WINDOW_SHARES.load(Ordering::Relaxed)
}

/// ASERT difficulty anchor time (unix seconds), shared process-wide.
///
/// The fixed regtest genesis timestamp is in the past, so the share chain is
/// permanently behind schedule and ASERT stays floored at the easy clamp (the
/// chain races at ~30× the target rate). Setting this to ~launch time lets
/// ASERT regulate around the 10s target. `0` means "unset": use the genesis
/// timestamp (original behavior). MUST be identical across nodes — the harness
/// writes one shared value — or ASERT targets diverge and shares are rejected.
static ASERT_ANCHOR_TIME: AtomicU64 = AtomicU64::new(0);

/// Set the simulated ASERT anchor time (unix seconds). Call once at startup,
/// before `PoolDifficulty::build`.
pub fn set_asert_anchor_time(secs: u64) {
    ASERT_ANCHOR_TIME.store(secs, Ordering::Relaxed);
}

/// The simulated ASERT anchor time (0 = unset / use genesis timestamp).
pub fn asert_anchor_time() -> u64 {
    ASERT_ANCHOR_TIME.load(Ordering::Relaxed)
}

/// Total network hashrate (hashes/sec), shared process-wide.
///
/// Set once at startup from `[sim].network_hashrate` (the harness writes the
/// sum of all nodes' hashrates — identical across nodes). Used to anchor the
/// genesis difficulty at the steady-state value so the chain starts regulated
/// instead of climbing from the easy clamp. `0` = unset → use the fixed genesis
/// target. MUST match across nodes (it sets the genesis target → genesis hash).
static NETWORK_HASHRATE: AtomicU64 = AtomicU64::new(0);

/// Set the total network hashrate (hashes/sec). Call once at startup, before
/// `build_genesis`.
pub fn set_network_hashrate(hps: u64) {
    NETWORK_HASHRATE.store(hps, Ordering::Relaxed);
}

/// The total network hashrate (hashes/sec); 0 = unset.
pub fn network_hashrate() -> u64 {
    NETWORK_HASHRATE.load(Ordering::Relaxed)
}
