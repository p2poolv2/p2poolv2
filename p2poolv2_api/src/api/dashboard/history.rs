// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hashrate history the node keeps for its dashboard.
//!
//! A sampler task records the pool's, this node's and the network's hashrate
//! once a minute into a bounded ring. The dashboard therefore draws from the
//! node, not from a browser that forgets on reload. The ring is bounded, so
//! the history cannot grow without limit.

use crate::api::server::AppState;
use bitcoin::{CompactTarget, Target};
use p2poolv2_lib::store::dag_store::ShareInfo;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::MissedTickBehavior;
use tracing::warn;

/// How often the sampler records a sample.
pub(crate) const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// Samples kept: one day at one a minute.
pub(crate) const MAX_SAMPLES: usize = 24 * 60;

/// Shares the pool hashrate is estimated from: the newest this many
/// confirmed shares.
pub(crate) const POOL_HASHRATE_SHARES: u32 = 120;

/// Expected seconds between Bitcoin Cash blocks, for network hashrate.
const BLOCK_INTERVAL_SECONDS: f64 = 600.0;

/// Hashes a difficulty-1 share takes on average.
const HASHES_PER_DIFFICULTY: f64 = 4_294_967_296.0;

/// One sample of the hashrates the dashboard charts, in hashes per second.
/// `None` where the value could not be known at that time.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Sample {
    /// Unix seconds.
    pub(crate) time: u64,
    /// The whole pool, from the share chain.
    pub(crate) pool: Option<f64>,
    /// This node's miners, from the work this node accepted.
    pub(crate) local: Option<f64>,
    /// The Bitcoin Cash network, from the block template's difficulty.
    pub(crate) network: Option<f64>,
}

#[derive(Default)]
struct Inner {
    samples: VecDeque<Sample>,
    /// The accepted work total at the previous sample: (unix seconds,
    /// accepted difficulty total), for this node's hashrate.
    last_accepted: Option<(u64, u64)>,
}

/// The dashboard's history. Cheap to share; every method takes the lock
/// briefly and never across an await.
#[derive(Default)]
pub(crate) struct HashrateHistory {
    inner: Mutex<Inner>,
}

impl HashrateHistory {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding this lock leaves plain data behind, still
        // fine to read.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Samples, oldest first.
    pub(crate) fn samples(&self) -> Vec<Sample> {
        self.lock().samples.iter().copied().collect()
    }

    pub(crate) fn push_sample(&self, sample: Sample) {
        let mut inner = self.lock();
        if inner.samples.len() == MAX_SAMPLES {
            inner.samples.pop_front();
        }
        inner.samples.push_back(sample);
    }

    /// This node's hashrate since the previous call, from its accepted
    /// difficulty total. `None` on the first call and after the total went
    /// backwards (the metrics were reset).
    pub(crate) fn local_hashrate(&self, time: u64, accepted_difficulty_total: u64) -> Option<f64> {
        let mut inner = self.lock();
        let previous = inner
            .last_accepted
            .replace((time, accepted_difficulty_total));
        previous.and_then(|previous| local_hashrate(previous, (time, accepted_difficulty_total)))
    }
}

/// Work one share of `bits` stands for, in hashes.
pub(crate) fn work_from_bits(bits: CompactTarget) -> f64 {
    Target::from_compact(bits).difficulty_float() * HASHES_PER_DIFFICULTY
}

/// Hashrate behind a run of shares, from their bits and timestamps.
///
/// The oldest share only opens the time span: its work was done before it,
/// outside the span. `None` with fewer than two shares or no time between
/// the oldest and the newest.
pub(crate) fn share_chain_hashrate(shares: &[(u32, CompactTarget)]) -> Option<f64> {
    let oldest = shares.iter().min_by_key(|(time, _)| *time)?;
    let newest = shares.iter().max_by_key(|(time, _)| *time)?;
    let span = newest.0.checked_sub(oldest.0).filter(|span| *span > 0)?;
    let total: f64 = shares.iter().map(|(_, bits)| work_from_bits(*bits)).sum();
    Some((total - work_from_bits(oldest.1)) / f64::from(span))
}

/// Hashrate between two readings of an accepted difficulty total.
pub(crate) fn local_hashrate(previous: (u64, u64), current: (u64, u64)) -> Option<f64> {
    let seconds = current
        .0
        .checked_sub(previous.0)
        .filter(|seconds| *seconds > 0)?;
    let difficulty = current.1.checked_sub(previous.1)?;
    Some(difficulty as f64 * HASHES_PER_DIFFICULTY / seconds as f64)
}

/// Network hashrate implied by a block difficulty.
pub(crate) fn network_hashrate(difficulty: f64) -> f64 {
    difficulty * HASHES_PER_DIFFICULTY / BLOCK_INTERVAL_SECONDS
}

/// Whether a share's Bitcoin Cash header met its own block target.
pub(crate) fn is_block(header: &bitcoin::block::Header) -> bool {
    header.validate_pow(header.target()).is_ok()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// The newest confirmed shares, up to `count`, oldest first.
pub(crate) fn newest_shares(state: &AppState, count: u32) -> Vec<ShareInfo> {
    let Ok(Some(tip)) = state.chain_store_handle.get_tip_height() else {
        return Vec::new();
    };
    let from = tip.saturating_sub(count.saturating_sub(1));
    state
        .chain_store_handle
        .store_handle()
        .store()
        .query_shares(from, tip)
        .unwrap_or_default()
}

/// The pool hashrate from the newest confirmed shares.
pub(crate) fn pool_hashrate(state: &AppState) -> Option<f64> {
    let shares = newest_shares(state, POOL_HASHRATE_SHARES);
    let points: Vec<(u32, CompactTarget)> = shares
        .iter()
        .map(|share| (share.timestamp, share.bits))
        .collect();
    share_chain_hashrate(&points)
}

/// Record one sample.
async fn tick(state: &Arc<AppState>, history: &Arc<HashrateHistory>) {
    let time = unix_now();
    let accepted = state
        .metrics_handle
        .get_metrics()
        .await
        .accepted_difficulty_total;
    let local = history.local_hashrate(time, accepted);
    let network = state
        .tracker_handle
        .get_network_difficulty()
        .map(network_hashrate);

    // The store is read synchronously; keep that off the async workers.
    let blocking_state = Arc::clone(state);
    let pool = match tokio::task::spawn_blocking(move || pool_hashrate(&blocking_state)).await {
        Ok(pool) => pool,
        Err(error) => {
            warn!("Dashboard sampler could not read the share chain: {error}");
            None
        }
    };

    history.push_sample(Sample {
        time,
        pool,
        local,
        network,
    });
}

/// Sample once a minute until the history is dropped with the API server.
///
/// Holds the history only weakly, so it never keeps it alive.
pub(crate) async fn run_sampler(state: Arc<AppState>, history: Weak<HashrateHistory>) {
    let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let Some(history) = history.upgrade() else {
            return;
        };
        tick(&state, &history).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bits of a difficulty-1 target.
    fn difficulty_one() -> CompactTarget {
        CompactTarget::from_consensus(0x1d00ffff)
    }

    #[test]
    fn a_difficulty_one_share_is_two_to_the_thirty_two_hashes() {
        assert!((work_from_bits(difficulty_one()) - HASHES_PER_DIFFICULTY).abs() < 1.0);
    }

    #[test]
    fn share_chain_hashrate_leaves_out_the_oldest_shares_work() {
        // Three difficulty-1 shares over 20 seconds: two shares of work
        // after the first one.
        let shares = [
            (1_000, difficulty_one()),
            (1_010, difficulty_one()),
            (1_020, difficulty_one()),
        ];
        let rate = share_chain_hashrate(&shares).unwrap();
        assert!((rate - 2.0 * HASHES_PER_DIFFICULTY / 20.0).abs() < 1.0);
    }

    #[test]
    fn share_chain_hashrate_does_not_depend_on_order() {
        let ordered = [(1_000, difficulty_one()), (1_030, difficulty_one())];
        let reversed = [(1_030, difficulty_one()), (1_000, difficulty_one())];
        assert_eq!(
            share_chain_hashrate(&ordered),
            share_chain_hashrate(&reversed)
        );
    }

    #[test]
    fn share_chain_hashrate_needs_two_shares_and_a_span() {
        assert_eq!(share_chain_hashrate(&[]), None);
        assert_eq!(share_chain_hashrate(&[(1_000, difficulty_one())]), None);
        assert_eq!(
            share_chain_hashrate(&[(1_000, difficulty_one()), (1_000, difficulty_one())]),
            None
        );
    }

    #[test]
    fn local_hashrate_is_accepted_work_over_time() {
        let rate = local_hashrate((100, 1_000), (160, 1_600)).unwrap();
        assert!((rate - 600.0 * HASHES_PER_DIFFICULTY / 60.0).abs() < 1.0);
    }

    #[test]
    fn local_hashrate_skips_a_reset_total_and_no_elapsed_time() {
        assert_eq!(local_hashrate((100, 1_000), (160, 500)), None);
        assert_eq!(local_hashrate((100, 1_000), (100, 2_000)), None);
    }

    #[test]
    fn history_local_hashrate_needs_a_previous_reading() {
        let history = HashrateHistory::default();
        assert_eq!(history.local_hashrate(100, 1_000), None);
        assert!(history.local_hashrate(160, 1_600).is_some());
    }

    #[test]
    fn network_hashrate_spreads_difficulty_over_ten_minutes() {
        assert!((network_hashrate(600.0) - HASHES_PER_DIFFICULTY).abs() < 1.0);
    }

    #[test]
    fn samples_are_capped_at_one_day() {
        let history = HashrateHistory::default();
        for time in 0..(MAX_SAMPLES as u64 + 10) {
            history.push_sample(Sample {
                time,
                pool: None,
                local: None,
                network: None,
            });
        }
        let samples = history.samples();
        assert_eq!(samples.len(), MAX_SAMPLES);
        assert_eq!(samples.first().unwrap().time, 10);
    }

    #[test]
    fn a_header_meeting_its_own_target_is_a_block() {
        // Regtest's easiest target: almost any hash meets it.
        let mut header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        assert!(is_block(&header));
        // A target no hash can meet.
        header.bits = CompactTarget::from_consensus(0x0300_0001);
        assert!(!is_block(&header));
    }
}
