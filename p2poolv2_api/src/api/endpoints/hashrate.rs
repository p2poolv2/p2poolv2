// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hashrate estimates and history for dashboards.
//!
//! Pool hashrate is read from the confirmed share chain: the expected hashes
//! of every share (and its uncles) in the window, divided by the window. It
//! is the same on every node. Local hashrate is this node's accepted stratum
//! difficulty, sampled from the metrics actor by [`LocalHashrateSampler`].
//! Network hashrate is derived from the current block template difficulty.

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Extension, Json,
    extract::{Query, State},
};
use bitcoin::{CompactTarget, Target};
use p2poolv2_lib::accounting::stats::metrics::MetricsHandle;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Expected hashes for one unit of difficulty.
const HASHES_PER_DIFFICULTY: f64 = 4_294_967_296.0;
/// Bitcoin Cash target block interval in seconds.
const BLOCK_INTERVAL_SECS: f64 = 600.0;
/// Default and maximum window, in seconds.
const DEFAULT_WINDOW_SECS: u64 = 3600;
const MAX_WINDOW_SECS: u64 = 86_400;
/// Default and maximum number of history buckets.
const DEFAULT_BUCKETS: usize = 60;
const MAX_BUCKETS: usize = 500;
/// Shares read from the store per batch while walking back from the tip.
const SHARE_BATCH: u32 = 500;
/// Upper bound on shares walked for one request, so a very fast share chain
/// cannot make a request unbounded.
const MAX_SHARES_SCANNED: u32 = 100_000;
/// How often the local sampler reads the metrics actor.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
/// Samples kept: 24 hours at the sample interval.
const MAX_SAMPLES: usize = 2880;

#[derive(Deserialize)]
pub struct HashrateQuery {
    /// Window in seconds ending now. Defaults to one hour, at most a day.
    pub window: Option<u64>,
    /// Number of equal history buckets in the window. Defaults to 60.
    pub buckets: Option<usize>,
}

/// One history bucket, in hashes per second. `time` is the bucket end.
#[derive(Serialize, Debug, PartialEq)]
pub struct HashratePoint {
    pub time: u64,
    pub pool_hashrate: f64,
    /// `None` where the sampler has no data for the bucket (before startup).
    pub local_hashrate: Option<f64>,
}

#[derive(Serialize)]
pub struct HashrateResponse {
    pub window_secs: u64,
    pub bucket_secs: u64,
    /// Pool hashrate over the whole window, hashes per second.
    pub pool_hashrate: f64,
    /// This node's stratum hashrate over the window, `None` until two samples exist.
    pub local_hashrate: Option<f64>,
    /// Network hashrate from the current template difficulty, if a template is known.
    pub network_hashrate: Option<f64>,
    pub network_difficulty: Option<f64>,
    /// Shares and uncles counted in the window.
    pub share_count: u64,
    pub history: Vec<HashratePoint>,
}

/// A `(unix time, cumulative accepted difficulty)` sample.
type Sample = (u64, u64);

/// Ring buffer of accepted-difficulty samples taken from the metrics actor.
///
/// The metrics totals survive restarts but the start time does not, so a
/// lifetime average is misleading; rates are taken between samples instead.
#[derive(Default)]
pub struct LocalHashrateSampler {
    samples: Mutex<VecDeque<Sample>>,
}

impl LocalHashrateSampler {
    /// Start sampling `metrics_handle` in the background.
    pub fn spawn(metrics_handle: MetricsHandle) -> Arc<Self> {
        let sampler = Arc::new(Self::default());
        let background = sampler.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
            loop {
                interval.tick().await;
                let metrics = metrics_handle.get_metrics().await;
                background.record(unix_now(), metrics.accepted_difficulty_total);
            }
        });
        sampler
    }

    fn record(&self, time: u64, accepted_difficulty_total: u64) {
        let mut samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        if samples.len() == MAX_SAMPLES {
            samples.pop_front();
        }
        samples.push_back((time, accepted_difficulty_total));
    }

    fn snapshot(&self) -> Vec<Sample> {
        let samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        samples.iter().copied().collect()
    }
}

/// Hashrate between the first and last sample inside `[start, end]`.
fn local_rate(samples: &[Sample], start: u64, end: u64) -> Option<f64> {
    let mut inside = samples.iter().filter(|(t, _)| *t >= start && *t <= end);
    let first = inside.next()?;
    let last = inside.next_back()?;
    let elapsed = last.0.checked_sub(first.0).filter(|e| *e > 0)?;
    // A counter reset (store wiped) makes the delta negative; report nothing.
    let delta = last.1.checked_sub(first.1)?;
    Some(delta as f64 * HASHES_PER_DIFFICULTY / elapsed as f64)
}

/// Expected hashes to find a share at `bits`.
fn share_work(bits: CompactTarget) -> f64 {
    let work = Target::from_compact(bits).to_work();
    work.to_le_bytes()
        .iter()
        .rev()
        .fold(0.0_f64, |acc, &byte| acc * 256.0 + byte as f64)
}

/// Sum `(timestamp, work)` items into `buckets` equal buckets ending at `end`,
/// returning per-bucket hashrates and the whole-window hashrate.
fn bucket_work(items: &[(u64, f64)], end: u64, window: u64, buckets: usize) -> (Vec<f64>, f64) {
    let start = end.saturating_sub(window);
    let bucket_secs = (window / buckets as u64).max(1);
    let mut sums = vec![0.0; buckets];
    let mut total = 0.0;
    for &(time, work) in items {
        if time < start || time > end {
            continue;
        }
        let index = (((time - start) / bucket_secs) as usize).min(buckets - 1);
        sums[index] += work;
        total += work;
    }
    let rates = sums.into_iter().map(|w| w / bucket_secs as f64).collect();
    (rates, total / window as f64)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Returns pool, local and network hashrate with a bucketed history.
pub(crate) async fn hashrate(
    State(state): State<Arc<AppState>>,
    sampler: Option<Extension<Arc<LocalHashrateSampler>>>,
    Query(query): Query<HashrateQuery>,
) -> Result<Json<HashrateResponse>, ApiError> {
    let window = query.window.unwrap_or(DEFAULT_WINDOW_SECS);
    if !(60..=MAX_WINDOW_SECS).contains(&window) {
        return Err(ApiError::BadRequest(format!(
            "window must be between 60 and {MAX_WINDOW_SECS} seconds, got {window}"
        )));
    }
    let buckets = query.buckets.unwrap_or(DEFAULT_BUCKETS);
    if !(1..=MAX_BUCKETS).contains(&buckets) {
        return Err(ApiError::BadRequest(format!(
            "buckets must be between 1 and {MAX_BUCKETS}, got {buckets}"
        )));
    }

    let end = unix_now();
    let start = end.saturating_sub(window);
    let items = shares_in_window(&state, start)?;
    let share_count = items.len() as u64;
    let (pool_rates, pool_hashrate) = bucket_work(&items, end, window, buckets);

    let samples = sampler.map(|s| s.snapshot()).unwrap_or_default();
    let bucket_secs = (window / buckets as u64).max(1);
    let history = pool_rates
        .into_iter()
        .enumerate()
        .map(|(index, pool_hashrate)| {
            let bucket_end = start + bucket_secs * (index as u64 + 1);
            // Widen to two sample intervals so short buckets still see two samples.
            let span = bucket_secs.max(2 * SAMPLE_INTERVAL.as_secs());
            HashratePoint {
                time: bucket_end,
                pool_hashrate,
                local_hashrate: local_rate(&samples, bucket_end.saturating_sub(span), bucket_end),
            }
        })
        .collect();

    let network_difficulty = state.tracker_handle.get_network_difficulty();
    Ok(Json(HashrateResponse {
        window_secs: window,
        bucket_secs,
        pool_hashrate,
        local_hashrate: local_rate(&samples, start, end),
        network_hashrate: network_difficulty
            .map(|d| d * HASHES_PER_DIFFICULTY / BLOCK_INTERVAL_SECS),
        network_difficulty,
        share_count,
        history,
    }))
}

/// Walk back from the confirmed tip collecting `(timestamp, work)` for shares
/// and their uncles until shares are older than `start`. Uncles carry no bits
/// of their own here, so they are counted at their nephew's target, which the
/// difficulty adjustment keeps close.
fn shares_in_window(state: &AppState, start: u64) -> Result<Vec<(u64, f64)>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;
    let Some(tip) = chain_store_handle
        .get_tip_height()
        .map_err(|error| ApiError::ServerError(format!("Failed to get tip height: {error}")))?
    else {
        return Ok(Vec::new());
    };
    let store = chain_store_handle.store_handle().store();
    let mut items = Vec::new();
    let mut to = tip;
    let mut scanned = 0;
    loop {
        let from = to.saturating_sub(SHARE_BATCH - 1);
        let shares = store
            .query_shares(from, to)
            .map_err(|error| ApiError::ServerError(format!("Failed to query shares: {error}")))?;
        let mut reached_start = false;
        for share in shares.iter().rev() {
            let time = u64::from(share.timestamp);
            if time < start {
                reached_start = true;
                continue;
            }
            let work = share_work(share.bits);
            items.push((time, work));
            items.extend(share.uncles.iter().map(|u| (u64::from(u.timestamp), work)));
        }
        scanned += to - from + 1;
        if reached_start || from == 0 || scanned >= MAX_SHARES_SCANNED {
            return Ok(items);
        }
        to = from - 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_work_spreads_and_totals() {
        let items = [(100, 60.0), (130, 60.0), (170, 120.0), (10, 1000.0)];
        let (rates, total) = bucket_work(&items, 180, 120, 2);
        // Buckets [60,120) and [120,180].
        assert_eq!(rates, vec![1.0, 3.0]);
        assert_eq!(total, 2.0);
    }

    #[test]
    fn test_local_rate_uses_first_and_last_sample() {
        let samples = [(0, 0), (30, 30), (60, 90)];
        let rate = local_rate(&samples, 0, 60).unwrap();
        assert_eq!(rate, 1.5 * HASHES_PER_DIFFICULTY);
        assert_eq!(local_rate(&samples, 50, 60), None);
    }

    #[test]
    fn test_local_rate_ignores_counter_reset() {
        assert_eq!(local_rate(&[(0, 100), (30, 10)], 0, 30), None);
    }

    #[test]
    fn test_share_work_difficulty_one() {
        let work = share_work(CompactTarget::from_consensus(0x1d00ffff));
        assert!((work / HASHES_PER_DIFFICULTY - 1.0).abs() < 1e-3);
    }

    #[test]
    fn test_sampler_ring_buffer_is_bounded() {
        let sampler = LocalHashrateSampler::default();
        for i in 0..(MAX_SAMPLES as u64 + 5) {
            sampler.record(i, i);
        }
        let snapshot = sampler.snapshot();
        assert_eq!(snapshot.len(), MAX_SAMPLES);
        assert_eq!(snapshot[0], (5, 5));
    }
}
