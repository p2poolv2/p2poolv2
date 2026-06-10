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

//! Synthetic share emitter task.
//!
//! Models one miner of hashrate `Hᵢ`. It subscribes to the notify watch
//! channel (the same prepared templates real stratum connections receive), and
//! between emissions sleeps for an exponentially-distributed interval whose
//! mean is `difficulty · 2^32 / Hᵢ`. As shares grow the chain, the existing
//! organise → `NewNotify` loop refreshes the watch with the new tip and ASERT
//! difficulty, so the controller is genuinely under test. Each emitted share
//! is independently a bitcoin block with probability `1/block_to_share_ratio`
//! (a Bernoulli draw).
//!
//! Only compiled under the `sim` feature. See docs/simulation/load-test-plan.md.

use crate::config::SimConfig;
use crate::sim::blockfind::submit_sim_block;
use crate::sim::share::{SimShareParams, build_sim_emission};
use crate::sim::timing::{
    block_find_probability, difficulty_from_bits, is_block_find, mean_share_interval_secs,
    sample_exponential_secs,
};
use crate::stratum::emission::EmissionSender;
use crate::stratum::work::prepared_notify::PreparedNotifyParams;
use crate::stratum::work::tracker::{JobTracker, start_tracker_actor};
use bitcoin::Address;
use bitcoindrpc::BitcoindRpcClient;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Any individual sleep not allowed to be above this; we just crash.
const MAX_SLEEP_SECS: f64 = 7200.0;

/// A synthetic share emitter modeling a single miner.
pub struct SimEmitter {
    emissions_tx: EmissionSender,
    template_rx: watch::Receiver<Option<Arc<PreparedNotifyParams>>>,
    miner_address: Address,
    config: SimConfig,
    /// RPC client used to submit a real regtest block on a statistical block-find.
    bitcoindrpc: BitcoindRpcClient,
    /// Private job tracker: the emitter inserts a job and immediately reads it
    /// back, so it does not share the stratum server's tracker.
    tracker: Arc<JobTracker>,
}

impl SimEmitter {
    /// Create a new emitter.
    pub fn new(
        emissions_tx: EmissionSender,
        template_rx: watch::Receiver<Option<Arc<PreparedNotifyParams>>>,
        miner_address: Address,
        config: SimConfig,
        bitcoindrpc: BitcoindRpcClient,
    ) -> Self {
        Self {
            emissions_tx,
            template_rx,
            miner_address,
            config,
            bitcoindrpc,
            tracker: start_tracker_actor(),
        }
    }

    /// Run the emission loop until the notify channel or emissions channel
    /// closes. Intended to be raced against a shutdown signal by the caller.
    pub async fn run(mut self) {
        let seed = self.config.seed.unwrap_or(0xC0FFEE);
        let mut rng = StdRng::seed_from_u64(seed);
        let p_block = block_find_probability(self.config.block_to_share_ratio);
        let mut enonce2_counter: u64 = 0;
        // Periodic stats for the metrics harness: per-node emitted count (→ verify
        // emission ∝ hashrate) and the current ASERT pool difficulty (→ trace
        // whether ASERT converges to a steady state).
        let mut emitted: u64 = 0;
        let mut last_stats = std::time::Instant::now();
        const STATS_INTERVAL: Duration = Duration::from_secs(15);

        info!(
            "Sim emitter started: address={}, hashrate={} h/s, block:share=1:{}, seed={}",
            self.miner_address, self.config.hashrate, self.config.block_to_share_ratio, seed
        );

        loop {
            // Wait until a prepared template is available. Clone into a local so
            // the watch Ref is dropped before we await `changed()`.
            let latest = self.template_rx.borrow().clone();
            let prepared = match latest {
                Some(prepared) => prepared,
                None => {
                    debug!("Sim emitter: no template yet, waiting");
                    if self.template_rx.changed().await.is_err() {
                        break; // notifier gone
                    }
                    continue;
                }
            };

            // Pace: sleep an exponential interval sized by the current ASERT
            // pool difficulty and this miner's modeled hashrate.
            let difficulty = difficulty_from_bits(prepared.bits());
            let mean = mean_share_interval_secs(difficulty, self.config.hashrate);
            let secs = sample_exponential_secs(mean, &mut rng);
            assert!(secs <= MAX_SLEEP_SECS, "sim emitter: {secs:.0}s sleep — misconfigured hashrate?");
            tokio::time::sleep(Duration::from_secs_f64(secs.max(0.0))).await;

            // Build a synthetic share for the latest template (re-read in case
            // the tip advanced while we slept).
            let latest = self.template_rx.borrow().clone();
            let prepared = match latest {
                Some(prepared) => prepared,
                None => continue,
            };

            let enonce1_hex = format!("{:08x}", rng.gen_range(0..=u32::MAX));
            let enonce2_hex = format!("{enonce2_counter:016x}");
            enonce2_counter = enonce2_counter.wrapping_add(1);
            let nonce: u32 = rng.gen_range(0..=u32::MAX);
            let ntime = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);

            let params = SimShareParams {
                prepared: &prepared,
                miner_address: &self.miner_address,
                tracker: &self.tracker,
                user_id: 0,
                difficulty: difficulty.max(1.0) as u64,
                btcaddress: self.miner_address.to_string(),
                workername: "sim".to_string(),
                enonce1_hex: &enonce1_hex,
                enonce2_hex: &enonce2_hex,
                nonce,
                ntime,
            };

            match build_sim_emission(params) {
                Ok(built) => {
                    // Keep what a block-find needs before the emission is moved.
                    let is_block = is_block_find(p_block, &mut rng);
                    let header = built.emission.header;
                    let template = built.emission.blocktemplate.clone();
                    let coinbase = if is_block {
                        Some(built.coinbase.clone())
                    } else {
                        None
                    };

                    if self.emissions_tx.send(built.emission).await.is_err() {
                        info!("Sim emitter: emissions channel closed, stopping");
                        break;
                    }

                    // Statistical block-find: submit a real regtest block. The
                    // coinbase already carries the PPLNS payout; we just grind
                    // the trivial regtest nonce and submit. Rare (1/ratio), so
                    // awaiting inline does not meaningfully affect pacing.
                    if let Some(coinbase) = coinbase {
                        submit_sim_block(header, coinbase, &template, &self.bitcoindrpc).await;
                    }

                    emitted += 1;
                    if last_stats.elapsed() >= STATS_INTERVAL {
                        info!(
                            "sim stats: emitted={emitted} pool_difficulty={difficulty:.1} hashrate={}",
                            self.config.hashrate
                        );
                        last_stats = std::time::Instant::now();
                    }
                }
                Err(e) => warn!("Sim emitter: failed to build emission: {e}"),
            }
        }

        info!("Sim emitter stopped");
    }
}
