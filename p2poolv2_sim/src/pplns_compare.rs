// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline payout comparison: upstream's fixed PPLNS window against the
//! Bitcoin Cash window sized by block difficulty, and two ideas from P2Pool
//! v1 on BCH (jtoomim): a three-block window and a finder bonus.
//!
//! For each pool size (as a fraction of BCH's hashrate) and each seed it draws
//! one share chain at the 10 s share target, with four miners and a Bernoulli
//! block find per share, then pays every block through the real `PplnsWindow`
//! code under each rule in `RULES`. Every rule sees the same chain and the
//! same blocks, so the differences come from the rule alone. It prints
//! Markdown tables of window length, payout delay and income variance,
//! averaged over the seeds.
//!
//! No node, store or bitcoind is involved, and no uncles are modelled. Must
//! be built with `--features sim`:
//!
//! ```sh
//! cargo run --release -p p2poolv2_sim --features sim --bin pplns_compare
//! cargo run --release -p p2poolv2_sim --features sim --bin pplns_compare -- --maturity 360
//! ```

use bitcoin::hashes::Hash;
use bitcoin::{Address, BlockHash, Network, PubkeyHash};
use clap::Parser;
use p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow;
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    BCH_PPLNS_WINDOW_BLOCKS, COINBASE_MATURITY, DIFFICULTY_SCALE, PPLNS_WINDOW_SHARES,
};
use p2poolv2_lib::config::Chain;
use p2poolv2_lib::sim_overrides;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::collections::HashMap;
use std::process::ExitCode;

/// Share chain target spacing, seconds.
const SHARE_SECONDS: f64 = 10.0;

/// BCH target block spacing, seconds.
const BLOCK_SECONDS: f64 = 600.0;

/// Shares per day at the 10 s share target.
const SHARES_PER_DAY: usize = 8_640;

/// Days per week, for weekly income.
const DAYS_PER_WEEK: usize = 7;

/// Difficulty of every share. Only its ratio to the block difficulty matters.
const SHARE_DIFFICULTY: u128 = 1_000_000;

/// Day the joining miner starts mining, after the fixed window has filled.
const JOIN_DAY: usize = 20;

/// Day the joining miner stops mining.
const LEAVE_DAY: usize = 40;

/// Miners, by index into every per-miner array.
const STEADY_MINER: usize = 0;
const SMALL_MINER: usize = 1;
const JOINING_MINER: usize = 2;
const REST_OF_POOL: usize = 3;
const MINER_COUNT: usize = 4;

/// Share of the pool's hashrate each named miner holds while mining. The rest
/// of the pool holds whatever is left, so the pool's hashrate, and with it the
/// share and block rates, stays constant.
const STEADY_MINER_FRACTION: f64 = 0.10;
const SMALL_MINER_FRACTION: f64 = 0.001;
const JOINING_MINER_FRACTION: f64 = 0.05;

#[derive(Parser, Debug)]
#[command(about = "Compare the fixed PPLNS window with the BCH difficulty-sized window")]
struct Args {
    /// First random seed. Each pool size runs `seeds` chains from it.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Chains drawn per pool size; the tables average over them.
    #[arg(long, default_value_t = 5)]
    seeds: u64,
    /// Maturity skip in shares, for every rule. A sim-only override of
    /// `COINBASE_MATURITY`, to measure a shorter skip.
    #[arg(long, default_value_t = COINBASE_MATURITY)]
    maturity: usize,
}

/// One pool size to simulate.
struct Regime {
    /// The pool's share of BCH's hashrate.
    network_fraction: f64,
    /// Shares to draw. Enough to leave a few hundred blocks after the warm-up
    /// where the regime finds blocks often enough to have them.
    share_count: usize,
}

const REGIMES: [Regime; 4] = [
    Regime {
        network_fraction: 0.0005,
        share_count: 1_000_000,
    },
    Regime {
        network_fraction: 0.01,
        share_count: 2_000_000,
    },
    Regime {
        network_fraction: 0.10,
        share_count: 600_000,
    },
    Regime {
        network_fraction: 0.30,
        share_count: 600_000,
    },
];

/// A payout rule to compare.
struct Rule {
    name: &'static str,
    /// Expected blocks of work the window holds, or `None` for the fixed
    /// `PPLNS_WINDOW_SHARES` window.
    window_blocks: Option<u128>,
    /// Fraction of each block paid to the miner of the share that found it,
    /// before the window splits the rest, as P2Pool v1 paid 0.5%.
    finder_bonus: f64,
}

const RULES: [Rule; 4] = [
    Rule {
        name: "fixed 120,960",
        window_blocks: None,
        finder_bonus: 0.0,
    },
    Rule {
        name: "BCH K=2",
        window_blocks: Some(2),
        finder_bonus: 0.0,
    },
    Rule {
        name: "BCH K=3 (v1 SPREAD)",
        window_blocks: Some(3),
        finder_bonus: 0.0,
    },
    Rule {
        name: "BCH K=3 + 0.5% finder",
        window_blocks: Some(3),
        finder_bonus: 0.005,
    },
];

/// A drawn share chain: who mined each height and which heights found blocks.
struct DrawnChain {
    miner_by_height: Vec<usize>,
    block_heights: Vec<usize>,
}

/// What one rule paid over one chain.
struct Ledger {
    /// Income per miner per day, indexed `[miner][day]`, each block paying 1.
    income_by_day: Vec<Vec<f64>>,
    /// Shares in each block's window.
    window_shares: Vec<u128>,
    /// Blocks counted.
    blocks: usize,
    /// Blocks whose distribution differs from the fixed window's.
    blocks_differing_from_fixed: usize,
    /// Heights of the first and last blocks that paid the joining miner.
    joiner_first_paid_height: Option<usize>,
    joiner_last_paid_height: Option<usize>,
}

impl Ledger {
    fn new(day_count: usize) -> Self {
        Self {
            income_by_day: vec![vec![0.0; day_count]; MINER_COUNT],
            window_shares: Vec::with_capacity(1024),
            blocks: 0,
            blocks_differing_from_fixed: 0,
            joiner_first_paid_height: None,
            joiner_last_paid_height: None,
        }
    }

    /// Book one block found at `height` by `finder`.
    fn record_block(
        &mut self,
        height: usize,
        finder: usize,
        rule: &Rule,
        weights: &HashMap<Address, u128>,
        miner_by_address: &HashMap<Address, usize>,
    ) {
        let total_weight: u128 = weights.values().sum();
        self.blocks += 1;
        self.window_shares
            .push(total_weight / (DIFFICULTY_SCALE * SHARE_DIFFICULTY));
        let day = height / SHARES_PER_DAY;
        let window_part = 1.0 - rule.finder_bonus;
        for (address, weight) in weights {
            let income = window_part * *weight as f64 / total_weight as f64;
            self.credit(miner_by_address[address], day, height, income);
        }
        if rule.finder_bonus > 0.0 {
            self.credit(finder, day, height, rule.finder_bonus);
        }
    }

    fn credit(&mut self, miner: usize, day: usize, height: usize, income: f64) {
        self.income_by_day[miner][day] += income;
        if miner == JOINING_MINER {
            self.joiner_first_paid_height.get_or_insert(height);
            self.joiner_last_paid_height = Some(height);
        }
    }

    fn total_income(&self, miner: usize) -> f64 {
        self.income_by_day[miner].iter().sum()
    }
}

/// Statistics of one rule over one chain.
struct RuleSummary {
    blocks: usize,
    blocks_differing_from_fixed: usize,
    mean_window_shares: f64,
    steady_daily_variation: f64,
    small_daily_variation: f64,
    small_weekly_variation: f64,
    small_income_over_fair: f64,
    joiner_first_payout_hours: f64,
    joiner_paid_after_leaving_hours: f64,
    joiner_income_over_fair: f64,
}

fn main() -> ExitCode {
    let args = Args::parse();
    sim_overrides::init_coinbase_maturity(args.maturity);
    println!(
        "Fixed window: {PPLNS_WINDOW_SHARES} shares. BCH window: K blocks' worth of work, capped \
         at {PPLNS_WINDOW_SHARES} (the code's K is {BCH_PPLNS_WINDOW_BLOCKS}). Maturity skip {} \
         shares. Seeds {}..{}. Each block pays 1; incomes are fractions of blocks.\n",
        args.maturity,
        args.seed,
        args.seed + args.seeds - 1
    );

    let mut summaries = Vec::with_capacity(REGIMES.len());
    for (regime_index, regime) in REGIMES.iter().enumerate() {
        let mut by_rule: Vec<Vec<RuleSummary>> = RULES
            .iter()
            .map(|_| Vec::with_capacity(args.seeds as usize))
            .collect();
        for seed_offset in 0..args.seeds {
            let seed = args.seed + seed_offset + 1000 * regime_index as u64;
            match run_regime(regime, seed, args.maturity) {
                Ok(rule_summaries) => {
                    for (rule_index, summary) in rule_summaries.into_iter().enumerate() {
                        by_rule[rule_index].push(summary);
                    }
                }
                Err(error) => {
                    eprintln!("regime {}: {error}", regime.network_fraction);
                    return ExitCode::FAILURE;
                }
            }
        }
        summaries.push(by_rule);
    }

    print_delay_table(&summaries, args.maturity);
    print_variance_table(&summaries);
    ExitCode::SUCCESS
}

/// Draw one chain and pay its blocks under every rule.
fn run_regime(regime: &Regime, seed: u64, maturity: usize) -> Result<Vec<RuleSummary>, String> {
    let shares_per_block = BLOCK_SECONDS / SHARE_SECONDS / regime.network_fraction;
    let block_difficulty = (SHARE_DIFFICULTY as f64 * shares_per_block).round() as u128;
    let drawn = draw_chain(regime.share_count, 1.0 / shares_per_block, seed);
    let addresses = miner_addresses();
    let miner_by_address: HashMap<Address, usize> = addresses
        .iter()
        .enumerate()
        .map(|(miner, address)| (address.clone(), miner))
        .collect();

    let entries = window_entries(&drawn, &addresses);
    let mut fixed_window = PplnsWindow::new(Network::Bitcoin);
    fixed_window.populate_for_benchmark(entries.clone());
    let mut sized_window = PplnsWindow::new(Network::Bitcoin).for_chain(Chain::BitcoinCash);
    sized_window.populate_for_benchmark(entries);

    // Skip blocks until the fixed window can fill, so no rule is cut short by
    // the start of the chain.
    let warm_up = maturity + PPLNS_WINDOW_SHARES;
    let day_count = regime.share_count.div_ceil(SHARES_PER_DAY);
    let mut ledgers: Vec<Ledger> = RULES.iter().map(|_| Ledger::new(day_count)).collect();
    for height in drawn
        .block_heights
        .iter()
        .copied()
        .filter(|height| *height >= warm_up)
    {
        let anchor = share_hash(height - 1);
        let fixed = fixed_window
            .distribution_for_cached_anchor(anchor, block_difficulty)
            .map_err(|error| error.to_string())?;
        for (rule, ledger) in RULES.iter().zip(ledgers.iter_mut()) {
            let weights = match rule.window_blocks {
                None => fixed.clone(),
                // The window holds the code's K blocks of the difficulty it is
                // given, so scaling the difficulty by window_blocks / K gives a
                // window of window_blocks blocks.
                Some(window_blocks) => sized_window
                    .distribution_for_cached_anchor(
                        anchor,
                        block_difficulty * window_blocks / BCH_PPLNS_WINDOW_BLOCKS,
                    )
                    .map_err(|error| error.to_string())?,
            };
            if weights != fixed {
                ledger.blocks_differing_from_fixed += 1;
            }
            ledger.record_block(
                height,
                drawn.miner_by_height[height],
                rule,
                &weights,
                &miner_by_address,
            );
        }
    }

    let first_full_day = warm_up.div_ceil(SHARES_PER_DAY);
    let last_full_day = regime.share_count / SHARES_PER_DAY;
    Ok(ledgers
        .iter()
        .map(|ledger| summarize_rule(ledger, shares_per_block, first_full_day, last_full_day))
        .collect())
}

/// Draw the miner of every share and whether it found a block.
fn draw_chain(share_count: usize, block_probability: f64, seed: u64) -> DrawnChain {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut miner_by_height = Vec::with_capacity(share_count);
    let mut block_heights = Vec::with_capacity(share_count / 100);
    let joiner_active = (JOIN_DAY * SHARES_PER_DAY)..(LEAVE_DAY * SHARES_PER_DAY);
    for height in 0..share_count {
        let joiner_fraction = if joiner_active.contains(&height) {
            JOINING_MINER_FRACTION
        } else {
            0.0
        };
        let draw: f64 = rng.random_range(0.0..1.0);
        let miner = if draw < STEADY_MINER_FRACTION {
            STEADY_MINER
        } else if draw < STEADY_MINER_FRACTION + SMALL_MINER_FRACTION {
            SMALL_MINER
        } else if draw < STEADY_MINER_FRACTION + SMALL_MINER_FRACTION + joiner_fraction {
            JOINING_MINER
        } else {
            REST_OF_POOL
        };
        miner_by_height.push(miner);
        if rng.random_range(0.0..1.0) < block_probability {
            block_heights.push(height);
        }
    }
    DrawnChain {
        miner_by_height,
        block_heights,
    }
}

/// One payout address per miner.
fn miner_addresses() -> Vec<Address> {
    (0..MINER_COUNT)
        .map(|miner| {
            Address::p2pkh(
                PubkeyHash::from_byte_array([miner as u8 + 1; 20]),
                Network::Bitcoin,
            )
        })
        .collect()
}

/// A distinct, never all-zero share hash for every height.
fn share_hash(height: usize) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(height as u64 + 1).to_le_bytes());
    BlockHash::from_byte_array(bytes)
}

/// The chain as the window's benchmark loader takes it, newest first.
#[allow(clippy::type_complexity)] // mirrors populate_for_benchmark's argument
fn window_entries(
    drawn: &DrawnChain,
    addresses: &[Address],
) -> Vec<(BlockHash, String, u128, Vec<(String, u128)>)> {
    let address_strings: Vec<String> = addresses.iter().map(Address::to_string).collect();
    (0..drawn.miner_by_height.len())
        .rev()
        .map(|height| {
            (
                share_hash(height),
                address_strings[drawn.miner_by_height[height]].clone(),
                SHARE_DIFFICULTY,
                Vec::new(),
            )
        })
        .collect()
}

fn summarize_rule(
    ledger: &Ledger,
    shares_per_block: f64,
    first_full_day: usize,
    last_full_day: usize,
) -> RuleSummary {
    let measured_days = first_full_day..last_full_day;
    let join_height = JOIN_DAY * SHARES_PER_DAY;
    let leave_height = LEAVE_DAY * SHARES_PER_DAY;
    let joiner_fair =
        JOINING_MINER_FRACTION * (leave_height - join_height) as f64 / shares_per_block;
    RuleSummary {
        blocks: ledger.blocks,
        blocks_differing_from_fixed: ledger.blocks_differing_from_fixed,
        mean_window_shares: ledger.window_shares.iter().sum::<u128>() as f64
            / ledger.window_shares.len().max(1) as f64,
        steady_daily_variation: variation(
            &ledger.income_by_day[STEADY_MINER][measured_days.clone()],
        ),
        small_daily_variation: variation(&ledger.income_by_day[SMALL_MINER][measured_days.clone()]),
        small_weekly_variation: variation(&weekly_totals(
            &ledger.income_by_day[SMALL_MINER][measured_days],
        )),
        small_income_over_fair: ledger.total_income(SMALL_MINER)
            / (SMALL_MINER_FRACTION * ledger.blocks as f64),
        joiner_first_payout_hours: ledger.joiner_first_paid_height.map_or(f64::NAN, |height| {
            shares_to_hours(height as f64 - join_height as f64)
        }),
        joiner_paid_after_leaving_hours: ledger
            .joiner_last_paid_height
            .map_or(f64::NAN, |height| {
                shares_to_hours(height as f64 - leave_height as f64)
            }),
        joiner_income_over_fair: ledger.total_income(JOINING_MINER) / joiner_fair,
    }
}

/// Coefficient of variation: standard deviation over mean.
fn variation(values: &[f64]) -> f64 {
    let (mean, deviation) = mean_and_deviation(values);
    deviation / mean
}

/// Mean and population standard deviation.
fn mean_and_deviation(values: &[f64]) -> (f64, f64) {
    let count = values.len() as f64;
    let mean = values.iter().sum::<f64>() / count;
    let variance = values
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / count;
    (mean, variance.sqrt())
}

/// Sum daily values into whole weeks, dropping a trailing partial week.
fn weekly_totals(daily: &[f64]) -> Vec<f64> {
    let (weeks, _partial_week) = daily.as_chunks::<DAYS_PER_WEEK>();
    weeks.iter().map(|week| week.iter().sum()).collect()
}

fn shares_to_hours(shares: f64) -> f64 {
    shares * SHARE_SECONDS / 3600.0
}

/// One field of a rule's summaries across the seeds.
fn across_seeds(summaries: &[RuleSummary], field: impl Fn(&RuleSummary) -> f64) -> (f64, f64) {
    let values: Vec<f64> = summaries.iter().map(field).collect();
    mean_and_deviation(&values)
}

fn mean_with_deviation(summaries: &[RuleSummary], field: impl Fn(&RuleSummary) -> f64) -> String {
    let (mean, deviation) = across_seeds(summaries, field);
    format!("{mean:.2} ({deviation:.2})")
}

fn print_delay_table(summaries: &[Vec<Vec<RuleSummary>>], maturity: usize) {
    println!(
        "Window and delay. Work-to-pay delay is the maturity skip plus half the window: the mean \
         time from a share to the blocks that pay it. Joiner: a 5% miner who mines from day \
         {JOIN_DAY} to day {LEAVE_DAY}. Hours are means over the seeds; (sd) is the spread \
         across seeds.\n"
    );
    println!(
        "| BCH hashrate share | Rule | Blocks per seed | Window shares | Window hours | \
         Blocks paid unlike fixed | Work-to-pay delay (h) | Joiner first payout (h) | \
         Joiner paid after leaving (h) | Joiner income / fair (sd) |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for (regime, by_rule) in REGIMES.iter().zip(summaries) {
        for (rule, rule_summaries) in RULES.iter().zip(by_rule) {
            let (blocks, _) = across_seeds(rule_summaries, |summary| summary.blocks as f64);
            let (differing, _) = across_seeds(rule_summaries, |summary| {
                summary.blocks_differing_from_fixed as f64
            });
            let (window_shares, _) =
                across_seeds(rule_summaries, |summary| summary.mean_window_shares);
            let (first_payout, _) =
                across_seeds(rule_summaries, |summary| summary.joiner_first_payout_hours);
            let (after_leaving, _) = across_seeds(rule_summaries, |summary| {
                summary.joiner_paid_after_leaving_hours
            });
            let work_to_pay = shares_to_hours(maturity as f64 + window_shares / 2.0);
            println!(
                "| {:.2}% | {} | {blocks:.0} | {window_shares:.0} | {:.1} | {differing:.0} | \
                 {work_to_pay:.1} | {first_payout:.1} | {after_leaving:.1} | {} |",
                regime.network_fraction * 100.0,
                rule.name,
                shares_to_hours(window_shares),
                mean_with_deviation(rule_summaries, |summary| summary.joiner_income_over_fair),
            );
        }
    }
}

fn print_variance_table(summaries: &[Vec<Vec<RuleSummary>>]) {
    println!(
        "\nIncome variation: coefficient of variation (standard deviation over mean) of each \
         miner's income per day or week, mean over the seeds with (sd) across seeds. Income / \
         fair is total income over the miner's hashrate share of all blocks.\n"
    );
    println!(
        "| BCH hashrate share | Rule | 10% miner daily CV | 0.1% miner daily CV | \
         0.1% miner weekly CV | 0.1% miner income / fair |"
    );
    println!("|---|---|---|---|---|---|");
    for (regime, by_rule) in REGIMES.iter().zip(summaries) {
        for (rule, rule_summaries) in RULES.iter().zip(by_rule) {
            println!(
                "| {:.2}% | {} | {} | {} | {} | {} |",
                regime.network_fraction * 100.0,
                rule.name,
                mean_with_deviation(rule_summaries, |summary| summary.steady_daily_variation),
                mean_with_deviation(rule_summaries, |summary| summary.small_daily_variation),
                mean_with_deviation(rule_summaries, |summary| summary.small_weekly_variation),
                mean_with_deviation(rule_summaries, |summary| summary.small_income_over_fair),
            );
        }
    }
}
