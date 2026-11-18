// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Share chain forks: consensus rule changes that activate at a share chain
//! height.
//!
//! A share at height `h` follows the rules of every fork whose activation
//! height is at or below `h`. Nodes that sync the chain apply the old rules
//! below the activation height and the new rules from it on, so one binary
//! validates the whole chain.
//!
//! Each network's activation heights are compiled in, one file per network,
//! like Bitcoin's chainparams. The `[forks]` config section can override them
//! for a single node, which is meant for private and test networks: a node
//! whose heights differ from its peers' disagrees with them on share validity
//! and splits from the network. See docs/architecture/forks.md.

mod main;
mod regtest;
mod signet;
mod testnet3;
mod testnet4;
mod testnet5;

use crate::config::{Chain, ForksConfig};
use std::fmt;
use tracing::{info, warn};

/// A consensus rule change activated by share chain height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fork {
    /// The coinbase carries at most a fixed number of miner outputs. Payouts
    /// use the raffled tail split: the largest miners are paid exactly and
    /// the remaining outputs are raffled among the other miners.
    CappedCoinbase,
}

impl Fork {
    /// Name used in logs and in the `[forks]` config keys.
    pub const fn as_str(self) -> &'static str {
        match self {
            Fork::CappedCoinbase => "capped_coinbase",
        }
    }
}

impl fmt::Display for Fork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Activation height of every fork for one node.
///
/// `None` means the fork is not scheduled and never activates. Each network
/// file builds its schedule as a struct literal, so adding a fork to this
/// struct does not compile until every network sets a height for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkSchedule {
    capped_coinbase_height: Option<u32>,
}

impl ForkSchedule {
    /// A schedule with explicit heights. Tests use it to place an activation
    /// height next to the shares they build.
    pub const fn new(capped_coinbase_height: Option<u32>) -> Self {
        Self {
            capped_coinbase_height,
        }
    }

    /// The schedule compiled in for a chain.
    pub fn for_chain(chain: Chain) -> Self {
        match chain {
            Chain::Main => main::SCHEDULE,
            Chain::Testnet3 => testnet3::SCHEDULE,
            Chain::Testnet4 => testnet4::SCHEDULE,
            Chain::Testnet5 => testnet5::SCHEDULE,
            Chain::Signet => signet::SCHEDULE,
            Chain::Regtest => regtest::SCHEDULE,
        }
    }

    /// This schedule with every height set in `overrides` replacing the
    /// compiled-in one. Heights left unset in `overrides` keep their value.
    pub fn with_overrides(self, overrides: &ForksConfig) -> Self {
        Self {
            capped_coinbase_height: overrides
                .capped_coinbase_height
                .or(self.capped_coinbase_height),
        }
    }

    /// Height from which `fork` applies, or `None` if it is not scheduled.
    pub const fn activation_height(&self, fork: Fork) -> Option<u32> {
        match fork {
            Fork::CappedCoinbase => self.capped_coinbase_height,
        }
    }

    /// Whether a share at `share_height` follows the rules of `fork`.
    pub fn is_active(&self, fork: Fork, share_height: u32) -> bool {
        self.activation_height(fork)
            .is_some_and(|activation_height| share_height >= activation_height)
    }
}

/// Build the fork schedule a node runs with: the chain's compiled-in heights
/// with the config overrides applied.
///
/// Logs a warning for each overridden fork, because a node whose heights
/// differ from the rest of the network splits from it, then logs the
/// resulting schedule.
pub fn build_fork_schedule(chain: Chain, overrides: &ForksConfig) -> ForkSchedule {
    let defaults = ForkSchedule::for_chain(chain);
    let schedule = defaults.with_overrides(overrides);
    warn_if_overridden(chain, Fork::CappedCoinbase, &defaults, &schedule);
    info!(
        "Fork schedule for {chain}: {}",
        describe_activation(Fork::CappedCoinbase, &schedule)
    );
    schedule
}

/// Warn when `fork` activates at a different height than the chain's default.
fn warn_if_overridden(chain: Chain, fork: Fork, defaults: &ForkSchedule, schedule: &ForkSchedule) {
    let default_height = defaults.activation_height(fork);
    let configured_height = schedule.activation_height(fork);
    if configured_height != default_height {
        warn!(
            "Fork {fork} activation height on {chain} overridden by config: default {default_height:?}, using {configured_height:?}. \
             Nodes using different fork heights reject each other's shares and split the network."
        );
    }
}

/// One fork's activation height, formatted for the startup log.
fn describe_activation(fork: Fork, schedule: &ForkSchedule) -> String {
    match schedule.activation_height(fork) {
        Some(height) => format!("{fork} at height {height}"),
        None => format!("{fork} not scheduled"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_schedule_has_no_capped_coinbase() {
        let schedule = ForkSchedule::for_chain(Chain::Main);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), None);
    }

    #[test]
    fn test_testnet3_schedule_has_no_capped_coinbase() {
        let schedule = ForkSchedule::for_chain(Chain::Testnet3);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), None);
    }

    #[test]
    fn test_testnet4_schedule_has_no_capped_coinbase() {
        let schedule = ForkSchedule::for_chain(Chain::Testnet4);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), None);
    }

    #[test]
    fn test_testnet5_schedule_activates_capped_coinbase_at_60000() {
        let schedule = ForkSchedule::for_chain(Chain::Testnet5);
        assert_eq!(
            schedule.activation_height(Fork::CappedCoinbase),
            Some(60_000)
        );
    }

    #[test]
    fn test_signet_schedule_activates_capped_coinbase_from_genesis() {
        let schedule = ForkSchedule::for_chain(Chain::Signet);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), Some(0));
    }

    #[test]
    fn test_regtest_schedule_activates_capped_coinbase_from_genesis() {
        let schedule = ForkSchedule::for_chain(Chain::Regtest);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), Some(0));
    }

    #[test]
    fn test_fork_is_inactive_below_activation_height() {
        let schedule = ForkSchedule::new(Some(100));
        assert!(!schedule.is_active(Fork::CappedCoinbase, 99));
    }

    #[test]
    fn test_fork_is_active_at_activation_height() {
        let schedule = ForkSchedule::new(Some(100));
        assert!(schedule.is_active(Fork::CappedCoinbase, 100));
    }

    #[test]
    fn test_fork_is_active_above_activation_height() {
        let schedule = ForkSchedule::new(Some(100));
        assert!(schedule.is_active(Fork::CappedCoinbase, 101));
    }

    #[test]
    fn test_unscheduled_fork_is_never_active() {
        let schedule = ForkSchedule::new(None);
        assert!(!schedule.is_active(Fork::CappedCoinbase, 0));
        assert!(!schedule.is_active(Fork::CappedCoinbase, u32::MAX));
    }

    #[test]
    fn test_override_replaces_default_height() {
        let overrides = ForksConfig {
            capped_coinbase_height: Some(250),
        };
        let schedule = build_fork_schedule(Chain::Testnet5, &overrides);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), Some(250));
    }

    #[test]
    fn test_override_schedules_fork_the_network_left_unscheduled() {
        let overrides = ForksConfig {
            capped_coinbase_height: Some(10),
        };
        let schedule = build_fork_schedule(Chain::Main, &overrides);
        assert_eq!(schedule.activation_height(Fork::CappedCoinbase), Some(10));
    }

    #[test]
    fn test_no_override_keeps_default_height() {
        let schedule = build_fork_schedule(Chain::Testnet5, &ForksConfig::default());
        assert_eq!(schedule, ForkSchedule::for_chain(Chain::Testnet5));
    }
}
