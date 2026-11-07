// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::commands::Command;
use bitcoin::Network;
use clap::{Parser, ValueHint};
use std::path::PathBuf;

/// Wallet command-line arguments.
#[derive(Parser)]
#[command(
    name = "p2pool-wallet",
    version,
    about = "P2Poolv2 wallet CLI skeleton (wallet operations not implemented)"
)]
pub struct Cli {
    /// Share network: main, testnet4, signet, or regtest.
    #[arg(short = 'n', long, global = true, default_value = "signet", value_parser = parse_network)]
    pub network: Network,

    /// Wallet data directory.
    #[arg(short = 'd', long, global = true, value_hint = ValueHint::DirPath)]
    pub datadir: Option<PathBuf>,

    /// Wallet to use; required for operations on a configured wallet.
    #[arg(short = 'w', long, global = true)]
    pub wallet: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// Parse a supported P2Pool network.
fn parse_network(value: &str) -> Result<Network, String> {
    let network = Network::from_core_arg(value).map_err(|_| {
        format!("unknown network '{value}', expected main, testnet4, signet or regtest")
    })?;
    match network {
        Network::Bitcoin | Network::Testnet4 | Network::Signet | Network::Regtest => Ok(network),
        _ => Err("expected main, testnet4, signet or regtest; testnet3 is unsupported".into()),
    }
}
