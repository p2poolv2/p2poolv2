// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::commands::{Command, TxCommand};
use crate::Address;
use bitcoin::{FeeRate, Network};
use clap::{CommandFactory, Parser, ValueHint, error::ErrorKind};
use std::path::PathBuf;

// One kiloweight unit equals 250 virtual bytes.
const FEE_RATE_SCALE: f64 = 250.0;
const MIN_FEE_RATE: f64 = 1.0 / FEE_RATE_SCALE;

/// Wallet command-line arguments.
#[derive(Parser)]
#[command(
    name = "p2pool-wallet",
    version,
    about = "P2Poolv2 wallet CLI skeleton (wallet operations not implemented)"
)]
pub struct Cli {
    /// Share network: bitcoin (mainnet), testnet4, signet, or regtest.
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

impl Cli {
    /// Validate wallet selection and destination networks.
    pub fn validate(&self) -> Result<(), clap::Error> {
        let mut definition = Self::command();
        if self.command.requires_wallet() && self.wallet.as_deref().is_none_or(str::is_empty) {
            return Err(definition.error(
                ErrorKind::MissingRequiredArgument,
                format!("--wallet <NAME> is required for {}", self.command.name()),
            ));
        }
        if let Command::Tx(TxCommand::Build(transaction)) = &self.command {
            for recipient in &transaction.recipients {
                recipient
                    .address
                    .require_network(self.network)
                    .map_err(|error| {
                        definition.error(ErrorKind::ValueValidation, error.to_string())
                    })?;
            }
            if let Some(address) = &transaction.drain_to {
                address.require_network(self.network).map_err(|error| {
                    definition.error(ErrorKind::ValueValidation, error.to_string())
                })?;
            }
        }
        Ok(())
    }
}

/// A P2Pool recipient address and amount in share base units.
#[derive(Clone)]
pub struct Recipient {
    pub address: Address,
    pub amount: u64,
}

/// Parse a supported P2Pool network.
fn parse_network(value: &str) -> Result<Network, String> {
    let network = value
        .parse::<Network>()
        .map_err(|error| error.to_string())?;
    match network {
        Network::Bitcoin | Network::Testnet4 | Network::Signet | Network::Regtest => Ok(network),
        _ => Err("expected bitcoin, testnet4, signet or regtest; testnet3 is unsupported".into()),
    }
}

/// Parse ADDRESS:AMOUNT with a positive integer amount in share base units.
pub fn parse_recipient(value: &str) -> Result<Recipient, String> {
    let (address, amount) = value
        .rsplit_once(':')
        .ok_or("expected ADDRESS:AMOUNT in share base units")?;
    let recipient = Recipient {
        address: address
            .parse::<Address>()
            .map_err(|error| error.to_string())?,
        amount: amount.parse::<u64>().map_err(|error| error.to_string())?,
    };
    if recipient.amount == 0 {
        return Err("recipient amount must be greater than zero; use --drain-to ADDRESS for remaining funds".into());
    }
    Ok(recipient)
}

/// Parse share base units per virtual byte into a fee rate.
///
/// Rates must be finite and at least 0.004. Values are rounded to the nearest
/// share base unit per 1,000 weight units. Overflow is rejected.
pub fn parse_fee_rate(value: &str) -> Result<FeeRate, String> {
    let rate = value
        .trim()
        .parse::<f64>()
        .map_err(|error| error.to_string())?;
    if !rate.is_finite() {
        return Err("fee rate must be finite".into());
    }
    if rate < MIN_FEE_RATE {
        return Err(format!(
            "fee rate must be at least {MIN_FEE_RATE} share base units/vbyte"
        ));
    }
    let rate_per_kwu = (rate * FEE_RATE_SCALE).round();
    if rate_per_kwu >= u64::MAX as f64 {
        return Err("fee rate is too large to represent".into());
    }
    Ok(FeeRate::from_sat_per_kwu(rate_per_kwu as u64))
}
