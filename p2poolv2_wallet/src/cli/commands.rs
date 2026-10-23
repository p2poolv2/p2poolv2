// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::args::{Recipient, parse_fee_rate, parse_recipient};
use bitcoin::{FeeRate, OutPoint};
use clap::{ArgAction, ArgGroup, Args, Subcommand, ValueEnum, ValueHint};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum Command {
    /// Import, discover, and synchronize wallets.
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Derive receiving addresses.
    #[command(subcommand)]
    Address(AddressCommand),
    /// Export wallet descriptors.
    #[command(subcommand)]
    Descriptor(DescriptorCommand),
    /// Inspect wallet balances.
    #[command(subcommand)]
    Balance(BalanceCommand),
    /// Inspect unspent outputs.
    #[command(subcommand)]
    Utxo(UtxoCommand),
    /// List, build, and broadcast transactions.
    #[command(subcommand)]
    Tx(TxCommand),
    /// Inspect, sign, finalize, and extract PSBTs.
    #[command(subcommand)]
    Psbt(PsbtCommand),
    /// Generate shell completion scripts.
    #[command(subcommand)]
    Completion(CompletionCommand),
}

impl Command {
    /// Return the object/action command name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Wallet(command) => match command {
                WalletCommand::Import(_) => "wallet import",
                WalletCommand::List => "wallet list",
                WalletCommand::Scan(_) => "wallet scan",
                WalletCommand::Sync => "wallet sync",
            },
            Self::Address(command) => match command {
                AddressCommand::New => "address new",
                AddressCommand::Unused => "address unused",
            },
            Self::Descriptor(DescriptorCommand::Export) => "descriptor export",
            Self::Balance(BalanceCommand::Show) => "balance show",
            Self::Utxo(UtxoCommand::List) => "utxo list",
            Self::Tx(command) => match command {
                TxCommand::List => "tx list",
                TxCommand::Build(_) => "tx build",
                TxCommand::Broadcast(_) => "tx broadcast",
            },
            Self::Psbt(command) => match command {
                PsbtCommand::Inspect(_) => "psbt inspect",
                PsbtCommand::Sign(_) => "psbt sign",
                PsbtCommand::Finalize(_) => "psbt finalize",
                PsbtCommand::Extract(_) => "psbt extract",
            },
            Self::Completion(CompletionCommand::Generate { .. }) => "completion generate",
        }
    }

    /// Return whether the command requires a selected wallet.
    pub fn requires_wallet(&self) -> bool {
        !matches!(
            self,
            Self::Wallet(WalletCommand::List)
                | Self::Psbt(PsbtCommand::Inspect(_) | PsbtCommand::Extract(_))
                | Self::Completion(_)
        )
    }
}

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Import wallet descriptors and configure the Electrum backend.
    Import(ImportArgs),
    /// List saved wallet configurations.
    List,
    /// Discover descriptor activity, stopping at the configured unused gap.
    Scan(ScanArgs),
    /// Update chain state and transactions for revealed addresses.
    Sync,
}

#[derive(Subcommand)]
pub enum AddressCommand {
    /// Derive and record a new external receiving address.
    New,
    /// Get the first unused external receiving address.
    Unused,
}

#[derive(Subcommand)]
pub enum DescriptorCommand {
    /// Export public wallet descriptors.
    Export,
}

#[derive(Subcommand)]
pub enum BalanceCommand {
    /// Show wallet balances in share base units.
    Show,
}

#[derive(Subcommand)]
pub enum UtxoCommand {
    /// List wallet unspent outputs.
    List,
}

#[derive(Subcommand)]
pub enum TxCommand {
    /// List incoming and outgoing wallet transactions.
    List,
    /// Build an unsigned PSBT from recipients and input preferences.
    Build(Box<BuildArgs>),
    /// Submit transaction hex, a transaction file, or a finalized PSBT.
    Broadcast(BroadcastArgs),
}

#[derive(Subcommand)]
pub enum PsbtCommand {
    /// Inspect a PSBT's inputs, outputs, and metadata.
    Inspect(PsbtArgs),
    /// Sign a PSBT and attempt finalization.
    Sign(SignArgs),
    /// Finalize a sufficiently signed PSBT.
    Finalize(SignArgs),
    /// Extract a raw transaction from a finalized PSBT.
    Extract(PsbtArgs),
}

#[derive(Subcommand)]
pub enum CompletionCommand {
    /// Print a shell completion script to stdout.
    Generate {
        /// Shell for which to generate completions.
        #[arg(long, value_enum)]
        shell: Shell,
    },
}

#[derive(Clone, ValueEnum)]
pub enum ClientType {
    Electrum,
}

#[derive(Clone, ValueEnum)]
pub enum DatabaseType {
    Sqlite,
}

#[derive(Args)]
pub struct ImportArgs {
    /// External receiving descriptor, or a multipath descriptor.
    #[arg(short = 'e', long)]
    pub ext_descriptor: String,
    /// Optional internal/change descriptor.
    #[arg(short = 'i', long)]
    pub int_descriptor: Option<String>,
    /// Wallet backend type.
    #[arg(short = 'c', long, value_enum, default_value = "electrum")]
    pub client_type: ClientType,
    /// Wallet database type.
    #[arg(long, value_enum, default_value = "sqlite")]
    pub database_type: DatabaseType,
    /// Electrum server URL.
    #[arg(short = 'u', long, value_hint = ValueHint::Url)]
    pub url: String,
    /// Maximum number of queries per Electrum batch.
    #[arg(short = 'b', long, default_value_t = 10)]
    pub batch_size: usize,
    /// Replace an existing wallet configuration.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Stop after this many consecutive unused addresses.
    #[arg(long, default_value_t = 20)]
    pub stop_gap: usize,
    /// Number of requests to run in parallel.
    #[arg(long, default_value_t = 5)]
    pub parallel_request: usize,
}

#[derive(Args)]
pub struct BuildArgs {
    /// Recipient as ADDRESS:AMOUNT in integer share base units; repeatable.
    #[arg(long = "to", required = true, value_name = "ADDRESS:AMOUNT", value_parser = parse_recipient)]
    pub recipients: Vec<Recipient>,
    /// Send all selected funds; requires one recipient with amount 0.
    #[arg(short = 'a', long)]
    pub send_all: bool,
    /// Request replace-by-fee signalling (true or false).
    #[arg(long, action = ArgAction::Set, default_value_t = true)]
    pub enable_rbf: bool,
    /// Include PSBT metadata needed by offline signers.
    #[arg(long)]
    pub offline_signer: bool,
    /// Outpoint that must be selected, TXID:VOUT; repeatable.
    #[arg(long, value_name = "TXID:VOUT")]
    pub utxos: Option<Vec<OutPoint>>,
    /// Outpoint to exclude, TXID:VOUT; repeatable.
    #[arg(long, value_name = "TXID:VOUT")]
    pub unspendable: Option<Vec<OutPoint>>,
    /// Fee rate in share base units per virtual byte.
    #[arg(short = 'f', long, value_parser = parse_fee_rate)]
    pub fee_rate: Option<FeeRate>,
    /// External descriptor spending-policy selection.
    #[arg(long)]
    pub external_policy: Option<String>,
    /// Internal descriptor spending-policy selection.
    #[arg(long)]
    pub internal_policy: Option<String>,
    /// Optional UTF-8 OP_RETURN data.
    #[arg(short = 's', long, conflicts_with = "add_data")]
    pub add_string: Option<String>,
    /// Optional base64 OP_RETURN data.
    #[arg(short = 'o', long, conflicts_with = "add_string")]
    pub add_data: Option<String>,
}

/// PSBT input source and encoding.
#[derive(Args)]
#[group(multiple = false)]
pub struct PsbtInput {
    /// Path to a binary PSBT file.
    #[arg(long = "psbt.file", value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub psbt_file: Option<PathBuf>,
    /// PSBT serialized as base64 text.
    #[arg(long = "psbt.base64", value_name = "BASE64")]
    pub psbt_base64: Option<String>,
    /// PSBT serialized as hexadecimal text.
    #[arg(long = "psbt.hex", value_name = "HEX")]
    pub psbt_hex: Option<String>,
}

#[derive(Args)]
#[command(group(ArgGroup::new("required_psbt").required(true).args(["psbt_file", "psbt_base64", "psbt_hex"])))]
pub struct PsbtArgs {
    #[command(flatten)]
    pub input: PsbtInput,
}

#[derive(Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub input: PsbtArgs,
    /// Assumed sharechain height for timelock satisfaction.
    #[arg(long)]
    pub assume_height: Option<u32>,
    /// Whether to trust witness_utxo without non_witness_utxo.
    #[arg(long)]
    pub trust_witness_utxo: Option<bool>,
}

#[derive(Args)]
#[command(group(ArgGroup::new("broadcast_input").required(true).args(["psbt_file", "psbt_base64", "psbt_hex", "tx_hex", "tx_file"])))]
pub struct BroadcastArgs {
    #[command(flatten)]
    pub input: PsbtInput,
    /// Raw transaction hex.
    #[arg(long = "tx.hex", value_name = "HEX")]
    pub tx_hex: Option<String>,
    /// Path to a binary transaction file.
    #[arg(long = "tx.file", value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub tx_file: Option<PathBuf>,
}
