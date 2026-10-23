// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::args::{Cli, parse_fee_rate};
use super::commands::{Command, PsbtCommand, TxCommand};
use clap::{CommandFactory, error::ErrorKind};
use std::path::PathBuf;

#[test]
fn command_definitions_are_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn action_option_before_object_preserves_its_value() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--psbt.file",
        "tx",
        "psbt",
        "sign",
        "--wallet",
        "alice",
    ])
    .unwrap();
    let Command::Psbt(PsbtCommand::Sign(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.input.input.psbt_file, Some(PathBuf::from("tx")));
    assert_eq!(parsed.wallet.as_deref(), Some("alice"));
}

#[test]
fn options_between_object_and_action_are_parsed() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "psbt",
        "--psbt.base64",
        "sign",
        "--wallet",
        "alice",
        "sign",
    ])
    .unwrap();
    let Command::Psbt(PsbtCommand::Sign(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.input.input.psbt_base64.as_deref(), Some("sign"));
}

#[test]
fn global_options_after_action_reach_root_fields() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "address",
        "new",
        "--wallet",
        "alice",
        "--network",
        "regtest",
        "--datadir",
        "my wallet",
    ])
    .unwrap();
    assert_eq!(parsed.wallet.as_deref(), Some("alice"));
    assert_eq!(parsed.network, bitcoin::Network::Regtest);
    assert_eq!(parsed.datadir, Some(PathBuf::from("my wallet")));
}

#[test]
fn equals_and_attached_short_values_are_preserved() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--psbt.base64=cHNidP8=",
        "-walice",
        "-nsignet",
        "psbt",
        "sign",
    ])
    .unwrap();
    let Command::Psbt(PsbtCommand::Sign(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(
        arguments.input.input.psbt_base64.as_deref(),
        Some("cHNidP8=")
    );
    assert_eq!(parsed.wallet.as_deref(), Some("alice"));
}

#[test]
fn short_cluster_keeps_attached_value() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "-awalice",
        "tx",
        "build",
        "--to",
        "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x:0",
    ])
    .unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert!(arguments.send_all);
    assert_eq!(parsed.wallet.as_deref(), Some("alice"));
}

#[test]
fn psbt_input_formats_are_mutually_exclusive_across_positions() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--psbt.file",
        "input.psbt",
        "psbt",
        "inspect",
        "--psbt.hex",
        "00",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn broadcast_rejects_transaction_and_psbt_together() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--psbt.base64",
        "mock",
        "tx",
        "broadcast",
        "--tx.hex",
        "00",
        "--wallet",
        "alice",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn explicit_psbt_source_is_required() {
    let error = Cli::try_parse_anywhere(["p2pool-wallet", "psbt", "inspect"])
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn raw_transaction_broadcast_does_not_require_a_psbt() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--tx.hex",
        "00",
        "tx",
        "broadcast",
        "--wallet",
        "alice",
    ])
    .unwrap();
    assert_eq!(parsed.command.name(), "tx broadcast");
}

#[test]
fn irrelevant_action_option_is_rejected_even_before_object() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--fee-rate",
        "1",
        "address",
        "new",
        "--wallet",
        "alice",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::UnknownArgument);
}

#[test]
fn terminator_prevents_flags_from_being_reinterpreted() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--",
        "--psbt.file",
        "input.psbt",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::UnknownArgument);
}

#[test]
fn repeated_scalar_option_is_not_silently_overridden() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--wallet",
        "alice",
        "balance",
        "show",
        "--wallet",
        "bob",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn wallet_selection_is_required_for_wallet_operations() {
    let error = Cli::try_parse_anywhere(["p2pool-wallet", "balance", "show"])
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn psbt_inspection_accepts_a_path_without_opening_it_or_loading_a_wallet() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--psbt.file",
        "nonexistent.psbt",
    ])
    .unwrap();
    assert_eq!(parsed.command.name(), "psbt inspect");
    assert!(parsed.wallet.is_none());
}

#[test]
fn recipient_network_is_checked_after_reordered_network_option() {
    let error = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--to",
        "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x:10",
        "tx",
        "build",
        "--wallet",
        "alice",
        "--network",
        "regtest",
    ])
    .err()
    .unwrap();
    assert_eq!(error.kind(), ErrorKind::ValueValidation);
}

#[test]
fn repeated_recipients_keep_order_across_command_words() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "--to",
        "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x:10",
        "tx",
        "--to",
        "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x:20",
        "build",
        "--wallet",
        "alice",
        "--enable-rbf",
        "false",
    ])
    .unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.recipients[0].amount, 10);
    assert_eq!(arguments.recipients[1].amount, 20);
    assert!(!arguments.enable_rbf);
}

#[test]
fn completion_generation_accepts_shell_before_command() {
    let parsed =
        Cli::try_parse_anywhere(["p2pool-wallet", "--shell", "zsh", "completion", "generate"])
            .unwrap();
    assert_eq!(parsed.command.name(), "completion generate");
    assert!(parsed.wallet.is_none());
}

#[test]
fn leaf_help_is_available_without_wallet_or_input() {
    let error = Cli::try_parse_anywhere(["p2pool-wallet", "psbt", "sign", "--help"])
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::DisplayHelp);
    assert!(error.to_string().contains("--psbt.file"));
}

#[test]
fn fee_rate_uses_bdk_fixed_units_and_rounding() {
    let rate = parse_fee_rate(" 1.234 ").unwrap();
    assert_eq!(rate.to_sat_per_kwu(), 309);
}

#[test]
fn minimum_bdk_fee_rate_is_representable() {
    let rate = parse_fee_rate("0.004").unwrap();
    assert_eq!(rate.to_sat_per_kwu(), 1);
}

#[test]
fn fee_rate_below_bdk_minimum_is_rejected() {
    assert!(parse_fee_rate("0.0039").is_err());
}

#[test]
fn zero_fee_rate_is_rejected_like_bdk_cli() {
    assert!(parse_fee_rate("0").is_err());
}

#[test]
fn nonfinite_fee_rate_is_rejected() {
    assert!(parse_fee_rate("NaN").is_err());
    assert!(parse_fee_rate("inf").is_err());
}

#[test]
fn overflowing_fee_rate_is_rejected() {
    assert!(parse_fee_rate("1e100").is_err());
}

#[test]
fn build_arguments_store_bdk_types_and_preserve_optional_input_selection() {
    let parsed = Cli::try_parse_anywhere([
        "p2pool-wallet",
        "tx",
        "build",
        "--wallet",
        "alice",
        "--to",
        "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x:10",
        "--fee-rate",
        "1.25",
        "--utxos",
        "0000000000000000000000000000000000000000000000000000000000000000:0",
        "--utxos",
        "0000000000000000000000000000000000000000000000000000000000000000:1",
    ])
    .unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.fee_rate.unwrap().to_sat_per_kwu(), 313);
    let outpoints = arguments.utxos.unwrap();
    assert_eq!(outpoints.len(), 2);
    assert_eq!(outpoints[0].vout, 0);
    assert_eq!(outpoints[1].vout, 1);
    assert!(arguments.unspendable.is_none());
}
