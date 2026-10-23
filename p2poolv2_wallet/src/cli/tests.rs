// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::args::{Cli, parse_fee_rate};
use super::commands::{Command, TxCommand};
use clap::{CommandFactory, Parser, error::ErrorKind};
use clap_complete::{Shell, generate};

const ADDRESS: &str = "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x";

#[test]
fn build_destinations_are_typed_positive_and_network_checked() {
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--to",
        &format!("{ADDRESS}:10"),
        "--to",
        &format!("{ADDRESS}:20"),
        "-walice",
        "--drain-to",
        ADDRESS,
        "--fee-rate",
        "1.25",
        "--utxos",
        "0000000000000000000000000000000000000000000000000000000000000000:1",
    ])
    .unwrap();
    parsed.validate().unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = parsed.command else {
        panic!("wrong action")
    };
    assert_eq!(arguments.recipients.len(), 2);
    assert_eq!(arguments.recipients[0].amount, 10);
    assert_eq!(arguments.recipients[1].amount, 20);
    assert_eq!(arguments.drain_to.unwrap().to_string(), ADDRESS);
    assert_eq!(arguments.fee_rate.unwrap().to_sat_per_kwu(), 313);
    assert_eq!(arguments.utxos.unwrap()[0].vout, 1);
    assert!(arguments.unspendable.is_none());

    let drain_only = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--drain-to",
        ADDRESS,
        "-walice",
    ])
    .unwrap();
    let Command::Tx(TxCommand::Build(arguments)) = drain_only.command else {
        panic!("wrong action")
    };
    assert!(arguments.recipients.is_empty());
    assert!(arguments.drain_to.is_some());
    let missing = Cli::try_parse_from(["p2pool-wallet", "tx", "build", "-walice"])
        .err()
        .unwrap();
    assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
    let zero = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "-walice",
        "--to",
        &format!("{ADDRESS}:0"),
    ])
    .err()
    .unwrap();
    assert_eq!(zero.kind(), ErrorKind::ValueValidation);
    assert!(
        zero.to_string()
            .contains("recipient amount must be greater than zero")
    );
    let wrong_recipient_network = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--to",
        &format!("{ADDRESS}:10"),
        "-walice",
        "--network",
        "regtest",
    ])
    .unwrap()
    .validate()
    .unwrap_err();
    assert_eq!(wrong_recipient_network.kind(), ErrorKind::ValueValidation);
    let wrong_drain_network = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "build",
        "--drain-to",
        ADDRESS,
        "-walice",
        "--network",
        "regtest",
    ])
    .unwrap()
    .validate()
    .unwrap_err();
    assert_eq!(wrong_drain_network.kind(), ErrorKind::ValueValidation);
}

#[test]
fn wallet_and_psbt_requirements_follow_the_selected_operation() {
    let missing_wallet = Cli::try_parse_from(["p2pool-wallet", "balance", "show"])
        .unwrap()
        .validate()
        .unwrap_err();
    assert_eq!(missing_wallet.kind(), ErrorKind::MissingRequiredArgument);
    let inspect = Cli::try_parse_from([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--psbt.file",
        "nonexistent.psbt",
    ])
    .unwrap();
    assert!(inspect.wallet.is_none());
    inspect.validate().unwrap();
    let missing_source = Cli::try_parse_from(["p2pool-wallet", "psbt", "inspect"])
        .err()
        .unwrap();
    assert_eq!(missing_source.kind(), ErrorKind::MissingRequiredArgument);
    let ambiguous_source = Cli::try_parse_from([
        "p2pool-wallet",
        "psbt",
        "inspect",
        "--psbt.file",
        "input.psbt",
        "--psbt.hex",
        "00",
    ])
    .err()
    .unwrap();
    assert_eq!(ambiguous_source.kind(), ErrorKind::ArgumentConflict);
    let ambiguous_broadcast = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "broadcast",
        "--psbt.base64",
        "mock",
        "--tx.hex",
        "00",
        "-walice",
    ])
    .err()
    .unwrap();
    assert_eq!(ambiguous_broadcast.kind(), ErrorKind::ArgumentConflict);
    let broadcast = Cli::try_parse_from([
        "p2pool-wallet",
        "tx",
        "broadcast",
        "--tx.hex",
        "00",
        "-walice",
    ])
    .unwrap();
    assert_eq!(broadcast.command.name(), "tx broadcast");
}

#[test]
fn fee_rate_conversion_enforces_precision_and_range() {
    assert_eq!(parse_fee_rate(" 1.234 ").unwrap().to_sat_per_kwu(), 309);
    assert_eq!(parse_fee_rate("0.004").unwrap().to_sat_per_kwu(), 1);
    assert!(parse_fee_rate("0.0039").is_err());
    assert!(parse_fee_rate("NaN").is_err());
    assert!(parse_fee_rate("inf").is_err());
    assert!(parse_fee_rate("1e100").is_err());
}

#[test]
fn help_and_completion_expose_commands_without_a_wallet() {
    Cli::command().debug_assert();
    let help = Cli::try_parse_from(["p2pool-wallet", "tx", "build", "--help"])
        .err()
        .unwrap();
    assert_eq!(help.kind(), ErrorKind::DisplayHelp);
    assert!(help.to_string().contains("--drain-to"));
    let completion =
        Cli::try_parse_from(["p2pool-wallet", "completion", "generate", "--shell", "zsh"]).unwrap();
    assert!(completion.wallet.is_none());
    completion.validate().unwrap();
    assert_eq!(completion.command.name(), "completion generate");
    let mut output = Vec::with_capacity(4096);
    generate(
        Shell::Zsh,
        &mut Cli::command(),
        "p2pool-wallet",
        &mut output,
    );
    let script = String::from_utf8(output).unwrap();
    assert!(script.contains("--drain-to"));
    assert!(!script.contains("--send-all"));
}
