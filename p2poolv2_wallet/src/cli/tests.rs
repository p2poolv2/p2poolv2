// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::args::Cli;
use super::commands::{Command, CompletionCommand};
use bitcoin::Network;
use clap::{CommandFactory, Parser, error::ErrorKind};
use clap_complete::Shell;
use std::path::Path;

#[test]
fn global_options_parse_before_and_after_the_subcommand() {
    Cli::command().debug_assert();
    let parsed = Cli::try_parse_from([
        "p2pool-wallet",
        "--network",
        "regtest",
        "completion",
        "generate",
        "--shell",
        "zsh",
        "--datadir",
        "/tmp/wallets",
        "-w",
        "alice",
    ])
    .unwrap();
    assert_eq!(parsed.network, Network::Regtest);
    assert_eq!(parsed.datadir.as_deref(), Some(Path::new("/tmp/wallets")));
    assert_eq!(parsed.wallet.as_deref(), Some("alice"));
    let Command::Completion(CompletionCommand::Generate { shell }) = parsed.command;
    assert_eq!(shell, Shell::Zsh);
}

#[test]
fn network_defaults_to_signet_and_uses_core_chain_names() {
    let parsed =
        Cli::try_parse_from(["p2pool-wallet", "completion", "generate", "--shell", "bash"])
            .unwrap();
    assert_eq!(parsed.network, Network::Signet);
    let mainnet = Cli::try_parse_from([
        "p2pool-wallet",
        "--network",
        "main",
        "completion",
        "generate",
        "--shell",
        "bash",
    ])
    .unwrap();
    assert_eq!(mainnet.network, Network::Bitcoin);
    let testnet3 = Cli::try_parse_from([
        "p2pool-wallet",
        "--network",
        "test",
        "completion",
        "generate",
        "--shell",
        "bash",
    ])
    .err()
    .unwrap();
    assert_eq!(testnet3.kind(), ErrorKind::ValueValidation);
    assert!(testnet3.to_string().contains("testnet3 is unsupported"));
}

#[test]
fn completion_requires_a_known_shell() {
    let missing = Cli::try_parse_from(["p2pool-wallet", "completion", "generate"])
        .err()
        .unwrap();
    assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
    let unknown =
        Cli::try_parse_from(["p2pool-wallet", "completion", "generate", "--shell", "cmd"])
            .err()
            .unwrap();
    assert_eq!(unknown.kind(), ErrorKind::InvalidValue);
}
