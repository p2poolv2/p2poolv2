// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet command-line interface and shell completions.

mod args;
mod commands;

#[cfg(test)]
mod tests;

use args::Cli;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use commands::{Command, CompletionCommand};
use std::io::{self, Write};
use thiserror::Error;

/// CLI failures after successful argument parsing.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("could not write completion script: {0}")]
    CompletionOutput(#[from] io::Error),
}

/// Parse arguments and execute the selected command.
pub fn run() -> Result<(), CliError> {
    let arguments = Cli::parse();
    let Command::Completion(CompletionCommand::Generate { shell }) = arguments.command;
    let mut script = Vec::new();
    generate(shell, &mut Cli::command(), "p2pool-wallet", &mut script);
    io::stdout().lock().write_all(&script)?;
    Ok(())
}
