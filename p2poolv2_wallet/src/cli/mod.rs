// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet commands, argument validation, and shell completions.
//!
//! Options may appear before, between, or after the object and action.

mod args;
mod commands;
mod ordering;

#[cfg(test)]
mod tests;

use args::Cli;
use clap::CommandFactory;
use clap_complete::generate;
use commands::{Command, CompletionCommand};
use std::env;
use std::io::{self, Write};
use thiserror::Error;

/// CLI failures after successful argument parsing.
#[derive(Debug, Error)]
pub enum CliError {
    #[error("{command}: not implemented (CLI skeleton only)")]
    NotImplemented { command: &'static str },
    #[error("could not write completion script: {0}")]
    CompletionOutput(#[from] io::Error),
}

/// Parse arguments and generate completions or report an unimplemented operation.
pub fn run() -> Result<(), CliError> {
    let arguments = Cli::try_parse_anywhere(env::args_os()).unwrap_or_else(|error| error.exit());
    if let Command::Completion(CompletionCommand::Generate { shell }) = arguments.command {
        let mut script = Vec::new();
        generate(shell, &mut Cli::command(), "p2pool-wallet", &mut script);
        io::stdout().lock().write_all(&script)?;
        Ok(())
    } else {
        Err(CliError::NotImplemented {
            command: arguments.command.name(),
        })
    }
}
