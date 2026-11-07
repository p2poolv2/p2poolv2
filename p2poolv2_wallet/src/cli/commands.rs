// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Subcommand;
use clap_complete::Shell;

#[derive(Subcommand)]
pub enum Command {
    /// Generate shell completion scripts.
    #[command(subcommand)]
    Completion(CompletionCommand),
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
