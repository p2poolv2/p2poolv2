// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use clap::{Parser, Subcommand};
use p2poolv2_lib::cli_commands;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::shares::ShareBlock;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use std::error::Error;
use std::sync::Arc;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to p2poolv2 config file
    #[arg(short, long)]
    config: String,

    /// Command to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List information about the store
    Info,
    /// Get PPLNS shares with optional filtering
    PplnsShares {
        /// Maximum number of shares to return
        #[arg(short, long, default_value = "100")]
        limit: usize,
        /// Start time (unix timestamp in seconds) to filter shares, optional
        #[arg(short, long)]
        start_time: Option<u64>,
        /// End time (unix timestamp in seconds) to filter shares, optional
        #[arg(short, long)]
        end_time: Option<u64>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    // Check if store path is provided and handle it
    let store = cli_commands::store::open_store(config.store.path.clone())?;
    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
    let chain = Arc::new(ChainStore::new(Arc::new(store), genesis));

    // Handle command if provided
    match &cli.command {
        Some(Commands::Info) => {
            cli_commands::chain_info::execute(chain)?;
        }
        Some(Commands::PplnsShares {
            limit,
            start_time,
            end_time,
        }) => {
            cli_commands::pplns_shares::execute(chain, *limit, *start_time, *end_time)?;
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    Ok(())
}
