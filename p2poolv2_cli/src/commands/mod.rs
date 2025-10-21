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

pub mod gen_auth;

use clap::{Parser, Subcommand};
use p2poolv2_lib::cli_commands;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::shares::share_block::ShareBlock;
use std::error::Error;
use std::sync::Arc;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to p2poolv2 config file (not required for gen-auth command)
    #[arg(short, long, global = true)]
    pub config: Option<String>,

    /// Command to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
    /// Generate API authentication credentials (salt, password, HMAC)
    GenAuth {
        /// Username for API authentication
        username: String,
        /// Password (leave empty to auto-generate, or use "-" to prompt)
        password: Option<String>,
    },
}

pub fn run() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Handle command if provided
    match &cli.command {
        Some(Commands::GenAuth { username, password }) => {
            // gen-auth doesn't need config or store
            crate::commands::gen_auth::execute(username.clone(), password.clone())?;
        }
        Some(Commands::Info) | Some(Commands::PplnsShares { .. }) => {
            // These commands require config and store
            let config_path = cli
                .config
                .as_ref()
                .ok_or("Config file required for this command. Use --config")?;
            let config = Config::load(config_path)?;

            let store = cli_commands::store::open_store(config.store.path.clone())?;
            let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
            let chain = Arc::new(ChainStore::new(
                Arc::new(store),
                genesis,
                config.stratum.network,
            ));

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
                _ => unreachable!(),
            }
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    Ok(())
}
