// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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
pub mod peers_info;

use clap::{ArgGroup, Parser, Subcommand};
use p2poolv2_lib::cli_commands;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::writer::{StoreHandle, StoreWriter, write_channel};
use std::error::Error;
use std::sync::Arc;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to p2poolv2 config file (not required for gen-auth command)
    #[arg(short, long, env("P2POOL_CONFIG"), global = true)]
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
    /// Display confirmed shares and their uncles for a height range
    SharesInfo {
        /// Height to get shares up to, inclusive. Default is chain tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of shares to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
    },
    /// Display candidate shares and their uncles for a height range
    CandidatesInfo {
        /// Height to get candidates up to, inclusive. Default is candidate tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of candidates to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
    },
    /// Look up a share by its blockhash or height
    #[command(group(ArgGroup::new("query").required(true).args(["hash", "height"])))]
    ShareLookup {
        /// Share blockhash to look up
        #[arg(short = 'a', long)]
        hash: Option<String>,
        /// Share height to look up (prints all shares at that height)
        #[arg(short = 'H', long)]
        height: Option<u32>,
        /// Show full share including transactions
        #[arg(short, long, default_value = "false")]
        full: bool,
    },
    /// Show connected peers by querying the running node's API
    PeersInfo,
    /// Generate API authentication credentials (salt, password, HMAC)
    GenAuth {
        /// Username for API authentication
        username: String,
        /// Password (leave empty to auto-generate, or use "-" to prompt)
        password: Option<String>,
    },
}

pub async fn run() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Handle command if provided
    match &cli.command {
        Some(Commands::GenAuth { username, password }) => {
            // gen-auth doesn't need config or store
            crate::commands::gen_auth::execute(username.clone(), password.clone())?;
        }
        Some(Commands::PeersInfo) => {
            // peers-info needs config (for API host/port) but not the store
            let config_path = cli
                .config
                .as_ref()
                .ok_or("Config file required for this command. Use --config")?;
            let config = Config::load(config_path)?;
            crate::commands::peers_info::execute(&config.api).await?;
        }
        Some(Commands::Info)
        | Some(Commands::PplnsShares { .. })
        | Some(Commands::SharesInfo { .. })
        | Some(Commands::CandidatesInfo { .. })
        | Some(Commands::ShareLookup { .. }) => {
            // These commands require config and store
            let config_path = cli
                .config
                .as_ref()
                .ok_or("Config file required for this command. Use --config")?;
            let config = Config::load(config_path)?;

            let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
            let store = match cli_commands::store::open_store(config.store.path.clone()) {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    panic!("Error opening store {e}");
                }
            };
            // Create StoreWriter for serialized database writes (runs on dedicated blocking thread)
            let (write_tx, write_rx) = write_channel();
            let store_writer = StoreWriter::new(store.clone(), write_rx);
            tokio::task::spawn_blocking(move || store_writer.run());

            // Create StoreHandle and ChainStoreHandle for new components
            let store_handle = StoreHandle::new(store.clone(), write_tx);
            let chain_store_handle = ChainStoreHandle::new(store_handle, config.stratum.network);
            if let Err(e) = chain_store_handle.init_or_setup_genesis(genesis).await {
                eprintln!("Error loading store");
                return Err(e.into());
            };

            match &cli.command {
                Some(Commands::Info) => {
                    cli_commands::chain_info::execute(chain_store_handle)?;
                }
                Some(Commands::PplnsShares {
                    limit,
                    start_time,
                    end_time,
                }) => {
                    cli_commands::pplns_shares::execute(
                        chain_store_handle,
                        *limit,
                        *start_time,
                        *end_time,
                    )?;
                }
                Some(Commands::SharesInfo { to, num }) => {
                    cli_commands::shares_info::execute(chain_store_handle, *to, *num)?;
                }
                Some(Commands::CandidatesInfo { to, num }) => {
                    cli_commands::candidates_info::execute(chain_store_handle, *to, *num)?;
                }
                Some(Commands::ShareLookup { hash, height, full }) => {
                    let query = if let Some(hash_value) = hash {
                        cli_commands::share_lookup::LookupQuery::Hash(hash_value)
                    } else if let Some(height_value) = height {
                        cli_commands::share_lookup::LookupQuery::Height(*height_value)
                    } else {
                        unreachable!("Provide at least one of hash or height")
                    };
                    cli_commands::share_lookup::execute(chain_store_handle, query, *full)?;
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
