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

pub mod api_client;
pub mod candidates;
pub mod chain_info;
pub mod db_query;
pub mod gen_auth;
pub mod peers_info;
pub mod pplns_shares;
pub mod share;
pub mod shares;

use crate::commands;
use clap::{ArgGroup, Parser, Subcommand};
use p2poolv2_lib::config::Config;
use std::error::Error;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to p2poolv2 config file (not required for gen-auth or --db-path commands)
    #[arg(short, long, env("P2POOL_CONFIG"), global = true)]
    pub config: Option<String>,

    /// Path to RocksDB database directory for direct offline queries
    #[arg(long, global = true)]
    pub db_path: Option<String>,

    /// Command to execute
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List information about the chain
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
    /// Display confirmed share headers for a height range
    Shares {
        /// Height to get shares up to, inclusive. Default is chain tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of shares to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
        /// Include share block transactions in the output
        #[arg(short, long, default_value = "false")]
        share_block_transactions: bool,
        /// Include template merkle branches in the output
        #[arg(short = 'm', long, default_value = "false")]
        template_merkle_branches: bool,
    },
    /// Display candidate shares and their uncles for a height range
    Candidates {
        /// Height to get candidates up to, inclusive. Default is candidate tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of candidates to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
    },
    /// Look up a share by its blockhash or height
    #[command(group(ArgGroup::new("query").required(true).args(["hash", "height"])))]
    Share {
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
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::GenAuth { username, password }) => {
            commands::gen_auth::execute(username.clone(), password.clone())?;
        }
        Some(
            Commands::PeersInfo
            | Commands::Info
            | Commands::PplnsShares { .. }
            | Commands::Shares { .. }
            | Commands::Candidates { .. }
            | Commands::Share { .. },
        ) => {
            if let Some(db_path) = &cli.db_path {
                // Direct database query mode (offline, no running node required)
                let store = commands::db_query::open_store(db_path)?;

                match &cli.command {
                    Some(Commands::PeersInfo) => {
                        return Err(
                            "peers-info requires a running node; cannot use with --db-path".into(),
                        );
                    }
                    Some(Commands::Info) => {
                        commands::db_query::info(&store)?;
                    }
                    Some(Commands::PplnsShares {
                        limit,
                        start_time,
                        end_time,
                    }) => {
                        commands::db_query::pplns_shares(&store, *limit, *start_time, *end_time)?;
                    }
                    Some(Commands::Shares {
                        to,
                        num,
                        share_block_transactions,
                        template_merkle_branches,
                    }) => {
                        commands::db_query::share_headers(
                            &store,
                            *to,
                            *num,
                            *share_block_transactions,
                            *template_merkle_branches,
                        )?;
                    }
                    Some(Commands::Candidates { to, num }) => {
                        commands::db_query::candidates(&store, *to, *num)?;
                    }
                    Some(Commands::Share { hash, height, full }) => {
                        commands::db_query::share_lookup(&store, hash.clone(), *height, *full)?;
                    }
                    _ => unreachable!(),
                }
            } else {
                // API query mode (requires running node)
                let config_path = cli
                    .config
                    .as_ref()
                    .ok_or("Config file required for this command. Use --config or --db-path")?;
                let config = Config::load(config_path)?;

                match &cli.command {
                    Some(Commands::PeersInfo) => {
                        commands::peers_info::execute(&config.api).await?;
                    }
                    Some(Commands::Info) => {
                        commands::chain_info::execute(&config.api).await?;
                    }
                    Some(Commands::PplnsShares {
                        limit,
                        start_time,
                        end_time,
                    }) => {
                        commands::pplns_shares::execute(
                            &config.api,
                            *limit,
                            *start_time,
                            *end_time,
                        )
                        .await?;
                    }
                    Some(Commands::Shares {
                        to,
                        num,
                        share_block_transactions,
                        template_merkle_branches,
                    }) => {
                        commands::shares::execute(
                            &config.api,
                            *to,
                            *num,
                            *share_block_transactions,
                            *template_merkle_branches,
                        )
                        .await?;
                    }
                    Some(Commands::Candidates { to, num }) => {
                        commands::candidates::execute(&config.api, *to, *num).await?;
                    }
                    Some(Commands::Share { hash, height, full }) => {
                        commands::share::execute(&config.api, hash.clone(), *height, *full).await?;
                    }
                    _ => unreachable!(),
                }
            }
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }

    Ok(())
}
