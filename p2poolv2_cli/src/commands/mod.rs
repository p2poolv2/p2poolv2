// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod address;
pub mod api_client;
pub mod bch_share_address;
pub mod blocked_ips;
pub mod candidates;
pub mod chain_info;
pub mod dag;
pub mod db;
pub mod db_query;
pub mod gen_auth;
pub mod peers;
pub mod peers_info;
pub mod pplns_shares;
pub mod share;
pub mod shares;
pub mod transactions;

use crate::commands;
use bitcoin::Network;
use clap::{ArgGroup, Parser, Subcommand};
use p2poolv2_lib::address::bch_share::BchShareNetwork;
use p2poolv2_lib::config::{BitcoinCashNetwork, Config};
use std::error::Error;
use std::path::Path;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to p2poolv2 config file (not required for address, bch-share-address, gen-auth or --db-path commands)
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
        /// Output as Graphviz DOT format DAG (requires --db-path)
        #[arg(short, long, default_value = "false")]
        dot: bool,
    },
    /// Display candidate shares and their uncles for a height range
    Candidates {
        /// Height to get candidates up to, inclusive. Default is candidate tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of candidates to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
        /// Output as Graphviz DOT format DAG (requires --db-path)
        #[arg(short, long, default_value = "false")]
        dot: bool,
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
    /// Display all share headers at each height in the height index (DAG view)
    Dag {
        /// Height to query up to, inclusive. Default is confirmed chain tip.
        #[arg(short, long)]
        to: Option<u32>,
        /// Number of heights to display going back from --to. Default 10.
        #[arg(short, long, default_value = "10")]
        num: u32,
        /// Output as Graphviz DOT format DAG (requires --db-path)
        #[arg(short, long, default_value = "false")]
        dot: bool,
    },
    /// Peer management commands (requires running node with --config)
    Peers {
        #[command(subcommand)]
        command: PeersCommands,
    },
    /// Transaction queries
    Transactions {
        #[command(subcommand)]
        command: TransactionsCommands,
    },
    /// Database maintenance commands (requires --db-path, node must be stopped)
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
    /// Print the share chain address for a taproot output key
    ///
    /// Takes the `witness_program` field of `bitcoin-cli getaddressinfo`, the
    /// already tweaked 32 byte taproot output key, in hex. Reads it from stdin
    /// when no argument is given.
    Address {
        /// Taproot output key, hex. Omit to read it from stdin.
        witness_program: Option<String>,
        /// Network whose prefix to encode under: main, testnet4, signet or regtest
        #[arg(short, long, value_parser = commands::address::parse_network)]
        network: Network,
    },
    /// Print the Bitcoin Cash share chain address for a P2PKH CashAddr
    ///
    /// Takes a regular receiving address (q...) from the wallet whose key
    /// should own your shares, and prints it under the share prefix
    /// (p2pool:, tp2pool: or rp2pool:). Reads it from stdin when no argument
    /// is given. Use it for `[stratum] miner_address` or a miner's `p2p=`.
    BchShareAddress {
        /// P2PKH CashAddr, with its prefix. Omit to read it from stdin.
        cash_address: Option<String>,
        /// Bitcoin Cash network: mainnet, chipnet or regtest
        #[arg(short, long, value_parser = commands::bch_share_address::parse_network)]
        network: BitcoinCashNetwork,
    },
    /// Generate API authentication credentials (salt, password, HMAC)
    GenAuth {
        /// Username for API authentication
        username: String,
        /// Password (leave empty to auto-generate, or use "-" to prompt)
        password: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DbCommands {
    /// Clean up dense heights by invalidating excess HeaderValid blocks
    CleanupDenseHeights,
}

#[derive(Subcommand, Debug)]
pub enum TransactionsCommands {
    /// Get a transaction by txid
    Get {
        /// Transaction hash
        txid: String,
        /// Output raw hex instead of JSON
        #[arg(long, default_value = "false")]
        raw: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeersCommands {
    /// Show connected peers
    Info,
    /// List blocked IPs
    Blocked,
    /// Block an IP address at runtime
    Block {
        /// IP address to block
        ip: String,
    },
    /// Unblock an IP address at runtime
    Unblock {
        /// IP address to unblock
        ip: String,
    },
}

pub async fn run() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Address {
            witness_program,
            network,
        }) => {
            commands::address::execute(witness_program.clone(), *network)?;
        }
        Some(Commands::BchShareAddress {
            cash_address,
            network,
        }) => {
            commands::bch_share_address::execute(cash_address.clone(), *network)?;
        }
        Some(Commands::GenAuth { username, password }) => {
            commands::gen_auth::execute(username.clone(), password.clone())?;
        }
        Some(Commands::Db { command }) => {
            let db_path = cli
                .db_path
                .as_ref()
                .ok_or("--db-path required for db commands")?;
            commands::db::execute(command, db_path)?;
        }
        Some(Commands::Peers { command }) => {
            let config_path = cli
                .config
                .as_ref()
                .ok_or("Config file required for peers commands. Use --config")?;
            let config = Config::load(config_path)?;
            commands::peers::execute(command, &config.api).await?;
        }
        Some(
            Commands::Info
            | Commands::PplnsShares { .. }
            | Commands::Shares { .. }
            | Commands::Candidates { .. }
            | Commands::Share { .. }
            | Commands::Dag { .. }
            | Commands::Transactions { .. },
        ) => {
            if let Some(db_path) = &cli.db_path {
                // Direct database query mode (offline, no running node required)
                let store = commands::db_query::open_store(db_path)?;

                // A miner address is stored without its text prefix. --config is
                // documented as not required here. The cash prefix comes from
                // bitcoin_cash_network, not from the Bitcoin share-chain network.
                let (network, cash_network) = match &cli.config {
                    Some(config_path) if Path::new(config_path).exists() => {
                        let loaded = Config::load(config_path)?;
                        (
                            Some(loaded.stratum.network),
                            loaded.stratum.bitcoin_cash_network.map(cash_share_network),
                        )
                    }
                    _ => (None, None),
                };

                match &cli.command {
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
                    Some(Commands::Shares { to, num, dot, .. }) => {
                        if *dot {
                            commands::db_query::shares_dot(
                                &store,
                                *to,
                                *num,
                                network,
                                cash_network,
                            )?;
                        } else {
                            commands::db_query::shares(&store, *to, *num, network, cash_network)?;
                        }
                    }
                    Some(Commands::Candidates { to, num, dot }) => {
                        if *dot {
                            commands::db_query::candidates_dot(
                                &store,
                                *to,
                                *num,
                                network,
                                cash_network,
                            )?;
                        } else {
                            commands::db_query::candidates(
                                &store,
                                *to,
                                *num,
                                network,
                                cash_network,
                            )?;
                        }
                    }
                    Some(Commands::Share { hash, height, full }) => {
                        commands::db_query::share_lookup(
                            &store,
                            hash.clone(),
                            *height,
                            *full,
                            network,
                            cash_network,
                        )?;
                    }
                    Some(Commands::Dag { to, num, dot }) => {
                        commands::db_query::dag(&store, *to, *num, *dot, network, cash_network)?;
                    }
                    Some(Commands::Transactions { command }) => {
                        commands::transactions::execute_db(&store, command)?;
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
                        dot: _,
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
                    Some(Commands::Candidates { to, num, dot: _ }) => {
                        commands::candidates::execute(&config.api, *to, *num).await?;
                    }
                    Some(Commands::Share { hash, height, full }) => {
                        commands::share::execute(&config.api, hash.clone(), *height, *full).await?;
                    }
                    Some(Commands::Dag { to, num, dot: _ }) => {
                        commands::dag::execute(&config.api, *to, *num).await?;
                    }
                    Some(Commands::Transactions { command }) => {
                        commands::transactions::execute_api(&config.api, command).await?;
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

fn cash_share_network(network: BitcoinCashNetwork) -> BchShareNetwork {
    match network {
        BitcoinCashNetwork::Mainnet => BchShareNetwork::Mainnet,
        BitcoinCashNetwork::Chipnet => BchShareNetwork::Chipnet,
        BitcoinCashNetwork::Regtest => BchShareNetwork::Regtest,
    }
}
