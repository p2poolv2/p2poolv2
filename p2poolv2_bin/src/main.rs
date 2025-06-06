// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use bitcoin::Address;
use bitcoindrpc::BitcoindRpcClient;
use clap::Parser;
use p2poolv2_lib::config::{Config, LoggingConfig};
use p2poolv2_lib::node::actor::NodeHandle;
use p2poolv2_lib::shares::chain::actor::ChainHandle;
use p2poolv2_lib::shares::ShareBlock;
use std::error::Error;
use std::fs::File;
use std::process::exit;
use std::str::FromStr;
use stratum::client_connections::spawn;
use stratum::server::StratumServer;
use stratum::work::gbt::start_gbt;
use stratum::work::tracker::start_tracker_actor;
use tracing::error;
use tracing::{debug, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

/// Interval in seconds to poll for new block templates since the last blocknotify signal
const GBT_POLL_INTERVAL: u64 = 60; // seconds

/// Path to the Unix socket for receiving blocknotify signals from bitcoind
pub const SOCKET_PATH: &str = "/tmp/p2pool_blocknotify.sock";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    info!("Starting P2Pool v2...");
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args.config);
    if config.is_err() {
        let err = config.unwrap_err();
        error!("Failed to load config: {}", err);
        return Err(format!("Failed to load config: {}", err).into());
    }
    let config = config.unwrap();
    // Configure logging based on config
    setup_logging(&config.logging)?;

    let genesis = ShareBlock::build_genesis_for_network(config.bitcoin.network);
    let chain_handle = ChainHandle::new(config.store.path.clone(), genesis);

    let tip = chain_handle.get_chain_tip().await;
    let height = chain_handle.get_tip_height().await;
    info!("Latest tip {} at height {}", tip.unwrap(), height.unwrap());

    let stratum_config = config.stratum.clone();
    let bitcoin_config = config.bitcoin.clone();
    let bitcoinrpc_config = config.bitcoinrpc.clone();
    let (stratum_shutdown_tx, stratum_shutdown_rx) = tokio::sync::oneshot::channel();
    let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(1);
    let tracker_handle = start_tracker_actor();

    let notify_tx_for_gbt = notify_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = start_gbt::<BitcoindRpcClient>(
            &bitcoinrpc_config,
            notify_tx_for_gbt,
            SOCKET_PATH,
            GBT_POLL_INTERVAL,
            bitcoin_config.network,
        )
        .await
        {
            tracing::error!("Failed to fetch block template. Shutting down. \n {}", e);
            exit(1);
        }
    });

    let connections_handle = spawn().await;
    let connections_cloned = connections_handle.clone();

    let output_address = Address::from_str(stratum_config.solo_address.unwrap().as_str())
        .expect("Invalid output address in Stratum config")
        .require_network(config.bitcoin.network)
        .expect("Output address must match the Bitcoin network in config");

    let tracker_handle_cloned = tracker_handle.clone();
    tokio::spawn(async move {
        info!("Starting Stratum notifier...");
        // This will run indefinitely, sending new block templates to the Stratum server as they arrive
        stratum::work::notify::start_notify(
            notify_rx,
            connections_cloned,
            Some(output_address),
            tracker_handle_cloned,
        )
        .await;
    });

    tokio::spawn(async move {
        let mut stratum_server = StratumServer::new(
            stratum_config.host,
            stratum_config.port,
            stratum_shutdown_rx,
            connections_handle.clone(),
        )
        .await;
        info!("Starting Stratum server...");
        let result = stratum_server
            .start(None, notify_tx, tracker_handle, bitcoinrpc_config)
            .await;
        if result.is_err() {
            error!("Failed to start Stratum server: {}", result.unwrap_err());
        }
        info!("Stratum server stopped");
    });

    if let Ok((_node_handle, stopping_rx)) = NodeHandle::new(config, chain_handle).await {
        info!("Node started");
        stopping_rx.await?;
        stratum_shutdown_tx
            .send(())
            .expect("Failed to send shutdown signal to Stratum server");
        info!("Node stopped");
    } else {
        error!("Failed to start node");
        return Err("Failed to start node".into());
    }
    Ok(())
}

/// Sets up logging according to the logging configuration
fn setup_logging(logging_config: &LoggingConfig) -> Result<(), Box<dyn Error>> {
    debug!("Setting up logging with config: {:?}", logging_config);
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let registry = Registry::default().with(filter);

    // Configure console logging if enabled
    if logging_config.console {
        let console_layer = fmt::layer().pretty();
        // Initialize with console output
        registry.with(console_layer).init();
    } else if let Some(file_path) = &logging_config.file {
        // Create directory structure if it doesn't exist
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Configure file logging if specified
        let file = File::create(file_path)?;
        info!("Logging to file: {}", file_path);
        let file_layer = fmt::layer().with_writer(file).with_ansi(false);

        registry.with(file_layer).init();
    } else {
        // If neither console nor file is configured, default to console
        let console_layer = fmt::layer();
        registry.with(console_layer).init();
    }

    info!("Logging initialized");
    Ok(())
}
