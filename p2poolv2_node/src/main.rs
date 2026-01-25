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

use clap::Parser;
use p2poolv2_api::start_api_server;
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use p2poolv2_lib::node::actor::NodeHandle;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::stratum::client_connections::start_connections_handler;
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::server::StratumServerBuilder;
use p2poolv2_lib::stratum::work::gbt::start_gbt;
use p2poolv2_lib::stratum::work::notify::start_notify;
use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
use p2poolv2_lib::stratum::zmq_listener::{ZmqListener, ZmqListenerTrait};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, trace};

use crate::signal::{ShutdownReason, setup_signal_handler};

mod signal;

/// Interval in seconds to poll for new block templates since the last zmq event signal
const GBT_POLL_INTERVAL: u64 = 10; // seconds

/// Maximum number of pending shares from all clients connected to stratum server
const STRATUM_SHARES_BUFFER_SIZE: usize = 1000;

/// 100% donation in bips, skip address validation
const FULL_DONATION_BIPS: u16 = 10_000;

/// Notify channel enqueues requests to send notify updates to new
/// clients. If we have more than the notify channel capacity of
/// pending notifications in the queue, senders are blocked unless
/// space is available. We want to avoid this blocking for up to 1000
/// notifications from new clients.
const NOTIFY_CHANNEL_CAPACITY: usize = 1000;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env("P2POOL_CONFIG"))]
    config: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    info!("Starting P2Pool v2...");
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args.config);
    if config.is_err() {
        let err = config.unwrap_err();
        error!("Failed to load config: {err}");
        return ExitCode::FAILURE;
    }
    let config = config.unwrap();
    // Configure logging based on config
    // hold guard to ensure logging is set up correctly
    let _guard = match logging_result {
        Ok(guard) => {
            info!("Logging set up successfully");
            guard
        }
        Err(e) => {
            error!("Failed to set up logging: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!("Running on {} network", &config.stratum.network);

    let exit_sender = tokio::sync::watch::Sender::new(ShutdownReason::None);

    let sig_handle = setup_signal_handler(exit_sender.clone());

    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
    let store = Arc::new(Store::new(config.store.path.clone(), false).unwrap());
    let chain_store = Arc::new(ChainStore::new(
        store.clone(),
        genesis,
        config.stratum.network,
    ));

    let tip = chain_store.store.get_chain_tip();
    let height = chain_store.get_tip_height();
    info!("Latest tip {:?} at height {:?}", tip, height);

    let background_tasks_store = store.clone();
    p2poolv2_lib::store::background_tasks::start_background_tasks(
        background_tasks_store,
        Duration::from_secs(config.store.background_task_frequency_hours * 3600),
        Duration::from_secs(config.store.pplns_ttl_days * 3600 * 24),
    );

    let stratum_config = config.stratum.clone().parse().unwrap();
    let miner_pubkey = config
        .miner
        .as_ref()
        .map(|miner_config| miner_config.pubkey);
    let bitcoinrpc_config = config.bitcoinrpc.clone();

    let (stratum_shutdown_tx, stratum_shutdown_rx) = tokio::sync::oneshot::channel();
    let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(NOTIFY_CHANNEL_CAPACITY);
    let tracker_handle = start_tracker_actor();

    let notify_tx_for_gbt = notify_tx.clone();
    let bitcoinrpc_config_cloned = bitcoinrpc_config.clone();
    // Setup ZMQ publisher for block notifications
    let zmq_trigger_rx = match ZmqListener.start(&stratum_config.zmqpubhashblock) {
        Ok(rx) => rx,
        Err(e) => {
            error!("Failed to set up ZMQ publisher: {e}");
            return ExitCode::FAILURE;
        }
    };

    let exit_sender_gbt = exit_sender.clone();
    tokio::spawn(async move {
        if let Err(e) = start_gbt(
            bitcoinrpc_config_cloned,
            notify_tx_for_gbt,
            GBT_POLL_INTERVAL,
            stratum_config.network,
            zmq_trigger_rx,
        )
        .await
        {
            tracing::error!("Failed to fetch block template. Shutting down. \n {e}");
            let _ = exit_sender_gbt.send(ShutdownReason::Error);
        }
    });

    let connections_handle = start_connections_handler().await;
    let connections_cloned = connections_handle.clone();

    let tracker_handle_cloned = tracker_handle.clone();
    let store_for_notify = chain_store.clone();

    let cloned_stratum_config = stratum_config.clone();
    tokio::spawn(async move {
        info!("Starting Stratum notifier...");
        // This will run indefinitely, sending new block templates to the Stratum server as they arrive
        start_notify(
            notify_rx,
            connections_cloned,
            store_for_notify,
            tracker_handle_cloned,
            &cloned_stratum_config,
            miner_pubkey,
        )
        .await;
    });

    let (emissions_tx, emissions_rx) =
        tokio::sync::mpsc::channel::<Emission>(STRATUM_SHARES_BUFFER_SIZE);

    let metrics_handle = match metrics::start_metrics(config.logging.stats_dir.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to start metrics: {e}");
            return ExitCode::FAILURE;
        }
    };
    let metrics_cloned = metrics_handle.clone();
    let metrics_for_shutdown = metrics_handle.clone();
    let stats_dir_for_shutdown = config.logging.stats_dir.clone();
    let store_for_stratum = chain_store.clone();
    let tracker_handle_cloned = tracker_handle.clone();
    let exit_sender_stratum = exit_sender.clone();

    tokio::spawn(async move {
        let mut stratum_server = StratumServerBuilder::default()
            .shutdown_rx(stratum_shutdown_rx)
            .connections_handle(connections_handle.clone())
            .emissions_tx(emissions_tx)
            .hostname(stratum_config.hostname)
            .port(stratum_config.port)
            .start_difficulty(stratum_config.start_difficulty)
            .minimum_difficulty(stratum_config.minimum_difficulty)
            .maximum_difficulty(stratum_config.maximum_difficulty)
            .ignore_difficulty(stratum_config.ignore_difficulty)
            .validate_addresses(Some(
                stratum_config.donation.unwrap_or_default() != FULL_DONATION_BIPS,
            ))
            .network(stratum_config.network)
            .version_mask(stratum_config.version_mask)
            .store(store_for_stratum)
            .build()
            .await
            .unwrap();
        info!("Starting Stratum server...");
        let result = stratum_server
            .start(
                None,
                notify_tx,
                tracker_handle_cloned,
                bitcoinrpc_config,
                metrics_cloned,
            )
            .await;
        if result.is_err() {
            error!("Failed to start Stratum server: {}", result.unwrap_err());
            let _ = exit_sender_stratum.send(ShutdownReason::Error);
        }
        info!("Stratum server stopped");
    });

    let api_shutdown_tx = match start_api_server(
        config.api.clone(),
        chain_store.clone(),
        metrics_handle.clone(),
        tracker_handle,
        stratum_config.network,
        stratum_config.pool_signature,
    )
    .await
    {
        Ok(shutdown_tx) => shutdown_tx,
        Err(e) => {
            error!("Error starting API server: {e}");
            return ExitCode::FAILURE;
        }
    };
    info!(
        "API server started on host {} port {}",
        config.api.hostname, config.api.port
    );

    let (node_handle, stopping_rx) =
        match NodeHandle::new(config, chain_store, emissions_rx, metrics_handle).await {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to start node: {e}");
                return ExitCode::FAILURE;
            }
        };

    info!("Node started");

    let mut exit_receiver = exit_sender.subscribe();
    let stop_all = async move |reason: ShutdownReason| -> ShutdownReason {
        info!("Node shutting down...");

        // Save metrics before shutdown to prevent data loss
        let metrics = metrics_for_shutdown.get_metrics().await;
        if let Err(e) = p2poolv2_lib::accounting::stats::pool_local_stats::save_pool_local_stats(
            &metrics,
            &stats_dir_for_shutdown,
        ) {
            error!("Failed to save metrics on shutdown: {e}");
        } else {
            info!("Metrics saved on shutdown");
        }

        // Shutdown node gracefully
        if let Err(e) = node_handle.shutdown().await {
            error!("Failed to shutdown node: {e}");
        }

        // channels might be closed already, ignore errors
        let _ = stratum_shutdown_tx.send(());
        let _ = api_shutdown_tx.send(());
        // Notify signal handler to exit
        let _ = exit_sender.send(reason);
        reason
    };

    // Check if shutdown was already requested before we started waiting
    let early_reason = *exit_receiver.borrow();
    if early_reason != ShutdownReason::None {
        stop_all(early_reason).await;
        trace!("Waiting signal handlers");
        sig_handle.await.unwrap();
        return if early_reason == ShutdownReason::Signal {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let shutdown_reason = tokio::select! {
        _ = stopping_rx => {
            // Node stopped unexpectedly - treat as error
            stop_all(ShutdownReason::Error).await
        },
        _ = exit_receiver.changed() => {
            let reason = *exit_receiver.borrow();
            stop_all(reason).await
        }
    };

    trace!("Waiting signal handlers");
    sig_handle.await.unwrap();

    if shutdown_reason == ShutdownReason::Signal {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
