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

//! P2Poolv2 node library.
//!
//! Provides [`build_node`] which constructs the full node pipeline (store,
//! stratum, P2P, API) and returns [`NodeHandles`] for injecting extra
//! producers (e.g. a sim emitter) plus a [`NodeRunner`] that drives the
//! event loop.

pub mod background_tasks;
pub mod preflight;
pub mod signal;

use p2poolv2_api::start_api_server;
use p2poolv2_lib::accounting::payout::build_payout_for_mode;
use p2poolv2_lib::accounting::stats::metrics;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::node::actor::NodeHandle;
use p2poolv2_lib::pool_difficulty::PoolDifficulty;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::writer::{StoreHandle, StoreWriter, write_channel};
use p2poolv2_lib::stratum::client_connections::start_connections_handler;
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::server::StratumServerBuilder;
use p2poolv2_lib::stratum::work::gbt::start_gbt;
use p2poolv2_lib::stratum::work::notify::start_notify;
use p2poolv2_lib::stratum::work::prepared_notify::PreparedNotifyParams;
use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
use p2poolv2_lib::stratum::zmq_listener::{ZmqListener, ZmqListenerTrait};
use signal::{ShutdownReason, setup_signal_handler};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, trace};

/// Interval in seconds to poll for new block templates since the last zmq event signal
const GBT_POLL_INTERVAL: u64 = 10;

/// Maximum number of pending shares from all clients connected to stratum server
const STRATUM_SHARES_BUFFER_SIZE: usize = 1000;

/// 100% donation in bips, skip address validation
const FULL_DONATION_BIPS: u16 = 10_000;

/// Notify channel capacity for pending notifications from new clients.
const NOTIFY_CHANNEL_CAPACITY: usize = 1000;

/// Handles exposed by [`build_node`] for wiring external producers (e.g. sim emitter).
pub struct NodeHandles {
    /// Sender for injecting share emissions into the node pipeline.
    pub emissions_tx: mpsc::Sender<Emission>,
    /// Watch receiver for template updates (subscribe to get new PreparedNotifyParams).
    pub template_rx: watch::Receiver<Option<Arc<PreparedNotifyParams>>>,
    /// Send a shutdown reason to trigger graceful node shutdown.
    pub shutdown_tx: watch::Sender<ShutdownReason>,
}

/// Opaque runner returned by [`build_node`]. Call [`NodeRunner::run`] to start
/// the event loop and block until shutdown.
pub struct NodeRunner {
    exit_sender: watch::Sender<ShutdownReason>,
    sig_handle: JoinHandle<()>,
    stopping_rx: tokio::sync::oneshot::Receiver<()>,
    node_handle: NodeHandle,
    stratum_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    api_shutdown_tx: tokio::sync::oneshot::Sender<()>,
    metrics_handle: metrics::MetricsHandle,
    stats_dir: String,
}

impl NodeRunner {
    /// Run the node event loop until shutdown. Returns an appropriate exit code.
    pub async fn run(self) -> ExitCode {
        let mut exit_receiver = self.exit_sender.subscribe();

        let exit_sender = self.exit_sender;
        let node_handle = self.node_handle;
        let stratum_shutdown_tx = self.stratum_shutdown_tx;
        let api_shutdown_tx = self.api_shutdown_tx;
        let metrics_handle = self.metrics_handle;
        let stats_dir = self.stats_dir;

        let stop_all = async move |reason: ShutdownReason| -> ShutdownReason {
            info!("Node shutting down...");

            let metrics = metrics_handle.get_metrics().await;
            if let Err(e) =
                p2poolv2_lib::accounting::stats::pool_local_stats::save_pool_local_stats(
                    &metrics, &stats_dir,
                )
            {
                error!("Failed to save metrics on shutdown: {e}");
            } else {
                info!("Metrics saved on shutdown");
            }

            if let Err(e) = node_handle.shutdown().await {
                error!("Failed to shutdown node: {e}");
            }

            let _ = stratum_shutdown_tx.send(());
            let _ = api_shutdown_tx.send(());
            let _ = exit_sender.send(reason);
            reason
        };

        // Check if shutdown was already requested before we started waiting
        let early_reason = *exit_receiver.borrow();
        if early_reason != ShutdownReason::None {
            stop_all(early_reason).await;
            trace!("Waiting signal handlers");
            self.sig_handle.await.unwrap();
            return if early_reason == ShutdownReason::Signal {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }

        let shutdown_reason = tokio::select! {
            _ = self.stopping_rx => {
                stop_all(ShutdownReason::Error).await
            },
            _ = exit_receiver.changed() => {
                let reason = *exit_receiver.borrow();
                stop_all(reason).await
            },
        };

        trace!("Waiting signal handlers");
        self.sig_handle.await.unwrap();

        if shutdown_reason == ShutdownReason::Signal {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

/// Build the full node pipeline and return handles + a runner.
///
/// The caller can wire extra producers (e.g. a sim emitter) into
/// `NodeHandles::emissions_tx` and `NodeHandles::template_rx` before
/// calling `NodeRunner::run()`.
pub async fn build_node(config: Config) -> Result<(NodeHandles, NodeRunner), ExitCode> {
    let exit_sender = watch::Sender::new(ShutdownReason::None);
    let sig_handle = setup_signal_handler(exit_sender.clone());

    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network).unwrap();
    let store = Arc::new(Store::new(config.store.path.clone(), false).unwrap());

    let (write_tx, write_rx) = write_channel();
    let store_writer = StoreWriter::new(store.clone(), write_rx);
    let exit_sender_store = exit_sender.clone();
    let exit_receiver_store = exit_sender.subscribe();
    tokio::task::spawn_blocking(move || {
        store_writer.run();
        if *exit_receiver_store.borrow() == ShutdownReason::None {
            tracing::error!("Store writer stopped unexpectedly");
            let _ = exit_sender_store.send(ShutdownReason::Error);
        }
    });

    let store_handle = StoreHandle::new(store.clone(), write_tx);
    let chain_store_handle = ChainStoreHandle::new(store_handle, config.stratum.network);

    if let Err(e) = chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
    {
        error!("Failed to initialise chain: {e}");
        return Err(ExitCode::FAILURE);
    }

    let Ok(tip) = chain_store_handle.get_chain_tip() else {
        error!("No chain tip found. Exiting.");
        return Err(ExitCode::FAILURE);
    };
    let Ok(Some(height)) = chain_store_handle.get_tip_height() else {
        error!("No chain tip found. Exiting.");
        return Err(ExitCode::FAILURE);
    };
    info!("Latest tip {} at height {}", tip, height);

    if let Err(error) = preflight::ensure_bitcoin_node_synced(&config.bitcoinrpc).await {
        error!("Bitcoin node still in IBD: {error}");
        return Err(ExitCode::FAILURE);
    }

    background_tasks::start_background_tasks(
        store.clone(),
        Duration::from_secs(
            config.store.background_task_frequency_hours * background_tasks::SECONDS_PER_HOUR,
        ),
        Duration::from_secs(config.store.pplns_ttl_days * background_tasks::SECONDS_PER_DAY),
        exit_sender.clone(),
        exit_sender.subscribe(),
    );

    let stratum_config = config.stratum.clone().parse().unwrap();
    let bitcoinrpc_config = config.bitcoinrpc.clone();

    let (stratum_shutdown_tx, stratum_shutdown_rx) = tokio::sync::oneshot::channel();
    let (notify_tx, notify_rx) = mpsc::channel(NOTIFY_CHANNEL_CAPACITY);
    let tracker_handle = start_tracker_actor();

    let notify_tx_for_gbt = notify_tx.clone();
    let bitcoinrpc_config_cloned = bitcoinrpc_config.clone();
    let zmq_trigger_rx = match ZmqListener.start(&stratum_config.zmqpubhashblock) {
        Ok(rx) => rx,
        Err(e) => {
            error!("Failed to set up ZMQ publisher: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    let exit_sender_gbt = exit_sender.clone();
    let exit_receiver_gbt = exit_sender.subscribe();
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
            if *exit_receiver_gbt.borrow() == ShutdownReason::None {
                tracing::error!("Failed to fetch block template. Shutting down. \n {e}");
                let _ = exit_sender_gbt.send(ShutdownReason::Error);
            }
        }
    });

    let connections_handle = start_connections_handler().await;

    let (template_tx, template_rx) = watch::channel(None);

    let chain_store_handle_for_notify = chain_store_handle.clone();
    let pool_difficulty_for_notify =
        PoolDifficulty::build(&chain_store_handle).expect("Failed to build pool difficulty");

    let cloned_stratum_config = stratum_config.clone();
    let (payout, shared_pplns_window) =
        build_payout_for_mode(stratum_config.mode, cloned_stratum_config.network);
    let exit_sender_notify = exit_sender.clone();
    let exit_receiver_notify = exit_sender.subscribe();
    tokio::spawn(async move {
        info!("Starting Stratum notifier...");
        start_notify(
            notify_rx,
            template_tx,
            chain_store_handle_for_notify,
            &cloned_stratum_config,
            payout,
            pool_difficulty_for_notify,
        )
        .await;
        if *exit_receiver_notify.borrow() == ShutdownReason::None {
            error!("Notifier stopped unexpectedly");
            let _ = exit_sender_notify.send(ShutdownReason::Error);
        }
    });

    let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(STRATUM_SHARES_BUFFER_SIZE);
    let emissions_tx_for_handles = emissions_tx.clone();
    let template_rx_for_handles = template_rx.clone();

    let metrics_handle = match metrics::start_metrics(config.logging.stats_dir.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to start metrics: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    let metrics_cloned = metrics_handle.clone();
    let chain_store_handle_for_stratum = chain_store_handle.clone();
    let tracker_handle_cloned = tracker_handle.clone();
    let notify_tx_for_node = notify_tx.clone();
    let exit_sender_stratum = exit_sender.clone();
    let exit_receiver_stratum = exit_sender.subscribe();

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
            .max_connections(stratum_config.max_connections)
            .wait_for_chain_sync(stratum_config.wait_for_chain_sync)
            .chain_store_handle(chain_store_handle_for_stratum)
            .mode(stratum_config.mode)
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
                template_rx.clone(),
            )
            .await;
        if result.is_err() && *exit_receiver_stratum.borrow() == ShutdownReason::None {
            error!("Failed to start Stratum server: {}", result.unwrap_err());
            let _ = exit_sender_stratum.send(ShutdownReason::Error);
        }
        info!("Stratum server stopped");
    });

    let (monitoring_event_sender, _monitoring_event_receiver) =
        p2poolv2_lib::monitoring_events::create_monitoring_event_channel();

    let (node_handle, stopping_rx) = match NodeHandle::new(
        config.clone(),
        chain_store_handle.clone(),
        emissions_rx,
        metrics_handle.clone(),
        monitoring_event_sender.clone(),
        notify_tx_for_node,
        shared_pplns_window,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to start node: {e}");
            return Err(ExitCode::FAILURE);
        }
    };

    info!("Node started");

    let api_shutdown_tx = match start_api_server(
        config.api.clone(),
        chain_store_handle.clone(),
        metrics_handle.clone(),
        tracker_handle,
        node_handle.clone(),
        monitoring_event_sender,
        stratum_config.network,
        stratum_config.pool_signature,
    )
    .await
    {
        Ok((shutdown_tx, _port)) => shutdown_tx,
        Err(e) => {
            error!("Error starting API server: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    info!(
        "API server started on host {} port {}",
        config.api.hostname, config.api.port
    );

    let handles = NodeHandles {
        emissions_tx: emissions_tx_for_handles,
        template_rx: template_rx_for_handles,
        shutdown_tx: exit_sender.clone(),
    };

    let runner = NodeRunner {
        exit_sender,
        sig_handle,
        stopping_rx,
        node_handle,
        stratum_shutdown_tx,
        api_shutdown_tx,
        metrics_handle,
        stats_dir: config.logging.stats_dir.clone(),
    };

    Ok((handles, runner))
}
