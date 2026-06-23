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

//! No-PoW load-test simulation binary for P2Poolv2.
//!
//! Builds a full node via `p2poolv2_node::build_node`, then wires a synthetic
//! share emitter that models one miner at a configured hashrate. Must be built
//! with `--features sim`.
//!
//! See docs/simulation/load-test-plan.md for the full design.

#[cfg(feature = "sim")]
mod config;

#[cfg(feature = "sim")]
use clap::Parser;
#[cfg(feature = "sim")]
use config::SimNodeConfig;
#[cfg(feature = "sim")]
use p2poolv2_lib::logging::setup_logging;
#[cfg(feature = "sim")]
use p2poolv2_lib::sim::emitter::SimEmitter;
#[cfg(feature = "sim")]
use p2poolv2_lib::sim_overrides;
#[cfg(feature = "sim")]
use p2poolv2_node::signal::ShutdownReason;
#[cfg(feature = "sim")]
use tracing::{error, info};

use std::process::ExitCode;

#[cfg(feature = "sim")]
#[derive(Parser, Debug)]
#[command(author, version, about = "P2Poolv2 no-PoW load-test simulation")]
struct Args {
    #[arg(short, long, env("P2POOL_CONFIG"))]
    config: String,
}

#[cfg(feature = "sim")]
#[tokio::main]
async fn main() -> ExitCode {
    info!("Starting P2Poolv2 sim...");
    let args = Args::parse();

    let sim_node_config = match SimNodeConfig::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };

    let node_config = sim_node_config.node.clone();
    let sim_cfg = sim_node_config.sim;

    let _guards = match setup_logging(&node_config.logging) {
        Ok(guards) => {
            info!("Logging set up successfully");
            guards
        }
        Err(e) => {
            error!("Failed to set up logging: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        "Running on {} network (sim mode)",
        &node_config.stratum.network
    );

    // Initialize sim overrides before build_node (ASERT anchor, genesis).
    sim_overrides::init_ideal_block_time(sim_cfg.ideal_block_time_secs.unwrap_or(10));
    sim_overrides::init_genesis_overrides(
        sim_cfg.asert_anchor_time.unwrap_or(0),
        sim_cfg.network_hashrate.unwrap_or(0),
    );
    sim_overrides::init_propagation_delay(sim_cfg.propagation_delay_ms.unwrap_or(0));

    let (handles, runner) = match p2poolv2_node::build_node(node_config.clone()).await {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };

    // Wire the sim emitter using the node handles.
    if sim_cfg.enabled {
        let sim_network = node_config.stratum.network;
        match sim_cfg
            .miner_address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| e.to_string())
            .and_then(|a| a.require_network(sim_network).map_err(|e| e.to_string()))
        {
            Ok(miner_address) => {
                match bitcoindrpc::BitcoindRpcClient::new(
                    &node_config.bitcoinrpc.url,
                    &node_config.bitcoinrpc.username,
                    &node_config.bitcoinrpc.password,
                ) {
                    Ok(sim_rpc) => {
                        let emitter = SimEmitter::new(
                            handles.emissions_tx.clone(),
                            handles.template_rx.clone(),
                            miner_address,
                            sim_cfg,
                            sim_rpc,
                        );
                        let mut sim_exit_rx = handles.shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            tokio::select! {
                                _ = emitter.run() => {}
                                _ = sim_exit_rx.wait_for(|r| *r != ShutdownReason::None) => {
                                    info!("Sim emitter shutting down");
                                }
                            }
                        });
                        info!("Sim emitter spawned");
                    }
                    Err(e) => error!("Failed to build sim bitcoind rpc client: {e}"),
                }
            }
            Err(e) => error!("Invalid sim miner_address, not starting sim emitter: {e}"),
        }
    }

    runner.run().await
}

#[cfg(not(feature = "sim"))]
fn main() -> ExitCode {
    eprintln!("p2poolv2_sim must be built with: cargo build -p p2poolv2_sim --features sim");
    ExitCode::FAILURE
}
