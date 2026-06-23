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

use clap::Parser;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
#[cfg(feature = "sim")]
use p2poolv2_lib::sim::emitter::SimEmitter;
#[cfg(feature = "sim")]
use p2poolv2_lib::sim_overrides;
use p2poolv2_node::signal::ShutdownReason;
use std::process::ExitCode;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env("P2POOL_CONFIG"))]
    config: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    info!("Starting P2Poolv2...");
    let args = Args::parse();

    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            error!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Hold guards to keep non-blocking writers alive
    let _guards = match setup_logging(&config.logging) {
        Ok(guards) => {
            info!("Logging set up successfully");
            guards
        }
        Err(e) => {
            error!("Failed to set up logging: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!("Running on {} network", &config.stratum.network);

    // Initialize sim overrides early -- before PoolDifficulty::build (ASERT
    // anchor) and before the first share. In production builds the init
    // functions do not exist; the bridge functions return compile-time constants.
    #[cfg(feature = "sim")]
    if let Some(sim_cfg) = config.sim.as_ref() {
        if sim_cfg.enabled {
            sim_overrides::init_ideal_block_time(sim_cfg.ideal_block_time_secs.unwrap_or(10));
            sim_overrides::init_genesis_overrides(
                sim_cfg.asert_anchor_time.unwrap_or(0),
                sim_cfg.network_hashrate.unwrap_or(0),
            );
            sim_overrides::init_propagation_delay(sim_cfg.propagation_delay_ms.unwrap_or(0));
        }
    }

    let (handles, runner) = match p2poolv2_node::build_node(config.clone()).await {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };

    // No-PoW load-test emitter. Only present under the `sim` feature.
    // See docs/simulation/load-test-plan.md. MUST NEVER run in production.
    #[cfg(feature = "sim")]
    if let Some(sim_cfg) = config.sim.clone() {
        if sim_cfg.enabled {
            let sim_network = config.stratum.network;
            match sim_cfg
                .miner_address
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map_err(|e| e.to_string())
                .and_then(|a| a.require_network(sim_network).map_err(|e| e.to_string()))
            {
                Ok(miner_address) => {
                    match bitcoindrpc::BitcoindRpcClient::new(
                        &config.bitcoinrpc.url,
                        &config.bitcoinrpc.username,
                        &config.bitcoinrpc.password,
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
    }

    runner.run().await
}
