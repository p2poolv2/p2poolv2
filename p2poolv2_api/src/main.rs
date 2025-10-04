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
use p2poolv2_lib::api::ApiServer;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use p2poolv2_lib::shares::ShareBlock;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::store::Store;
use std::sync::Arc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to p2poolv2 config file
    #[arg(short, long)]
    config: String,
    
    /// API server port
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting P2Pool v2 API Server...");
    
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let config = Config::load(&args.config)?;
    
    // Configure logging based on config
    let _guard = setup_logging(&config.logging).map_err(|e| format!("Failed to setup logging: {}", e))?;
    info!("Logging set up successfully");

    // Initialize store and chain
    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
    let store = Arc::new(Store::open_read_only(config.store.path.clone()).map_err(|e| format!("Failed to create store: {}", e))?);
    let chain_store = Arc::new(ChainStore::new(store, genesis));

    let tip = chain_store.store.get_chain_tip();
    let height = chain_store.get_tip_height();
    info!("Latest tip {:?} at height {:?}", tip, height);

    // Parse stratum config
    let stratum_config = config.stratum.parse().map_err(|e| format!("Failed to parse stratum config: {}", e))?;

    // Create and start API server
    let api_server = ApiServer::new(chain_store, stratum_config, args.port);
    
    info!("Starting API server on port {}", args.port);
    api_server.start().await?;
    
    Ok(())
}