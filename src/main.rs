// Copyright (C) 2024 [Kulpreet Singh]
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

use crate::shares::ShareBlock;
use clap::Parser;
use std::error::Error;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

mod bitcoind_rpc;
mod command;
mod config;
mod node;
mod shares;
mod utils;

#[mockall_double::double]
use crate::node::actor::NodeHandle;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use bitcoin::PublicKey;
use tracing::error;

#[cfg(test)]
mod test_utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse command line arguments
    let args = Args::parse();
    debug!("Parsed args: {:?}", args);

    // Load configuration
    let config = config::Config::load(&args.config)?;
    let chain_handle = ChainHandle::new(config.store.path.clone());
    let public_key = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
        .parse::<PublicKey>()
        .unwrap();
    let genesis = ShareBlock::build_genesis_for_network(public_key, config.bitcoin.network);
    if chain_handle
        .get_share(genesis.cached_blockhash.unwrap())
        .await
        .is_none()
    {
        if let Err(e) = chain_handle.add_share(genesis).await {
            error!("Failed to create genesis block: {}", e);
            std::process::exit(1);
        }
    }
    if let Ok((_node_handle, stopping_rx)) = NodeHandle::new(config, chain_handle).await {
        info!("Node started");
        stopping_rx.await?;
        info!("Node stopped");
    } else {
        error!("Failed to start node");
    }
    Ok(())
}
