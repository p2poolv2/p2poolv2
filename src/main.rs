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

use clap::Parser;
use std::error::Error;
use tracing_subscriber::EnvFilter;
use tracing::{debug, info};
mod node;
mod behaviour;
mod config;
mod shares;
mod command;

use crate::node::actor::NodeHandle;
use tracing::error;
use crate::shares::ShareBlock;

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

    if let Ok((node_handle, stopping_rx)) = NodeHandle::new(config).await {
        info!("Node started");
        tokio::spawn(async move {
            send_share(node_handle).await;
        });
        stopping_rx.await?;
        info!("Node stopped");
    } else {
        error!("Failed to start node");
    }
    Ok(())
}

/// Place holder for sending shares to the network
async fn send_share(node_handle: NodeHandle) {
    loop {  
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let share = ShareBlock::default();
        if let Err(e) = node_handle.send_gossip(share).await {
            error!("Failed to send share: {}", e);
        }
    }
}