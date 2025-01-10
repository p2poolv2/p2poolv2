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
use std::thread;
use tracing_subscriber::EnvFilter;
use tracing::{debug, info};
mod node;
mod config;
mod shares;
mod command;

use crate::node::actor::NodeHandle;
use tracing::error;
use crate::node::messages::Message;
use crate::shares::miner_work::MinerWork;
use crate::shares::receiver::receive;

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
        if let Err(e) = start_receiving_shares(node_handle.clone()) {
            error!("Failed to start receiving shares: {}", e);
            return Err(e.into());
        }
        stopping_rx.await?;
        info!("Node stopped");
    } else {
        error!("Failed to start node");
    }
    Ok(())
}

fn start_receiving_shares(node_handle: NodeHandle) -> Result<(), Box<dyn Error>> {
    let (share_tx, mut share_rx) = tokio::sync::mpsc::channel::<serde_json::Value>(100);
    thread::spawn(move || {
        if let Err(e) = receive(share_tx) {
            error!("Share receiver failed: {}", e);
        }
    });
    tokio::spawn(async move {
        while let Some(miner_work_data) = share_rx.recv().await {
            info!("Received share: {:?}", miner_work_data);
            let miner_work: MinerWork = serde_json::from_value(miner_work_data).unwrap();
            // if let Err(e) = node_handle.send_gossip(Message::MinerWork(miner_work)).await {
            //     error!("Failed to send share: {}", e);
            // }
        }
    });
    Ok(())
}