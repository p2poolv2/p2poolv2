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
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

mod command;
mod config;
mod node;
mod shares;
mod test_utils;

#[mockall_double::double]
use crate::node::actor::NodeHandle;
use crate::node::messages::Message;
use crate::shares::chain::ChainHandle;
use crate::shares::ckpool_socket::receive_from_ckpool;
use crate::shares::handle_mining_message::handle_mining_message;
use crate::shares::miner_message::MinerMessage;
use tracing::error;

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
    if let Ok((node_handle, stopping_rx)) = NodeHandle::new(config, chain_handle).await {
        info!("Node started");
        if let Err(e) = start_receiving_mining_messages(node_handle.clone()) {
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

fn start_receiving_mining_messages(node_handle: NodeHandle) -> Result<(), Box<dyn Error>> {
    let (mining_message_tx, mut mining_message_rx) =
        tokio::sync::mpsc::channel::<serde_json::Value>(100);
    thread::spawn(move || {
        if let Err(e) = receive_from_ckpool(mining_message_tx) {
            error!("Share receiver failed: {}", e);
        }
    });
    tokio::spawn(async move {
        while let Some(mining_message_data) = mining_message_rx.recv().await {
            info!(
                "Received mining message serialized: {:?}",
                mining_message_data
            );
            let mining_message: MinerMessage = serde_json::from_value(mining_message_data).unwrap();
            info!("Received mining message deserialized: {:?}", mining_message);

            if let Err(e) = handle_mining_message(mining_message, &node_handle).await {
                error!("Failed to handle mining message: {}", e);
            }
        }
    });
    Ok(())
}
