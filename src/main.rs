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
use tokio::sync::mpsc;
mod node;
mod behaviour;
mod config;
mod shares;
mod command;

use crate::node::actor::NodeHandle;
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

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

    // let mut node = node::Node::new(&config)?;
    if let Err(e) = NodeHandle::new(config, stop_tx).await {
        error!("Exiting node: {}", e);
        return Err(e);
    }
    stop_rx.await.unwrap();
    info!("Exiting node");
    Ok(())
}
