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

use crate::node::Config;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::handle_mining_message::handle_mining_message;
use crate::shares::miner_message::CkPoolMessage;
use crate::{node::SwarmSend, shares::ckpool_socket::receive_from_ckpool};
use std::error::Error;
use std::thread;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Receives messages from ckpool and sends them to the node asynchronously
/// Each new message received starts a new tokio task
/// TODO: Add limits to how many concurrent tasks are run
pub fn start_receiving_mining_messages<C: Send + 'static>(
    config: &Config,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error>> {
    let (mining_message_tx, mut mining_message_rx) =
        tokio::sync::mpsc::channel::<serde_json::Value>(100);
    let ckpool_config = config.ckpool.clone();
    thread::spawn(move || {
        if let Err(e) = receive_from_ckpool(&ckpool_config, mining_message_tx) {
            error!("Share receiver failed: {}", e);
        }
    });
    let miner_pubkey = config.miner.pubkey.clone();
    tokio::spawn(async move {
        while let Some(mining_message_data) = mining_message_rx.recv().await {
            let mining_message: CkPoolMessage =
                serde_json::from_value(mining_message_data).unwrap();
            info!("Received mining message deserialized: {:?}", mining_message);

            if let Err(e) = handle_mining_message::<C>(
                mining_message,
                chain_handle.clone(),
                swarm_tx.clone(),
                miner_pubkey,
            )
            .await
            {
                error!("Failed to handle mining message: {}", e);
            }
        }
    });
    Ok(())
}
