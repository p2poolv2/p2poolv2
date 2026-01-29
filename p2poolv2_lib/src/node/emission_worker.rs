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

//! Emission worker processes stratum share submissions in a dedicated task.
//!
//! This offloads CPU-intensive merkle tree calculations from the main swarm
//! event loop, improving P2P responsiveness. Storage is delegated to the
//! ChainStoreHandle for serialized database writes.

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::organise_worker::OrganiseSender;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::handle_stratum_share::handle_stratum_share;
use crate::stratum::emission::EmissionReceiver;
use libp2p::request_response::ResponseChannel;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Worker that processes emissions from the stratum server.
///
/// Runs in a separate tokio task to avoid blocking the main swarm event loop
/// during CPU-intensive share processing operations.
pub struct EmissionWorker {
    emissions_rx: EmissionReceiver,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    chain_store_handle: ChainStoreHandle,
    network: bitcoin::Network,
    organise_tx: OrganiseSender,
}

impl EmissionWorker {
    /// Creates a new emission worker.
    pub fn new(
        emissions_rx: EmissionReceiver,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        chain_store_handle: ChainStoreHandle,
        network: bitcoin::Network,
        organise_tx: OrganiseSender,
    ) -> Self {
        Self {
            emissions_rx,
            swarm_tx,
            chain_store_handle,
            network,
            organise_tx,
        }
    }

    /// Runs the emission worker until the emissions channel is closed.
    pub async fn run(mut self) {
        info!("Emission worker started");
        while let Some(emission) = self.emissions_rx.recv().await {
            debug!("Processing emission");
            // Pass a references to chain store handle to avoid clones on each loop
            match handle_stratum_share(emission, &self.chain_store_handle, self.network).await {
                Ok(Some(share_block)) => {
                    // Send to organise worker for candidate/confirmed indexing
                    if let Err(e) = self.organise_tx.send(share_block.clone()).await {
                        error!("Failed to send share to organise worker: {e}");
                    }
                    // Send to swarm_tx for broadcast to peers
                    if let Err(e) = self.swarm_tx.send(SwarmSend::Broadcast(share_block)).await {
                        error!("Failed to queue share for broadcast: {e}");
                    }
                }
                Ok(None) => {
                    // PPLNS-only share (p2p disabled), no broadcast needed
                }
                Err(e) => {
                    error!("Error processing emission: {e}");
                }
            }
        }
        info!("Emission worker stopped - channel closed");
    }
}
