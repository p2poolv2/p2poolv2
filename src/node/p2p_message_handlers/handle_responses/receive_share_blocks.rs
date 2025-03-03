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

use crate::node::messages::{InventoryMessage, Message};
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::validation;
use crate::shares::ShareBlock;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info};

/// Handle a ShareBlock received from a peer
/// Validate the ShareBlock and store it in the chain
pub async fn handle_share_blocks(
    share_blocks: Vec<ShareBlock>,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend>,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Received share blocks: {:?}", share_blocks);
    for share_block in &share_blocks {
        if let Err(e) = validation::validate(share_block, &chain_handle, time_provider).await {
            error!("Share block validation failed: {}", e);
            return Err("Share block validation failed".into());
        }
        if let Err(e) = chain_handle.add_share(share_block.clone()).await {
            error!("Failed to add share: {}", e);
            return Err("Error adding share to chain".into());
        }
    }
    info!("Successfully added share blocks to chain");

    // Trigger gossip of share block inventory message
    let inventory = Message::Inventory(InventoryMessage::ShareBlock(
        share_blocks
            .iter()
            .map(|block| block.header.blockhash)
            .collect(),
    ));
    let swarm_send = SwarmSend::Gossip(inventory);
    swarm_tx.send(swarm_send).await.unwrap();
    Ok(())
}
