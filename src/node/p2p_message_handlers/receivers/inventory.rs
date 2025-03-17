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

use crate::node::messages::InventoryMessage;
use crate::node::Message;
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Handle Inventory message request from a peer.
/// inv is sent unsolicited, or in response to getblocks message,
/// therefore we include this message in the handle_requests module.
///
/// We wrap all inventory update messages in the same message type
/// - Depending on the type of the inventory, we query the database for the relevant data
/// - Send the data to the peer via the swarm_tx channel
/// - We send one message for each found object. See block and tx messages.
/// Note: At the moment, we only support sending blockhashes as inventory.
pub async fn handle_inventory<C: Clone + 'static>(
    inventory: Vec<InventoryMessage>,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    response_channel: C,
) -> Result<(), Box<dyn Error>> {
    info!("Received inventory update: {:?}", inventory);

    for inv_item in inventory {
        match inv_item {
            InventoryMessage::BlockHashes(locator) => {
                info!("Received block hashes locator: {:?}", locator);
                let stop_blockhash =
                    "0000000000000000000000000000000000000000000000000000000000000000".into();
                let block_hashes = chain_handle
                    .get_blockhashes_for_locator(locator, stop_blockhash, 2000)
                    .await;
                if !block_hashes.is_empty() {
                    let response = Message::Inventory(InventoryMessage::BlockHashes(block_hashes));
                    swarm_tx
                        .send(SwarmSend::Response(response_channel.clone(), response))
                        .await?;
                }
            }
            // Handle other inventory types as needed
            _ => {
                info!("Unsupported inventory type: {:?}", inv_item);
            }
        }
    }

    Ok(())
}
