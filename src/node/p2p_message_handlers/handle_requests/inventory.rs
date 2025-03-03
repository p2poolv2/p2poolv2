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
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Handle Inventory message request from a peer.
/// Inventory results in a GetData message being sent to the peer,
/// therefore we include this message in the handle_requests module.
/// We wrap all inventory update messages in the same message type
/// TODO
/// - Depending on the type of the inventory, we query the database for the relevant data
/// - Send the data to the peer via the swarm_tx channel
/// - We send one message for each found object. See block and tx messages.
/// Note: headers are not sent as inventory, but as headers message.
pub async fn handle_inventory(
    inventory: Vec<InventoryMessage>,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend>,
) -> Result<(), Box<dyn Error>> {
    info!("Received inventory update: {:?}", inventory);
    Ok(())
}
