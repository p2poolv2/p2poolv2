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
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tracing::info;

/// Send blocks inventory update to a peer. This is not a response, but is triggered
/// by the node when it has new data to share.
pub async fn handle_blocks_inventory(
    inventory: Vec<InventoryMessage>,
    chain_handle: ChainHandle,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Sending inventory update: {:?}", inventory);
    Ok(())
}

/// Send transactions inventory update to a peer. This is not a response, but is triggered
/// by the node when it has new data to share.
pub async fn handle_transactions_inventory(
    inventory: Vec<InventoryMessage>,
    chain_handle: ChainHandle,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Sending inventory update: {:?}", inventory);
    Ok(())
}
