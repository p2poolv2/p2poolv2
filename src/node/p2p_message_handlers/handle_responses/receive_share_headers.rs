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

#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::ShareHeader;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tracing::info;

/// Handle a ShareHeader received from a peer
/// We need to:
/// 1. TODO: Validate the PoW on the share header
/// 2. TODO: Push the header into a task queue to fetch the matching share block
/// 3. TODO: We need to start a task in node to pull from the task queue and send getData message
/// 4. DONE: We already handle responses to getData in the shape of ShareBlock messages
pub async fn handle_share_headers(
    share_headers: Vec<ShareHeader>,
    chain_handle: ChainHandle,
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Received share headers: {:?}", share_headers);
    Ok(())
}
