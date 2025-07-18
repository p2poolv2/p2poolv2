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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
#[cfg(not(test))]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::ShareHeader;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tracing::info;

/// Handle ShareHeaders received from a peer
/// We need to:
/// 1. TODO: Validate the PoW on the share header
/// 2. TODO: Store the headers
/// 2. TODO: Push the header into a task queue to fetch txs to build the ShareBlock
/// 3. TODO: We need to start a task in node to pull from the task queue and send getData message for txs
pub async fn handle_share_headers<T: TimeProvider + Send + Sync>(
    share_headers: Vec<ShareHeader>,
    _chain_handle: ChainHandle,
    _time_provider: &T,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Received share headers: {:?}", share_headers);
    Ok(())
}
