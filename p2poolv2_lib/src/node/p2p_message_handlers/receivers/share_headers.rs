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

use crate::node::SwarmSend;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareHeader;
use crate::shares::validation::validate_share_header;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Handle ShareHeaders received from a peer
///
/// - validate: received share header using shares::validation::validate_share_header
///
/// - getheader: If MAX_HEADERS headers are received, send getheaders to request next batch
///
/// - getdata: If less than MAX_HEADERs received, request first set of
///   blocks. Then response for blocks will ask for next set of
///   blocks.
pub async fn handle_share_headers<C: Send + Sync>(
    share_headers: Vec<ShareHeader>,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let all_valid = share_headers
        .iter()
        .all(|header| validate_share_header(header, &chain_store_handle).is_ok());
    debug!("Received share headers: {:?}", share_headers);
    Ok(())
}
