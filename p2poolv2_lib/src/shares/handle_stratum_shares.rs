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
use tracing::info;

pub async fn handle_stratum_shares(
    mut shares_rx: tokio::sync::mpsc::Receiver<stratum::share_block::StratumShare>,
    chain_handle: ChainHandle,
) {
    while let Some(share) = shares_rx.recv().await {
        info!("Received share: {:?}", share);
        // chain_handle.add_stratum_share(share).await;
    }
    info!("Shares channel closed, stopping share handler.");
}
