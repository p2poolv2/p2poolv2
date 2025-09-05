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
use p2poolv2_accounting::stats::metrics::MetricsHandle;
use p2poolv2_accounting::{AccountingShare, simple_pplns::SimplePplnsShare};
use tracing::info;

/// Save share to database for persistence in case we need to recover from a crash
/// Shares are saved with a TTL for 1 week or when we reach accumulated work required for 5 blocks at current difficulty.
pub async fn handle_stratum_shares(
    mut shares_rx: tokio::sync::mpsc::Receiver<SimplePplnsShare>,
    chain_handle: ChainHandle,
    metrics: MetricsHandle,
) {
    while let Some(share) = shares_rx.recv().await {
        info!("Received share: {:?}", share);

        let _ = metrics.record_share_accepted(share.get_difficulty()).await;
        let _ = chain_handle.add_pplns_share(share).await;
    }
    info!("Shares channel closed, stopping share handler.");
}
