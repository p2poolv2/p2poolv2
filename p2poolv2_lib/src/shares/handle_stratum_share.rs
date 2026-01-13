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
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::stratum::emission::Emission;
use std::error::Error;
use std::sync::Arc;
use tracing::debug;

/// Save share to database for persistence in case we need to recover from a crash
/// Shares are saved with a TTL for 1 week or when we reach accumulated work required for 5 blocks at current difficulty.
pub fn handle_stratum_share(
    emission: Emission,
    chain_store: Arc<ChainStore>,
) -> Result<Option<ShareBlock>, Box<dyn Error + Send + Sync>> {
    // save pplns share for accounting
    chain_store.add_pplns_share(emission.pplns)?;

    // Send share to peers only in p2p mode, i.e. if the pool is run with a miner pubkey that results in a commitment
    if emission.share_commitment.is_none() {
        debug!("No share commitment emitted by stratum. Won't send share to peers");
        Ok(None)
    } else {
        let share_header = ShareHeader::from_commitment_and_header(
            emission.share_commitment.unwrap(),
            emission.block.header,
        );
        // For now, send the entire block, we will do tx deltas or compact block optimisation later on
        let share_block = ShareBlock {
            header: share_header,
            transactions: vec![],
            bitcoin_transactions: emission.block.txdata,
        };

        // save and reorg share
        chain_store.add_share(&share_block, true)?;

        Ok(Some(share_block))
    }
}
