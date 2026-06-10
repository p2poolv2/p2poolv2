// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

//! Statistical block-find submission.
//!
//! When the emitter's Bernoulli draw says a share is also a bitcoin block, we
//! submit a real block to the shared regtest bitcoind. The share's bitcoin
//! coinbase already carries the PPLNS payout distribution (built from the
//! window via the notify path), so we reuse it: grind the regtest nonce (~1-2
//! hashes, since the regtest target is ~2^255), assemble the full block, and
//! submit. The real path then runs for free — ZMQ `hashblock` → GBT refresh →
//! re-notify across all nodes → bitcoin confirmation → payout. This exercises
//! the block-submit + payout path and the re-template fanout under load.
//!
//! Only compiled under the `sim` feature. See docs/simulation/load-test-plan.md.

use crate::stratum::message_handlers::submit::{build_full_block, submit_block};
use crate::stratum::work::block_template::BlockTemplate;
use bitcoin::block::Header;
use bitcoindrpc::BitcoindRpcClient;
use tracing::{info, warn};

/// Upper bound on grind iterations. Regtest meets target ~50% per nonce, so
/// this is about 2^128 likelihood, not 2^7, so fully absurd.
const MAX_GRIND: u64 = 1 << 7;

/// Grind the regtest nonce until the header meets its (trivial) target, then
/// assemble and submit the full block. Reuses `coinbase` (which carries the
/// PPLNS payout) and the template's transactions.
pub async fn submit_sim_block(
    mut header: Header,
    coinbase: bitcoin::Transaction,
    template: &BlockTemplate,
    client: &BitcoindRpcClient,
) {
    let target = bitcoin::Target::from_compact(header.bits);

    let mut grinds = 0u64;
    while !target.is_met_by(header.block_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
        grinds += 1;
        if grinds >= MAX_GRIND {
            warn!("sim block-find: gave up grinding after {grinds} nonces (target too hard?)");
            return;
        }
    }

    info!(
        "sim block-find: header meets regtest target after {grinds} grind(s), submitting block {} at height {}",
        header.block_hash(),
        template.height
    );

    let block = build_full_block(header, coinbase, template);
    submit_block(&block, client).await;
}
