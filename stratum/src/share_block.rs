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

use bitcoin::secp256k1::rand::{self, RngCore};
use bitcoin::{bip152::HeaderAndShortIds, p2p::message_compact_blocks::CmpctBlock, Block};
use tokio::sync::mpsc;

/// Send a compact block message to the tx channel
pub fn emit_share_block(
    share_block: &Block,
    version: u32,
    shares_tx: mpsc::Sender<CmpctBlock>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let nonce: u64 = rng.next_u64();
    let header_and_short_ids: HeaderAndShortIds =
        HeaderAndShortIds::from_block(share_block, nonce, version, &[0])
            .map_err(|e| format!("Failed to create HeaderAndShortIds: {e}"))?;
    let message = CmpctBlock {
        compact_block: header_and_short_ids,
    };
    shares_tx.try_send(message)?;
    Ok(())
}
