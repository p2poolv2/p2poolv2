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

use crate::node::compact_block_relay::CompactBlockRelay;
use crate::service::peer_state::{PeerState, PeerStates};
use std::error::Error;
use tracing::debug;

/// Handle SendCompact message from a peer (sendcmpct).
///
/// As per BIP152, this message negotiates compact block relay support.
/// - High-bandwidth mode (announce=true): Peer will send cmpctblock unsolicited
/// - Low-bandwidth mode (announce=false): Peer uses inv/headers announcements but supports compact block messages
///
/// We limit high-bandwidth mode to up to 3 peers as recommended by BIP152.
/// Version 1 is the only supported version (segwit is always enabled in this sidechain).
///
/// # Arguments
/// * `high_bandwidth` - Whether peer wants high-bandwidth announcements
/// * `version` - Compact block protocol version (ignore if we don't support it)
/// * `peer_id` - The peer that sent the message
/// * `node_handle` - Handle to interact with the node for peer state updates
///
/// # Returns
/// Returns Ok(()) on success, or an error if peer state update fails
///
pub async fn handle_send_compact(
    high_bandwidth: bool,
    version: u64,
    peer_id: libp2p::PeerId,
    peer_states: &PeerStates,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let hb_count = peer_states
        .all()
        .iter()
        .filter(|p| matches!(p.compact_block_from, CompactBlockRelay::HighBandwidth))
        .count() as u8;

    let mode = match version {
        1 => {
            let mode = match (high_bandwidth, hb_count) {
                (true, 0..=2) => CompactBlockRelay::HighBandwidth,
                (true, _) => CompactBlockRelay::LowBandwidth,
                _ => CompactBlockRelay::Disabled,
            };

            debug!(
                %peer_id,
                ?mode,
                ?hb_count,
                "Setting compact block relay mode for peer",
            );

            mode
        }
        _ => {
            debug!(
                %peer_id,
                "Received unsupported version for compact block relay",
            );

            CompactBlockRelay::Disabled
        }
    };

    peer_states.update(peer_id, move |peer_state: &mut PeerState| {
        peer_state.compact_block_from = mode;
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add integration tests for handle_send_compact
    // These tests require a properly set up Node with working command channels
    // For now, the functionality is tested through the integration test suite
}
