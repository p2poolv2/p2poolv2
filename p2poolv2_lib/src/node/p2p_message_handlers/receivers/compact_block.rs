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

use crate::node::compact_block_relay::CompactBlockRelayStatus;

/// Decide the CompactBlockRelayStatus to apply to the peer based on their sendcmpct message.
///
/// BIP152: high-bandwidth (announce=true) means peer will send unsolicited cmpctblock.
/// We cap our own high-bandwidth peer count at 3. Version 1 is the only supported version
/// (segwit always enabled on this sidechain).
pub fn decide_send_compact_mode(
    high_bandwidth: bool,
    version: u64,
    current_hb_count: u8,
) -> CompactBlockRelayStatus {
    match version {
        1 => match (high_bandwidth, current_hb_count) {
            (true, 0..=2) => CompactBlockRelayStatus::HighBandwidth,
            (true, _) => CompactBlockRelayStatus::LowBandwidth,
            _ => CompactBlockRelayStatus::Disabled,
        },
        _ => CompactBlockRelayStatus::Disabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decide_send_compact_high_bandwidth_within_cap() {
        assert_eq!(
            decide_send_compact_mode(true, 1, 0),
            CompactBlockRelayStatus::HighBandwidth
        );
        assert_eq!(
            decide_send_compact_mode(true, 1, 2),
            CompactBlockRelayStatus::HighBandwidth
        );
    }

    #[test]
    fn test_decide_send_compact_high_bandwidth_over_cap() {
        assert_eq!(
            decide_send_compact_mode(true, 1, 3),
            CompactBlockRelayStatus::LowBandwidth
        );
    }

    #[test]
    fn test_decide_send_compact_low_bandwidth() {
        assert_eq!(
            decide_send_compact_mode(false, 1, 0),
            CompactBlockRelayStatus::Disabled
        );
    }

    #[test]
    fn test_decide_send_compact_unsupported_version() {
        assert_eq!(
            decide_send_compact_mode(true, 2, 0),
            CompactBlockRelayStatus::Disabled
        );
        assert_eq!(
            decide_send_compact_mode(false, 2, 0),
            CompactBlockRelayStatus::Disabled
        );
    }
}
