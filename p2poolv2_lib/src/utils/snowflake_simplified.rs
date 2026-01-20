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

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU32 = AtomicU32::new(0);

pub const CUSTOM_EPOCH: u64 = 1735689600000; // 2025-01-01 in ms

/// A simplified snowflake inspired ID generator where we drop the
/// machine and node id as we always run on a single machine/process.
///
/// We retain the benefits of sorted ids and avoid any conflicts in
/// the same millisecond by using the atomic u32 sequence.
///
/// Generates an 8 byte id, with ms timestamp and ~4M sequence per ms
/// Depends on global atomic, so if we use it in a lot of places, we
/// can stripe it into key type
pub fn get_next_id() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let timestamp = now - CUSTOM_EPOCH;

    // increment sequence, wrap every ~4M
    let seq = SEQ.fetch_add(1, Ordering::SeqCst) & ((1 << 22) - 1);

    // 42 bits for timestamp, 22 bits for sequence
    (timestamp << 22) | seq as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_id() {
        let id1 = get_next_id();
        let id2 = get_next_id();

        // IDs should be different
        assert_ne!(id1, id2);

        // IDs should be increasing (since sequence increments)
        assert!(id2 > id1);

        // IDs should be non-zero
        assert!(id1 > 0);
        assert!(id2 > 0);
    }
}
