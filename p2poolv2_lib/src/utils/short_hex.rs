// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Return the first 8 hex characters of a string, git-style short ID.
pub fn short_id(hex_string: &str) -> &str {
    if hex_string.len() >= 8 {
        &hex_string[..8]
    } else {
        hex_string
    }
}
