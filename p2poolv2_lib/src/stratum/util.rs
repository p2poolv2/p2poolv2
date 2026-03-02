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

use crate::stratum::work::error::WorkError;

/// Convert the previousblockhash from big-endian to the format expected by miners
pub fn reverse_four_byte_chunks(
    hash_hex: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Ensure the hash is of correct length (64 chars = 32 bytes)
    if hash_hex.len() != 64 {
        return Err(Box::new(WorkError {
            message: format!("Hash length is incorrect: {}", hash_hex.len()),
        }));
    }

    // Convert the hex string to bytes
    let bytes = hex::decode(hash_hex)?;

    // Reverse the byte order in 4-byte chunks
    let mut reversed_bytes = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(4).rev() {
        reversed_bytes.extend_from_slice(chunk);
    }

    // Convert back to a hex string
    Ok(hex::encode(reversed_bytes))
}

/// Convert a hash to big-endian hex string.
pub fn to_be_hex(le: &str) -> String {
    // Decode the little-endian hex string to bytes
    let bytes = hex::decode(le).expect("Invalid hex string");

    // Convert to big-endian by reversing the byte order
    let be_bytes: Vec<u8> = bytes.iter().rev().cloned().collect();

    // Convert back to a hex string
    hex::encode(be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_byte_order() {
        let input = "00000000cbdd48c69c45ffd07dc26fc3668bb70870374354535061f8f5304c7c";
        let expected = "f5304c7c535061f870374354668bb7087dc26fc39c45ffd0cbdd48c600000000";
        assert_eq!(reverse_four_byte_chunks(input).unwrap(), expected);
    }

    #[test]
    fn test_reverse_byte_order_invalid_length() {
        let input = "abc123"; // Too short
        assert!(reverse_four_byte_chunks(input).is_err());
    }

    #[test]
    fn test_reverse_byte_order_invalid_hex() {
        let input = "z".repeat(64); // Not valid hex
        assert!(reverse_four_byte_chunks(&input).is_err());
    }

    #[test]
    fn test_to_be_hex() {
        let be_hash = to_be_hex("2305d23e3d6a9f55189723e0dfc653908455a9162b263a0b7b584711cff8cdfe");
        assert_eq!(
            be_hash,
            "fecdf8cf1147587b0b3a262b16a955849053c6dfe0239718559f6a3d3ed20523"
        );
    }
}
