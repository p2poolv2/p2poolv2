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

use crate::stratum::session::{EXTRANONCE1_SIZE, EXTRANONCE2_SIZE};
use bitcoin::consensus::{Decodable, Encodable};
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Total extranonce length: enonce1 (4 bytes) + enonce2 (8 bytes).
pub const EXTRANONCE_LENGTH: usize = EXTRANONCE1_SIZE + EXTRANONCE2_SIZE;

/// Combined extranonce (enonce1 || enonce2) embedded in the coinbase scriptSig.
///
/// Stores the concatenated extranonce bytes that replace the placeholder
/// separator in the coinbase transaction. Validators use this to
/// reconstruct the exact coinbase txid for merkle root verification.
#[derive(Clone, PartialEq, Eq)]
pub struct Extranonce([u8; EXTRANONCE_LENGTH]);

impl Default for Extranonce {
    fn default() -> Self {
        Self([0u8; EXTRANONCE_LENGTH])
    }
}

impl fmt::Debug for Extranonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Extranonce({})", hex::encode(self.0))
    }
}

impl Extranonce {
    /// Create from the concatenated hex strings of enonce1 and enonce2.
    ///
    /// Returns an error if the hex is invalid or the combined length is
    /// not exactly 12 bytes.
    pub fn from_enonce_hex(enonce1_hex: &str, enonce2_hex: &str) -> Result<Self, ExtranonceError> {
        let enonce1_bytes = hex::decode(enonce1_hex)
            .map_err(|error| ExtranonceError(format!("invalid enonce1 hex: {error}")))?;
        let enonce2_bytes = hex::decode(enonce2_hex)
            .map_err(|error| ExtranonceError(format!("invalid enonce2 hex: {error}")))?;
        if enonce1_bytes.len() != EXTRANONCE1_SIZE {
            return Err(ExtranonceError(format!(
                "enonce1 must be {} bytes, got {}",
                EXTRANONCE1_SIZE,
                enonce1_bytes.len()
            )));
        }
        if enonce2_bytes.len() != EXTRANONCE2_SIZE {
            return Err(ExtranonceError(format!(
                "enonce2 must be {} bytes, got {}",
                EXTRANONCE2_SIZE,
                enonce2_bytes.len()
            )));
        }
        let mut bytes = [0u8; EXTRANONCE_LENGTH];
        bytes[..EXTRANONCE1_SIZE].copy_from_slice(&enonce1_bytes);
        bytes[EXTRANONCE1_SIZE..].copy_from_slice(&enonce2_bytes);
        Ok(Self(bytes))
    }

    /// Return the extranonce bytes as a slice.
    pub fn as_bytes(&self) -> &[u8; EXTRANONCE_LENGTH] {
        &self.0
    }
}

/// Error for invalid extranonce construction.
#[derive(Debug)]
pub struct ExtranonceError(String);

impl fmt::Display for ExtranonceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for ExtranonceError {}

impl Encodable for Extranonce {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        writer.write_all(&self.0)?;
        Ok(EXTRANONCE_LENGTH)
    }
}

impl Decodable for Extranonce {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let mut bytes = [0u8; EXTRANONCE_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Extranonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for Extranonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(de::Error::custom)?;
        let array: [u8; EXTRANONCE_LENGTH] = bytes.try_into().map_err(|vec: Vec<u8>| {
            de::Error::custom(format!(
                "extranonce must be exactly {} bytes, got {}",
                EXTRANONCE_LENGTH,
                vec.len()
            ))
        })?;
        Ok(Self(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};

    #[test]
    fn test_from_enonce_hex_valid() {
        let extranonce = Extranonce::from_enonce_hex("aabbccdd", "0011223344556677").unwrap();
        assert_eq!(
            extranonce.as_bytes(),
            &[
                0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
            ]
        );
    }

    #[test]
    fn test_from_enonce_hex_wrong_enonce1_length() {
        let result = Extranonce::from_enonce_hex("aabb", "0011223344556677");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("enonce1 must be 4 bytes")
        );
    }

    #[test]
    fn test_from_enonce_hex_wrong_enonce2_length() {
        let result = Extranonce::from_enonce_hex("aabbccdd", "0011");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("enonce2 must be 8 bytes")
        );
    }

    #[test]
    fn test_from_enonce_hex_invalid_hex() {
        let result = Extranonce::from_enonce_hex("not_hex!", "0011223344556677");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_is_all_zeros() {
        let extranonce = Extranonce::default();
        assert_eq!(extranonce.as_bytes(), &[0u8; EXTRANONCE_LENGTH]);
    }

    #[test]
    fn test_consensus_round_trip() {
        let original = Extranonce::from_enonce_hex("aabbccdd", "0011223344556677").unwrap();
        let encoded = serialize(&original);
        assert_eq!(encoded.len(), EXTRANONCE_LENGTH);
        let decoded: Extranonce = deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_round_trip() {
        let original = Extranonce::from_enonce_hex("aabbccdd", "0011223344556677").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"aabbccdd0011223344556677\"");
        let decoded: Extranonce = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
