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

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::script::ScriptBuf;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// BIP141 witness commitment length in bytes.
///
/// Structure: OP_RETURN (1) + push_36 (1) + header "aa21a9ed" (4) + 32-byte hash = 38.
pub const WITNESS_COMMITMENT_LENGTH: usize = 38;

/// Stack-allocated BIP141 witness commitment (exactly 38 bytes).
///
/// Stores the full commitment script bytes, avoiding heap allocation.
#[derive(Clone, PartialEq, Eq)]
pub struct WitnessCommitment([u8; WITNESS_COMMITMENT_LENGTH]);

/// Error for invalid witness commitment construction.
#[derive(Debug)]
pub struct WitnessCommitmentError(String);

impl fmt::Display for WitnessCommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for WitnessCommitmentError {}

impl fmt::Debug for WitnessCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WitnessCommitment({})", hex::encode(self.0))
    }
}

impl WitnessCommitment {
    /// Create from a fixed-size byte array.
    pub fn new(bytes: [u8; WITNESS_COMMITMENT_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Create from a hex-encoded string.
    ///
    /// Returns an error if the hex is invalid or not exactly 38 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, WitnessCommitmentError> {
        let bytes = hex::decode(hex_str).map_err(|error| {
            WitnessCommitmentError(format!("invalid witness commitment hex: {error}"))
        })?;
        let array: [u8; WITNESS_COMMITMENT_LENGTH] = bytes.try_into().map_err(|vec: Vec<u8>| {
            WitnessCommitmentError(format!(
                "witness commitment must be exactly {} bytes, got {}",
                WITNESS_COMMITMENT_LENGTH,
                vec.len()
            ))
        })?;
        Ok(Self(array))
    }

    /// Return the commitment bytes as a slice.
    pub fn as_bytes(&self) -> &[u8; WITNESS_COMMITMENT_LENGTH] {
        &self.0
    }

    /// Convert to ScriptBuf for use as a transaction output script.
    pub fn to_script_buf(&self) -> ScriptBuf {
        ScriptBuf::from(self.0.to_vec())
    }
}

impl Encodable for WitnessCommitment {
    /// Encode the 38 raw bytes directly (no length prefix needed since size is fixed).
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        writer.write_all(&self.0)?;
        Ok(WITNESS_COMMITMENT_LENGTH)
    }
}

impl Decodable for WitnessCommitment {
    /// Decode 38 raw bytes.
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let mut bytes = [0u8; WITNESS_COMMITMENT_LENGTH];
        reader.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl Serialize for WitnessCommitment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for WitnessCommitment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};

    const VALID_COMMITMENT_HEX: &str =
        "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9";

    #[test]
    fn test_from_hex_valid() {
        let commitment = WitnessCommitment::from_hex(VALID_COMMITMENT_HEX).unwrap();
        assert_eq!(commitment.as_bytes()[0], 0x6a);
        assert_eq!(commitment.as_bytes()[1], 0x24);
        assert_eq!(commitment.as_bytes()[2], 0xaa);
    }

    #[test]
    fn test_from_hex_wrong_length() {
        let result = WitnessCommitment::from_hex("6a24aa21a9ed");
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("must be exactly 38 bytes"));
    }

    #[test]
    fn test_from_hex_invalid_hex() {
        let result = WitnessCommitment::from_hex("not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_to_script_buf() {
        let commitment = WitnessCommitment::from_hex(VALID_COMMITMENT_HEX).unwrap();
        let script = commitment.to_script_buf();
        assert_eq!(script.as_bytes(), commitment.as_bytes());
    }

    #[test]
    fn test_consensus_round_trip() {
        let original = WitnessCommitment::from_hex(VALID_COMMITMENT_HEX).unwrap();
        let encoded = serialize(&original);
        assert_eq!(encoded.len(), WITNESS_COMMITMENT_LENGTH);
        let decoded: WitnessCommitment = deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_serde_round_trip() {
        let commitment = Some(WitnessCommitment::from_hex(VALID_COMMITMENT_HEX).unwrap());
        let json = serde_json::to_string(&TestWrapper {
            commitment: commitment.clone(),
        })
        .unwrap();
        assert!(json.contains(VALID_COMMITMENT_HEX));
        let decoded: TestWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.commitment, commitment);
    }

    #[test]
    fn test_serde_none() {
        let json = serde_json::to_string(&TestWrapper { commitment: None }).unwrap();
        let decoded: TestWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.commitment, None);
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestWrapper {
        #[serde(default)]
        commitment: Option<WitnessCommitment>,
    }
}
