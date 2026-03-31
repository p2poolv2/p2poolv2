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
use bitcoin::script::PushBytesBuf;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum length of coinbaseaux flags in bytes.
pub const MAX_COINBASEAUX_FLAGS_LENGTH: usize = 32;

/// Stack-allocated coinbaseaux flags with a maximum of 32 bytes.
///
/// Stores decoded bytes directly, avoiding heap allocation. Flags
/// longer than 32 bytes are truncated at construction time.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoinbaseAuxFlags {
    data: [u8; MAX_COINBASEAUX_FLAGS_LENGTH],
    length: u8,
}

impl CoinbaseAuxFlags {
    /// Create from a byte slice, truncating to 32 bytes if longer.
    pub fn new(bytes: &[u8]) -> Self {
        let actual_length = bytes.len().min(MAX_COINBASEAUX_FLAGS_LENGTH);
        let mut data = [0u8; MAX_COINBASEAUX_FLAGS_LENGTH];
        data[..actual_length].copy_from_slice(&bytes[..actual_length]);
        Self {
            data,
            length: actual_length as u8,
        }
    }

    /// Return the actual flag bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.length as usize]
    }

    /// Convert to PushBytesBuf for use in coinbase script building.
    ///
    /// This is infallible because 32 bytes is well under the 520-byte
    /// PushBytesBuf limit.
    pub fn to_push_bytes_buf(&self) -> PushBytesBuf {
        PushBytesBuf::try_from(self.as_bytes().to_vec())
            .expect("32 bytes always fits in PushBytesBuf")
    }
}

impl Encodable for CoinbaseAuxFlags {
    /// Encode as VarInt length prefix followed by raw bytes.
    ///
    /// Wire-compatible with Vec<u8> consensus encoding.
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        self.as_bytes().to_vec().consensus_encode(writer)
    }
}

impl Decodable for CoinbaseAuxFlags {
    /// Decode from VarInt length prefix followed by raw bytes.
    ///
    /// Rejects lengths greater than 32 bytes.
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let bytes = Vec::<u8>::consensus_decode(reader)?;
        if bytes.len() > MAX_COINBASEAUX_FLAGS_LENGTH {
            return Err(bitcoin::consensus::encode::Error::ParseFailed(
                "coinbaseaux flags exceed 32 bytes",
            ));
        }
        Ok(Self::new(&bytes))
    }
}

impl Serialize for CoinbaseAuxFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for CoinbaseAuxFlags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(de::Error::custom)?;
        Ok(Self::new(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};

    #[test]
    fn test_new_stores_bytes() {
        let flags = CoinbaseAuxFlags::new(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(flags.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_new_empty() {
        let flags = CoinbaseAuxFlags::new(&[]);
        assert!(flags.as_bytes().is_empty());
    }

    #[test]
    fn test_new_truncates_at_32_bytes() {
        let long_bytes = [0xff; 64];
        let flags = CoinbaseAuxFlags::new(&long_bytes);
        assert_eq!(flags.as_bytes().len(), 32);
        assert_eq!(flags.as_bytes(), &[0xff; 32]);
    }

    #[test]
    fn test_new_exactly_32_bytes() {
        let bytes = [0xab; 32];
        let flags = CoinbaseAuxFlags::new(&bytes);
        assert_eq!(flags.as_bytes(), &[0xab; 32]);
    }

    #[test]
    fn test_to_push_bytes_buf() {
        let flags = CoinbaseAuxFlags::new(&[0xde, 0xad]);
        let push_buf = flags.to_push_bytes_buf();
        assert_eq!(push_buf.as_bytes(), &[0xde, 0xad]);
    }

    #[test]
    fn test_consensus_round_trip() {
        let original = CoinbaseAuxFlags::new(&[0xde, 0xad, 0xbe, 0xef]);
        let encoded = serialize(&original);
        let decoded: CoinbaseAuxFlags = deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_consensus_round_trip_empty() {
        let original = CoinbaseAuxFlags::new(&[]);
        let encoded = serialize(&original);
        let decoded: CoinbaseAuxFlags = deserialize(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_consensus_decode_rejects_over_32_bytes() {
        let long_vec: Vec<u8> = vec![0xff; 33];
        let encoded = serialize(&long_vec);
        let result = deserialize::<CoinbaseAuxFlags>(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_round_trip() {
        let flags = Some(CoinbaseAuxFlags::new(&[0xde, 0xad, 0xbe, 0xef]));
        let json = serde_json::to_string(&TestWrapper {
            flags: flags.clone(),
        })
        .unwrap();
        assert!(json.contains("deadbeef"));
        let decoded: TestWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.flags, flags);
    }

    #[test]
    fn test_serde_none() {
        let json = serde_json::to_string(&TestWrapper { flags: None }).unwrap();
        let decoded: TestWrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.flags, None);
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct TestWrapper {
        #[serde(default)]
        flags: Option<CoinbaseAuxFlags>,
    }
}
