// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Who owns a share coinbase output.
//!
//! Bitcoin stores a taproot witness program. Those bytes are exactly the
//! historical encoding in [`crate::witness_program_codec`]: a version byte, a
//! length byte, then the program. A Bitcoin node that only knows that layout
//! still decodes every share it already accepted.
//!
//! Bitcoin Cash has no taproot. Its owner is a 20-byte P2PKH hash. The first
//! byte is [`CASH_P2PKH_TAG`], which is not a witness version, so a decoder
//! that only accepts versions 0 through 16 rejects the share instead of
//! reading the hash as a program. The prefix of the CashAddr form is not
//! stored: the chain already knows its network.

use crate::bch_share::{BchShareAddress, BchShareNetwork};
use crate::witness_program_codec;
use bitcoin::consensus::encode::{self, Error as EncodeError};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Network, PubkeyHash, ScriptBuf, WitnessProgram};

/// First byte of a Bitcoin Cash P2PKH share owner.
///
/// Witness versions stop at 16. This tag sits outside that range so the two
/// layouts cannot be confused, and so an older decoder fails closed.
pub const CASH_P2PKH_TAG: u8 = 0x20;

/// Byte length of the HASH160 a Bitcoin Cash share coinbase pays.
pub const CASH_P2PKH_HASH_LENGTH: usize = 20;

/// Largest owner encoding: a max-size witness program, or the cash tag plus
/// its length and hash. The cash form is the smaller of the two.
pub const MAX_ENCODED_LENGTH: usize = witness_program_codec::MAX_ENCODED_LENGTH;

/// Owner of a share coinbase output, as committed in a share header.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ShareOwner {
    /// Bitcoin taproot program. Encoded exactly as a bare witness program.
    Taproot(WitnessProgram),
    /// Bitcoin Cash P2PKH key hash. The network prefix is not part of this.
    CashP2pkh([u8; CASH_P2PKH_HASH_LENGTH]),
}

impl From<WitnessProgram> for ShareOwner {
    fn from(program: WitnessProgram) -> Self {
        Self::Taproot(program)
    }
}

impl ShareOwner {
    /// Script the share coinbase pays.
    pub fn script_pubkey(self) -> ScriptBuf {
        match self {
            Self::Taproot(program) => ScriptBuf::new_witness_program(&program),
            Self::CashP2pkh(hash) => ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)),
        }
    }

    /// True when this is a taproot witness program.
    pub fn is_taproot(self) -> bool {
        matches!(self, Self::Taproot(program) if program.is_p2tr())
    }
}

/// Write an owner with [`witness_program_codec::consensus_encode`] for taproot.
pub fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
    owner: &ShareOwner,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    match owner {
        ShareOwner::Taproot(program) => witness_program_codec::consensus_encode(program, writer),
        ShareOwner::CashP2pkh(hash) => {
            let mut written = CASH_P2PKH_TAG.consensus_encode(writer)?;
            written += (CASH_P2PKH_HASH_LENGTH as u8).consensus_encode(writer)?;
            writer.write_all(hash)?;
            Ok(written + hash.len())
        }
    }
}

/// Read an owner written by [`consensus_encode`].
pub fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<ShareOwner, EncodeError> {
    let tag = u8::consensus_decode(reader)?;
    if tag == CASH_P2PKH_TAG {
        let hash_length = usize::from(u8::consensus_decode(reader)?);
        if hash_length != CASH_P2PKH_HASH_LENGTH {
            return Err(encode::Error::ParseFailed(
                "bitcoin cash share hash must be 20 bytes",
            ));
        }
        let mut hash = [0u8; CASH_P2PKH_HASH_LENGTH];
        reader.read_exact(&mut hash)?;
        return Ok(ShareOwner::CashP2pkh(hash));
    }
    witness_program_codec::consensus_decode_from_version(tag, reader).map(ShareOwner::Taproot)
}

/// Hex of the consensus encoding.
pub fn to_hex(owner: &ShareOwner) -> String {
    let mut encoded = Vec::with_capacity(MAX_ENCODED_LENGTH);
    consensus_encode(owner, &mut encoded).expect("encoding to a Vec should never fail");
    encoded.to_lower_hex_string()
}

/// Text form an operator can match against configuration.
///
/// Taproot uses the Bitcoin share address for `network`. A cash owner uses
/// `cash_network`, which is `bitcoin_cash_network`, not the Bitcoin
/// share-chain network. Signet and testnet4 are not chipnet. Without a cash
/// network the consensus hex is returned, so a missing prefix is not spelled
/// as `tp2pool`.
pub fn to_address_string(
    owner: &ShareOwner,
    network: Network,
    cash_network: Option<BchShareNetwork>,
) -> String {
    match owner {
        ShareOwner::Taproot(program) => witness_program_codec::to_address_string(program, network),
        ShareOwner::CashP2pkh(hash) => match cash_network {
            Some(cash_network) => BchShareAddress::new(cash_network, *hash).encode(),
            None => to_hex(owner),
        },
    }
}

/// Serde for a [`ShareOwner`] field, as hex of its consensus encoding.
pub mod serde_hex {
    use super::{MAX_ENCODED_LENGTH, ShareOwner, consensus_decode, consensus_encode};
    use bitcoin::hex::{DisplayHex, FromHex};
    use serde::de::Error as DeserializeError;
    use serde::ser::Error as SerializeError;

    pub fn serialize<S: serde::Serializer>(
        owner: &ShareOwner,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut encoded = Vec::with_capacity(MAX_ENCODED_LENGTH);
        consensus_encode(owner, &mut encoded).map_err(S::Error::custom)?;
        serializer.serialize_str(&encoded.to_lower_hex_string())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ShareOwner, D::Error> {
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        let bytes = Vec::<u8>::from_hex(&encoded).map_err(D::Error::custom)?;
        consensus_decode(&mut bytes.as_slice()).map_err(D::Error::custom)
    }
}

/// Serde for an `Option<ShareOwner>` field.
pub mod serde_hex_option {
    use super::ShareOwner;
    use serde::Deserialize;

    pub fn serialize<S: serde::Serializer>(
        owner: &Option<ShareOwner>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match owner {
            Some(owner) => super::serde_hex::serialize(owner, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ShareOwner>, D::Error> {
        let encoded = Option::<String>::deserialize(deserializer)?;
        match encoded {
            Some(encoded) => {
                let owner = super::serde_hex::deserialize(
                    serde::de::value::StringDeserializer::new(encoded),
                )?;
                Ok(Some(owner))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::WitnessVersion;

    fn taproot_program() -> WitnessProgram {
        WitnessProgram::new(WitnessVersion::V1, &[0x11; 32]).expect("32 byte v1 program")
    }

    #[test]
    fn taproot_bytes_match_the_witness_program_codec() {
        let program = taproot_program();
        let owner = ShareOwner::Taproot(program);
        let mut owner_bytes = Vec::new();
        let mut program_bytes = Vec::new();
        consensus_encode(&owner, &mut owner_bytes).unwrap();
        witness_program_codec::consensus_encode(&program, &mut program_bytes).unwrap();
        assert_eq!(owner_bytes, program_bytes);
        assert_eq!(
            consensus_decode(&mut owner_bytes.as_slice()).unwrap(),
            owner
        );
    }

    #[test]
    fn cash_hash_round_trips_under_its_own_tag() {
        let hash = [0x22; 20];
        let owner = ShareOwner::CashP2pkh(hash);
        let mut encoded = Vec::new();
        consensus_encode(&owner, &mut encoded).unwrap();
        assert_eq!(encoded[0], CASH_P2PKH_TAG);
        assert_eq!(encoded[1], 20);
        assert_eq!(&encoded[2..], &hash);
        assert_eq!(consensus_decode(&mut encoded.as_slice()).unwrap(), owner);
        assert!(owner.script_pubkey().is_p2pkh());
    }

    #[test]
    fn cash_tag_is_not_decoded_as_a_witness_program() {
        let owner = ShareOwner::CashP2pkh([0x22; 20]);
        let mut encoded = Vec::new();
        consensus_encode(&owner, &mut encoded).unwrap();
        assert!(witness_program_codec::consensus_decode(&mut encoded.as_slice()).is_err());
    }

    #[test]
    fn cash_address_text_uses_the_supplied_cash_network() {
        let owner = ShareOwner::CashP2pkh([0x22; 20]);
        let text = to_address_string(&owner, Network::Signet, Some(BchShareNetwork::Regtest));
        assert!(text.starts_with("rp2pool:"));
        assert_eq!(
            crate::bch_share::parse(&text, BchShareNetwork::Regtest)
                .unwrap()
                .hash,
            [0x22; 20]
        );
        let mainnet = to_address_string(&owner, Network::Signet, Some(BchShareNetwork::Mainnet));
        assert!(mainnet.starts_with("p2pool:"));
        assert_eq!(
            to_address_string(&owner, Network::Signet, None),
            to_hex(&owner)
        );
    }
}
