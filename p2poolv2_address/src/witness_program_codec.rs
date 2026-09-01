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

//! How a bare [`WitnessProgram`] is represented on the wire and in serde.
//!
//! A `ShareHeader` stores the witness program an [`Address`](crate::Address)
//! encodes, and not the address itself, because an address also names a
//! network and the network is not consensus data. `WitnessProgram` is a
//! `bitcoin` type with neither a consensus codec nor a serde implementation,
//! so both live here.
//!
//! The layout is defined once, in [`consensus_encode`]: a witness version
//! byte, a program length byte, then the program. [`serde_hex`] is that same
//! encoding as a hex string rather than a second layout, so the two cannot
//! drift apart. A header a peer decodes has to be byte identical to the header
//! its miner encoded, or its `block_hash` differs and it is a different block.
//!
//! Every length here is bounded by construction. The version occupies one
//! byte, the program is 2 to 40 bytes ([`witness_program::MAX_SIZE`]), and
//! [`consensus_decode`] refuses a longer length before it reads any program
//! bytes. Nothing an untrusted peer sends can make a header allocate.

use crate::Address;
use bitcoin::consensus::encode;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hex::DisplayHex;
use bitcoin::{Network, WitnessProgram, WitnessVersion, witness_program};

/// Bytes a witness program can occupy: version, length, and the program.
pub const MAX_ENCODED_LENGTH: usize = 1 + 1 + witness_program::MAX_SIZE;

/// Write a witness program as a version byte, a length byte, then the program.
pub fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
    witness_program: &WitnessProgram,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    let program = witness_program.program().as_bytes();
    // WitnessProgram holds at most MAX_SIZE bytes, so the length is a u8.
    let program_length = program.len() as u8;

    let mut written = witness_program
        .version()
        .to_num()
        .consensus_encode(writer)?;
    written += program_length.consensus_encode(writer)?;
    writer.write_all(program)?;
    Ok(written + program.len())
}

/// Read a witness program written by [`consensus_encode`].
///
/// The length is checked against [`witness_program::MAX_SIZE`] before any
/// program bytes are read, so a hostile length cannot drive a large read.
/// `WitnessProgram::new` then applies the BIP141 bounds, which is what rejects
/// a program under 2 bytes and a version 0 program of an illegal length.
pub fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
) -> Result<WitnessProgram, encode::Error> {
    let version_byte = u8::consensus_decode(reader)?;
    let version = WitnessVersion::try_from(version_byte)
        .map_err(|_| encode::Error::ParseFailed("invalid witness version"))?;

    let program_length = usize::from(u8::consensus_decode(reader)?);
    if program_length > witness_program::MAX_SIZE {
        return Err(encode::Error::ParseFailed("witness program is too long"));
    }

    let mut program = [0u8; witness_program::MAX_SIZE];
    reader.read_exact(&mut program[..program_length])?;

    WitnessProgram::new(version, &program[..program_length])
        .map_err(|_| encode::Error::ParseFailed("invalid witness program"))
}

/// Render a witness program as hex of its consensus encoding.
///
/// For display paths that have no network to render a share chain address
/// with, such as the store and the organise worker, which are both network
/// agnostic by design. Callers that do know the network should build an
/// [`Address`](crate::Address) instead: the bech32m form is what an operator
/// can match against their own configuration.
pub fn to_hex(witness_program: &WitnessProgram) -> String {
    let mut encoded = Vec::with_capacity(MAX_ENCODED_LENGTH);
    consensus_encode(witness_program, &mut encoded).expect("encoding to a Vec should never fail");
    encoded.to_lower_hex_string()
}

/// Render a witness program as a share chain address on `network`.
///
/// This is the other end of storing the owner as a bare program: a
/// `ShareHeader` cannot name a network, so the layers that know the
/// configured one -- the API and the CLI -- turn the program back into the
/// bech32m form an operator recognises.
///
/// Falls back to [`to_hex`] when the program is not one this network can
/// name, which today means a witness version the address format does not
/// accept. Such a program can still reach a node in a header from a peer, and
/// a diagnostic view should render it rather than fail; the hex is the same
/// encoding the header uses, so it stays comparable with a raw header dump.
pub fn to_address_string(witness_program: &WitnessProgram, network: Network) -> String {
    Address::from_witness_program(*witness_program, network)
        .map(|address| address.to_string())
        .unwrap_or_else(|_| to_hex(witness_program))
}

/// Serde for a `WitnessProgram` field, as hex of its consensus encoding.
///
/// Use with `#[serde(with = "p2poolv2_address::witness_program_codec::serde_hex")]`.
///
/// Deliberately not a share chain address string: an address names a network,
/// a witness program does not, and a reader who saw one here would reasonably
/// but wrongly conclude the network round-tripped through the field.
pub mod serde_hex {
    use super::{MAX_ENCODED_LENGTH, consensus_decode, consensus_encode};
    use bitcoin::WitnessProgram;
    use bitcoin::hex::{DisplayHex, FromHex};
    use serde::de::Error as DeserializeError;
    use serde::ser::Error as SerializeError;

    pub fn serialize<S: serde::Serializer>(
        witness_program: &WitnessProgram,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut encoded = Vec::with_capacity(MAX_ENCODED_LENGTH);
        consensus_encode(witness_program, &mut encoded).map_err(S::Error::custom)?;
        serializer.serialize_str(&encoded.to_lower_hex_string())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<WitnessProgram, D::Error> {
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        let bytes = Vec::<u8>::from_hex(&encoded).map_err(D::Error::custom)?;
        consensus_decode(&mut bytes.as_slice()).map_err(D::Error::custom)
    }
}

/// Serde for an `Option<WitnessProgram>` field, as hex of its consensus
/// encoding when present.
///
/// Use with `#[serde(with = "p2poolv2_address::witness_program_codec::serde_hex_option")]`.
pub mod serde_hex_option {
    use bitcoin::WitnessProgram;

    pub fn serialize<S: serde::Serializer>(
        witness_program: &Option<WitnessProgram>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match witness_program {
            Some(program) => serializer.serialize_some(&super::to_hex(program)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<WitnessProgram>, D::Error> {
        let encoded: Option<String> = serde::Deserialize::deserialize(deserializer)?;
        match encoded {
            Some(encoded) => {
                super::serde_hex::deserialize(serde::de::value::StringDeserializer::new(encoded))
                    .map(Some)
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use bitcoin::Network;
    use serde::{Deserialize, Serialize};

    /// A field holding a bare witness program, standing in for the one in
    /// `ShareHeader`.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Owner {
        #[serde(with = "serde_hex")]
        witness_program: WitnessProgram,
    }

    const SIGNET_ADDRESS: &str =
        "sp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks0hep27";

    fn witness_program() -> WitnessProgram {
        SIGNET_ADDRESS.parse::<Address>().unwrap().witness_program()
    }

    #[test]
    fn consensus_round_trips_a_p2tr_program() {
        let mut encoded = Vec::new();
        let written = consensus_encode(&witness_program(), &mut encoded).unwrap();

        assert_eq!(written, encoded.len());
        assert_eq!(encoded.len(), 1 + 1 + 32);
        assert_eq!(
            consensus_decode(&mut encoded.as_slice()).unwrap(),
            witness_program()
        );
    }

    /// The version leads, so a decoder reads it before it can know how to
    /// interpret anything that follows.
    #[test]
    fn consensus_encoding_starts_with_the_version_then_the_length() {
        let mut encoded = Vec::new();
        consensus_encode(&witness_program(), &mut encoded).unwrap();

        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1], 32);
    }

    /// The whole point of storing the program rather than the address: four
    /// networks, one encoding, so one share cannot be spelled four ways.
    #[test]
    fn networks_that_differ_encode_identically() {
        let signet: Address = SIGNET_ADDRESS.parse().unwrap();
        let mainnet =
            Address::from_witness_program(signet.witness_program(), Network::Bitcoin).unwrap();

        let mut signet_encoded = Vec::new();
        consensus_encode(&signet.witness_program(), &mut signet_encoded).unwrap();
        let mut mainnet_encoded = Vec::new();
        consensus_encode(&mainnet.witness_program(), &mut mainnet_encoded).unwrap();

        assert_ne!(signet.to_string(), mainnet.to_string());
        assert_eq!(signet_encoded, mainnet_encoded);
    }

    /// A length byte above the BIP141 maximum must be refused on its own,
    /// before it is used to size a read.
    #[test]
    fn decode_rejects_a_length_over_the_maximum() {
        let too_long = [1u8, 41];
        assert!(consensus_decode(&mut too_long.as_slice()).is_err());
    }

    #[test]
    fn decode_rejects_an_invalid_witness_version() {
        let bad_version = [17u8, 32];
        assert!(consensus_decode(&mut bad_version.as_slice()).is_err());
    }

    /// A truncated program must fail rather than decode a short program.
    #[test]
    fn decode_rejects_a_program_shorter_than_its_length_byte() {
        let truncated = [1u8, 32, 0xaa, 0xbb];
        assert!(consensus_decode(&mut truncated.as_slice()).is_err());
    }

    #[test]
    fn serde_round_trips_as_hex_of_the_consensus_encoding() {
        let owner = Owner {
            witness_program: witness_program(),
        };
        let json = serde_json::to_string(&owner).unwrap();

        assert_eq!(
            json,
            "{\"witness_program\":\"0120ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d\"}"
        );
        assert_eq!(serde_json::from_str::<Owner>(&json).unwrap(), owner);
    }

    /// The same owner is one owner, spelled for whichever network the pool
    /// runs on. This is exactly the presentation the consensus encoding
    /// deliberately does not carry.
    #[test]
    fn to_address_string_spells_one_owner_per_network() {
        let owner = witness_program();
        assert!(to_address_string(&owner, Network::Signet).starts_with("sp2pool1"));
        assert!(to_address_string(&owner, Network::Bitcoin).starts_with("p2pool1"));
        assert!(to_address_string(&owner, Network::Testnet4).starts_with("tp2pool1"));
        assert_eq!(to_address_string(&owner, Network::Signet), SIGNET_ADDRESS);
    }

    /// A network with no share chain prefix must still render something a
    /// reader can compare against a header dump.
    #[test]
    fn to_address_string_falls_back_to_hex_without_a_prefix() {
        assert_eq!(
            to_address_string(&witness_program(), Network::Testnet),
            to_hex(&witness_program())
        );
    }

    #[test]
    fn serde_rejects_a_share_chain_address_string() {
        let json = format!("{{\"witness_program\":\"{SIGNET_ADDRESS}\"}}");
        assert!(serde_json::from_str::<Owner>(&json).is_err());
    }

    /// The codec is deliberately wider than the address policy: it carries any
    /// witness version and any legal length, which is what lets a later
    /// version be a policy change at `Address::from_witness_program` rather
    /// than a change to this encoding. A version 0, 20 byte program is one no
    /// `Address` will build, so it can only round trip if the version and
    /// length are genuinely read back rather than assumed.
    #[test]
    fn consensus_round_trips_a_program_no_address_would_accept() {
        let p2wpkh = WitnessProgram::new(WitnessVersion::V0, &[0x11; 20]).unwrap();

        let mut encoded = Vec::new();
        consensus_encode(&p2wpkh, &mut encoded).unwrap();

        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 20);
        assert_eq!(consensus_decode(&mut encoded.as_slice()).unwrap(), p2wpkh);
        assert!(Address::from_witness_program(p2wpkh, Network::Signet).is_err());
    }

    #[test]
    fn serde_round_trips_a_program_no_address_would_accept() {
        let owner = Owner {
            witness_program: WitnessProgram::new(WitnessVersion::V0, &[0x11; 20]).unwrap(),
        };
        let json = serde_json::to_string(&owner).unwrap();

        assert_eq!(
            json,
            "{\"witness_program\":\"00141111111111111111111111111111111111111111\"}"
        );
        assert_eq!(serde_json::from_str::<Owner>(&json).unwrap(), owner);
    }

    /// The shortest and longest programs BIP141 allows, so the length byte is
    /// exercised at both ends rather than only at 32.
    #[test]
    fn consensus_round_trips_the_shortest_legal_program() {
        let shortest = WitnessProgram::new(WitnessVersion::V1, &[0x07; 2]).unwrap();

        let mut encoded = Vec::new();
        consensus_encode(&shortest, &mut encoded).unwrap();

        assert_eq!(encoded.len(), 1 + 1 + 2);
        assert_eq!(consensus_decode(&mut encoded.as_slice()).unwrap(), shortest);
    }

    #[test]
    fn consensus_round_trips_the_longest_legal_program() {
        let longest =
            WitnessProgram::new(WitnessVersion::V1, &[0x09; witness_program::MAX_SIZE]).unwrap();

        let mut encoded = Vec::new();
        consensus_encode(&longest, &mut encoded).unwrap();

        assert_eq!(encoded.len(), MAX_ENCODED_LENGTH);
        assert_eq!(consensus_decode(&mut encoded.as_slice()).unwrap(), longest);
    }

    /// Decoding must stop at the end of the program rather than consuming
    /// whatever follows it, because a `ShareHeader` has more fields after
    /// this one.
    #[test]
    fn decode_leaves_trailing_bytes_untouched() {
        let mut encoded = Vec::new();
        consensus_encode(&witness_program(), &mut encoded).unwrap();
        encoded.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let mut reader = encoded.as_slice();
        assert_eq!(consensus_decode(&mut reader).unwrap(), witness_program());
        assert_eq!(reader, [0xde, 0xad, 0xbe, 0xef]);
    }
}
