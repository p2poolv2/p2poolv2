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

//! Share chain addresses.
//!
//! A share chain address identifies the owner of a share coinbase output. It
//! is deliberately not a bitcoin address: shares are traded for bitcoin UTXOs,
//! so the identity that owns a share and the identity that receives a bitcoin
//! payout must be impossible to confuse for one another.
//!
//! The encoding is bech32m (BIP350) over a witness version followed by a 32
//! byte taproot output key, under a P2Poolv2 specific human readable part:
//!
//! | Network  | HRP       |
//! |----------|-----------|
//! | Mainnet  | `p2pool`  |
//! | Testnet4 | `tp2pool` |
//! | Signet   | `sp2pool` |
//! | Regtest  | `rp2pool` |
//!
//! Only witness version 1 (P2TR) is accepted. Everything earlier, P2WPKH and
//! P2WSH included, is rejected outright rather than supported and deprecated:
//!
//! * The share chain already verifies taproot in full. `validate_scripts_for_tx`
//!   passes the spent output set to `bitcoinconsensus::verify`, which selects
//!   `VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT`, so nothing needs to change in
//!   the validator to make this work.
//! * Trading a share for a bitcoin UTXO is a cross chain atomic swap. Taproot
//!   on both sides allows adaptor signatures, where the swap is an ordinary key
//!   path spend on each chain with no HTLC script and no preimage published.
//!   Witness version 0 would force HTLC scripts, and therefore P2WSH and 32
//!   byte programs, so it does not even avoid the wider format.
//! * A single output type keeps a single swap protocol. Supporting both would
//!   split the share chain into shares that trade via adaptor signatures and
//!   shares that need HTLCs, and every downstream tool would carry both paths.
//! * Ark is taproot only.
//!
//! Wider support can be soft forked in later: the witness version travels in
//! the encoding, so accepting a new one is a format extension rather than a
//! redesign. It is a consensus change because `miner_address` is committed in
//! `ShareHeader`.
//!
//! The encoded key is the taproot *output* key, matching BIP086 and matching
//! what lands in the `scriptPubKey`. Whether that key commits a script tree is
//! not visible in the address and is not restricted; [`Address::from_internal_key`]
//! applies the BIP086 key path only tweak, which is what the tooling produces.
//!
//! Because only witness version 1 is accepted, the data part is exactly what
//! BIP350 prescribes for a segwit v1 address. **The HRP is the only thing
//! separating a share address from a bitcoin taproot address**, and that is
//! enough: the checksum covers the HRP, so neither string can be reinterpreted
//! as the other, and `bitcoin::Address::from_str` rejects a share address
//! because `p2pool` and friends are not a `KnownHrp`. Note the corollary -- a
//! raw segwit parser that does not restrict the HRP, `bech32::segwit::decode`
//! included, will decode a share address quite happily. Any code deciding
//! whether a string is a bitcoin address must check the HRP, not merely that it
//! parses as segwit.
//!
//! This module never generates, stores or handles a private key. The node only
//! needs the address to build a share coinbase output.

use bitcoin::bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError, PaddingError};
use bitcoin::bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::key::{Parity, TapTweak, TweakedPublicKey, UntweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::taproot::TapNodeHash;
use bitcoin::{Network, ScriptBuf};
use std::fmt::{self, Write};
use std::str::FromStr;

/// Byte length of the taproot output key carried by a share chain address.
const OUTPUT_KEY_LENGTH: usize = 32;

/// The only witness version share chain addresses encode. Fe32::P is 1.
const WITNESS_VERSION_1: Fe32 = Fe32::P;

/// Human readable part for each supported network.
const HRP_MAINNET: &str = "p2pool";
const HRP_TESTNET4: &str = "tp2pool";
const HRP_SIGNET: &str = "sp2pool";
const HRP_REGTEST: &str = "rp2pool";

/// Errors produced when building or parsing a share chain address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// The bitcoin network has no share chain address prefix assigned.
    #[error(
        "No share chain address prefix for network {0}, expected mainnet, testnet4, signet or regtest"
    )]
    UnsupportedNetwork(Network),
    /// The prefix before the bech32 separator is not one of the known HRPs.
    #[error("Unknown share chain address prefix '{0}'")]
    UnknownPrefix(String),
    /// The string is not valid bech32m, including a bech32 checksummed string.
    #[error("Invalid bech32m share chain address: {0}")]
    Encoding(#[from] CheckedHrpstringError),
    /// The trailing bits of the witness program are not valid padding.
    #[error("Invalid padding in share chain address: {0}")]
    Padding(#[from] PaddingError),
    /// The data part is empty, so it carries no witness version.
    #[error("Share chain address is missing a witness version")]
    MissingWitnessVersion,
    /// The first data symbol decodes above 16, so it is not a witness version
    /// at all. Distinct from `UnsupportedWitnessVersion`, which is a real
    /// version we do not accept.
    #[error(
        "Share chain address has '{0}' where a witness version was expected, valid versions are 0 to 16"
    )]
    InvalidWitnessVersion(char),
    /// Only witness version 1 is accepted; see the module docs for why.
    #[error(
        "Unsupported witness version {0} in share chain address, only version 1 (P2TR) is accepted"
    )]
    UnsupportedWitnessVersion(u8),
    /// The taproot output key is not 32 bytes.
    #[error(
        "Invalid taproot output key length {0} in share chain address, expected {OUTPUT_KEY_LENGTH}"
    )]
    InvalidOutputKeyLength(usize),
    /// The 32 bytes are not a valid x-only point, so the output is unspendable.
    #[error("Share chain address does not encode a valid taproot output key: {0}")]
    InvalidOutputKey(#[from] bitcoin::secp256k1::Error),
    /// The address belongs to a different network than the caller requires.
    #[error("Share chain address is for {address_network} but {required_network} is required")]
    NetworkMismatch {
        /// Network the address encodes.
        address_network: Network,
        /// Network the caller asked for.
        required_network: Network,
    },
}

/// Return the human readable part for a network.
fn hrp_for(network: Network) -> Result<Hrp, AddressError> {
    let prefix = match network {
        Network::Bitcoin => HRP_MAINNET,
        Network::Testnet4 => HRP_TESTNET4,
        Network::Signet => HRP_SIGNET,
        Network::Regtest => HRP_REGTEST,
        other => return Err(AddressError::UnsupportedNetwork(other)),
    };
    Ok(Hrp::parse(prefix).expect("share chain HRP constants are valid bech32 HRPs"))
}

/// Return the network that the human readable part belongs to.
///
/// The comparison is between two `Hrp` values, and `Hrp` implements `PartialEq`
/// case insensitively, so an all uppercase address resolves to the same network
/// as its lowercase form.
fn network_for_hrp(hrp: Hrp) -> Result<Network, AddressError> {
    for network in [
        Network::Bitcoin,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        if hrp_for(network)? == hrp {
            return Ok(network);
        }
    }
    Err(AddressError::UnknownPrefix(hrp.to_lowercase()))
}

/// A share chain address: the owner of a share coinbase output.
///
/// Holds the taproot output key already validated as a curve point, so
/// [`Address::script_pubkey`] cannot fail and parsing pays the point
/// decompression once rather than on every use.
///
/// There is deliberately no constructor that takes a bitcoin address:
/// a bitcoin payout address is a receive only identity or watch only
/// script whose owner can never sign a share chain spend.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address {
    network: Network,
    output_key: XOnlyPublicKey,
}

impl Address {
    /// Build a share chain address from a taproot output key.
    ///
    /// The key must already be tweaked. Use [`Address::from_internal_key`] to
    /// apply the BIP086 tweak to an internal key.
    pub fn from_output_key(
        output_key: XOnlyPublicKey,
        network: Network,
    ) -> Result<Self, AddressError> {
        hrp_for(network)?;
        Ok(Self {
            network,
            output_key,
        })
    }

    /// Build a share chain address from an untweaked internal key.
    ///
    /// With `merkle_root` `None` the tweak is `t = H_TapTweak(P)`, committing
    /// to no script tree at all, which makes the script path provably unusable.
    /// That is the BIP341 key path only recommendation and the construction
    /// BIP086 wallets produce for a single key, so it is what the CLI emits.
    ///
    /// Pass `Some(root)` to commit a script tree, giving `t = H_TapTweak(P ||
    /// root)`. Swap contracts need this for their timelocked refund path, and
    /// doing the tweak here keeps the parity and x-only handling in one tested
    /// place rather than in every caller.
    pub fn from_internal_key<C: Verification>(
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        network: Network,
        secp: &Secp256k1<C>,
    ) -> Result<Self, AddressError> {
        let (output_key, _parity): (TweakedPublicKey, Parity) =
            internal_key.tap_tweak(secp, merkle_root);
        Self::from_output_key(output_key.to_x_only_public_key(), network)
    }

    /// The network this address encodes.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The 32 byte taproot output key.
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.output_key
    }

    /// The script this address pays to in a share coinbase output.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(self.output_key))
    }

    /// Return the address if it is for `network`, otherwise error.
    pub fn require_network(self, network: Network) -> Result<Self, AddressError> {
        if self.network == network {
            Ok(self)
        } else {
            Err(AddressError::NetworkMismatch {
                address_network: self.network,
                required_network: network,
            })
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = hrp_for(self.network).map_err(|_| fmt::Error)?;
        let key_bytes = self.output_key.serialize();
        let characters = key_bytes
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(WITNESS_VERSION_1)
            .chars();
        for character in characters {
            formatter.write_char(character)?;
        }
        Ok(())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        //* Requiring Bech32m here is what rejects a bech32 checksummed string
        //* carrying the same payload; bech32::decode would accept either and
        //* not report which one matched. The HRP check below, not the
        //* checksum, is what separates this from a bitcoin taproot address.
        let mut checked = CheckedHrpstring::new::<Bech32m>(address)?;
        let network = network_for_hrp(checked.hrp())?;

        //* The witness version is a single field element and must come off
        //* before the remaining elements regroup into key bytes.
        //*
        //* remove_witness_version returns None for two different reasons, an
        //* empty data part and a first symbol above 16, so they are separated
        //* here rather than reported as one misleading error. The slice borrows
        //* the input string, not `checked`, so taking it before the mutable
        //* call is fine.
        let data_part = checked.data_part_ascii_no_checksum();
        let Some(&first_symbol) = data_part.first() else {
            return Err(AddressError::MissingWitnessVersion);
        };
        let witness_version = checked
            .remove_witness_version()
            .ok_or(AddressError::InvalidWitnessVersion(first_symbol as char))?;
        if witness_version != WITNESS_VERSION_1 {
            return Err(AddressError::UnsupportedWitnessVersion(
                witness_version.to_u8(),
            ));
        }
        checked.validate_segwit_padding()?;

        let key_bytes: Vec<u8> = checked.byte_iter().collect();
        if key_bytes.len() != OUTPUT_KEY_LENGTH {
            return Err(AddressError::InvalidOutputKeyLength(key_bytes.len()));
        }
        //* Validating the point here keeps script_pubkey infallible and stops
        //* an unspendable output key entering the share chain at all.
        let output_key = XOnlyPublicKey::from_slice(&key_bytes)?;
        Ok(Self {
            network,
            output_key,
        })
    }
}

impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let address: String = serde::Deserialize::deserialize(deserializer)?;
        address.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::CompressedPublicKey;

    /// Genesis NUMS pubkey. Its x coordinate is used directly as an output key
    /// in the encoding vectors below, and as an internal key in the tweak test.
    const GENESIS_PUBKEY: &str =
        "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d";
    const OUTPUT_KEY_HEX: &str = "ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d";

    const MAINNET_ADDRESS: &str =
        "p2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksxgg7wd";
    const TESTNET4_ADDRESS: &str =
        "tp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5kst4gevn";
    const SIGNET_ADDRESS: &str =
        "sp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks0hep27";
    const REGTEST_ADDRESS: &str =
        "rp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksqy32kj";

    fn output_key() -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex::decode(OUTPUT_KEY_HEX).unwrap()).unwrap()
    }

    #[test]
    fn display_encodes_mainnet_address() {
        let address = Address::from_output_key(output_key(), Network::Bitcoin).unwrap();
        assert_eq!(address.to_string(), MAINNET_ADDRESS);
    }

    #[test]
    fn display_encodes_testnet4_address() {
        let address = Address::from_output_key(output_key(), Network::Testnet4).unwrap();
        assert_eq!(address.to_string(), TESTNET4_ADDRESS);
    }

    #[test]
    fn display_encodes_signet_address() {
        let address = Address::from_output_key(output_key(), Network::Signet).unwrap();
        assert_eq!(address.to_string(), SIGNET_ADDRESS);
    }

    #[test]
    fn display_encodes_regtest_address() {
        let address = Address::from_output_key(output_key(), Network::Regtest).unwrap();
        assert_eq!(address.to_string(), REGTEST_ADDRESS);
    }

    #[test]
    fn parse_round_trips_mainnet_address() {
        let address: Address = MAINNET_ADDRESS.parse().unwrap();
        assert_eq!(address.network(), Network::Bitcoin);
        assert_eq!(address.output_key(), output_key());
        assert_eq!(address.to_string(), MAINNET_ADDRESS);
    }

    #[test]
    fn parse_round_trips_testnet4_address() {
        let address: Address = TESTNET4_ADDRESS.parse().unwrap();
        assert_eq!(address.network(), Network::Testnet4);
        assert_eq!(address.output_key(), output_key());
        assert_eq!(address.to_string(), TESTNET4_ADDRESS);
    }

    #[test]
    fn parse_round_trips_signet_address() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        assert_eq!(address.network(), Network::Signet);
        assert_eq!(address.output_key(), output_key());
        assert_eq!(address.to_string(), SIGNET_ADDRESS);
    }

    #[test]
    fn parse_round_trips_regtest_address() {
        let address: Address = REGTEST_ADDRESS.parse().unwrap();
        assert_eq!(address.network(), Network::Regtest);
        assert_eq!(address.output_key(), output_key());
        assert_eq!(address.to_string(), REGTEST_ADDRESS);
    }

    #[test]
    fn mainnet_address_is_rejected_for_every_other_network() {
        let address: Address = MAINNET_ADDRESS.parse().unwrap();
        assert!(address.require_network(Network::Testnet4).is_err());
        assert!(address.require_network(Network::Signet).is_err());
        assert!(address.require_network(Network::Regtest).is_err());
    }

    #[test]
    fn testnet4_address_is_rejected_for_every_other_network() {
        let address: Address = TESTNET4_ADDRESS.parse().unwrap();
        assert!(address.require_network(Network::Bitcoin).is_err());
        assert!(address.require_network(Network::Signet).is_err());
        assert!(address.require_network(Network::Regtest).is_err());
    }

    #[test]
    fn signet_address_is_rejected_for_every_other_network() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        assert!(address.require_network(Network::Bitcoin).is_err());
        assert!(address.require_network(Network::Testnet4).is_err());
        assert!(address.require_network(Network::Regtest).is_err());
    }

    #[test]
    fn regtest_address_is_rejected_for_every_other_network() {
        let address: Address = REGTEST_ADDRESS.parse().unwrap();
        assert!(address.require_network(Network::Bitcoin).is_err());
        assert!(address.require_network(Network::Testnet4).is_err());
        assert!(address.require_network(Network::Signet).is_err());
    }

    #[test]
    fn require_network_returns_address_on_match() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        assert!(address.require_network(Network::Signet).is_ok());
    }

    #[test]
    fn require_network_reports_both_networks() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        assert_eq!(
            address.require_network(Network::Bitcoin).unwrap_err(),
            AddressError::NetworkMismatch {
                address_network: Network::Signet,
                required_network: Network::Bitcoin,
            }
        );
    }

    /// Witness version 0 is what a P2WPKH share address would have used. It
    /// must be rejected rather than silently accepted, so that a future soft
    /// fork widening the format is a deliberate consensus change.
    #[test]
    fn witness_version_0_is_rejected() {
        let version_zero = "sp2pool1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6aujzp6";
        assert_eq!(
            version_zero.parse::<Address>().unwrap_err(),
            AddressError::UnsupportedWitnessVersion(0)
        );
    }

    #[test]
    fn witness_version_2_is_rejected() {
        let version_two = "sp2pool1z43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks82qwy4";
        assert_eq!(
            version_two.parse::<Address>().unwrap_err(),
            AddressError::UnsupportedWitnessVersion(2)
        );
    }

    /// A first symbol above 16 is not a witness version at all, so it must not
    /// be reported as a missing one. `3` decodes to 17.
    #[test]
    fn first_symbol_above_sixteen_is_not_a_witness_version() {
        let symbol_seventeen =
            "sp2pool1343yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksnrrrlj";
        assert_eq!(
            symbol_seventeen.parse::<Address>().unwrap_err(),
            AddressError::InvalidWitnessVersion('3')
        );
    }

    /// An empty data part carries no witness version, which is a different
    /// failure from one that is present but out of range.
    #[test]
    fn empty_data_part_is_missing_a_witness_version() {
        let empty_data_part = "sp2pool1pyhy6a";
        assert_eq!(
            empty_data_part.parse::<Address>().unwrap_err(),
            AddressError::MissingWitnessVersion
        );
    }

    #[test]
    fn twenty_byte_program_is_rejected() {
        let twenty_bytes = "sp2pool1px6e0gj7q7xurl08cwnpmeve6w6zf4tw6kz9fv3";
        assert_eq!(
            twenty_bytes.parse::<Address>().unwrap_err(),
            AddressError::InvalidOutputKeyLength(20)
        );
    }

    /// Thirty two bytes that are not a curve point would encode an unspendable
    /// output, so they are refused at parse time rather than at spend time.
    #[test]
    fn invalid_curve_point_is_rejected() {
        let not_a_point = "sp2pool1plllllllllllllllllllllllllllllllllllllllllllllllllllskmdz0g";
        assert!(matches!(
            not_a_point.parse::<Address>(),
            Err(AddressError::InvalidOutputKey(_))
        ));
    }

    /// The same payload under a BIP173 bech32 checksum must not parse. This is
    /// the guard that keeps share addresses out of generic segwit decoders.
    #[test]
    fn bech32_checksum_is_rejected() {
        let bech32_encoded = "sp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks6tfd0u";
        assert!(matches!(
            bech32_encoded.parse::<Address>(),
            Err(AddressError::Encoding(_))
        ));
    }

    /// `p2p` was the prefix in the original issue before it was widened to
    /// `p2pool`; it must not resolve to any network.
    #[test]
    fn unknown_prefix_is_rejected() {
        let unknown = "p2p1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks3cfkdm";
        assert_eq!(
            unknown.parse::<Address>().unwrap_err(),
            AddressError::UnknownPrefix("p2p".to_string())
        );
    }

    #[test]
    fn bitcoin_taproot_address_is_rejected() {
        let bitcoin_address = "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqhqjek6";
        assert!(bitcoin_address.parse::<Address>().is_err());
    }

    #[test]
    fn bitcoin_testnet_bech32_address_is_rejected() {
        let bitcoin_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        assert!(bitcoin_address.parse::<Address>().is_err());
    }

    #[test]
    fn bitcoin_legacy_base58_address_is_rejected() {
        let bitcoin_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        assert!(bitcoin_address.parse::<Address>().is_err());
    }

    /// BIP173 permits an all uppercase encoding, and `Hrp` compares case
    /// insensitively, so it must resolve to the same address.
    #[test]
    fn uppercase_address_parses_to_same_address() {
        let uppercase = "SP2POOL1P43YN7GFSEFTVKHP62KVXPNHE4P8EPDDGTHLYA3HXQELWACTLF5KS0HEP27";
        assert_eq!(
            uppercase.parse::<Address>().unwrap(),
            SIGNET_ADDRESS.parse::<Address>().unwrap()
        );
    }

    #[test]
    fn mixed_case_address_is_rejected() {
        let mixed_case = "sP2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks0hep27";
        assert!(matches!(
            mixed_case.parse::<Address>(),
            Err(AddressError::Encoding(_))
        ));
    }

    #[test]
    fn unsupported_network_has_no_prefix() {
        assert_eq!(
            Address::from_output_key(output_key(), Network::Testnet).unwrap_err(),
            AddressError::UnsupportedNetwork(Network::Testnet)
        );
    }

    /// Cross check the BIP086 tweak against rust-bitcoin: the address must
    /// carry the same output key that `bitcoin::Address::p2tr` derives from the
    /// same internal key, so a share address and a bitcoin taproot address for
    /// one key agree on the program while differing in every other respect.
    #[test]
    fn from_internal_key_applies_the_bip086_tweak() {
        let secp = Secp256k1::verification_only();
        let internal_key = CompressedPublicKey::from_str(GENESIS_PUBKEY)
            .unwrap()
            .0
            .x_only_public_key()
            .0;

        let address =
            Address::from_internal_key(internal_key, None, Network::Signet, &secp).unwrap();
        let bitcoin_address = bitcoin::Address::p2tr(&secp, internal_key, None, Network::Signet);

        assert_eq!(address.script_pubkey(), bitcoin_address.script_pubkey());
        assert_ne!(address.to_string(), bitcoin_address.to_string());
    }

    /// A script tree commitment must reach the output key. Swap contracts will
    /// pass a merkle root here for their timelocked refund path, so the tweak
    /// has to differ from the key path only one and match rust-bitcoin.
    #[test]
    fn from_internal_key_commits_a_script_tree_merkle_root() {
        let secp = Secp256k1::verification_only();
        let internal_key = CompressedPublicKey::from_str(GENESIS_PUBKEY)
            .unwrap()
            .0
            .x_only_public_key()
            .0;
        let merkle_root = TapNodeHash::assume_hidden([0x42; 32]);

        let with_tree =
            Address::from_internal_key(internal_key, Some(merkle_root), Network::Signet, &secp)
                .unwrap();
        let key_path_only =
            Address::from_internal_key(internal_key, None, Network::Signet, &secp).unwrap();

        assert_ne!(with_tree.output_key(), key_path_only.output_key());
        assert_eq!(
            with_tree.script_pubkey(),
            bitcoin::Address::p2tr(&secp, internal_key, Some(merkle_root), Network::Signet)
                .script_pubkey()
        );
    }

    /// The share coinbase pays this script and `validate_share_coinbase`
    /// compares against it, so it must be the standard P2TR script.
    #[test]
    fn script_pubkey_is_p2tr_for_the_output_key() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        let expected =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key()));
        assert_eq!(address.script_pubkey(), expected);
        assert!(address.script_pubkey().is_p2tr());
    }

    /// The guarantee that actually matters: a bitcoin address parser must not
    /// accept a share address. With v1 only, the data part is exactly BIP350
    /// segwit v1, so the HRP is the sole separator -- this pins that it is
    /// enough.
    #[test]
    fn bitcoin_address_parser_rejects_a_share_address() {
        assert!(
            SIGNET_ADDRESS
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .is_err()
        );
    }

    /// The converse of the above, and the reason the module docs warn about it:
    /// a share address and a bitcoin taproot address for the same output key
    /// differ only in the HRP, so they share a script_pubkey while being
    /// entirely distinct strings.
    #[test]
    fn share_and_bitcoin_taproot_addresses_differ_only_by_prefix() {
        let share: Address = SIGNET_ADDRESS.parse().unwrap();
        let bitcoin_address = bitcoin::Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(output_key()),
            Network::Signet,
        );

        assert_eq!(share.script_pubkey(), bitcoin_address.script_pubkey());
        assert_ne!(share.to_string(), bitcoin_address.to_string());
        assert!(share.to_string().starts_with("sp2pool1"));
        assert!(bitcoin_address.to_string().starts_with("tb1"));
    }

    #[test]
    fn serde_round_trips_through_string() {
        let address: Address = SIGNET_ADDRESS.parse().unwrap();
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(json, format!("\"{SIGNET_ADDRESS}\""));
        assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), address);
    }

    #[test]
    fn serde_rejects_a_bitcoin_address() {
        let json = "\"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqhqjek6\"";
        assert!(serde_json::from_str::<Address>(json).is_err());
    }
}
