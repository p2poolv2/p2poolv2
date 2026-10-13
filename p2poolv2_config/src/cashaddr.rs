// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CashAddr (Bitcoin Cash address) decoding for payout scripts.
//!
//! The checksum and version byte follow the CashAddr specification. Only
//! 20-byte pay-to-public-key-hash and pay-to-script-hash payloads are
//! accepted. Token-aware addresses and longer hashes are rejected so a
//! payout cannot be aimed at a script this node does not construct.

use super::BitcoinCashNetwork;
use bitcoin::hashes::Hash;
use bitcoin::{Address, PubkeyHash, ScriptHash};

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CHECKSUM_SYMBOLS: usize = 8;
const GENERATORS: [u64; 5] = [
    0x98f2bc8e61,
    0x79b76d99e2,
    0xf33e5fb3c4,
    0xae2eabe2a8,
    0x1e4f43e470,
];
const HASH_SIZE_BYTES: [usize; 8] = [20, 24, 28, 32, 40, 48, 56, 64];
const PUBLIC_KEY_HASH_SIZE: usize = 20;

/// A decoded CashAddr that can be paid by a coinbase output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CashAddr {
    network: BitcoinCashNetwork,
    kind: CashAddrKind,
    payload: [u8; PUBLIC_KEY_HASH_SIZE],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CashAddrKind {
    PayToPublicKeyHash,
    PayToScriptHash,
}

/// Why a string is not a payout CashAddr for the selected network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CashAddrError {
    MixedCase,
    MissingPrefix,
    UnknownPrefix,
    PrefixMismatch,
    InvalidCharacter,
    Checksum,
    Payload,
    UnsupportedVersion,
}

impl std::fmt::Display for CashAddrError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            CashAddrError::MixedCase => "mixed-case CashAddr",
            CashAddrError::MissingPrefix => "CashAddr prefix is required",
            CashAddrError::UnknownPrefix => "unknown CashAddr prefix",
            CashAddrError::PrefixMismatch => "CashAddr prefix does not match bitcoin_cash_network",
            CashAddrError::InvalidCharacter => "invalid CashAddr character",
            CashAddrError::Checksum => "invalid CashAddr checksum",
            CashAddrError::Payload => "invalid CashAddr payload",
            CashAddrError::UnsupportedVersion => {
                "only 20-byte P2PKH and P2SH CashAddr payouts are accepted"
            }
        };
        write!(formatter, "{message}")
    }
}

impl CashAddr {
    /// Bitcoin script this address pays. The legacy network tag exists so the
    /// existing coinbase builder can call `script_pubkey`; the script bytes
    /// are the CashAddr payload, not a Bitcoin witness program.
    pub fn to_address(&self) -> Address {
        let network = self.network.legacy_network();
        match self.kind {
            CashAddrKind::PayToPublicKeyHash => {
                Address::p2pkh(PubkeyHash::from_byte_array(self.payload), network)
            }
            CashAddrKind::PayToScriptHash => {
                Address::p2sh_from_hash(ScriptHash::from_byte_array(self.payload), network)
            }
        }
    }
}

/// Decode `address` and require its prefix to identify `network`.
pub fn decode(address: &str, network: BitcoinCashNetwork) -> Result<CashAddr, CashAddrError> {
    let normalized = normalize_case(address)?;
    let (prefix, payload_text) = split_prefix(&normalized)?;
    if prefix != network.cashaddr_prefix() {
        return Err(CashAddrError::PrefixMismatch);
    }
    let symbols = decode_symbols(payload_text)?;
    if symbols.len() <= CHECKSUM_SYMBOLS {
        return Err(CashAddrError::Payload);
    }
    let mut checksum_input = expand_prefix(prefix);
    checksum_input.extend_from_slice(&symbols);
    if polymod(&checksum_input) != 0 {
        return Err(CashAddrError::Checksum);
    }
    let payload_symbols = &symbols[..symbols.len() - CHECKSUM_SYMBOLS];
    let payload = regroup_five_to_eight(payload_symbols)?;
    decode_version(network, &payload)
}

fn normalize_case(address: &str) -> Result<String, CashAddrError> {
    let has_lower = address.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = address.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(CashAddrError::MixedCase);
    }
    Ok(address.to_ascii_lowercase())
}

fn split_prefix(address: &str) -> Result<(&str, &str), CashAddrError> {
    let Some((prefix, payload_text)) = address.split_once(':') else {
        return Err(CashAddrError::MissingPrefix);
    };
    if prefix.is_empty() || payload_text.is_empty() || payload_text.contains(':') {
        return Err(CashAddrError::MissingPrefix);
    }
    if prefix_for(prefix).is_none() {
        return Err(CashAddrError::UnknownPrefix);
    }
    Ok((prefix, payload_text))
}

fn prefix_for(prefix: &str) -> Option<BitcoinCashNetwork> {
    match prefix {
        "bitcoincash" => Some(BitcoinCashNetwork::Mainnet),
        "bchtest" => Some(BitcoinCashNetwork::Chipnet),
        "bchreg" => Some(BitcoinCashNetwork::Regtest),
        _ => None,
    }
}

fn decode_symbols(payload_text: &str) -> Result<Vec<u8>, CashAddrError> {
    let mut symbols = Vec::with_capacity(payload_text.len());
    for character in payload_text.bytes() {
        let Some(index) = CHARSET.iter().position(|symbol| *symbol == character) else {
            return Err(CashAddrError::InvalidCharacter);
        };
        symbols.push(index as u8);
    }
    Ok(symbols)
}

fn expand_prefix(prefix: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(prefix.len() + 1);
    for character in prefix.bytes() {
        expanded.push(character & 0x1f);
    }
    expanded.push(0);
    expanded
}

fn polymod(values: &[u8]) -> u64 {
    let mut checksum: u64 = 1;
    for value in values {
        let overflow = checksum >> 35;
        checksum = ((checksum & 0x07_ffff_ffff) << 5) ^ u64::from(*value);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if overflow & (1_u64 << bit) != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum ^ 1
}

fn regroup_five_to_eight(symbols: &[u8]) -> Result<Vec<u8>, CashAddrError> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut payload = Vec::with_capacity((symbols.len() * 5) / 8);
    for symbol in symbols {
        if *symbol >= 32 {
            return Err(CashAddrError::Payload);
        }
        accumulator = ((accumulator << 5) | u32::from(*symbol)) & 0x0fff;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            payload.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || ((accumulator << (8 - bits)) & 0xff) != 0 {
        return Err(CashAddrError::Payload);
    }
    Ok(payload)
}

fn decode_version(network: BitcoinCashNetwork, payload: &[u8]) -> Result<CashAddr, CashAddrError> {
    let Some((version, hash)) = payload.split_first() else {
        return Err(CashAddrError::Payload);
    };
    if version & 0x80 != 0 {
        return Err(CashAddrError::UnsupportedVersion);
    }
    let kind_bits = (version >> 3) & 0x0f;
    let size_index = usize::from(version & 0x07);
    if hash.len() != HASH_SIZE_BYTES[size_index] || hash.len() != PUBLIC_KEY_HASH_SIZE {
        return Err(CashAddrError::UnsupportedVersion);
    }
    let kind = match kind_bits {
        0 => CashAddrKind::PayToPublicKeyHash,
        1 => CashAddrKind::PayToScriptHash,
        _ => return Err(CashAddrError::UnsupportedVersion),
    };
    let mut hash_bytes = [0_u8; PUBLIC_KEY_HASH_SIZE];
    hash_bytes.copy_from_slice(hash);
    Ok(CashAddr {
        network,
        kind,
        payload: hash_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mainnet_public_key_hash_vector() {
        let decoded = decode(
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            BitcoinCashNetwork::Mainnet,
        )
        .unwrap();
        assert_eq!(
            decoded.to_address().script_pubkey().as_bytes(),
            [
                0x76, 0xa9, 0x14, 0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c,
                0xca, 0x47, 0x93, 0xf8, 0xeb, 0x2b, 0x6c, 0xda, 0xc9, 0x88, 0xac,
            ]
        );
    }

    #[test]
    fn decodes_uppercase_script_hash_vector_for_chipnet_prefix() {
        let decoded = decode(
            "BCHTEST:PR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYVWC0UZ5T",
            BitcoinCashNetwork::Chipnet,
        )
        .unwrap();
        assert_eq!(
            decoded.to_address().script_pubkey().as_bytes(),
            [
                0xa9, 0x14, 0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c, 0xca,
                0x47, 0x93, 0xf8, 0xeb, 0x2b, 0x6c, 0xda, 0xc9, 0x87,
            ]
        );
    }

    #[test]
    fn rejects_mixed_case() {
        let error = decode(
            "bitcoincash:QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2",
            BitcoinCashNetwork::Mainnet,
        )
        .unwrap_err();
        assert_eq!(error, CashAddrError::MixedCase);
    }

    #[test]
    fn rejects_a_prefix_for_another_network() {
        let error = decode(
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            BitcoinCashNetwork::Regtest,
        )
        .unwrap_err();
        assert_eq!(error, CashAddrError::PrefixMismatch);
    }

    #[test]
    fn rejects_a_corrupted_checksum() {
        let error = decode(
            "bchreg:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            BitcoinCashNetwork::Regtest,
        )
        .unwrap_err();
        assert_eq!(error, CashAddrError::Checksum);
    }
}
