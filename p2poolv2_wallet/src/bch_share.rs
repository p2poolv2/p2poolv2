// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bitcoin Cash share-chain address.
//!
//! This is not a payout address and not the Bitcoin taproot share address.
//! Payouts use `bitcoincash`, `bchtest`, and `bchreg`. Bitcoin share ownership
//! uses bech32m with no colon. This form is CashAddr P2PKH, so the script a
//! share coinbase pays is spendable with an ordinary BCH signature, and the
//! prefix plus the CashAddr checksum stop either of the other strings from
//! decoding as this one.
//!
//! The 20-byte hash is what a share header will store. The prefix is not
//! consensus data: the chain already knows its network.

use bitcoin::hashes::Hash;
use bitcoin::{Address, PubkeyHash, ScriptBuf};

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0x98f2bc8e61,
    0x79b76d99e2,
    0xf33e5fb3c4,
    0xae2eabe2a8,
    0x1e4f43e470,
];
const P2PKH_VERSION: u8 = 0x00;

/// Network a Bitcoin Cash share address names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BchShareNetwork {
    /// CashAddr prefix `p2pool`.
    Mainnet,
    /// CashAddr prefix `tp2pool`. Chipnet, not Bitcoin testnet4.
    Chipnet,
    /// CashAddr prefix `rp2pool`.
    Regtest,
}

impl BchShareNetwork {
    /// CashAddr prefix for this share network.
    pub fn prefix(self) -> &'static str {
        match self {
            BchShareNetwork::Mainnet => "p2pool",
            BchShareNetwork::Chipnet => "tp2pool",
            BchShareNetwork::Regtest => "rp2pool",
        }
    }
}

/// A decoded Bitcoin Cash share address: network plus the 20-byte key hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BchShareAddress {
    /// Network selected by the prefix.
    pub network: BchShareNetwork,
    /// HASH160 of the spend key.
    pub hash: [u8; 20],
}

/// Failure while encoding a Bitcoin Cash payout or decoding a share address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BchShareAddressError {
    message: String,
}

impl std::fmt::Display for BchShareAddressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for BchShareAddressError {}

impl BchShareAddress {
    /// Build an address from a network and a 20-byte key hash.
    pub fn new(network: BchShareNetwork, hash: [u8; 20]) -> Self {
        Self { network, hash }
    }

    /// P2PKH script the share coinbase pays.
    pub fn script_pubkey(self) -> ScriptBuf {
        ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(self.hash))
    }

    /// CashAddr text form, including the prefix.
    pub fn encode(self) -> String {
        let mut payload = [0u8; 21];
        payload[0] = P2PKH_VERSION;
        payload[1..].copy_from_slice(&self.hash);
        encode_payload(self.network.prefix(), &payload)
    }
}

/// Format a 20-byte P2PKH or P2SH payout under the chain's CashAddr prefix.
pub fn encode_payout_address(
    address: &Address,
    network: BchShareNetwork,
) -> Result<String, BchShareAddressError> {
    let script = address.script_pubkey();
    let mut payload = [0u8; 21];
    if script.is_p2pkh() {
        payload[1..].copy_from_slice(&script.as_bytes()[3..23]);
    } else if script.is_p2sh() {
        payload[0] = 8;
        payload[1..].copy_from_slice(&script.as_bytes()[2..22]);
    } else {
        return Err(BchShareAddressError {
            message: "payout is not a 20-byte P2PKH or P2SH".to_string(),
        });
    }
    let prefix = match network {
        BchShareNetwork::Mainnet => "bitcoincash",
        BchShareNetwork::Chipnet => "bchtest",
        BchShareNetwork::Regtest => "bchreg",
    };
    Ok(encode_payload(prefix, &payload))
}

fn encode_payload(prefix: &str, payload: &[u8; 21]) -> String {
    let payload_five = convert_bits(payload, 8, 5, true).expect("21 bytes convert to 5-bit");
    let checksum = create_checksum(prefix, &payload_five);
    let mut characters = String::with_capacity(prefix.len() + 1 + payload_five.len() + 8);
    characters.push_str(prefix);
    characters.push(':');
    for value in payload_five.iter().chain(checksum.iter()) {
        characters.push(CHARSET[*value as usize] as char);
    }
    characters
}

/// Decode `address` and require `expected`.
pub fn parse(
    address: &str,
    expected: BchShareNetwork,
) -> Result<BchShareAddress, BchShareAddressError> {
    let decoded = decode(address)?;
    if decoded.network != expected {
        return Err(BchShareAddressError {
            message: format!(
                "share address prefix is {:?}, not {expected:?}",
                decoded.network
            ),
        });
    }
    Ok(decoded)
}

/// Decode a CashAddr share address.
pub fn decode(address: &str) -> Result<BchShareAddress, BchShareAddressError> {
    let lowered = if address
        .chars()
        .all(|character| !character.is_ascii_uppercase())
    {
        address.to_string()
    } else if address
        .chars()
        .all(|character| !character.is_ascii_lowercase())
    {
        address.to_ascii_lowercase()
    } else {
        return Err(BchShareAddressError {
            message: "share address mixes uppercase and lowercase".to_string(),
        });
    };
    let Some((prefix, payload)) = lowered.rsplit_once(':') else {
        return Err(BchShareAddressError {
            message: "share address is missing its network prefix".to_string(),
        });
    };
    if prefix.is_empty() || payload.is_empty() {
        return Err(BchShareAddressError {
            message: "share address prefix or payload is empty".to_string(),
        });
    }
    let network = network_for_prefix(prefix)?;
    let data = base32_decode(payload)?;
    let mut expanded = prefix_expand(prefix);
    expanded.extend_from_slice(&data);
    if polymod(&expanded) != 1 {
        return Err(BchShareAddressError {
            message: "share address checksum is invalid".to_string(),
        });
    }
    let payload_bytes =
        convert_bits(&data[..data.len() - 8], 5, 8, false).ok_or_else(|| BchShareAddressError {
            message: "share address payload bits are invalid".to_string(),
        })?;
    decode_payload(&payload_bytes, network)
}

fn network_for_prefix(prefix: &str) -> Result<BchShareNetwork, BchShareAddressError> {
    match prefix {
        "p2pool" => Ok(BchShareNetwork::Mainnet),
        "tp2pool" => Ok(BchShareNetwork::Chipnet),
        "rp2pool" => Ok(BchShareNetwork::Regtest),
        "bitcoincash" | "bchtest" | "bchreg" => Err(BchShareAddressError {
            message: "payout CashAddr is not a share address".to_string(),
        }),
        _ => Err(BchShareAddressError {
            message: format!("unknown share address prefix: {prefix}"),
        }),
    }
}

fn decode_payload(
    payload: &[u8],
    network: BchShareNetwork,
) -> Result<BchShareAddress, BchShareAddressError> {
    let Some((version, hash)) = payload.split_first() else {
        return Err(BchShareAddressError {
            message: "share address payload is empty".to_string(),
        });
    };
    if *version != P2PKH_VERSION || hash.len() != 20 {
        return Err(BchShareAddressError {
            message: "share address is not a 20-byte P2PKH".to_string(),
        });
    }
    let mut hash_bytes = [0u8; 20];
    hash_bytes.copy_from_slice(hash);
    Ok(BchShareAddress {
        network,
        hash: hash_bytes,
    })
}

fn prefix_expand(prefix: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(prefix.len() + 1);
    for byte in prefix.bytes() {
        expanded.push(byte & 0x1f);
    }
    expanded.push(0);
    expanded
}

fn polymod(values: &[u8]) -> u64 {
    let mut checksum = 1u64;
    for value in values {
        let top = checksum >> 35;
        checksum = ((checksum & 0x07_ffff_ffff) << 5) ^ u64::from(*value);
        for (index, generator) in GENERATOR.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn create_checksum(prefix: &str, payload: &[u8]) -> [u8; 8] {
    let mut values = prefix_expand(prefix);
    values.extend_from_slice(payload);
    values.extend_from_slice(&[0u8; 8]);
    let polymod = polymod(&values) ^ 1;
    let mut checksum = [0u8; 8];
    for (index, byte) in checksum.iter_mut().enumerate() {
        *byte = ((polymod >> (5 * (7 - index))) & 0x1f) as u8;
    }
    checksum
}

fn base32_decode(payload: &str) -> Result<Vec<u8>, BchShareAddressError> {
    let mut decoded = Vec::with_capacity(payload.len());
    for character in payload.bytes() {
        let index = CHARSET
            .iter()
            .position(|symbol| *symbol == character)
            .ok_or_else(|| BchShareAddressError {
                message: "share address contains a character outside its alphabet".to_string(),
            })?;
        decoded.push(index as u8);
    }
    Ok(decoded)
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let maximum = (1u32 << to) - 1;
    let mut converted = Vec::with_capacity(data.len());
    for value in data {
        if u32::from(*value) >> from != 0 {
            return None;
        }
        accumulator = (accumulator << from) | u32::from(*value);
        bits += from;
        while bits >= to {
            bits -= to;
            converted.push(((accumulator >> bits) & maximum) as u8);
        }
    }
    if pad {
        if bits > 0 {
            converted.push(((accumulator << (to - bits)) & maximum) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & maximum) != 0 {
        return None;
    }
    Some(converted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2pkh_payout_matches_the_cashaddr_vector() {
        let address = "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();
        assert_eq!(
            encode_payout_address(&address, BchShareNetwork::Mainnet).unwrap(),
            "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
        );
    }

    #[test]
    fn p2sh_payout_matches_the_cashaddr_vector() {
        let address = "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();
        assert_eq!(
            encode_payout_address(&address, BchShareNetwork::Mainnet).unwrap(),
            "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"
        );
    }

    #[test]
    fn witness_payout_has_no_cashaddr_encoding() {
        let address = "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d"
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked();
        assert!(encode_payout_address(&address, BchShareNetwork::Chipnet).is_err());
    }

    #[test]
    fn round_trip_keeps_the_hash_and_prefix() {
        let hash = [0x22u8; 20];
        let address = BchShareAddress::new(BchShareNetwork::Chipnet, hash);
        let encoded = address.encode();
        assert!(encoded.starts_with("tp2pool:"));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, address);
        assert!(decoded.script_pubkey().is_p2pkh());
    }

    #[test]
    fn changed_character_fails_checksum() {
        let encoded = BchShareAddress::new(BchShareNetwork::Mainnet, [0x11; 20]).encode();
        let mut broken = encoded.into_bytes();
        let last = broken.len() - 1;
        broken[last] = if broken[last] == b'q' { b'p' } else { b'q' };
        let broken = String::from_utf8(broken).unwrap();
        let error = decode(&broken).unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }

    #[test]
    fn payout_prefix_is_rejected() {
        let error = decode("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a").unwrap_err();
        assert!(error.to_string().contains("payout"));
    }

    #[test]
    fn bitcoin_share_address_is_rejected() {
        let error = decode("sp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls4zffd6")
            .unwrap_err();
        assert!(error.to_string().contains("prefix"));
    }

    #[test]
    fn chipnet_address_is_not_mainnet() {
        let encoded = BchShareAddress::new(BchShareNetwork::Chipnet, [0x33; 20]).encode();
        let error = parse(&encoded, BchShareNetwork::Mainnet).unwrap_err();
        assert!(error.to_string().contains("Chipnet"));
    }
}
