// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encode a Bitcoin Cash P2PKH key hash as a share chain address.
//!
//! The input is a P2PKH CashAddr from the miner's own wallet, naming the key
//! that will own their shares. The share coinbase pays that same P2PKH
//! script, so the wallet that holds the key can spend it. Only the prefix
//! changes (`bitcoincash:` to `p2pool:`, `bchtest:` to `tp2pool:`, `bchreg:`
//! to `rp2pool:`), which keeps the two strings from being mistaken for each
//! other.
//!
//! The node never does this on its own: the share address and the payout
//! address are separate settings, and the miner chooses which key owns
//! shares. A fresh wallet address, rather than the payout address, keeps the
//! two roles apart.
//!
//! Deliberately takes an address and never a private key: no P2Poolv2 crate
//! generates or handles private keys.

use bitcoin::ScriptBuf;
use p2poolv2_lib::address::bch_share::BchShareAddress;
use p2poolv2_lib::config::{BitcoinCashNetwork, Chain, parse_payout_address};
use std::error::Error;
use std::io::Read;

/// Bytes of the public key hash inside a P2PKH script:
/// `OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG`.
const PUBKEY_HASH_START: usize = 3;
const PUBKEY_HASH_END: usize = 23;

/// Parse a Bitcoin Cash network name as the config spells it.
///
/// Used as a clap value parser, so the error names the accepted values.
pub fn parse_network(value: &str) -> Result<BitcoinCashNetwork, String> {
    match value {
        "mainnet" | "main" => Ok(BitcoinCashNetwork::Mainnet),
        "chipnet" => Ok(BitcoinCashNetwork::Chipnet),
        "regtest" => Ok(BitcoinCashNetwork::Regtest),
        _ => Err(format!(
            "unknown Bitcoin Cash network '{value}', expected mainnet, chipnet or regtest"
        )),
    }
}

/// Build the share chain address for a P2PKH CashAddr on `network`.
///
/// A P2SH CashAddr is rejected: a share is owned by a P2PKH script.
fn encode(cash_address: &str, network: BitcoinCashNetwork) -> Result<String, Box<dyn Error>> {
    let decoded = parse_payout_address(
        cash_address,
        Chain::BitcoinCash,
        network.legacy_network(),
        Some(network),
    )?;
    let script = decoded.script_pubkey();
    let hash = pubkey_hash(&script).ok_or(
        "only a P2PKH CashAddr (q...) can own shares. Ask the wallet for a regular receiving address.",
    )?;
    Ok(BchShareAddress::new(network.share_network(), hash).encode())
}

fn pubkey_hash(script: &ScriptBuf) -> Option<[u8; 20]> {
    if !script.is_p2pkh() {
        return None;
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&script.as_bytes()[PUBKEY_HASH_START..PUBKEY_HASH_END]);
    Some(hash)
}

/// Read the CashAddr from the argument, or from stdin when none was given.
fn read_cash_address(cash_address: Option<String>) -> Result<String, Box<dyn Error>> {
    let raw = match cash_address {
        Some(value) => value,
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("no CashAddr given. Pass one as an argument or on stdin.".into());
    }
    Ok(trimmed.to_string())
}

/// Execute the command, printing the share chain address alone so it can be
/// piped or copied into `[stratum] miner_address` or a miner's `p2p=`.
pub fn execute(
    cash_address: Option<String>,
    network: BitcoinCashNetwork,
) -> Result<(), Box<dyn Error>> {
    let cash_address = read_cash_address(cash_address)?;
    println!("{}", encode(&cash_address, network)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::address::bch_share;

    #[test]
    fn mainnet_p2pkh_keeps_its_hash_under_the_share_prefix() {
        let encoded = encode(
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            BitcoinCashNetwork::Mainnet,
        )
        .unwrap();
        assert!(encoded.starts_with("p2pool:q"));
        let decoded =
            bch_share::parse(&encoded, BitcoinCashNetwork::Mainnet.share_network()).unwrap();
        assert_eq!(
            decoded.hash,
            [
                0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c, 0xca, 0x47, 0x93,
                0xf8, 0xeb, 0x2b, 0x6c, 0xda, 0xc9,
            ]
        );
    }

    #[test]
    fn regtest_p2pkh_encodes_under_rp2pool() {
        let encoded = encode(
            "bchreg:qrr4pe4ret3zwmj0428rtksq83ql80w6myqjlk828q",
            BitcoinCashNetwork::Regtest,
        )
        .unwrap();
        assert_eq!(
            encoded,
            "rp2pool:qrr4pe4ret3zwmj0428rtksq83ql80w6my7w2wp75h"
        );
    }

    #[test]
    fn p2sh_cashaddr_is_rejected() {
        let error = encode(
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
            BitcoinCashNetwork::Chipnet,
        )
        .unwrap_err();
        assert!(error.to_string().contains("P2PKH"), "{error}");
    }

    #[test]
    fn cashaddr_for_another_network_is_rejected() {
        assert!(
            encode(
                "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
                BitcoinCashNetwork::Chipnet,
            )
            .is_err()
        );
    }

    #[test]
    fn network_names_match_the_config() {
        assert_eq!(parse_network("mainnet"), Ok(BitcoinCashNetwork::Mainnet));
        assert_eq!(parse_network("chipnet"), Ok(BitcoinCashNetwork::Chipnet));
        assert_eq!(parse_network("regtest"), Ok(BitcoinCashNetwork::Regtest));
        assert!(parse_network("signet").is_err());
    }
}
