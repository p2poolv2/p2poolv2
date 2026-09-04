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

//! Encode a taproot output key as a share chain address.
//!
//! The input is the `witness_program` field of `bitcoin-cli getaddressinfo`,
//! which is the already tweaked 32 byte output key that lands in the
//! `scriptPubKey`. No tweak is applied here, because the wallet applied it.
//!
//! Deliberately takes a public key and never a private key: no P2Poolv2 crate
//! generates or handles private keys. See `docs/architecture/address-format.md`.

use bitcoin::Network;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::XOnlyPublicKey;
use p2poolv2_address::Address;
use std::error::Error;
use std::io::Read;

/// Length of a taproot output key, the only witness program this encodes.
const OUTPUT_KEY_LENGTH: usize = 32;

/// Parse a network the way the config and `bitcoin-cli -chain=` name it.
///
/// Used as a clap value parser, so the error names the accepted values rather
/// than leaving a typo to fail as an unknown network.
pub fn parse_network(value: &str) -> Result<Network, String> {
    Network::from_core_arg(value).map_err(|_| {
        format!("unknown network '{value}', expected main, testnet4, signet or regtest")
    })
}

/// Build the share chain address for a taproot output key on `network`.
///
/// Rejects a key that is not a curve point. Those 32 bytes would encode an
/// output nobody can ever spend, so a share paid to it would be lost.
fn encode(output_key_hex: &str, network: Network) -> Result<Address, Box<dyn Error>> {
    let output_key_bytes = Vec::from_hex(output_key_hex)
        .map_err(|error| format!("witness program is not hex: {error}"))?;

    if output_key_bytes.len() != OUTPUT_KEY_LENGTH {
        return Err(format!(
            "witness program is {} bytes, expected {OUTPUT_KEY_LENGTH} for a taproot output key. \
             Ask the wallet for a bech32m address, not an older type.",
            output_key_bytes.len()
        )
        .into());
    }

    let output_key = XOnlyPublicKey::from_slice(&output_key_bytes)
        .map_err(|error| format!("witness program is not a valid taproot output key: {error}"))?;

    Ok(Address::from_output_key(output_key, network)?)
}

/// Read the output key from the argument, or from stdin when none was given.
fn read_output_key_hex(output_key_hex: Option<String>) -> Result<String, Box<dyn Error>> {
    let raw = match output_key_hex {
        Some(value) => value,
        None => {
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        }
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("no witness program given. Pass one as an argument or on stdin.".into());
    }
    Ok(trimmed.to_string())
}

/// Execute the address command, printing the share chain address alone so it
/// can be piped or copied into `[stratum] miner_address`.
pub fn execute(output_key_hex: Option<String>, network: Network) -> Result<(), Box<dyn Error>> {
    let output_key_hex = read_output_key_hex(output_key_hex)?;
    println!("{}", encode(&output_key_hex, network)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in docs/architecture/address-format.md: the witness
    /// program of tb1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq0gh57d.
    const WALLET_OUTPUT_KEY: &str =
        "a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900";

    #[test]
    fn encodes_the_signet_worked_example_from_the_address_format_doc() {
        assert_eq!(
            encode(WALLET_OUTPUT_KEY, Network::Signet)
                .unwrap()
                .to_string(),
            "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x"
        );
    }

    #[test]
    fn encodes_the_same_key_under_the_mainnet_prefix() {
        assert!(
            encode(WALLET_OUTPUT_KEY, Network::Bitcoin)
                .unwrap()
                .to_string()
                .starts_with("p2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq")
        );
    }

    #[test]
    fn produces_the_same_script_pubkey_as_the_wallet_address() {
        let address = encode(WALLET_OUTPUT_KEY, Network::Signet).unwrap();
        assert_eq!(
            address.script_pubkey().to_string(),
            format!("OP_PUSHNUM_1 OP_PUSHBYTES_32 {WALLET_OUTPUT_KEY}")
        );
    }

    #[test]
    fn rejects_a_20_byte_witness_program() {
        let error = encode("751e76e8199196d454941c45d1b3a323f1433bd6", Network::Signet)
            .unwrap_err()
            .to_string();
        assert!(error.contains("20 bytes"), "{error}");
    }

    #[test]
    fn rejects_a_non_hex_witness_program() {
        let error = encode("not hex at all", Network::Signet)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not hex"), "{error}");
    }

    #[test]
    fn rejects_32_bytes_that_are_not_a_curve_point() {
        let error = encode(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            Network::Signet,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a valid taproot output key"), "{error}");
    }

    #[test]
    fn rejects_testnet3_which_has_no_prefix() {
        assert!(encode(WALLET_OUTPUT_KEY, Network::Testnet).is_err());
    }

    #[test]
    fn parses_the_core_chain_name_for_signet() {
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
    }

    #[test]
    fn parses_main_as_the_bitcoin_network() {
        assert_eq!(parse_network("main").unwrap(), Network::Bitcoin);
    }

    #[test]
    fn rejects_an_unknown_network_name_by_listing_the_accepted_ones() {
        let error = parse_network("mainnet").unwrap_err();
        assert!(
            error.contains("expected main, testnet4, signet or regtest"),
            "{error}"
        );
    }

    #[test]
    fn trims_the_trailing_newline_jq_writes() {
        assert_eq!(
            read_output_key_hex(Some(format!("{WALLET_OUTPUT_KEY}\n"))).unwrap(),
            WALLET_OUTPUT_KEY
        );
    }
}
