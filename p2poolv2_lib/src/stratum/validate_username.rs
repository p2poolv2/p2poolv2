// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::config::{BitcoinCashNetwork, Chain, parse_payout_address};
use bitcoin::Address;

/// Max username includes the dot and the worker name
/// btcaddress.workername, with btcaddress max at 62 bytes, we get 66 character worker name
/// npubs are 63 characters, we still get enough room for workername
const MAX_USERNAME_LENGTH: usize = 128;

/// Result of a successful username validation.
#[derive(Debug)]
pub struct ValidatedUsername<'a> {
    /// The address portion of the username as a string slice
    pub address_str: &'a str,
    /// Parsed and network-checked bitcoin Address (None when validation is skipped)
    pub parsed_address: Option<Address>,
    /// Optional worker name after the first dot
    pub worker_name: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsernameValidationError {
    #[error("Invalid Bitcoin address: {0}")]
    InvalidAddress(String),
    #[error("Worker name too long (max {0} characters)")]
    UserNameTooLong(usize),
    #[error("No username provided. Use <username>.<workername>")]
    UserNameMissing(),
}

/// Validates a stratum username in the format <btcaddress>.<workername>
///
/// # Arguments
///
/// * `username` - The username to validate
/// * `validate_address` - Whether to parse and validate the bitcoin address
/// * `network` - The Bitcoin network to validate the address against
///
/// # Returns
///
/// * `Ok(ValidatedUsername)` - Parsed address string, checked Address, and worker name
/// * `Err(UsernameValidationError)` - Error if validation fails
pub fn validate(
    username: &str,
    validate_address: bool,
    network: bitcoin::Network,
) -> Result<ValidatedUsername<'_>, UsernameValidationError> {
    let (address_part, worker_name) = split_username(username)?;

    let parsed_address = if validate_address {
        let address = address_part.parse::<bitcoin::Address<_>>().map_err(|e| {
            UsernameValidationError::InvalidAddress(format!("Failed to parse address: {e}"))
        })?;

        // Verify the network, return error on failure
        let checked = address.require_network(network).map_err(|_| {
            UsernameValidationError::InvalidAddress(format!(
                "Expected an address for network {network}",
            ))
        })?;
        Some(checked)
    } else {
        None
    };

    Ok(ValidatedUsername {
        address_str: address_part,
        parsed_address,
        worker_name,
    })
}

/// Validates a Bitcoin Cash stratum username, `<cashaddr>.<workername>`.
///
/// The address is a 20-byte P2PKH or P2SH CashAddr for `cash_network`. Its
/// prefix (`bitcoincash:`, `bchtest:`, `bchreg:`) may be left out, as BCH
/// miners commonly enter it; the network's prefix is then assumed and the
/// checksum still has to match it. `address_str` keeps the text as typed.
pub fn validate_bitcoin_cash(
    username: &str,
    validate_address: bool,
    cash_network: BitcoinCashNetwork,
) -> Result<ValidatedUsername<'_>, UsernameValidationError> {
    let (address_part, worker_name) = split_username(username)?;

    let parsed_address = if validate_address {
        let parsed = if address_part.contains(':') {
            parse_cash_payout(address_part, cash_network)
        } else {
            let prefixed = format!("{}:{address_part}", cash_network.cashaddr_prefix());
            parse_cash_payout(&prefixed, cash_network)
        }?;
        Some(parsed)
    } else {
        None
    };

    Ok(ValidatedUsername {
        address_str: address_part,
        parsed_address,
        worker_name,
    })
}

/// Validate `username` for the chain this node mines.
///
/// A Bitcoin Cash node with no Bitcoin Cash network cannot parse a payout
/// address, so its usernames are rejected rather than read as Bitcoin.
pub fn validate_for_chain(
    username: &str,
    validate_address: bool,
    network: bitcoin::Network,
    chain: Chain,
    cash_network: Option<BitcoinCashNetwork>,
) -> Result<ValidatedUsername<'_>, UsernameValidationError> {
    match (chain, cash_network) {
        (Chain::Bitcoin, _) => validate(username, validate_address, network),
        (Chain::BitcoinCash, Some(cash_network)) => {
            validate_bitcoin_cash(username, validate_address, cash_network)
        }
        (Chain::BitcoinCash, None) => Err(UsernameValidationError::InvalidAddress(
            "Bitcoin Cash usernames need bitcoin_cash_network".to_string(),
        )),
    }
}

fn parse_cash_payout(
    address: &str,
    cash_network: BitcoinCashNetwork,
) -> Result<Address, UsernameValidationError> {
    parse_payout_address(
        address,
        Chain::BitcoinCash,
        cash_network.legacy_network(),
        Some(cash_network),
    )
    .map_err(|error| UsernameValidationError::InvalidAddress(error.message))
}

/// Split `<address>.<worker>` at the first dot, enforcing the length limit.
fn split_username(username: &str) -> Result<(&str, Option<&str>), UsernameValidationError> {
    if username.is_empty() {
        return Err(UsernameValidationError::UserNameMissing());
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return Err(UsernameValidationError::UserNameTooLong(
            MAX_USERNAME_LENGTH,
        ));
    }

    match username.split_once('.') {
        Some((address_part, worker_name)) => Ok((address_part, Some(worker_name))),
        None => Ok((username, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_valid_address_no_worker() {
        let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let result = validate(testnet_address, true, Network::Testnet);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.address_str, testnet_address);
        assert!(validated.parsed_address.is_some());
        assert_eq!(validated.worker_name, None);
    }

    #[test]
    fn test_valid_address_with_worker() {
        let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.worker1";
        let result = validate(testnet_address, true, Network::Testnet);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(
            validated.address_str,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert!(validated.parsed_address.is_some());
        assert_eq!(validated.worker_name, Some("worker1"));
    }

    #[test]
    fn test_invalid_address() {
        let invalid_address = "not_a_bitcoin_address";
        let result = validate(invalid_address, true, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn test_wrong_network() {
        // Using a testnet address on mainnet
        let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let result = validate(testnet_address, true, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn test_worker_name_too_long() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let long_worker = format!("{}.{}", mainnet_address, "a".repeat(100));
        let result = validate(&long_worker, true, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::UserNameTooLong(MAX_USERNAME_LENGTH)
        ));
    }

    #[test]
    fn test_worker_name_max_length() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let max_worker = format!("{}.{}", mainnet_address, "a".repeat(29));
        let result = validate(&max_worker, true, Network::Bitcoin);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_dots_in_username() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let multiple_dots = format!("{mainnet_address}.worker.with.dots");
        let result = validate(&multiple_dots, true, Network::Bitcoin);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.address_str, mainnet_address);
        assert!(validated.parsed_address.is_some());
        assert_eq!(validated.worker_name, Some("worker.with.dots"));
    }

    #[test]
    fn bitcoin_cash_accepts_a_prefixed_cashaddr_with_a_worker() {
        let result = validate_bitcoin_cash(
            "bchreg:qzh5k63rhy4jg6jtyssmzddju5kkng4jzu8ktcypfm.rig1",
            true,
            BitcoinCashNetwork::Regtest,
        )
        .unwrap();
        assert_eq!(
            result.address_str,
            "bchreg:qzh5k63rhy4jg6jtyssmzddju5kkng4jzu8ktcypfm"
        );
        assert_eq!(result.worker_name, Some("rig1"));
        assert!(result.parsed_address.unwrap().script_pubkey().is_p2pkh());
    }

    #[test]
    fn bitcoin_cash_accepts_a_cashaddr_without_its_prefix() {
        let result = validate_bitcoin_cash(
            "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            true,
            BitcoinCashNetwork::Mainnet,
        )
        .unwrap();
        assert_eq!(
            result.address_str,
            "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );
        assert!(result.parsed_address.unwrap().script_pubkey().is_p2pkh());
    }

    #[test]
    fn bitcoin_cash_rejects_a_cashaddr_for_another_network() {
        let result = validate_bitcoin_cash(
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            true,
            BitcoinCashNetwork::Regtest,
        );
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn bitcoin_cash_rejects_a_prefixless_cashaddr_from_another_network() {
        // The checksum covers the prefix, so a mainnet string read as regtest fails.
        let result = validate_bitcoin_cash(
            "qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
            true,
            BitcoinCashNetwork::Regtest,
        );
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn bitcoin_cash_rejects_a_bitcoin_address() {
        let result = validate_bitcoin_cash(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            true,
            BitcoinCashNetwork::Chipnet,
        );
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn bitcoin_cash_chain_without_a_network_rejects_usernames() {
        let result = validate_for_chain(
            "bchreg:qzh5k63rhy4jg6jtyssmzddju5kkng4jzu8ktcypfm",
            true,
            Network::Regtest,
            Chain::BitcoinCash,
            None,
        );
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn bitcoin_chain_keeps_bitcoin_username_parsing() {
        let result = validate_for_chain(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.worker1",
            true,
            Network::Testnet,
            Chain::Bitcoin,
            None,
        )
        .unwrap();
        assert_eq!(result.worker_name, Some("worker1"));
        assert!(result.parsed_address.is_some());
    }

    #[test]
    fn test_empty_username() {
        let result = validate("", true, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::UserNameMissing()
        ));
    }

    #[test]
    fn test_empty_username_without_address_validation() {
        let result = validate("", false, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::UserNameMissing()
        ));
    }
}
