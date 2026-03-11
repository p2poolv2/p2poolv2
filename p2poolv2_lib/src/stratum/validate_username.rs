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
    if username.is_empty() {
        return Err(UsernameValidationError::UserNameMissing());
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return Err(UsernameValidationError::UserNameTooLong(
            MAX_USERNAME_LENGTH,
        ));
    }

    // Split by the first dot
    let parts: Vec<&str> = username.splitn(2, '.').collect();

    // Parse the Bitcoin address
    let address_part = parts[0];

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

    let worker_name = if parts.len() > 1 {
        Some(parts[1])
    } else {
        None
    };

    Ok(ValidatedUsername {
        address_str: address_part,
        parsed_address,
        worker_name,
    })
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
        let multiple_dots = format!("{}.worker.with.dots", mainnet_address);
        let result = validate(&multiple_dots, true, Network::Bitcoin);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.address_str, mainnet_address);
        assert!(validated.parsed_address.is_some());
        assert_eq!(validated.worker_name, Some("worker.with.dots"));
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
