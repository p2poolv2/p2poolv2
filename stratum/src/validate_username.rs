// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use bitcoin::{address::NetworkChecked, Address};

const MAX_WORKER_NAME_LENGTH: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum UsernameValidationError {
    #[error("Invalid Bitcoin address: {0}")]
    InvalidAddress(String),
    #[error("Worker name too long (max {0} characters)")]
    WorkerNameTooLong(usize),
}

/// Validates a stratum username in the format <btcaddress>.<workername>
///
/// # Arguments
///
/// * `username` - The username to validate
/// * `network` - The Bitcoin network to validate the address against
///
/// # Returns
///
/// * `Ok((address, worker_name))` - Tuple with parsed address and worker name
/// * `Err(UsernameValidationError)` - Error if validation fails
pub fn validate(
    username: &str,
    network: bitcoin::Network,
) -> Result<(Address<NetworkChecked>, Option<String>), UsernameValidationError> {
    // Split by the first dot
    let parts: Vec<&str> = username.splitn(2, '.').collect();

    // Parse the Bitcoin address
    let address_str = parts[0];
    let address = address_str.parse::<bitcoin::Address<_>>().map_err(|e| {
        UsernameValidationError::InvalidAddress(format!("Failed to parse address: {e}"))
    })?;

    // Verify the network
    let checked_address = address.require_network(network).map_err(|_| {
        UsernameValidationError::InvalidAddress(format!(
            "Expected an address for network {network}",
        ))
    })?;

    // Extract worker name if present
    let worker_name = if parts.len() > 1 {
        let worker = parts[1].to_string();

        // Check worker name length
        if worker.len() > MAX_WORKER_NAME_LENGTH {
            return Err(UsernameValidationError::WorkerNameTooLong(
                MAX_WORKER_NAME_LENGTH,
            ));
        }

        Some(worker)
    } else {
        None
    };

    Ok((checked_address, worker_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    fn test_valid_address_no_worker() {
        let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let result = validate(testnet_address, Network::Testnet);
        assert!(result.is_ok());
        let (address, worker_name) = result.unwrap();
        assert_eq!(address.to_string(), testnet_address);
        assert_eq!(worker_name, None);
    }

    #[test]
    fn test_valid_address_with_worker() {
        let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.worker1";
        let result = validate(testnet_address, Network::Testnet);
        assert!(result.is_ok());
        let (address, worker_name) = result.unwrap();
        assert_eq!(
            address.to_string(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert_eq!(worker_name, Some("worker1".to_string()));
    }

    #[test]
    fn test_invalid_address() {
        let invalid_address = "not_a_bitcoin_address";
        let result = validate(invalid_address, Network::Bitcoin);
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
        let result = validate(testnet_address, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::InvalidAddress(_)
        ));
    }

    #[test]
    fn test_worker_name_too_long() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let long_worker = format!("{}.{}", mainnet_address, "a".repeat(33));
        let result = validate(&long_worker, Network::Bitcoin);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UsernameValidationError::WorkerNameTooLong(MAX_WORKER_NAME_LENGTH)
        ));
    }

    #[test]
    fn test_worker_name_max_length() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let max_worker = format!("{}.{}", mainnet_address, "a".repeat(32));
        let result = validate(&max_worker, Network::Bitcoin);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_dots_in_username() {
        let mainnet_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let multiple_dots = format!("{}.worker.with.dots", mainnet_address);
        let result = validate(&multiple_dots, Network::Bitcoin);
        assert!(result.is_ok());
        let (address, worker_name) = result.unwrap();
        assert_eq!(address.to_string(), mainnet_address);
        assert_eq!(worker_name, Some("worker.with.dots".to_string()));
    }
}
