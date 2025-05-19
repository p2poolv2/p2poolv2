// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::network::Network;
use bitcoin::transaction::{Sequence, Transaction, TxIn, TxOut, Version};
use bitcoin::{Address, Amount};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::str::FromStr;

/// Error handling when dealing with work and coinbase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkError {
    pub message: String,
}

impl Error for WorkError {}
impl std::fmt::Display for WorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// Parse Address from a string provided by the miner
pub fn parse_address(address: &str, network: Network) -> Result<Address, WorkError> {
    let parsed_address = Address::from_str(address).map_err(|e| WorkError {
        message: format!("Invalid address: {}", e),
    })?;

    parsed_address
        .require_network(network)
        .map_err(|_| WorkError {
            message: format!("Address does not match network: {}", network),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_valid_mainnet() {
        let addr = "1HpRF3JgafxaqjhMEjLNbevpRVvAp15t3A";
        let result = parse_address(addr, Network::Bitcoin);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_address_valid_testnet() {
        let addr = "tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f";
        let result = parse_address(addr, Network::Testnet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_address_invalid_format() {
        let addr = "not_a_valid_address";
        let result = parse_address(addr, Network::Bitcoin);
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Invalid address"));
    }

    #[test]
    fn test_parse_address_wrong_network() {
        // This is a mainnet address, but we require testnet
        let addr = "1HpRF3JgafxaqjhMEjLNbevpRVvAp15t3A";
        let result = parse_address(addr, Network::Testnet);
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        println!("Error message: {}", msg);
        assert!(msg.contains("Address does not match network"));
        assert!(msg.contains("testnet"));
    }
}
