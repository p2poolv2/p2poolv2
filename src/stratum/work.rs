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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Work {
    /// The job ID
    pub job_id: String,
    /// The previous block hash
    pub prev_hash: String,
    /// The coinbase1 part of the coinbase transaction
    pub coinbase1: String,
    /// The coinbase2 part of the coinbase transaction
    pub coinbase2: String,
    /// The merkle branch for the block
    pub merkle_branch: Vec<String>,
    /// The version of the block
    pub version: String,
    /// The nbits (difficulty target) for the block
    pub nbits: String,
    /// The ntime (timestamp) for the block
    pub ntime: String,
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

/// Build a coinbase from the provided address, network and height.
/// This handles a single address for now - i.e. for solo mining.
/// TODO: Handle multiple addresses and payout proportions.
pub fn build_coinbase_transaction(
    address: Address,
    value: u64,
    height: i64,
    default_witness_commitment: Option<String>,
) -> Result<Transaction, WorkError> {
    let script_pubkey = address.script_pubkey();

    let coinbase_script = Builder::new()
        .push_int(height) // block height in coinbase script
        .into_script();

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(value),
        script_pubkey,
    }];
    if let Some(default_witness_commitment) = default_witness_commitment {
        let commitment_bytes = hex::decode(&default_witness_commitment).map_err(|e| WorkError {
            message: format!("Invalid witness commitment hex: {}", e),
        })?;
        let commitment = ScriptBuf::from(commitment_bytes);
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: commitment,
        });
    }
    let coinbase_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: sha256d::Hash::all_zeros().into(),
                vout: u32::MAX,
            },
            script_sig: coinbase_script,
            sequence: Sequence::MAX,
            witness: Vec::<Vec<u8>>::new().into(),
        }],
        output: outputs,
    };
    Ok(coinbase_tx)
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
