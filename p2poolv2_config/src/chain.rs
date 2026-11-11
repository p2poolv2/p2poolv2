// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::Network;
use std::fmt;
use std::str::FromStr;

/// The bitcoin chain a node mines on.
///
/// rust-bitcoin has no testnet5 network, and testnet5 shares its address
/// formats with testnet4. So `Chain` names the chain itself, for what has to
/// tell testnet4 and testnet5 apart (genesis share, DNS seeds, protocol
/// string). `bitcoin_network` gives the rust-bitcoin network for everything
/// else, such as address validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chain {
    Main,
    Testnet3,
    Testnet4,
    Testnet5,
    Signet,
    Regtest,
}

impl Chain {
    /// The rust-bitcoin network whose address formats and parameters this
    /// chain uses. Testnet5 maps to testnet4.
    pub fn bitcoin_network(self) -> Network {
        match self {
            Chain::Main => Network::Bitcoin,
            Chain::Testnet3 => Network::Testnet,
            Chain::Testnet4 | Chain::Testnet5 => Network::Testnet4,
            Chain::Signet => Network::Signet,
            Chain::Regtest => Network::Regtest,
        }
    }

    /// The chain name as bitcoind's `-chain=` argument spells it. Matches
    /// `bitcoin::Network::to_core_arg` for the networks rust-bitcoin knows, so
    /// protocol strings derived from it stay unchanged for those networks.
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Testnet3 => "test",
            Chain::Testnet4 => "testnet4",
            Chain::Testnet5 => "testnet5",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned when a chain name is not recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownChainError(String);

impl fmt::Display for UnknownChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unknown chain {:?}, expected one of main, test, testnet4, testnet5, signet, regtest",
            self.0
        )
    }
}

impl std::error::Error for UnknownChainError {}

impl FromStr for Chain {
    type Err = UnknownChainError;

    /// Parse a chain name as bitcoind's `-chain=` argument spells it.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "main" => Ok(Chain::Main),
            "test" => Ok(Chain::Testnet3),
            "testnet4" => Ok(Chain::Testnet4),
            "testnet5" => Ok(Chain::Testnet5),
            "signet" => Ok(Chain::Signet),
            "regtest" => Ok(Chain::Regtest),
            other => Err(UnknownChainError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet5_parses_from_its_core_name() {
        assert_eq!("testnet5".parse::<Chain>().unwrap(), Chain::Testnet5);
    }

    #[test]
    fn testnet5_uses_testnet4_bitcoin_network() {
        assert_eq!(Chain::Testnet5.bitcoin_network(), Network::Testnet4);
    }

    #[test]
    fn testnet5_name_differs_from_testnet4() {
        assert_eq!(Chain::Testnet5.as_str(), "testnet5");
        assert_eq!(Chain::Testnet4.as_str(), "testnet4");
    }

    /// Protocol strings are built from `as_str`, so for every network
    /// rust-bitcoin knows it must keep the `to_core_arg` spelling, or deployed
    /// nodes stop negotiating with upgraded ones.
    #[test]
    fn known_networks_keep_core_arg_names() {
        assert_eq!(Chain::Main.as_str(), Network::Bitcoin.to_core_arg());
        assert_eq!(Chain::Testnet3.as_str(), Network::Testnet.to_core_arg());
        assert_eq!(Chain::Testnet4.as_str(), Network::Testnet4.to_core_arg());
        assert_eq!(Chain::Signet.as_str(), Network::Signet.to_core_arg());
        assert_eq!(Chain::Regtest.as_str(), Network::Regtest.to_core_arg());
    }

    #[test]
    fn unknown_chain_name_is_rejected() {
        assert!("testnet6".parse::<Chain>().is_err());
    }
}
