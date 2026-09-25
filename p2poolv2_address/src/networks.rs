// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::Network;
use bitcoin::constants::ChainHash;
use std::fmt;
use std::fmt::Formatter;

/// A network in the Bitcoin/P2Poolv2 ecosystem. Uniquely (but non-exhaustively) identifies a network
/// in the ecosystem. Since we support atomic swaps between networks, this type represents
/// the "internetwork" of known/supported blockchains.
/// Note that much of the P2poolv2 codebase uses the Bitcoin [Network] type for P2Pool networks, because
/// there is normally a 1-to-1 mapping. This `Internetwork` type is provided for wallets and applications
/// that track balances on multiple chains and for future p2poolv2 implementations where we may have multiple p2pool
/// chains for a single Bitcoin chain.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum InterNetwork {
    Bitcoin(Network),
    P2Pool(P2PoolNetwork),
}

impl InterNetwork {
    const fn as_display_str(self) -> &'static str {
        match self {
            InterNetwork::Bitcoin(net) => match net {
                Network::Bitcoin => "bitcoin",
                Network::Testnet => "testnet",
                Network::Testnet4 => "testnet4",
                Network::Signet => "signet",
                Network::Regtest => "regtest",
            },
            InterNetwork::P2Pool(net) => match net {
                P2PoolNetwork::P2Pool => "p2pool",
                P2PoolNetwork::P2PoolTestnet(_) => "p2pool-testnet",
                P2PoolNetwork::P2PoolSignet(_) => "p2pool-signet",
                P2PoolNetwork::P2PoolRegtest => "p2pool-regtest",
            },
        }
    }
}

impl fmt::Display for InterNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.pad(self.as_display_str())
    }
}

/// P2Pool sharechains
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
pub enum P2PoolNetwork {
    P2Pool,
    P2PoolTestnet(P2PoolTestnetVersion),
    // TODO: Use sub-enum or always use ChainHash?
    P2PoolSignet(P2PoolSignetChain),
    P2PoolRegtest,
}

impl P2PoolNetwork {
    /// Return the default P2PoolNetwork for a Bitcoin network. In the future, there may
    /// be more than one P2PoolNetwork per Bitcoin network, but currently there is a 1-to-1 mapping.
    pub(crate) fn from_bitcoin(bitcoin_network: Network) -> P2PoolNetwork {
        match bitcoin_network {
            Network::Bitcoin => P2PoolNetwork::P2Pool,
            Network::Testnet => panic!("Testnet3 not supported"),
            Network::Testnet4 => P2PoolNetwork::P2PoolTestnet(P2PoolTestnetVersion::V4),
            Network::Signet => P2PoolNetwork::P2PoolSignet(P2PoolSignetChain::Default),
            Network::Regtest => P2PoolNetwork::P2PoolRegtest,
        }
    }

    /// Get the Bitcoin Network for which this P2PoolNetwork mines.
    pub(crate) fn to_mined(self) -> Network {
        match self {
            P2PoolNetwork::P2Pool => Network::Bitcoin,
            P2PoolNetwork::P2PoolTestnet(ver) => match ver {
                P2PoolTestnetVersion::V4 => Network::Testnet4,
                P2PoolTestnetVersion::V5 => Network::Testnet4, // TODO: Fix this
            },
            // TODO: Support custom P2Pool signet mapping to custom Bitcoin Signet
            P2PoolNetwork::P2PoolSignet(P2PoolSignetChain::Default) => Network::Signet,
            P2PoolNetwork::P2PoolRegtest => Network::Signet,
            _ => {
                panic!("unsupported/unmapped network")
            }
        }
    }
}

/// P2Pool sharechains corresponding to Bitcoin test networks. We do not
/// support Testnet3 or earlier.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum P2PoolTestnetVersion {
    /// Testnet version 4.
    V4,
    /// Testnet version 5.
    V5,
}

#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum P2PoolSignetChain {
    Default,
    Custom(ChainHash), // TODO: Define our own ChainHash type?
}

#[cfg(test)]
mod tests {
    use crate::networks::{InterNetwork, P2PoolNetwork, P2PoolSignetChain, P2PoolTestnetVersion};
    use bitcoin::Network;

    #[test]
    fn test_internetwork_fmt() {
        let cases: &[(InterNetwork, &str)] = &[
            (InterNetwork::Bitcoin(Network::Bitcoin), "bitcoin"),
            (InterNetwork::P2Pool(P2PoolNetwork::P2Pool), "p2pool"),
        ];
        for (net, expected_string) in cases {
            assert_eq!(*expected_string, net.to_string())
        }
    }

    const NETWORK_PAIRS: &[(P2PoolNetwork, Network)] = &[
        (P2PoolNetwork::P2Pool, Network::Bitcoin),
        (
            P2PoolNetwork::P2PoolTestnet(P2PoolTestnetVersion::V4),
            Network::Testnet4,
        ),
        (
            P2PoolNetwork::P2PoolSignet(P2PoolSignetChain::Default),
            Network::Signet,
        ),
    ];

    #[test]
    fn test_network_mapping_to_mined() {
        for (p2p_net, expected_btc_net) in NETWORK_PAIRS {
            assert_eq!(*expected_btc_net, p2p_net.to_mined())
        }
    }

    #[test]
    fn test_network_mapping_from_bitcoin() {
        for (expected_p2p_net, btc_net) in NETWORK_PAIRS {
            assert_eq!(*expected_p2p_net, P2PoolNetwork::from_bitcoin(*btc_net))
        }
    }
}
