// Copyright (C) 2024 [Kulpreet Singh]
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

use p2poolv2::config::{
    BitcoinConfig, CkPoolConfig, Config, MinerConfig, NetworkConfig, StoreConfig,
};

#[cfg(test)]
/// Build a default test configuration with test values that can be replaced later by each test
/// We avoid providing a Default implementation for Config as it exposes us to the risk of
/// accidentally using the default values in production.
/// WARNING: This is a test fixture and should not be used anywhere else.
pub fn default_test_config() -> Config {
    Config {
        network: NetworkConfig {
            listen_address: "/ip4/0.0.0.0/tcp/6887".to_string(),
            dial_peers: vec![],
        },
        bitcoin: BitcoinConfig {
            network: bitcoin::Network::Regtest,
            url: "http://localhost:8332".to_string(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        },
        store: StoreConfig {
            path: "test_chain.db".to_string(),
        },
        ckpool: CkPoolConfig {
            host: "127.0.0.1".to_string(),
            port: 8881,
        },
        miner: MinerConfig {
            pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap(),
        },
    }
}
