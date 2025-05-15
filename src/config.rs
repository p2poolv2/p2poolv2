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

use bitcoin::PublicKey;
use serde::Deserialize;

use crate::stratum::server::StratumServer;

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub dial_peers: Vec<String>,
    pub enable_mdns: bool,
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_established_incoming: u32,
    pub max_established_outgoing: u32,
    pub max_established_per_peer: u32,
    pub max_workbase_per_second: u32,
    pub max_userworkbase_per_second: u32,
    pub max_miningshare_per_second: u32,
    pub max_inventory_per_second: u32,
    pub max_transaction_per_second: u32,
    pub rate_limit_window_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoreConfig {
    pub path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CkPoolConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StratumConfig {
    pub host: String,
    pub port: u16,
    pub start_difficulty: u32,
    pub minimum_difficulty: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MinerConfig {
    pub pubkey: PublicKey,
}

/// helper function to deserialize the network from the config file, which is provided as a string like Core
/// Possible values are: main, test, testnet4, signet, regtest
fn deserialize_network<'de, D>(deserializer: D) -> Result<bitcoin::Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    bitcoin::Network::from_core_arg(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct BitcoinConfig {
    #[serde(deserialize_with = "deserialize_network")]
    pub network: bitcoin::Network,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct LoggingConfig {
    /// Log to file if specified
    pub file: Option<String>,
    /// Log to console if true (defaults to true)
    #[serde(default = "default_console_logging")]
    pub console: bool,
    /// Log level (defaults to "info")
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_console_logging() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub network: NetworkConfig,
    pub store: StoreConfig,
    pub ckpool: CkPoolConfig,
    pub stratum: StratumConfig,
    pub miner: MinerConfig,
    pub bitcoin: BitcoinConfig,
    pub logging: LoggingConfig,
}

#[allow(dead_code)]
impl Config {
    pub fn load(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("P2POOL").separator("_"))
            .build()?
            .try_deserialize()
    }

    pub fn with_listen_address(mut self, listen_address: String) -> Self {
        self.network.listen_address = listen_address;
        self
    }

    pub fn with_dial_peers(mut self, dial_peers: Vec<String>) -> Self {
        self.network.dial_peers = dial_peers;
        self
    }

    pub fn with_enable_mdns(mut self, enable_mdns: bool) -> Self {
        self.network.enable_mdns = enable_mdns;
        self
    }

    pub fn with_max_pending_incoming(mut self, max_pending_incoming: u32) -> Self {
        self.network.max_pending_incoming = max_pending_incoming;
        self
    }

    pub fn with_max_pending_outgoing(mut self, max_pending_outgoing: u32) -> Self {
        self.network.max_pending_outgoing = max_pending_outgoing;
        self
    }

    pub fn with_max_established_incoming(mut self, max_established_incoming: u32) -> Self {
        self.network.max_established_incoming = max_established_incoming;
        self
    }

    pub fn with_max_established_outgoing(mut self, max_established_outgoing: u32) -> Self {
        self.network.max_established_outgoing = max_established_outgoing;
        self
    }

    pub fn with_max_established_per_peer(mut self, max_established_per_peer: u32) -> Self {
        self.network.max_established_per_peer = max_established_per_peer;
        self
    }

    pub fn with_store_path(mut self, store_path: String) -> Self {
        self.store.path = store_path;
        self
    }

    pub fn with_ckpool_host(mut self, ckpool_host: String) -> Self {
        self.ckpool.host = ckpool_host;
        self
    }

    pub fn with_ckpool_port(mut self, ckpool_port: u16) -> Self {
        self.ckpool.port = ckpool_port;
        self
    }

    pub fn with_stratum_host(mut self, stratum_host: String) -> Self {
        self.stratum.host = stratum_host;
        self
    }

    pub fn with_stratum_port(mut self, stratum_port: u16) -> Self {
        self.stratum.port = stratum_port;
        self
    }

    pub fn with_start_difficulty(mut self, start_difficulty: u32) -> Self {
        self.stratum.start_difficulty = start_difficulty;
        self
    }

    pub fn with_minimum_difficulty(mut self, minimum_difficulty: u32) -> Self {
        self.stratum.minimum_difficulty = minimum_difficulty;
        self
    }

    pub fn with_miner_pubkey(mut self, miner_pubkey: String) -> Self {
        self.miner.pubkey = miner_pubkey.parse().unwrap();
        self
    }

    pub fn with_bitcoin_url(mut self, bitcoin_url: String) -> Self {
        self.bitcoin.url = bitcoin_url;
        self
    }

    pub fn with_bitcoin_username(mut self, bitcoin_username: String) -> Self {
        self.bitcoin.username = bitcoin_username;
        self
    }

    pub fn with_bitcoin_password(mut self, bitcoin_password: String) -> Self {
        self.bitcoin.password = bitcoin_password;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = Config::load("./config.toml").unwrap();
        let config = config
            .with_listen_address("127.0.0.1:8080".to_string())
            .with_dial_peers(vec![
                "peer1.example.com".to_string(),
                "peer2.example.com".to_string(),
            ])
            .with_enable_mdns(true)
            .with_max_pending_incoming(10)
            .with_max_pending_outgoing(10)
            .with_max_established_incoming(50)
            .with_max_established_outgoing(50)
            .with_max_established_per_peer(1)
            .with_store_path("/tmp/store".to_string())
            .with_ckpool_host("ckpool.example.com".to_string())
            .with_ckpool_port(3333)
            .with_stratum_host("stratum.example.com".to_string())
            .with_stratum_port(3333)
            .with_start_difficulty(1)
            .with_minimum_difficulty(1)
            .with_miner_pubkey(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            )
            .with_bitcoin_url("http://localhost:8332".to_string())
            .with_bitcoin_username("testuser".to_string())
            .with_bitcoin_password("testpass".to_string());

        assert_eq!(config.network.listen_address, "127.0.0.1:8080");
        assert_eq!(
            config.network.dial_peers,
            vec!["peer1.example.com", "peer2.example.com"]
        );
        assert_eq!(config.store.path, "/tmp/store");
        assert_eq!(config.ckpool.host, "ckpool.example.com");
        assert_eq!(config.ckpool.port, 3333);

        assert_eq!(config.stratum.host, "stratum.example.com");
        assert_eq!(config.stratum.port, 3333);
        assert_eq!(config.stratum.start_difficulty, 1);
        assert_eq!(config.stratum.minimum_difficulty, 1);

        assert_eq!(
            config.miner.pubkey.to_string(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(config.bitcoin.url, "http://localhost:8332");
        assert_eq!(config.bitcoin.username, "testuser");
        assert_eq!(config.bitcoin.password, "testpass");

        assert_eq!(config.network.max_pending_incoming, 10);
        assert_eq!(config.network.max_pending_outgoing, 10);
        assert_eq!(config.network.max_established_incoming, 50);
        assert_eq!(config.network.max_established_outgoing, 50);
        assert_eq!(config.network.max_established_per_peer, 1);
    }

    #[test]
    fn test_config_from_env_vars() {
        // Set environment variable for bitcoin URL
        std::env::set_var("P2POOL_BITCOIN_URL", "http://bitcoin-from-env:8332");

        // Load config from file first
        let config = Config::load("./config.toml").unwrap();

        // Check that the environment variable overrides the config file value
        assert_eq!(config.bitcoin.url, "http://bitcoin-from-env:8332");

        // Clean up environment variable after test
        std::env::remove_var("P2POOL_BITCOIN_URL");
    }
}
