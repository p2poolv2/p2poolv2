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

use crate::stratum::work::coinbase::parse_address;
use crate::stratum::work::error::WorkError;
use bitcoin::address::NetworkChecked;
use bitcoin::{Address, PublicKey};
use bitcoindrpc::BitcoinRpcConfig;
use serde::Deserialize;
use std::marker::PhantomData;

/// Marker type for raw (unparsed) StratumConfig state
#[derive(Debug, Clone, Default)]
pub struct Raw;

/// Marker type for parsed (validated) StratumConfig state
#[derive(Debug, Clone, Default)]
pub struct Parsed;

#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = "State: Default"))]
pub struct StratumConfig<State = Raw> {
    /// The hostname for the Stratum server
    pub hostname: String,
    /// The port for the Stratum server
    pub port: u16,
    /// The start difficulty for all miners that connect to the server
    pub start_difficulty: u64,
    /// The minimum difficulty for the pool
    pub minimum_difficulty: u64,
    /// The maximum difficulty for the pool, if set to None, it is not enforced
    pub maximum_difficulty: Option<u64>,
    /// The address for solo mining payouts
    pub solo_address: Option<String>,
    /// The ZMQ publisher address for block hashes
    pub zmqpubhashblock: String,
    /// The bitcoin address to use for first jobs when there are no shares (string in Raw state)
    pub bootstrap_address: String,
    /// The donation address for developers (string in Raw state)
    pub donation_address: Option<String>,
    /// The donation basis points
    pub donation: Option<u16>,
    /// The fee address (string in Raw state)
    pub fee_address: Option<String>,
    /// The fee basis points
    pub fee: Option<u16>,
    /// The network can be "main", "testnet4" or "signet
    #[serde(deserialize_with = "deserialize_network")]
    pub network: bitcoin::Network,
    /// The version mask to use for version-rolling
    #[serde(deserialize_with = "deserialize_version_mask")]
    pub version_mask: i32,
    /// The difficulty multiplier for dynamic difficulty adjustment
    pub difficulty_multiplier: f64,

    // Parsed addresses - only available when State = Parsed
    #[serde(skip)]
    pub(crate) bootstrap_address_parsed: Option<Address<NetworkChecked>>,
    #[serde(skip)]
    pub(crate) donation_address_parsed: Option<Address<NetworkChecked>>,
    #[serde(skip)]
    pub(crate) fee_address_parsed: Option<Address<NetworkChecked>>,

    #[serde(skip)]
    #[serde(default)]
    _state: PhantomData<State>,
}

impl StratumConfig<Raw> {
    /// Parse and validate addresses, converting from Raw to Parsed state
    pub fn parse(self) -> Result<StratumConfig<Parsed>, WorkError> {
        let bootstrap_address_parsed = parse_address(&self.bootstrap_address, self.network)?;

        let donation_address_parsed = self
            .donation_address
            .as_ref()
            .map(|addr| parse_address(addr, self.network))
            .transpose()?;

        let fee_address_parsed = self
            .fee_address
            .as_ref()
            .map(|addr| parse_address(addr, self.network))
            .transpose()?;

        Ok(StratumConfig {
            hostname: self.hostname,
            port: self.port,
            start_difficulty: self.start_difficulty,
            minimum_difficulty: self.minimum_difficulty,
            maximum_difficulty: self.maximum_difficulty,
            solo_address: self.solo_address,
            zmqpubhashblock: self.zmqpubhashblock,
            bootstrap_address: self.bootstrap_address,
            donation_address: self.donation_address,
            donation: self.donation,
            fee_address: self.fee_address,
            fee: self.fee,
            network: self.network,
            version_mask: self.version_mask,
            difficulty_multiplier: self.difficulty_multiplier,
            bootstrap_address_parsed: Some(bootstrap_address_parsed),
            donation_address_parsed,
            fee_address_parsed,
            _state: PhantomData,
        })
    }
}

impl StratumConfig<Parsed> {
    /// Get the parsed and validated bootstrap address
    pub fn bootstrap_address(&self) -> &Address<NetworkChecked> {
        self.bootstrap_address_parsed
            .as_ref()
            .expect("bootstrap_address_parsed should always be Some in Parsed state")
    }

    /// Get the parsed and validated donation address, if any
    pub fn donation_address(&self) -> Option<&Address<NetworkChecked>> {
        self.donation_address_parsed.as_ref()
    }

    /// Get the parsed and validated fee address, if any
    pub fn fee_address(&self) -> Option<&Address<NetworkChecked>> {
        self.fee_address_parsed.as_ref()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl StratumConfig<Raw> {
    /// Helper for tests to create a basic StratumConfig
    /// Uses regtest network by default with a valid regtest address
    pub fn new_for_test_default() -> Self {
        StratumConfig {
            hostname: "127.0.0.1".to_string(),
            port: 3333,
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: Some(1000),
            solo_address: None,
            zmqpubhashblock: "tcp://127.0.0.1:28332".to_string(),
            bootstrap_address: "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string(),
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            network: bitcoin::Network::Signet,
            version_mask: 0x1fffe000,
            difficulty_multiplier: 1.0,
            bootstrap_address_parsed: None,
            donation_address_parsed: None,
            fee_address_parsed: None,
            _state: PhantomData,
        }
    }
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

fn deserialize_version_mask<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    i32::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub dial_peers: Vec<String>,
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
    pub max_requests_per_second: u64,
    pub peer_inactivity_timeout_secs: u64,
    pub dial_timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoreConfig {
    pub path: String,
    /// How often to run background cleanup tasks (in hours)
    #[serde(default = "default_background_task_frequency_hours")]
    pub background_task_frequency_hours: u64,
    /// Time-to-live for PPLNS shares (in days)
    #[serde(default = "default_pplns_ttl_days")]
    pub pplns_ttl_days: u64,
}

fn default_background_task_frequency_hours() -> u64 {
    1
}

fn default_pplns_ttl_days() -> u64 {
    7
}

#[derive(Debug, Deserialize, Clone)]
pub struct CkPoolConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MinerConfig {
    pub pubkey: PublicKey,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct LoggingConfig {
    /// Log to file if specified
    pub file: Option<String>,
    /// Log level (defaults to "info")
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Directory for stats
    #[serde(default = "default_stats_dir")]
    pub stats_dir: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_stats_dir() -> String {
    "./logs/stats".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub network: NetworkConfig,
    pub store: StoreConfig,
    pub ckpool: CkPoolConfig,
    pub stratum: StratumConfig,
    pub miner: MinerConfig,
    pub bitcoinrpc: BitcoinRpcConfig,
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

    pub fn with_background_task_frequency_hours(mut self, hours: u64) -> Self {
        self.store.background_task_frequency_hours = hours;
        self
    }

    pub fn with_pplns_ttl_days(mut self, days: u64) -> Self {
        self.store.pplns_ttl_days = days;
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

    pub fn with_stratum_hostname(mut self, stratum_hostname: String) -> Self {
        self.stratum.hostname = stratum_hostname;
        self
    }

    pub fn with_stratum_port(mut self, stratum_port: u16) -> Self {
        self.stratum.port = stratum_port;
        self
    }

    pub fn with_stratum_solo_address(mut self, solo_address: String) -> Self {
        self.stratum.solo_address = Some(solo_address);
        self
    }

    pub fn with_stratum_zmqpubhashblock(mut self, zmqpubhashblock: String) -> Self {
        self.stratum.zmqpubhashblock = zmqpubhashblock;
        self
    }

    pub fn with_stratum_bootstrap_address(mut self, bootstrap_address: String) -> Self {
        self.stratum.bootstrap_address = bootstrap_address;
        self
    }

    pub fn with_start_difficulty(mut self, start_difficulty: u64) -> Self {
        self.stratum.start_difficulty = start_difficulty;
        self
    }

    pub fn with_minimum_difficulty(mut self, minimum_difficulty: u64) -> Self {
        self.stratum.minimum_difficulty = minimum_difficulty;
        self
    }

    pub fn with_maximum_difficulty(mut self, maximum_difficulty: Option<u64>) -> Self {
        self.stratum.maximum_difficulty = maximum_difficulty;
        self
    }

    pub fn with_difficulty_multiplier(mut self, difficulty_multiplier: f64) -> Self {
        self.stratum.difficulty_multiplier = difficulty_multiplier;
        self
    }

    pub fn with_miner_pubkey(mut self, miner_pubkey: String) -> Self {
        self.miner.pubkey = miner_pubkey.parse().unwrap();
        self
    }

    pub fn with_bitcoinrpc_url(mut self, bitcoin_url: String) -> Self {
        self.bitcoinrpc.url = bitcoin_url;
        self
    }

    pub fn with_bitcoinrpc_username(mut self, bitcoin_username: String) -> Self {
        self.bitcoinrpc.username = bitcoin_username;
        self
    }

    pub fn with_bitcoinrpc_password(mut self, bitcoin_password: String) -> Self {
        self.bitcoinrpc.password = bitcoin_password;
        self
    }

    pub fn with_bitcoin_network(mut self, network: bitcoin::Network) -> Self {
        self.stratum.network = network;
        self
    }

    pub fn with_stats_dir(mut self, stats_dir: String) -> Self {
        self.logging.stats_dir = stats_dir;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use temp_env::with_var;

    #[test]
    fn test_config_builder() {
        let config = Config::load("../config.toml").unwrap();
        let config = config
            .with_listen_address("127.0.0.1:8080".to_string())
            .with_dial_peers(vec![
                "peer1.example.com".to_string(),
                "peer2.example.com".to_string(),
            ])
            .with_max_pending_incoming(10)
            .with_max_pending_outgoing(10)
            .with_max_established_incoming(50)
            .with_max_established_outgoing(50)
            .with_max_established_per_peer(1)
            .with_store_path("/tmp/store".to_string())
            .with_ckpool_host("ckpool.example.com".to_string())
            .with_ckpool_port(3333)
            .with_stratum_hostname("stratum.example.com".to_string())
            .with_stratum_port(3333)
            .with_stratum_solo_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string())
            .with_stratum_zmqpubhashblock("tcp://127.0.0.1:28332".to_string())
            .with_stratum_bootstrap_address("bcrt1qxyz123example456bitcoin789address".to_string())
            .with_start_difficulty(1)
            .with_minimum_difficulty(1)
            .with_maximum_difficulty(Some(100))
            .with_difficulty_multiplier(2.0)
            .with_miner_pubkey(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            )
            .with_bitcoinrpc_url("http://localhost:8332".to_string())
            .with_bitcoinrpc_username("testuser".to_string())
            .with_bitcoinrpc_password("testpass".to_string())
            .with_bitcoin_network(bitcoin::Network::Signet)
            .with_stats_dir("./logs/stats".to_string());

        assert_eq!(config.network.listen_address, "127.0.0.1:8080");
        assert_eq!(
            config.network.dial_peers,
            vec!["peer1.example.com", "peer2.example.com"]
        );
        assert_eq!(config.store.path, "/tmp/store");
        assert_eq!(config.ckpool.host, "ckpool.example.com");
        assert_eq!(config.ckpool.port, 3333);

        assert_eq!(config.stratum.hostname, "stratum.example.com");
        assert_eq!(config.stratum.port, 3333);
        assert_eq!(config.stratum.start_difficulty, 1);
        assert_eq!(config.stratum.minimum_difficulty, 1);
        assert_eq!(config.stratum.maximum_difficulty, Some(100));
        assert_eq!(config.stratum.difficulty_multiplier, 2.0);
        assert_eq!(
            config.stratum.solo_address,
            Some("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string())
        );
        assert_eq!(
            config.stratum.zmqpubhashblock,
            "tcp://127.0.0.1:28332".to_string()
        );
        assert_eq!(
            config.stratum.bootstrap_address.to_string(),
            "bcrt1qxyz123example456bitcoin789address".to_string()
        );

        assert_eq!(
            config.miner.pubkey.to_string(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(config.bitcoinrpc.url, "http://localhost:8332");
        assert_eq!(config.bitcoinrpc.username, "testuser");
        assert_eq!(config.bitcoinrpc.password, "testpass");

        assert_eq!(config.network.max_pending_incoming, 10);
        assert_eq!(config.network.max_pending_outgoing, 10);
        assert_eq!(config.network.max_established_incoming, 50);
        assert_eq!(config.network.max_established_outgoing, 50);
        assert_eq!(config.network.max_established_per_peer, 1);
        assert_eq!(config.logging.stats_dir, "./logs/stats");

        // Test values from config.toml
        assert_eq!(config.store.background_task_frequency_hours, 24);
        assert_eq!(config.store.pplns_ttl_days, 7);
    }

    #[test]
    fn test_config_store_background_settings() {
        let config = Config::load("../config.toml")
            .unwrap()
            .with_background_task_frequency_hours(2)
            .with_pplns_ttl_days(7);

        assert_eq!(config.store.background_task_frequency_hours, 2);
        assert_eq!(config.store.pplns_ttl_days, 7);
    }

    #[test]
    fn test_config_from_env_vars() {
        with_var(
            "P2POOL_BITCOINRPC_URL",
            Some("http://bitcoin-from-env:8332"),
            || {
                // Load config from file first
                let config = Config::load("../config.toml").unwrap();

                // Check that the environment variable overrides the config file value
                assert_eq!(config.bitcoinrpc.url, "http://bitcoin-from-env:8332");
            },
        );
    }
}
