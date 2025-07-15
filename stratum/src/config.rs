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

use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct StratumConfig {
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
    /// The network can be "main", "testnet4" or "signet
    #[serde(deserialize_with = "deserialize_network")]
    pub network: bitcoin::Network,
    /// The version mask to use for version-rolling
    #[serde(deserialize_with = "deserialize_version_mask")]
    pub version_mask: u32,
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

fn deserialize_version_mask<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    u32::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deserialize_stratum_config() {
        let config_json = json!({
            "hostname": "127.0.0.1",
            "port": 3333,
            "start_difficulty": 1000,
            "minimum_difficulty": 100,
            "maximum_difficulty": 10000,
            "solo_address": "bc1qexample",
            "zmqpubhashblock": "tcp://127.0.0.1:28332",
            "network": "main",
            "version_mask": "1fffe000"
        });

        let config: StratumConfig = serde_json::from_value(config_json).unwrap();

        assert_eq!(config.hostname, "127.0.0.1");
        assert_eq!(config.port, 3333);
        assert_eq!(config.start_difficulty, 1000);
        assert_eq!(config.minimum_difficulty, 100);
        assert_eq!(config.maximum_difficulty, Some(10000));
        assert_eq!(config.solo_address, Some("bc1qexample".to_string()));
        assert_eq!(config.zmqpubhashblock, "tcp://127.0.0.1:28332");
        assert_eq!(config.network, bitcoin::Network::Bitcoin);
        assert_eq!(config.version_mask, 0x1fffe000);
    }
}
