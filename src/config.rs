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

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub dial_peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub store: StoreConfig,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
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

    pub fn with_store_path(mut self, store_path: String) -> Self {
        self.store.path = store_path;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            network: NetworkConfig {
                listen_address: "/ip4/0.0.0.0/tcp/6884".to_string(),
                dial_peers: vec![],
            },
            store: StoreConfig {
                path: "./store.db".to_string(),
            },
        }
    }
}