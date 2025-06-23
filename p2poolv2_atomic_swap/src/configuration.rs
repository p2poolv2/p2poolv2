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


use serde::{Deserialize, Serialize};
use std::io;
use config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub storage_dir_path: String,
    pub network: String,
    #[serde(default)]
    pub listening_addresses: String,
    pub node_alias: String,
    pub esplora_url: String,
    pub rgs_server_url: String,
}

pub fn parse_config(file_path: &str) -> io::Result<NodeConfig> {
    // Use config crate to load the TOML file
    let config = Config::builder()
        .add_source(config::File::with_name(file_path))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Deserialize into NodeConfig
    let node_config: NodeConfig = config
        .try_deserialize()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Validate node_alias length (max 32 bytes)
    if node_config.node_alias.as_bytes().len() > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "node_alias exceeds 32 bytes",
        ));
    }

    Ok(node_config)
}