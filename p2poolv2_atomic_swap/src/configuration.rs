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

use config::{Config, File, FileFormat};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub storage_dir_path: String,
    pub network: String,
    pub listening_addresses: String,
    pub node_alias: String,
    pub esplora_url: String,
    pub rgs_server_url: String,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct HtlcConfig {
    pub db_path: String,
    pub private_key: String,
    pub rpc_url: String,
    pub confirmation_threshold: u32, 
    pub min_buffer_block_for_refund: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub node: NodeConfig,
    pub htlc: HtlcConfig,
}

pub fn parse_config(file_path: &str) -> io::Result<AppConfig> {
    // Use config crate to load the TOML file explicitly as TOML format
    let config = Config::builder()
        .add_source(File::with_name(file_path).format(FileFormat::Toml))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Deserialize into AppConfig
    let app_config: AppConfig = config
        .try_deserialize()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Validate node_alias length (max 32 bytes)
    if app_config.node.node_alias.as_bytes().len() > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "node_alias exceeds 32 bytes",
        ));
    }

    // Validate listening_addresses format (basic check for comma-separated socket addresses)
    if !app_config.node.listening_addresses.is_empty() {
        let addresses = app_config.node.listening_addresses.split(',');
        for addr in addresses {
            let addr = addr.trim();
            if !addr.contains(':') || !(addr.starts_with("127.0.0.1") || addr.contains("::") || addr.ends_with(".onion")) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid listening address format: {}", addr),
                ));
            }
        }
    }

    // Validate network
    let valid_networks = vec!["Bitcoin", "Testnet", "Testnet4", "Signet", "Regtest"];
    if !valid_networks.contains(&app_config.node.network.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid network: {}", app_config.node.network),
        ));
    }

    // Validate private_key length (expecting 32 bytes hex, so 64 chars)
    if app_config.htlc.private_key.len() != 64 || !app_config.htlc.private_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private_key must be a 32-byte hexadecimal string",
        ));
    }

    Ok(app_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_toml(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(file, "{}", content).expect("Failed to write to temp file");
        file
    }

    #[test]
    fn test_parse_valid_config() {
        let toml_content = r#"
            [node]
            storage_dir_path = "data/ldk_node"
            network = "Signet"
            listening_addresses = "127.0.0.1:9735"
            node_alias = "p2pool_mm_node"
            esplora_url = "https://mutinynet.com/api/"
            rgs_server_url = "https://mutinynet.ltbl.io/snapshot"

            [ htlc ]
            db_path = "data/htlc_db"
            private_key = "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee"
            rpc_url = "https://mutinynet.com/api/"
            confirmation_threshold = 3
            min_buffer_block_for_refund = 2
        "#;

        let temp_file = create_temp_toml(toml_content);
        let result = parse_config(temp_file.path().to_str().unwrap());

        assert!(result.is_ok(), "Failed to parse config: {:?}", result);
        let config = result.unwrap();
        assert_eq!(config.node.storage_dir_path, "data/ldk_node");
        assert_eq!(config.node.network, "Signet");
        assert_eq!(config.node.listening_addresses, "127.0.0.1:9735");
        assert_eq!(config.node.node_alias, "p2pool_mm_node");
        assert_eq!(config.node.esplora_url, "https://mutinynet.com/api/");
        assert_eq!(config.node.rgs_server_url, "https://mutinynet.ltbl.io/snapshot");
        assert_eq!(config.htlc.db_path, "data/htlc_db");
        assert_eq!(config.htlc.private_key, "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee");
        assert_eq!(config.htlc.rpc_url, "https://mutinynet.com/api/");

        println!("Parsed config: {:?}", config);
    }
}