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

// Example showing how to integrate the API server with the main P2Pool node

use p2poolv2_lib::api::ApiServer;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::shares::ShareBlock;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::stratum::work::block_template::BlockTemplate;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};

/// Example of integrating API server with main node
pub async fn integrate_api_with_node(
    config: Config,
    chain_store: Arc<ChainStore>,
    mut template_rx: mpsc::Receiver<BlockTemplate>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse stratum config
    let stratum_config = config.stratum.parse()?;
    
    // Create API server
    let api_server = ApiServer::new(chain_store.clone(), stratum_config, 8080);
    
    // Start API server in background
    let api_server_handle = {
        let api_server = api_server.clone();
        tokio::spawn(async move {
            if let Err(e) = api_server.start().await {
                error!("API server failed: {}", e);
            }
        })
    };
    
    info!("API server started on port 8080");
    
    // Forward block template updates to API server
    while let Some(template) = template_rx.recv().await {
        info!("Received new block template, updating API server");
        api_server.update_template(template).await;
    }
    
    // Wait for API server to finish
    let _ = api_server_handle.await;
    
    Ok(())
}

/// Example of running API server standalone
pub async fn run_standalone_api_server(
    config_path: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load configuration
    let config = Config::load(config_path)?;
    
    // Initialize store and chain
    let genesis = ShareBlock::build_genesis_for_network(config.stratum.network);
    let store = Arc::new(Store::open_read_only(config.store.path.clone())?);
    let chain_store = Arc::new(ChainStore::new(store, genesis));
    
    // Parse stratum config
    let stratum_config = config.stratum.parse()?;
    
    // Create and start API server
    let api_server = ApiServer::new(chain_store, stratum_config, port);
    
    info!("Starting standalone API server on port {}", port);
    api_server.start().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_api_server_creation() {
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let chain_store = Arc::new(ChainStore::new(
            store,
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));
        
        // Create a minimal config for testing
        let mut config = Config::default();
        config.stratum.network = bitcoin::Network::Signet;
        
        let stratum_config = config.stratum.parse().unwrap();
        let api_server = ApiServer::new(chain_store, stratum_config, 8080);
        
        // API server should be created successfully
        assert!(api_server.port == 8080);
    }
}