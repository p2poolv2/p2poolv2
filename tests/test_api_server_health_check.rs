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

use p2poolv2_api::ApiServer;
use p2poolv2_api::api::error::ApiError;
use p2poolv2_lib::config::Raw;
use p2poolv2_lib::config::StratumConfig;
use p2poolv2_lib::shares::{ShareBlock, chain::chain_store::ChainStore};
use p2poolv2_lib::store::Store;
use reqwest::Client;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_api_server_health_check() -> Result<(), ApiError> {
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(ChainStore::new(store, genesis_block));

    // Stratum config
    let stratum_config_raw = StratumConfig::<Raw>::new_for_test_default();
    let stratum_config = stratum_config_raw
        .parse()
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // Start API server
    let port = 4000;
    let api_server = ApiServer::new(chain_store.clone(), stratum_config, port);
    let shutdown_tx = api_server.start().await.unwrap();

    // Give server a moment to start
    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Check /health endpoint
    let response = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    assert!(
        response.status().is_success(),
        "Health endpoint did not return 200 OK"
    );
    let body = response
        .text()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert_eq!(body, "ok", "Health endpoint returned unexpected body");

    // Send shutdown signal
    let _ = shutdown_tx.send(());

    // Give server a moment to shut down
    sleep(Duration::from_millis(200)).await;

    let result = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await;

    assert!(
        result.is_err(),
        "API server should not respond after shutdown"
    );

    Ok(())
}
