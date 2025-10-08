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

use base64::Engine;
use p2poolv2_api::api::error::ApiError;
use p2poolv2_api::start_api_server;
use p2poolv2_lib::accounting::stats::metrics::start_metrics;
use p2poolv2_lib::config::ApiConfig;
use p2poolv2_lib::shares::{ShareBlock, chain::chain_store::ChainStore};
use p2poolv2_lib::store::Store;
use reqwest::{Client, header};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_api_server_without_authentication() -> Result<(), ApiError> {
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(ChainStore::new(store, genesis_block));

    // Start metrics actor
    let metrics_handle = start_metrics(temp_dir.path().to_str().unwrap().to_string())
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    let api_config = ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 4000,
        auth_user: None,
        auth_token: None,
    };

    // Start API server with the new signature
    let shutdown_tx = start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // Give server a moment to start
    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Check /health endpoint
    let response = client
        .get(format!("http://127.0.0.1:{}/health", api_config.port))
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
    assert_eq!(body, "OK", "Health endpoint returned unexpected body");

    // Send shutdown signal
    let _ = shutdown_tx.send(());

    // Give server a moment to shut down
    sleep(Duration::from_millis(200)).await;

    let result = client
        .get(format!("http://127.0.0.1:{}/health", api_config.port))
        .send()
        .await;

    assert!(
        result.is_err(),
        "API server should not respond after shutdown"
    );

    Ok(())
}

#[tokio::test]
async fn test_api_server_with_authentication() -> Result<(), ApiError> {
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(ChainStore::new(store, genesis_block));

    // Start metrics actor
    let metrics_handle = start_metrics(temp_dir.path().to_str().unwrap().to_string())
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // Known test credentials from gen_auth with fixed salt
    // Generated with: gen_auth testuser testpassword
    // This is a test token with salt=0123456789abcdef0123456789abcdef
    let test_salt = "0123456789abcdef0123456789abcdef";
    let test_password = "testpassword";

    // Pre-computed HMAC-SHA256 for salt=0123456789abcdef0123456789abcdef, password=testpassword
    let test_hmac = "ae9b643bfa9f224a9c11accafec1ab89c3851c54ac036af2ac7f5b7a7d064fcb";
    let test_token = format!("{}${}", test_salt, test_hmac);

    let api_config = ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 4001,
        auth_user: Some("testuser".to_string()),
        auth_token: Some(test_token),
    };

    // Start API server with authentication
    let shutdown_tx = start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // Give server a moment to start
    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Test 1: Request without auth should fail
    let response = client
        .get(format!("http://127.0.0.1:{}/health", api_config.port))
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Request without auth should return 401"
    );

    // Test 2: Request with invalid credentials should fail
    let invalid_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("testuser:wrongpassword")
    );
    let response = client
        .get(format!("http://127.0.0.1:{}/health", api_config.port))
        .header(header::AUTHORIZATION, invalid_auth)
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Request with invalid password should return 401"
    );

    // Test 3: Request with valid credentials should succeed
    let valid_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("testuser:{}", test_password))
    );
    let response = client
        .get(format!("http://127.0.0.1:{}/health", api_config.port))
        .header(header::AUTHORIZATION, valid_auth.clone())
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    assert!(
        response.status().is_success(),
        "Request with valid auth should return 200 OK"
    );
    let body = response
        .text()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert_eq!(body, "OK", "Health endpoint returned unexpected body");

    // Test 4: Metrics endpoint should also require auth
    let response = client
        .get(format!("http://127.0.0.1:{}/metrics", api_config.port))
        .header(header::AUTHORIZATION, valid_auth)
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    assert!(
        response.status().is_success(),
        "Metrics endpoint with valid auth should return 200 OK"
    );

    // Send shutdown signal
    let _ = shutdown_tx.send(());

    // Give server a moment to shut down
    sleep(Duration::from_millis(200)).await;

    Ok(())
}
