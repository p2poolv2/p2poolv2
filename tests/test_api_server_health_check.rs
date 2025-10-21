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
use chrono::{TimeZone, Utc};
use p2poolv2_api::api::error::ApiError;
use p2poolv2_api::start_api_server;
use p2poolv2_lib::accounting::{simple_pplns::SimplePplnsShare, stats::metrics::start_metrics};
use p2poolv2_lib::config::ApiConfig;
use p2poolv2_lib::shares::chain::chain_store::ChainStore;
use p2poolv2_lib::shares::share_block::ShareBlock;
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
    let chain_store = Arc::new(ChainStore::new(
        store,
        genesis_block,
        bitcoin::Network::Signet,
    ));

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
    let chain_store = Arc::new(ChainStore::new(
        store,
        genesis_block,
        bitcoin::Network::Signet,
    ));

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
    let test_token = format!("{test_salt}${test_hmac}");

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
        base64::engine::general_purpose::STANDARD.encode(format!("testuser:{test_password}"))
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

#[tokio::test]
async fn test_pplns_shares_endpoint_get_all() -> Result<(), ApiError> {
    // Setup temporary DB
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(p2poolv2_lib::shares::chain::chain_store::ChainStore::new(
        store.clone(),
        genesis_block,
        bitcoin::Network::Signet,
    ));

    // Start metrics actor
    let metrics_handle = p2poolv2_lib::accounting::stats::metrics::start_metrics(
        temp_dir.path().to_str().unwrap().to_string(),
    )
    .await
    .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // API config without auth
    let api_config = p2poolv2_lib::config::ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 40002,
        auth_user: None,
        auth_token: None,
    };

    // Start API server
    let shutdown_tx =
        p2poolv2_api::start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;

    sleep(Duration::from_millis(500)).await;

    // Insert test shares
    let user_id = store
        .add_user("tb1qtestaddress".to_string())
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    let share1_timestamp = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 40, 0)
        .single()
        .unwrap()
        .timestamp() as u64;
    let share2_timestamp = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 50, 0)
        .single()
        .unwrap()
        .timestamp() as u64;

    let shares = vec![
        SimplePplnsShare::new(
            user_id,
            100,
            "tb1qtestaddress".to_string(),
            "worker1".to_string(),
            share1_timestamp,
            "job1".to_string(),
            "extra".to_string(),
            "nonce1".to_string(),
        ),
        SimplePplnsShare::new(
            user_id,
            101,
            "tb1qtestaddress".to_string(),
            "worker2".to_string(),
            share2_timestamp,
            "job2".to_string(),
            "extra".to_string(),
            "nonce2".to_string(),
        ),
    ];

    for share in &shares {
        store
            .add_pplns_share(share.clone())
            .map_err(|e| ApiError::ServerError(e.to_string()))?;
    }

    let client = Client::new();

    let start_iso = "2025-10-17T19:39:59Z";
    let end_iso = "2025-10-17T19:55:00Z";

    // Test: Get all shares
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/pplns_shares?start_time={}&end_time={}&limit=10",
            api_config.port, start_iso, end_iso
        ))
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert!(response.status().is_success(), "Expected 200 OK");
    let body: Vec<SimplePplnsShare> = response
        .json()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert_eq!(body.len(), 2, "Should return 2 shares");

    // Shutdown server
    let _ = shutdown_tx.send(());
    sleep(Duration::from_millis(200)).await;

    Ok(())
}

#[tokio::test]
async fn test_pplns_shares_endpoint_limit() -> Result<(), ApiError> {
    // Setup temporary DB
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(p2poolv2_lib::shares::chain::chain_store::ChainStore::new(
        store.clone(),
        genesis_block,
        bitcoin::Network::Signet,
    ));

    // Start metrics actor
    let metrics_handle = p2poolv2_lib::accounting::stats::metrics::start_metrics(
        temp_dir.path().to_str().unwrap().to_string(),
    )
    .await
    .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // API config without auth
    let api_config = p2poolv2_lib::config::ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 40003,
        auth_user: None,
        auth_token: None,
    };

    // Start API server
    let shutdown_tx =
        p2poolv2_api::start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;

    sleep(Duration::from_millis(500)).await;

    // Insert test shares
    let user_id = store
        .add_user("tb1qtestaddress".to_string())
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    let t1 = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 40, 0)
        .single()
        .unwrap()
        .timestamp() as u64;
    let t2 = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 50, 0)
        .single()
        .unwrap()
        .timestamp() as u64;

    let shares = vec![
        SimplePplnsShare::new(
            user_id,
            100,
            "tb1qtestaddress".to_string(),
            "worker1".to_string(),
            t1,
            "job1".to_string(),
            "extra".to_string(),
            "nonce1".to_string(),
        ),
        SimplePplnsShare::new(
            user_id,
            101,
            "tb1qtestaddress".to_string(),
            "worker2".to_string(),
            t2,
            "job2".to_string(),
            "extra".to_string(),
            "nonce2".to_string(),
        ),
    ];

    for share in &shares {
        store
            .add_pplns_share(share.clone())
            .map_err(|e| ApiError::ServerError(e.to_string()))?;
    }

    let client = Client::new();

    // Test: Limit filtering
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/pplns_shares?limit=1",
            api_config.port
        ))
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    let limited: Vec<SimplePplnsShare> = response
        .json()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert_eq!(limited.len(), 1, "Limit=1 should return 1 share");

    // Shutdown server
    let _ = shutdown_tx.send(());
    sleep(Duration::from_millis(200)).await;

    Ok(())
}

#[tokio::test]
async fn test_pplns_shares_endpoint_time_filter() -> Result<(), ApiError> {
    // Setup temporary DB
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(p2poolv2_lib::shares::chain::chain_store::ChainStore::new(
        store.clone(),
        genesis_block,
        bitcoin::Network::Signet,
    ));

    // Start metrics actor
    let metrics_handle = p2poolv2_lib::accounting::stats::metrics::start_metrics(
        temp_dir.path().to_str().unwrap().to_string(),
    )
    .await
    .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // API config without auth
    let api_config = p2poolv2_lib::config::ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 40004,
        auth_user: None,
        auth_token: None,
    };

    // Start API server
    let shutdown_tx =
        p2poolv2_api::start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;

    sleep(Duration::from_millis(500)).await;

    // Insert test shares
    let user_id = store
        .add_user("tb1qtestaddress".to_string())
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    let share1_timestamp = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 40, 0)
        .single()
        .unwrap()
        .timestamp() as u64;
    let share2_timestamp = Utc
        .with_ymd_and_hms(2025, 10, 17, 19, 50, 0)
        .single()
        .unwrap()
        .timestamp() as u64;

    let shares = vec![
        SimplePplnsShare::new(
            user_id,
            100,
            "tb1qtestaddress".to_string(),
            "worker1".to_string(),
            share1_timestamp,
            "job1".to_string(),
            "extra".to_string(),
            "nonce1".to_string(),
        ),
        SimplePplnsShare::new(
            user_id,
            101,
            "tb1qtestaddress".to_string(),
            "worker2".to_string(),
            share2_timestamp,
            "job2".to_string(),
            "extra".to_string(),
            "nonce2".to_string(),
        ),
    ];

    for share in &shares {
        store
            .add_pplns_share(share.clone())
            .map_err(|e| ApiError::ServerError(e.to_string()))?;
    }

    let client = Client::new();

    // Test: Time filtering
    let response = client
        .get(format!(
            "http://127.0.0.1:{}/pplns_shares?start_time=2025-10-17T19:40:01Z&end_time=2025-10-17T19:50:00Z",
            api_config.port
        ))
        .send()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    let filtered: Vec<SimplePplnsShare> = response
        .json()
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;
    assert_eq!(filtered.len(), 1, "Time filter should return 1 share");
    assert_eq!(
        filtered[0].n_time, share2_timestamp,
        "Returned share should have correct timestamp"
    );

    // Shutdown server
    let _ = shutdown_tx.send(());
    sleep(Duration::from_millis(200)).await;

    Ok(())
}
#[tokio::test]
async fn test_pplns_shares_rate_limiting() -> Result<(), ApiError> {
    // Setup temporary DB
    let temp_dir = tempdir().map_err(|e| ApiError::ServerError(e.to_string()))?;
    let store = Arc::new(
        Store::new(temp_dir.path().to_str().unwrap().to_string(), false)
            .map_err(|e| ApiError::ServerError(e.to_string()))?,
    );
    let genesis_block = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
    let chain_store = Arc::new(ChainStore::new(
        store.clone(),
        genesis_block,
        bitcoin::Network::Signet,
    ));

    // Start metrics actor
    let metrics_handle = start_metrics(temp_dir.path().to_str().unwrap().to_string())
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    // API config without auth
    let api_config = ApiConfig {
        hostname: "127.0.0.1".into(),
        port: 40005,
        auth_user: None,
        auth_token: None,
    };

    // Start API server
    let shutdown_tx = start_api_server(api_config.clone(), chain_store.clone(), metrics_handle)
        .await
        .map_err(|e| ApiError::ServerError(e.to_string()))?;

    sleep(Duration::from_millis(500)).await;

    let client = Client::new();

    // Test rate limiting - make 11 requests (limit is 10 per minute)
    let mut success_count = 0;
    let mut rate_limited_count = 0;

    for _i in 0..11 {
        let response = client
            .get(format!("http://127.0.0.1:{}/pplns_shares", api_config.port))
            .send()
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;

        if response.status().is_success() {
            success_count += 1;
        } else if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            rate_limited_count += 1;
        }

        // Small delay between requests
        sleep(Duration::from_millis(10)).await;
    }

    // Should have exactly 10 successful requests and 1 rate limited
    assert_eq!(success_count, 10, "Expected 10 successful requests");
    assert_eq!(rate_limited_count, 1, "Expected 1 rate limited request");

    // Send shutdown signal
    let _ = shutdown_tx.send(());
    sleep(Duration::from_millis(200)).await;

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_window_reset() -> Result<(), ApiError> {
    use p2poolv2_api::api::rate_limiter::RateLimiter;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::time::sleep;

    // Create rate limiter with 2 requests per 100ms window
    let rate_limiter = RateLimiter::new(2, Duration::from_millis(100));
    let test_ip = IpAddr::from_str("127.0.0.1").unwrap();

    // First 2 requests should succeed
    assert!(
        rate_limiter.is_allowed(test_ip),
        "First request should be allowed"
    );
    assert!(
        rate_limiter.is_allowed(test_ip),
        "Second request should be allowed"
    );

    // Third request should fail
    assert!(
        !rate_limiter.is_allowed(test_ip),
        "Third request should be rate limited"
    );

    // Wait for window to reset
    sleep(Duration::from_millis(150)).await;

    // Should be allowed again after window reset
    assert!(
        rate_limiter.is_allowed(test_ip),
        "Request should be allowed after window reset"
    );

    Ok(())
}

#[tokio::test]
async fn test_rate_limiter_different_ips() -> Result<(), ApiError> {
    use p2poolv2_api::api::rate_limiter::RateLimiter;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    // Create rate limiter with 1 request per minute
    let rate_limiter = RateLimiter::new(1, Duration::from_secs(60));
    let ip1 = IpAddr::from_str("127.0.0.1").unwrap();
    let ip2 = IpAddr::from_str("192.168.1.1").unwrap();

    // First request from IP1 should succeed
    assert!(
        rate_limiter.is_allowed(ip1),
        "First request from IP1 should be allowed"
    );

    // Second request from IP1 should fail
    assert!(
        !rate_limiter.is_allowed(ip1),
        "Second request from IP1 should be rate limited"
    );

    // First request from IP2 should succeed (different IP)
    assert!(
        rate_limiter.is_allowed(ip2),
        "First request from IP2 should be allowed"
    );

    // Second request from IP2 should fail
    assert!(
        !rate_limiter.is_allowed(ip2),
        "Second request from IP2 should be rate limited"
    );

    Ok(())
}
