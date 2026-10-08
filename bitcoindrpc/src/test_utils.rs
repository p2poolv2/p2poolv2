// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::BitcoinRpcConfig;
use base64::Engine;
#[cfg(any(test, feature = "test-utils"))]
use wiremock::MockServer;
#[cfg(any(test, feature = "test-utils"))]
use wiremock::matchers::body_partial_json;
#[cfg(any(test, feature = "test-utils"))]
use wiremock::matchers::{header, method, path};
#[cfg(any(test, feature = "test-utils"))]
use wiremock::{Mock, ResponseTemplate};

#[cfg(any(test, feature = "test-utils"))]
pub async fn setup_mock_bitcoin_rpc() -> (MockServer, BitcoinRpcConfig) {
    let mock_server = MockServer::start().await;

    // Create test config
    let config = BitcoinRpcConfig {
        url: mock_server.uri(),
        username: "testuser".to_string(),
        password: "testpass".to_string(),
    };

    (mock_server, config)
}

#[cfg(any(test, feature = "test-utils"))]
pub async fn mock_method(
    mock_server: &MockServer,
    api_method: &str,
    params: serde_json::Value,
    response: String,
) {
    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
    );

    let template_json: serde_json::Value =
        serde_json::from_str(&response).expect("Template response should be valid JSON");

    // Use body_partial_json to match method and params without requiring exact id match
    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", auth_header))
        .and(body_partial_json(serde_json::json!({
            "method": api_method,
            "params": params,
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "result": template_json, "error": null, "id": 0 }),
            ),
        )
        .mount(mock_server)
        .await;
}

#[cfg(any(test, feature = "test-utils"))]
pub async fn mock_submit_block_with_any_body(mock_server: &MockServer) {
    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
    );

    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", auth_header))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "result": serde_json::Value::Null, "error": null, "id": 0 }),
        ))
        .mount(mock_server)
        .await;
}
