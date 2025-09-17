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

use crate::BitcoinRpcConfig;
use base64::Engine;
#[cfg(any(test, feature = "test-utils"))]
use wiremock::MockServer;
#[cfg(any(test, feature = "test-utils"))]
use wiremock::matchers::{body_json, header, method, path};
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

    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("Authorization", auth_header))
        .and(body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": api_method,
            "params": params,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "jsonrpc": "2.0", "result": template_json, "id": 0 }),
        ))
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
        // .and(any())
        // .and(body_json(serde_json::json!({
        //     "jsonrpc": "2.0",
        //     "id": 0,
        //     "method":"submitblock",
        // })))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "jsonrpc": "2.0", "result": serde_json::Value::Null, "id": 0 }),
        ))
        .mount(mock_server)
        .await;
}
