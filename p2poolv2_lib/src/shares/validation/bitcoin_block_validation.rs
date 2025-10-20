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

use bitcoin::consensus::encode::serialize;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use serde_json::json;
use std::error::Error;

/// Validate the bitcoin block
/// Expect the block to exist in the chain, if it does not, return an error and the client should retry
#[allow(dead_code)]
pub async fn validate_bitcoin_block(
    block: &bitcoin::Block,
    config: &BitcoinRpcConfig,
) -> Result<bool, Box<dyn Error>> {
    // Serialize block to hex string for RPC call
    let block_hex = hex::encode(serialize(block));

    // Create parameters for getblocktemplate call in proposal mode
    let params = vec![json!({
        "mode": "proposal",
        "data": block_hex
    })];

    // Call getblocktemplate RPC method using config values
    let bitcoind = BitcoindRpcClient::new(&config.url, &config.username, &config.password)?;
    let result: Result<serde_json::Value, _> = bitcoind.request("getblocktemplate", params).await;

    if let Err(e) = result {
        return Err(format!("Bitcoin block validation failed: {e}").into());
    }

    if let Ok(response) = result {
        Ok(response == "duplicate")
    } else {
        Err(format!("Bitcoin block validation failed: {result:?}").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use bitcoin::consensus::Decodable;
    use bitcoindrpc::BitcoinRpcConfig;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    #[tokio::test]
    async fn test_validate_bitcoin_block_success() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "duplicate",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let result = validate_bitcoin_block(&block, &config).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_reject() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response (JSON-RPC 1.0)
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "rejected",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let result = validate_bitcoin_block(&block, &config).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_http_error() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response with HTTP 500 error
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let result = validate_bitcoin_block(&block, &config).await;
        assert!(result.is_err());
    }
}
