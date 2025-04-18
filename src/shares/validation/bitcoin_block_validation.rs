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

use crate::config::BitcoinConfig;
use crate::bitcoind_rpc::BitcoindRpcClient;
use crate::shares::ShareBlock;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{Hash as BitcoinHash, HashEngine, sha256};
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use bitcoin::pow::{CompactTarget, Target};
use serde_json::json;
use std::error::Error;
use uint::construct_uint;

// Define a 256-bit unsigned integer type
construct_uint! {
    pub struct U256(4);
}

/// Validate the P2Pool-specific difficulty requirements for a share
/// Returns true if the share meets P2Pool difficulty requirements
pub fn validate_p2pool_difficulty(share: &ShareBlock) -> bool {
    // Calculate share hash using double SHA256
    let mut engine = sha256::Hash::engine();
    
    // Serialize share data manually
    let workinfoid_bytes = share.header.miner_share.workinfoid.to_le_bytes();
    let nonce_bytes = share.header.miner_share.nonce.as_bytes();
    let ntime_bytes = share.header.miner_share.ntime.to_consensus_u32().to_le_bytes();
    
    engine.input(&workinfoid_bytes);
    engine.input(&nonce_bytes);
    engine.input(&ntime_bytes);
    
    let first_hash = sha256::Hash::from_engine(engine);
    let mut second_engine = sha256::Hash::engine();
    second_engine.input(&first_hash.to_byte_array());
    let share_hash = sha256::Hash::from_engine(second_engine);
    
    // Convert hash to U256
    let hash_int = U256::from_big_endian(&share_hash.to_byte_array());
    
    // Calculate target from difficulty
    // Target = (2^256 - 1) / difficulty
    let max_target = U256::MAX;
    let difficulty = share.header.miner_share.diff.to_u64().unwrap_or(1);
    let target = max_target / U256::from(difficulty);
    
    // Check if hash is below target (meets difficulty requirement)
    hash_int <= target
}

/// Get current bitcoin difficulty from rpc
/// Compare that to the share difficulty.
/// If the share difficulty is higher than or equal to current bitcoin difficulty, then validate bitcoin block using rpc
/// Finally return true is the block is accepted as valid by getblocktemplate proposal mode.
/// Raises an error if any of the rpc call fails
pub async fn meets_bitcoin_difficulty(
    share: &ShareBlock,
    block: &bitcoin::Block,
    config: &BitcoinConfig,
) -> Result<bool, Box<dyn Error>> {
    // First check P2Pool-specific difficulty requirements
    if !validate_p2pool_difficulty(share) {
        return Ok(false);
    }

    let bitcoind = BitcoindRpcClient::new(&config.url, &config.username, &config.password)?;
    let difficulty = bitcoind.get_difficulty().await?;
    let share_difficulty = share.header.miner_share.sdiff;
    if share_difficulty >= Decimal::from_f64_retain(difficulty).unwrap() {
        Ok(validate_bitcoin_block(block, config).await?)
    } else {
        Ok(false)
    }
}

/// Validate the bitcoin block
/// Expect the block to exist in the chain, if it does not, return an error and the client should retry
#[allow(dead_code)]
pub async fn validate_bitcoin_block(
    block: &bitcoin::Block,
    config: &BitcoinConfig,
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
        return Err(format!("Bitcoin block validation failed: {}", e).into());
    }

    if let Ok(response) = result {
        Ok(response == "duplicate")
    } else {
        Err(format!("Bitcoin block validation failed: {:?}", result).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use bitcoin::consensus::Decodable;
    use rust_decimal_macros::dec;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_validate_bitcoin_block_success() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "duplicate",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
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
        let block_hex_string = include_str!("../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Set up expected request/response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "rejected",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
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
        let block_hex_string = include_str!("../../../tests/test_data/seralized/block_1.txt");
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
                "jsonrpc": "2.0",
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
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Test validation
        let result = validate_bitcoin_block(&block, &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_meets_bitcoin_difficulty_matching() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Mock getdifficulty call
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", &auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getdifficulty",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": 1.0,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Mock getblocktemplate call
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", &auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": "duplicate",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Create share with matching difficulty
        let share = crate::test_utils::TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .diff(dec!(1.0))
            .build();

        // Test validation
        let result = meets_bitcoin_difficulty(&share, &block, &config).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_validate_bitcoin_block_share_difficulty_too_low() {
        // Start mock server
        let mock_server = MockServer::start().await;
        let block_hex_string = include_str!("../../../tests/test_data/seralized/block_1.txt");
        let block_hex = hex::decode(block_hex_string).unwrap();
        let block = bitcoin::Block::consensus_decode(&mut block_hex.as_slice()).unwrap();

        // Set up mock auth
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("testuser:testpass")
        );

        // Mock difficulty call to return higher difficulty than share
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", &auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "getdifficulty",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": 2.0, // Network difficulty is 2.0
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        // Create test config
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        // Create share with difficulty lower than network
        let share = crate::test_utils::TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .sdiff(dec!(1.0))
            .build();

        // Test validation - should return Ok(false) since share difficulty is too low
        let result = meets_bitcoin_difficulty(&share, &block, &config).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
