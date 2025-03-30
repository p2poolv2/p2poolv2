// Copyright (C) 2024 [Kulpreet Singh]
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

use base64::{engine::general_purpose::STANDARD, Engine};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HeaderMap, HttpClient, HttpClientBuilder};
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoindRpcClient {
    client: HttpClient,
    max_retries: u8,
}

#[allow(dead_code)]
impl BitcoindRpcClient {
    pub fn new(
        url: &str,
        username: &str,
        password: &str,
        timeout: Duration,
        max_retries: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", username, password))
            )
            .parse()
            .unwrap(),
        );
        let client = HttpClientBuilder::default()
            .set_headers(headers)
            .request_timeout(timeout)
            .build(url)?;
        Ok(Self {
            client,
            max_retries,
        })
    }

    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut attempts = 0;
        let mut delay = Duration::from_millis(100);
        while attempts < self.max_retries {
            match self.client.request(method, params.clone()).await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    attempts += 1;
                    error!(
                        "RPC call '{}' failed (attempt {}): {:?}",
                        method, attempts, err
                    );
                    if attempts > self.max_retries {
                        return Err(Box::new(err));
                    }
                    sleep(Duration::from_secs(2_u64.pow(attempts as u32))).await;
                    delay *= 2; // Exponential backoff
                }
            }
        }
        Err("Max retries reached for RPC request".into())
    }

    /// Get current bitcoin difficulty from bitcoind rpc
    pub async fn get_difficulty(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let params: Vec<Value> = vec![];
        let result: Value = self.request("getdifficulty", params).await?;
        result
            .as_f64()
            .ok_or_else(|| "Failed to parse difficulty".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_bitcoin_client() {
        // Start mock server
        let mock_server = MockServer::start().await;

        let block_hex_string = "0000002000000000000000000000000000000000000000000000000000000000";

        let auth_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Define expected request and response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", &auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getblocktemplate",
                "params": [{
                    "mode": "proposal",
                    "data": block_hex_string
                }],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": "duplicate",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            &mock_server.uri(),
            "testuser",
            "testpass",
            Duration::from_secs(5),
            2,
        )
        .unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }

    #[tokio::test]
    async fn test_bitcoin_client_with_invalid_credentials() {
        let mock_server = MockServer::start().await;

        let client = BitcoindRpcClient::new(
            &mock_server.uri(),
            "invaliduser",
            "invalidpass",
            Duration::from_secs(5),
            2,
        )
        .unwrap();
        let params: Vec<serde_json::Value> = vec![];
        let result: Result<String, Box<dyn std::error::Error>> =
            client.request("test", params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since we only use it to test the connection to a locally running bitcoind
    async fn test_bitcoin_client_real_connection() {
        let client = BitcoindRpcClient::new(
            "http://localhost:38332",
            "p2pool",
            "p2pool",
            Duration::from_secs(30),
            3,
        )
        .unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = client.request("getblockchaininfo", params).await.unwrap();

        assert!(result.is_object());
        assert!(result.get("chain").is_some());
    }

    #[tokio::test]
    async fn test_get_difficulty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getdifficulty",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": 1234.56,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            &mock_server.uri(),
            "p2pool",
            "p2pool",
            Duration::from_secs(5),
            2,
        )
        .unwrap();
        let difficulty = client.get_difficulty().await.unwrap();

        assert_eq!(difficulty, 1234.56);
    }
}
