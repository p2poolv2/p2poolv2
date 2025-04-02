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
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoindRpcClient {
    client: HttpClient,
    semaphore: Arc<Semaphore>,
}

#[allow(dead_code)]
impl BitcoindRpcClient {
    pub fn new(
        url: &str,
        username: &str,
        password: &str,
        max_concurrent_requests: usize,
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
            .build(url)?;
        let semaphore = Arc::new(Semaphore::new(max_concurrent_requests));
        Ok(Self { client, semaphore })
    }

    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let _permit = self.semaphore.acquire().await?; // Limit concurrent requests
        let response = self.client.request(method, params).await?;
        Ok(response)
    }

    /// Get current bitcoin difficulty from bitcoind rpc
    pub async fn get_difficulty(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = self.request("getdifficulty", params).await?;
        Ok(result.as_f64().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_bitcoin_client() {
        // Start mock server
        let mock_server = MockServer::start().await;

        let auth_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Define expected request and response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "test",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": "test response",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "testuser", "testpass", 5).unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }

    #[tokio::test]
    async fn test_bitcoin_client_with_invalid_credentials() {
        let mock_server = MockServer::start().await;

        let client =
            BitcoindRpcClient::new(&mock_server.uri(), "invaliduser", "invalidpass", 5).unwrap();
        let params: Vec<serde_json::Value> = vec![];
        let result: Result<String, Box<dyn std::error::Error>> =
            client.request("test", params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since we only use it to test the connection to a locally running bitcoind
    async fn test_bitcoin_client_real_connection() {
        let client =
            BitcoindRpcClient::new("http://localhost:38332", "p2pool", "p2pool", 5).unwrap();

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

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool", 5).unwrap();
        let difficulty = client.get_difficulty().await.unwrap();

        assert_eq!(difficulty, 1234.56);

        #[tokio::test]
        async fn test_rate_limit_enforced() {
            let mock_server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": "ok",
                    "id": 0
                })))
                .mount(&mock_server)
                .await;

            let client = BitcoindRpcClient::new(&mock_server.uri(), "user", "pass", 2).unwrap();

            let start_time = Instant::now();

            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let client = client.clone();
                    task::spawn(async move {
                        let params: Vec<serde_json::Value> = vec![];
                        client.request::<String>("test", params).await.unwrap()
                    })
                })
                .collect();

            let results: Vec<String> = futures::future::join_all(handles)
                .await
                .into_iter()
                .map(|res| res.unwrap())
                .collect();

            let elapsed_time = start_time.elapsed();

            assert_eq!(results.len(), 4);
            assert!(results.iter().all(|r| r == "ok"));

            // Since we allow 2 concurrent requests, the second batch should have waited
            assert!(elapsed_time > Duration::from_millis(50));
        }
    }
}
