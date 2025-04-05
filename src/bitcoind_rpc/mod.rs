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

use base64::{engine::general_purpose::STANDARD, Engine};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HeaderMap, HttpClient, HttpClientBuilder};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoindRpcClient {
    client: HttpClient,
}

#[allow(dead_code)]
impl BitcoindRpcClient {
    pub fn new(
        url: &str,
        username: &str,
        password: &str,
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
        Ok(Self { client })
    }

    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, Box<dyn std::error::Error>> {
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

        let client = BitcoindRpcClient::new(&mock_server.uri(), "testuser", "testpass").unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }

    #[tokio::test]
    async fn test_bitcoin_client_with_invalid_credentials() {
        let mock_server = MockServer::start().await;

        let client =
            BitcoindRpcClient::new(&mock_server.uri(), "invaliduser", "invalidpass").unwrap();
        let params: Vec<serde_json::Value> = vec![];
        let result: Result<String, Box<dyn std::error::Error>> =
            client.request("test", params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since we only use it to test the connection to a locally running bitcoind
    async fn test_bitcoin_client_real_connection() {
        let client = BitcoindRpcClient::new("http://localhost:38332", "p2pool", "p2pool").unwrap();

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

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let difficulty = client.get_difficulty().await.unwrap();

        assert_eq!(difficulty, 1234.56);
    }
}
