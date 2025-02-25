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

#[derive(Debug, Clone)]
pub struct BitcoinClient {
    client: HttpClient,
}

impl BitcoinClient {
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

        let client = BitcoinClient::new(&mock_server.uri(), "testuser", "testpass").unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }
}
