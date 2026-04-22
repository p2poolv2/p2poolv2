// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::commands::api_client::ApiClient;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// Execute the info command by querying the running node's API.
pub async fn execute(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let response: serde_json::Value = api_client.get_json("/chain_info").await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_api_config(port: u16) -> ApiConfig {
        ApiConfig {
            hostname: "127.0.0.1".to_string(),
            port,
            auth_user: None,
            auth_token: None,
            auth_password: None,
            cors_allowed: false,
        }
    }

    #[tokio::test]
    async fn test_execute_prints_chain_info() {
        let mock_server = MockServer::start().await;
        let body = r#"{
            "genesis_blockhash": "abc123",
            "chain_tip_height": 100,
            "total_work": "0xff",
            "chain_tip_blockhash": "def456",
            "top_candidate_height": 101,
            "top_candidate_blockhash": "ghi789"
        }"#;

        Mock::given(method("GET"))
            .and(path("/chain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19997);
        let result = execute(&api_config).await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Is the node running?"));
    }

    #[tokio::test]
    async fn test_execute_returns_error_on_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/chain_info"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config).await;
        assert!(result.is_err());
    }
}
