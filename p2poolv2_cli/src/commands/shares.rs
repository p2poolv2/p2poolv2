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

/// Execute the shares command by querying the running node's share_headers API.
pub async fn execute(
    api_config: &ApiConfig,
    to: Option<u32>,
    num: u32,
    share_block_transactions: bool,
) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);

    let mut path = format!("/share_headers?num={num}");
    if let Some(to_height) = to {
        path.push_str(&format!("&to={to_height}"));
    }
    if share_block_transactions {
        path.push_str("&share_block_transactions=true");
    }

    let response: serde_json::Value = api_client.get_json(&path).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_api_config(port: u16) -> ApiConfig {
        ApiConfig {
            hostname: "127.0.0.1".to_string(),
            port,
            auth_user: None,
            auth_token: None,
            auth_password: None,
        }
    }

    #[tokio::test]
    async fn test_execute_with_default_params() {
        let mock_server = MockServer::start().await;
        let body = r#"{"from_height":0,"to_height":10,"headers":[]}"#;

        Mock::given(method("GET"))
            .and(path("/share_headers"))
            .and(query_param("num", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, None, 10, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_to_param() {
        let mock_server = MockServer::start().await;
        let body = r#"{"from_height":0,"to_height":5,"headers":[]}"#;

        Mock::given(method("GET"))
            .and(path("/share_headers"))
            .and(query_param("num", "5"))
            .and(query_param("to", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, Some(100), 5, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_share_block_transactions() {
        let mock_server = MockServer::start().await;
        let body = r#"{"from_height":0,"to_height":10,"headers":[]}"#;

        Mock::given(method("GET"))
            .and(path("/share_headers"))
            .and(query_param("num", "10"))
            .and(query_param("share_block_transactions", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, None, 10, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19995);
        let result = execute(&api_config, None, 10, false).await;
        assert!(result.is_err());
    }
}
