// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::commands::api_client::ApiClient;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// Execute the candidates command by querying the running node's API.
pub async fn execute(
    api_config: &ApiConfig,
    to: Option<u32>,
    num: u32,
) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);

    let mut path = format!("/candidates?num={num}");
    if let Some(to_height) = to {
        path.push_str(&format!("&to={to_height}"));
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
            cors_allowed: false,
        }
    }

    #[tokio::test]
    async fn test_execute_with_default_params() {
        let mock_server = MockServer::start().await;
        let body = r#"{"from_height":0,"to_height":10,"shares":[]}"#;

        Mock::given(method("GET"))
            .and(path("/candidates"))
            .and(query_param("num", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, None, 10).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_to_param() {
        let mock_server = MockServer::start().await;
        let body = r#"{"from_height":0,"to_height":50,"shares":[]}"#;

        Mock::given(method("GET"))
            .and(path("/candidates"))
            .and(query_param("num", "5"))
            .and(query_param("to", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, Some(50), 5).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19994);
        let result = execute(&api_config, None, 10).await;
        assert!(result.is_err());
    }
}
