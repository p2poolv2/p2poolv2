// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::commands::api_client::ApiClient;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// Execute the peers-info command by querying the running node's API.
pub async fn execute(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let response: serde_json::Value = api_client.get_json("/peers").await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::auth::build_basic_auth_header;
    use wiremock::matchers::{header, method, path};
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
    async fn test_execute_without_auth_fails_when_server_requires_auth() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/peers"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let port = mock_server.address().port();
        let api_config = make_api_config(port);

        let result = execute(&api_config).await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("401"));
    }

    #[tokio::test]
    async fn test_execute_with_auth_sends_basic_header() {
        let mock_server = MockServer::start().await;
        let body = r#"[{"peer_id":"12D3KooWAbcDef"}]"#;

        let expected_header = build_basic_auth_header("testuser", "testpass");

        Mock::given(method("GET"))
            .and(path("/peers"))
            .and(header("Authorization", expected_header.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let port = mock_server.address().port();
        let mut api_config = make_api_config(port);
        api_config.auth_user = Some("testuser".to_string());
        api_config.auth_password = Some("testpass".to_string());

        let result = execute(&api_config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        // Use a port where nothing is listening
        let api_config = make_api_config(19999);

        let result = execute(&api_config).await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Is the node running?"));
    }
}
