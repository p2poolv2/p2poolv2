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

/// Execute the share command by querying the running node's API.
pub async fn execute(
    api_config: &ApiConfig,
    hash: Option<String>,
    height: Option<u32>,
    full: bool,
) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);

    let mut path = "/share?".to_string();
    if let Some(hash_value) = hash {
        path.push_str(&format!("hash={hash_value}"));
    } else if let Some(height_value) = height {
        path.push_str(&format!("height={height_value}"));
    }
    if full {
        path.push_str("&full=true");
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
    async fn test_execute_with_hash() {
        let mock_server = MockServer::start().await;
        let body = r#"[{"blockhash":"abc123","height":1,"status":"Confirmed","parent":"000","uncles":[],"btcaddress":"02aa","merkle_root":"ff","bits":"0x1b4188f5","time":"2024-01-01","bitcoin_header":{"block_hash":"bb","version":2,"prev_blockhash":"00","merkle_root":"ff","time":"2024-01-01","bits":"0x1d00ffff","nonce":0},"template_merkle_branches_count":1}]"#;

        Mock::given(method("GET"))
            .and(path("/share"))
            .and(query_param("hash", "abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, Some("abc123".to_string()), None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_height() {
        let mock_server = MockServer::start().await;
        let body = r#"[{"blockhash":"abc123","height":42,"status":"Confirmed","parent":"000","uncles":[],"btcaddress":"02aa","merkle_root":"ff","bits":"0x1b4188f5","time":"2024-01-01","bitcoin_header":{"block_hash":"bb","version":2,"prev_blockhash":"00","merkle_root":"ff","time":"2024-01-01","bits":"0x1d00ffff","nonce":0},"template_merkle_branches_count":1}]"#;

        Mock::given(method("GET"))
            .and(path("/share"))
            .and(query_param("height", "42"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, None, Some(42), false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_full_flag() {
        let mock_server = MockServer::start().await;
        let body = r#"[{"blockhash":"abc123","height":1,"status":"Confirmed","parent":"000","uncles":[],"btcaddress":"02aa","merkle_root":"ff","bits":"0x1b4188f5","time":"2024-01-01","bitcoin_header":{"block_hash":"bb","version":2,"prev_blockhash":"00","merkle_root":"ff","time":"2024-01-01","bits":"0x1d00ffff","nonce":0},"template_merkle_branches_count":1,"transactions":["txid1"]}]"#;

        Mock::given(method("GET"))
            .and(path("/share"))
            .and(query_param("hash", "abc123"))
            .and(query_param("full", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, Some("abc123".to_string()), None, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19993);
        let result = execute(&api_config, Some("abc".to_string()), None, false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_returns_error_on_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/share"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string(r#"{"error":"Share not found"}"#),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, Some("nonexistent".to_string()), None, false).await;
        assert!(result.is_err());
    }
}
