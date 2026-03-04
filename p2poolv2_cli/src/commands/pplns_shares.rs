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
use chrono::DateTime;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// Execute the pplns-shares command by querying the running node's API.
pub async fn execute(
    api_config: &ApiConfig,
    limit: usize,
    start_time: Option<u64>,
    end_time: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);

    let mut path = format!("/pplns_shares?limit={limit}");

    if let Some(timestamp) = start_time {
        let rfc3339 = DateTime::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| format!("Invalid start_time timestamp: {timestamp}"))?
            .to_rfc3339();
        path.push_str(&format!("&start_time={rfc3339}"));
    }

    if let Some(timestamp) = end_time {
        let rfc3339 = DateTime::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| format!("Invalid end_time timestamp: {timestamp}"))?
            .to_rfc3339();
        path.push_str(&format!("&end_time={rfc3339}"));
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
    async fn test_execute_with_limit_only() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/pplns_shares"))
            .and(query_param("limit", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(r#"[]"#, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, 50, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_with_start_and_end_time() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/pplns_shares"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(r#"[]"#, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        // 1700000000 -> 2023-11-14T22:13:20+00:00
        let result = execute(&api_config, 10, Some(1_700_000_000), Some(1_700_100_000)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19996);
        let result = execute(&api_config, 10, None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_returns_error_on_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/pplns_shares"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let result = execute(&api_config, 10, None, None).await;
        assert!(result.is_err());
    }
}
