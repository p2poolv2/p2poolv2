// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use p2poolv2_lib::auth::build_basic_auth_header;
use p2poolv2_lib::config::ApiConfig;
use serde::Deserialize;
use std::error::Error;

/// Peer info returned from the API.
#[derive(Deserialize)]
struct PeerResponse {
    peer_id: String,
}

/// Format peers as a human-readable text table.
fn format_table(peers: &[PeerResponse]) -> String {
    let mut output = String::with_capacity(peers.len() * 80);

    output.push_str(&format!("Connected peers ({}):\n", peers.len()));
    output.push_str(&format!("{}\n", "=".repeat(72)));

    if peers.is_empty() {
        output.push_str("No connected peers\n");
        return output;
    }

    for peer in peers {
        output.push_str(&format!("{}\n", peer.peer_id));
    }

    output
}

/// Execute the peers-info command by querying the running node's API.
pub async fn execute(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let url = format!("http://{}:{}/peers", api_config.hostname, api_config.port);

    let client = reqwest::Client::new();
    let mut request = client.get(&url);

    if let (Some(username), Some(password)) = (&api_config.auth_user, &api_config.auth_password) {
        let auth_header = build_basic_auth_header(username, password);
        request = request.header("Authorization", auth_header);
    }

    let response = request.send().await.map_err(|error| {
        format!("Failed to connect to API at {url}: {error}. Is the node running?")
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "API returned status {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )
        .into());
    }

    let peers: Vec<PeerResponse> = response.json().await?;
    let formatted_output = format_table(&peers);
    println!("{formatted_output}");

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
        }
    }

    #[test]
    fn test_format_table_empty() {
        let peers: Vec<PeerResponse> = Vec::new();
        let output = format_table(&peers);
        assert!(output.contains("0)"));
        assert!(output.contains("No connected peers"));
    }

    #[test]
    fn test_format_table_with_peers() {
        let peers = vec![
            PeerResponse {
                peer_id: "12D3KooWAbcDef".to_string(),
            },
            PeerResponse {
                peer_id: "12D3KooWXyzGhi".to_string(),
            },
        ];
        let output = format_table(&peers);
        assert!(output.contains("2)"));
        assert!(output.contains("12D3KooWAbcDef"));
        assert!(output.contains("12D3KooWXyzGhi"));
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
