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

use p2poolv2_lib::auth::build_basic_auth_header;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// HTTP client wrapper for calling the P2Pool API with optional Basic auth.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    auth_header: Option<String>,
}

impl ApiClient {
    /// Create a new API client from the API configuration.
    pub fn new(api_config: &ApiConfig) -> Self {
        let base_url = format!("http://{}:{}", api_config.hostname, api_config.port);
        let auth_header = match (&api_config.auth_user, &api_config.auth_password) {
            (Some(username), Some(password)) => Some(build_basic_auth_header(username, password)),
            _ => None,
        };
        ApiClient {
            client: reqwest::Client::new(),
            base_url,
            auth_header,
        }
    }

    /// Perform an authenticated GET request to the given path.
    ///
    /// Returns the response body as a string on success. Returns an error if
    /// the server is unreachable, the response status is not successful, or the
    /// body cannot be read.
    pub async fn get(&self, path: &str) -> Result<String, Box<dyn Error>> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.get(&url);

        if let Some(header_value) = &self.auth_header {
            request = request.header("Authorization", header_value.clone());
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

        Ok(response.text().await?)
    }

    /// Wrapper around get returning parsed JSON respons.
    /// Perform an authenticated GET request and deserialize the JSON response.
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, Box<dyn Error>> {
        let body = self.get(path).await?;
        let parsed: T = serde_json::from_str(&body)?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::auth::build_basic_auth_header;
    use serde::Deserialize;
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

    #[test]
    fn test_new_without_auth() {
        let api_config = make_api_config(8080);
        let client = ApiClient::new(&api_config);

        assert_eq!(client.base_url, "http://127.0.0.1:8080");
        assert!(client.auth_header.is_none());
    }

    #[test]
    fn test_new_with_auth() {
        let mut api_config = make_api_config(8080);
        api_config.auth_user = Some("admin".to_string());
        api_config.auth_password = Some("secret".to_string());

        let client = ApiClient::new(&api_config);

        assert_eq!(client.base_url, "http://127.0.0.1:8080");
        assert!(client.auth_header.is_some());

        let expected = build_basic_auth_header("admin", "secret");
        assert_eq!(client.auth_header.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_get_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let client = ApiClient::new(&api_config);

        let result = client.get("/test").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_get_sends_auth_header() {
        let mock_server = MockServer::start().await;
        let expected_header = build_basic_auth_header("user", "pass");

        Mock::given(method("GET"))
            .and(path("/secure"))
            .and(header("Authorization", expected_header.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut api_config = make_api_config(mock_server.address().port());
        api_config.auth_user = Some("user".to_string());
        api_config.auth_password = Some("pass".to_string());

        let client = ApiClient::new(&api_config);
        let result = client.get("/secure").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_returns_error_on_non_success_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let client = ApiClient::new(&api_config);

        let result = client.get("/fail").await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("500"));
    }

    #[tokio::test]
    async fn test_get_returns_error_when_server_unreachable() {
        let api_config = make_api_config(19998);
        let client = ApiClient::new(&api_config);

        let result = client.get("/unreachable").await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Is the node running?"));
    }

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestPayload {
        value: i32,
    }

    #[tokio::test]
    async fn test_get_json_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{"value":42}"#, "application/json"),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let client = ApiClient::new(&api_config);

        let result: Result<TestPayload, _> = client.get_json("/json").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TestPayload { value: 42 });
    }

    #[tokio::test]
    async fn test_get_json_returns_error_on_invalid_json() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/bad-json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("not json", "text/plain"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let api_config = make_api_config(mock_server.address().port());
        let client = ApiClient::new(&api_config);

        let result: Result<TestPayload, _> = client.get_json("/bad-json").await;
        assert!(result.is_err());
    }
}
