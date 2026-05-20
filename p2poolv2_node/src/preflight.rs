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

use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};

pub async fn ensure_bitcoin_node_synced(
    bitcoinrpc_config: &BitcoinRpcConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoinrpc_config.url,
        &bitcoinrpc_config.username,
        &bitcoinrpc_config.password,
    )?;

    let is_in_ibd = bitcoind.getblockchaininfo().await?.initial_block_download;

    if is_in_ibd {
        return Err("Bitcoin node still in initial block download".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, header, method, path},
    };

    async fn setup_mock_bitcoin_rpc() -> (MockServer, BitcoinRpcConfig) {
        let mock_server = MockServer::start().await;
        let config = BitcoinRpcConfig {
            url: mock_server.uri(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };
        (mock_server, config)
    }

    fn test_auth_header() -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", "testuser", "testpass"))
        )
    }

    #[tokio::test]
    async fn ensure_bitcoin_node_synced_returns_ok_when_not_in_ibd() {
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", test_auth_header().as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "initialblockdownload": false,
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let result = ensure_bitcoin_node_synced(&bitcoinrpc_config).await;
        assert!(
            result.is_ok(),
            "ensure_bitcoin_node_synced returned an error"
        );
    }

    #[tokio::test]
    async fn ensure_bitcoin_node_synced_returns_err_when_in_ibd() {
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", test_auth_header().as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "initialblockdownload": true,
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let result = ensure_bitcoin_node_synced(&bitcoinrpc_config).await;
        assert!(
            result.is_err(),
            "ensure_bitcoin_node_synced should return error when in IBD"
        );
    }
}
