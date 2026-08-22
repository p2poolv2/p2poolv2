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

use crate::signal::ShutdownReason;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use std::time::Duration;
use tokio::sync::watch;
use tracing::warn;

#[derive(Debug)]
pub enum PreflightError {
    NotSynced,
    Rpc(Box<dyn std::error::Error + Send + Sync>),
    ShutdownRequested,
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::NotSynced => write!(f, "Bitcoin node still in initial block download"),
            PreflightError::Rpc(e) => write!(f, "{e}"),
            PreflightError::ShutdownRequested => write!(f, "shutdown requested while waiting for Bitcoin node to sync"),
        }
    }
}

impl std::error::Error for PreflightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PreflightError::Rpc(e) => Some(e.as_ref()),
            PreflightError::NotSynced => None,
            PreflightError::ShutdownRequested => None,
        }
    }
}

fn check_synced(bitcoind: &BitcoindRpcClient) -> impl std::future::Future<Output = Result<(), PreflightError>> + '_ {
    async move {
        let is_in_ibd = bitcoind
            .getblockchaininfo()
            .await
            .map_err(|e| PreflightError::Rpc(e.into()))?
            .initial_block_download;

        if is_in_ibd {
            return Err(PreflightError::NotSynced);
        }

        Ok(())
    }
}

pub async fn ensure_bitcoin_node_synced(
    bitcoinrpc_config: &BitcoinRpcConfig,
) -> Result<(), PreflightError> {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoinrpc_config.url,
        &bitcoinrpc_config.username,
        &bitcoinrpc_config.password,
    )
    .map_err(|e| PreflightError::Rpc(e.into()))?;

    check_synced(&bitcoind).await
}

/// Waits for the Bitcoin node to finish initial block download, checking
/// periodically and logging progress, instead of failing immediately.
///
/// The RPC client is built once and reused across polls. Any error other
/// than "still syncing" is returned right away. If a shutdown is signalled
/// via `shutdown_rx` while waiting, this returns early with
/// `PreflightError::ShutdownRequested` instead of sleeping out the full
/// interval.
pub async fn wait_for_bitcoin_node_synced(
    bitcoinrpc_config: &BitcoinRpcConfig,
    poll_interval: Duration,
    mut shutdown_rx: watch::Receiver<ShutdownReason>,
) -> Result<(), PreflightError> {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoinrpc_config.url,
        &bitcoinrpc_config.username,
        &bitcoinrpc_config.password,
    )
    .map_err(|e| PreflightError::Rpc(e.into()))?;

    loop {
        match check_synced(&bitcoind).await {
            Ok(()) => return Ok(()),
            Err(PreflightError::NotSynced) => {
                warn!(
                    "Bitcoin node still syncing, checking again in {}s...",
                    poll_interval.as_secs()
                );
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {},
                    _ = shutdown_rx.changed() => {
                        return Err(PreflightError::ShutdownRequested);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
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

    #[tokio::test]
    async fn wait_for_bitcoin_node_synced_retries_until_synced() {
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        // First two checks: still syncing
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
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&mock_server)
            .await;

        // After that: synced
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
            .with_priority(2)
            .mount(&mock_server)
            .await;

        let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownReason::None);
        let result = wait_for_bitcoin_node_synced(
            &bitcoinrpc_config,
            Duration::from_millis(10),
            shutdown_rx,
        )
        .await;
        assert!(
            result.is_ok(),
            "wait_for_bitcoin_node_synced should eventually succeed once the node is synced"
        );
    }
}
