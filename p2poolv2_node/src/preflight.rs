// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::signal::ShutdownReason;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient, BitcoindRpcError};
use p2poolv2_lib::stratum::work::block_weight::{
    MINIMUM_BITCOIND_VERSION, RECOMMENDED_RESERVED_WEIGHT,
};
use std::time::Duration;
use tokio::sync::watch;
use tracing::warn;

#[derive(Debug)]
pub enum PreflightError {
    NotSynced,
    Rpc(Box<dyn std::error::Error + Send + Sync>),
    VersionUnavailable(BitcoindRpcError),
    UnsupportedVersion(u64),
    ShutdownRequested,
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::NotSynced => write!(f, "Bitcoin node still in initial block download"),
            PreflightError::Rpc(e) => write!(f, "{e}"),
            PreflightError::VersionUnavailable(e) => write!(
                f,
                "Cannot read the bitcoind version: bitcoind getnetworkinfo failed: {e}. \
                 Check the bitcoind RPC credentials and that rpcwhitelist allows getnetworkinfo."
            ),
            PreflightError::UnsupportedVersion(version) => write!(
                f,
                "P2Poolv2 requires Bitcoin Core 29.0 or newer for blockreservedweight, \
                 bitcoind reports version {version}."
            ),
            PreflightError::ShutdownRequested => write!(
                f,
                "shutdown requested while waiting for Bitcoin node to sync"
            ),
        }
    }
}

impl std::error::Error for PreflightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PreflightError::Rpc(e) => Some(e.as_ref()),
            PreflightError::VersionUnavailable(e) => Some(e),
            PreflightError::NotSynced => None,
            PreflightError::UnsupportedVersion(_) => None,
            PreflightError::ShutdownRequested => None,
        }
    }
}

async fn check_synced(bitcoind: &BitcoindRpcClient) -> Result<(), PreflightError> {
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

/// Check that bitcoind is Bitcoin Core 29.0 or newer, the first with
/// `blockreservedweight`.
async fn check_version(bitcoind: &BitcoindRpcClient) -> Result<(), PreflightError> {
    let version = bitcoind
        .getnetworkinfo()
        .await
        .map_err(PreflightError::VersionUnavailable)?
        .version;

    if version < MINIMUM_BITCOIND_VERSION {
        return Err(PreflightError::UnsupportedVersion(version));
    }

    Ok(())
}

/// Warn the operator to set `blockreservedweight` in bitcoin.conf. bitcoind
/// does not report the setting, so it cannot be checked at startup, and a
/// value too small for the coinbase only shows once a template is full, when
/// the node stops.
fn warn_to_check_reserved_weight() {
    warn!(
        "bitcoind does not report blockreservedweight, so P2Poolv2 cannot check it at \
         startup. Make sure bitcoin.conf sets blockreservedweight={RECOMMENDED_RESERVED_WEIGHT} \
         or higher. With the default of 8000, the node stops at the first full block template."
    );
}

/// Checks that bitcoind is Bitcoin Core 29.0 or newer, warns the operator to
/// set `blockreservedweight`, then waits for the Bitcoin node to finish
/// initial block download, checking periodically and logging progress,
/// instead of failing immediately.
///
/// The RPC client is built once and reused across polls. The version is
/// checked once, before waiting, so an unsupported bitcoind fails fast. Any
/// error other than "still syncing" is returned right away. If a shutdown is signalled
/// via `shutdown_rx` while waiting, this returns early with
/// `PreflightError::ShutdownRequested` instead of sleeping out the full
/// interval.
pub async fn wait_for_bitcoin_node_ready(
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

    check_version(&bitcoind).await?;
    warn_to_check_reserved_weight();

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
    async fn check_synced_returns_ok_when_not_in_ibd() {
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

        let bitcoind = BitcoindRpcClient::new(
            &bitcoinrpc_config.url,
            &bitcoinrpc_config.username,
            &bitcoinrpc_config.password,
        )
        .unwrap();
        let result = check_synced(&bitcoind).await;
        assert!(result.is_ok(), "check_synced returned an error");
    }

    #[tokio::test]
    async fn check_synced_returns_err_when_in_ibd() {
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

        let bitcoind = BitcoindRpcClient::new(
            &bitcoinrpc_config.url,
            &bitcoinrpc_config.username,
            &bitcoinrpc_config.password,
        )
        .unwrap();
        let result = check_synced(&bitcoind).await;
        assert!(
            result.is_err(),
            "check_synced should return error when in IBD"
        );
    }

    #[tokio::test]
    async fn wait_for_bitcoin_node_ready_retries_until_synced() {
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", test_auth_header().as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getnetworkinfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "version": 290000,
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

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
        let result =
            wait_for_bitcoin_node_ready(&bitcoinrpc_config, Duration::from_millis(10), shutdown_rx)
                .await;
        assert!(
            result.is_ok(),
            "wait_for_bitcoin_node_ready should eventually succeed once the node is synced"
        );
    }

    #[tokio::test]
    async fn wait_for_bitcoin_node_ready_fails_when_bitcoind_older_than_29() {
        //* Bitcoin Core 28.1 has no blockreservedweight. The node is still in
        //* IBD, so this also shows the version fails fast instead of waiting
        //* for the sync.
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", test_auth_header().as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getnetworkinfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "version": 280100,
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

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

        let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownReason::None);
        let result =
            wait_for_bitcoin_node_ready(&bitcoinrpc_config, Duration::from_secs(60), shutdown_rx)
                .await;

        let Err(error) = result else {
            panic!("wait_for_bitcoin_node_ready should fail when bitcoind is older than 29.0");
        };
        assert_eq!(
            error.to_string(),
            "P2Poolv2 requires Bitcoin Core 29.0 or newer for blockreservedweight, \
             bitcoind reports version 280100."
        );
    }

    #[tokio::test]
    async fn wait_for_bitcoin_node_ready_fails_when_getnetworkinfo_is_forbidden() {
        //* An rpcwhitelist without getnetworkinfo makes bitcoind answer 403.
        //* Retrying cannot fix it, so the error is returned right away.
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(serde_json::json!({
                "method": "getnetworkinfo",
            })))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownReason::None);
        let result =
            wait_for_bitcoin_node_ready(&bitcoinrpc_config, Duration::from_secs(60), shutdown_rx)
                .await;

        let Err(error) = result else {
            panic!("wait_for_bitcoin_node_ready should fail when getnetworkinfo is forbidden");
        };
        assert_eq!(
            error.to_string(),
            "Cannot read the bitcoind version: bitcoind getnetworkinfo failed: \
             HTTP error 403: Forbidden. Check the bitcoind RPC credentials and that \
             rpcwhitelist allows getnetworkinfo."
        );
        mock_server.verify().await;
    }
}
