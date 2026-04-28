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
use std::time::Duration;
use tokio::time::{Instant, sleep};
use tracing::{info, warn};

const IBD_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const IBD_LOG_INTERVAL: Duration = Duration::from_secs(60);
const MAX_IBD_INFO_ERRORS: u8 = 3;

pub async fn wait_for_ibd(
    bitcoinrpc_config: &BitcoinRpcConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoinrpc_config.url,
        &bitcoinrpc_config.username,
        &bitcoinrpc_config.password,
    )?;
    let mut last_ibd_log = None;
    let mut error_count = 0;

    loop {
        let info = match bitcoind.getblockchaininfo().await {
            Ok(info) => info,
            Err(error) => {
                warn!("Failed to query Bitcoin blockchain info during IBD wait: {error}");
                sleep(IBD_RETRY_INTERVAL).await;

                if error_count >= MAX_IBD_INFO_ERRORS {
                    return Err(error.into());
                }

                error_count += 1;
                continue;
            }
        };

        error_count = 0;

        if info.headers == 0 {
            // header sync hasn't finished yet
            sleep(IBD_RETRY_INTERVAL).await;
            continue;
        }

        if !info.initial_block_download {
            info!("Bitcoin node is synced with the network");
            return Ok(());
        }

        log_every(&mut last_ibd_log, || {
            info!(
                "Bitcoin node is still in IBD; waiting for blocks to catch up to {} headers",
                info.headers
            );
        });

        wait_for_block_count(&bitcoind, info.headers, &mut last_ibd_log).await;
    }
}

async fn wait_for_block_count(
    bitcoind: &BitcoindRpcClient,
    headers: u64,
    last_ibd_log: &mut Option<Instant>,
) {
    loop {
        sleep(IBD_RETRY_INTERVAL).await;

        let count = match bitcoind.getblockcount().await {
            Ok(count) => count,
            Err(error) => {
                warn!("Failed to query Bitcoin block count during IBD wait: {error}");
                continue;
            }
        };

        log_every(last_ibd_log, || {
            info!("Bitcoin IBD progress: {count}/{headers}+ blocks downloaded");
        });

        if count >= headers {
            info!(
                "Bitcoin block count reached known headers ({count}/{headers}), re-checking IBD state"
            );
            return;
        }
    }
}

fn log_every(last_log: &mut Option<Instant>, log: impl FnOnce()) {
    let now = Instant::now();
    if last_log.is_some_and(|last_log| now.duration_since(last_log) < IBD_LOG_INTERVAL) {
        return;
    }

    log();
    *last_log = Some(now);
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
    async fn wait_for_ibd_exits_immediately_when_not_in_ibd() {
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
                    "headers": 1
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let result =
            tokio::time::timeout(Duration::from_secs(5), wait_for_ibd(&bitcoinrpc_config)).await;
        assert!(result.is_ok(), "wait_for_ibd timed out");
        assert!(result.unwrap().is_ok(), "wait_for_ibd returned an error");
    }

    #[tokio::test]
    async fn wait_for_ibd_waits_for_headers_then_rechecks_ibd() {
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let auth_header = test_auth_header();

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header.as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "initialblockdownload": false,
                    "headers": 1
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header.as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockcount",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": 1,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header.as_str()))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockchaininfo",
                "params": [],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {
                    "initialblockdownload": true,
                    "headers": 1
                },
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let result =
            tokio::time::timeout(Duration::from_secs(5), wait_for_ibd(&bitcoinrpc_config)).await;
        assert!(result.is_ok(), "wait_for_ibd timed out");
        assert!(result.unwrap().is_ok(), "wait_for_ibd returned an error");
    }
}
