// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::server::run_server;
use p2poolv2_lib::config::ElectrumConfig;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Delay before restarting a failed server instance. Doubles after each
/// failure up to `maximum`, and resets to `initial` once an instance has
/// run longer than `maximum`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RestartBackoff {
    pub initial: Duration,
    pub maximum: Duration,
}

const PRODUCTION_BACKOFF: RestartBackoff = RestartBackoff {
    initial: Duration::from_secs(1),
    maximum: Duration::from_secs(60),
};

/// Spawn the Electrum server under a supervisor and return its task.
///
/// Methods read the share chain through `chain_store_handle`.
///
/// The supervisor restarts the server with backoff whenever it fails, for
/// as long as the node runs, so an Electrum failure never stops the node.
/// Cancelling `shutdown` closes the listener and every open connection; the
/// task completes once they are closed.
///
/// Restart covers returned errors only. The release profile is
/// `panic = "abort"`, so a panic anywhere takes the node down; this crate
/// must not `unwrap` or `expect` on runtime paths.
pub fn start_electrum_server(
    config: ElectrumConfig,
    chain_store_handle: ChainStoreHandle,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(supervise(
        config,
        chain_store_handle,
        shutdown,
        PRODUCTION_BACKOFF,
    ))
}

/// Run server instances until `shutdown` is cancelled, waiting out the
/// backoff delay between a failure and the next attempt. Shutdown during
/// the delay ends the supervisor at once.
pub(crate) async fn supervise(
    config: ElectrumConfig,
    chain_store_handle: ChainStoreHandle,
    shutdown: CancellationToken,
    backoff: RestartBackoff,
) {
    let mut delay = backoff.initial;
    while !shutdown.is_cancelled() {
        let started = Instant::now();
        // Returns Ok only once shutdown is cancelled, which ends the loop.
        if let Err(server_error) =
            run_server(&config, &chain_store_handle, shutdown.child_token(), None).await
        {
            if started.elapsed() > backoff.maximum {
                delay = backoff.initial;
            }
            error!("Electrum server failed: {server_error}. Restarting in {delay:?}");
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.cancelled() => {}
            }
            delay = (delay * 2).min(backoff.maximum);
        }
    }
    info!("Electrum server stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{connect_with_retry, test_config};
    use p2poolv2_lib::test_utils::setup_test_chain_store_handle;
    use serde_json::json;
    use std::net::TcpListener as StdTcpListener;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#;
    const FAST_BACKOFF: RestartBackoff = RestartBackoff {
        initial: Duration::from_millis(10),
        maximum: Duration::from_millis(50),
    };

    #[tokio::test]
    async fn restarts_after_bind_failure() {
        let held = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = held.local_addr().unwrap();
        let mut config = test_config();
        config.port = address.port();
        let shutdown = CancellationToken::new();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let supervisor = tokio::spawn(supervise(
            config,
            chain_store_handle,
            shutdown.clone(),
            FAST_BACKOFF,
        ));

        drop(held);
        let mut client = connect_with_retry(address).await;

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
        shutdown.cancel();
        timeout(TEST_TIMEOUT, supervisor).await.unwrap().unwrap();
    }

    /// A backoff far longer than the test timeout, so the supervisor can
    /// only finish in time by leaving the delay on shutdown.
    #[tokio::test]
    async fn shutdown_during_backoff_ends_supervisor() {
        let held = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = test_config();
        config.port = held.local_addr().unwrap().port();
        let shutdown = CancellationToken::new();
        let long_backoff = RestartBackoff {
            initial: Duration::from_secs(60),
            maximum: Duration::from_secs(60),
        };
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let supervisor = tokio::spawn(supervise(
            config,
            chain_store_handle,
            shutdown.clone(),
            long_backoff,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown.cancel();

        timeout(TEST_TIMEOUT, supervisor).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_while_serving_ends_supervisor_and_closes_clients() {
        let free = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = free.local_addr().unwrap();
        drop(free);
        let mut config = test_config();
        config.port = address.port();
        let shutdown = CancellationToken::new();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let supervisor = tokio::spawn(supervise(
            config,
            chain_store_handle,
            shutdown.clone(),
            FAST_BACKOFF,
        ));
        let mut client = connect_with_retry(address).await;
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );

        shutdown.cancel();

        timeout(TEST_TIMEOUT, supervisor).await.unwrap().unwrap();
        assert_eq!(client.read_line().await.unwrap(), None);
    }
}
