// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::connection::handle_connection;
use crate::error::ElectrumServerError;
use p2poolv2_lib::config::ElectrumConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Accept failures in a row before the instance gives up and returns, so
/// the caller can rebind a fresh listener.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 10;

/// Pause after an accept failure, so a persistent error such as fd
/// exhaustion does not spin the accept loop.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

/// How long open connections get to close once the server stops, before
/// their tasks are aborted.
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Run one Electrum server instance until `shutdown` is cancelled or the
/// listener fails.
///
/// Binds `hostname:port` and, once bound, sends the actual local address on
/// `ready_tx` (useful with port 0). Each accepted connection runs as its own
/// task holding a permit from a `max_connections` semaphore; a connection
/// over the cap is dropped. Returns `Ok(())` after shutdown, or an error if
/// binding fails or accepting fails `MAX_CONSECUTIVE_ACCEPT_ERRORS` times in
/// a row. In every case the listener is closed and all connection tasks have
/// finished, or been aborted, before this returns.
pub(crate) async fn run_server(
    config: &ElectrumConfig,
    shutdown: CancellationToken,
    ready_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<(), ElectrumServerError> {
    let (listener, local_address) = bind(config).await?;
    info!("Electrum server listening on {local_address}");
    if let Some(ready_tx) = ready_tx {
        ready_tx.send(local_address).ok();
    }

    let connection_shutdown = shutdown.child_token();
    let mut connections = JoinSet::new();
    let outcome = accept_loop(
        &listener,
        config.max_connections,
        &shutdown,
        &connection_shutdown,
        &mut connections,
    )
    .await;

    drop(listener);
    connection_shutdown.cancel();
    drain_connections(&mut connections).await;
    info!("Electrum server on {local_address} closed");
    outcome
}

/// Bind the configured address and read back the bound local address.
async fn bind(config: &ElectrumConfig) -> Result<(TcpListener, SocketAddr), ElectrumServerError> {
    let address = format!("{}:{}", config.hostname, config.port);
    let listener =
        TcpListener::bind(&address)
            .await
            .map_err(|source| ElectrumServerError::Bind {
                address: address.clone(),
                source,
            })?;
    let local_address = listener
        .local_addr()
        .map_err(|source| ElectrumServerError::Bind { address, source })?;
    Ok((listener, local_address))
}

/// Accept connections until shutdown or too many consecutive accept
/// failures. Finished connection tasks are reaped as they complete.
async fn accept_loop(
    listener: &TcpListener,
    max_connections: u32,
    shutdown: &CancellationToken,
    connection_shutdown: &CancellationToken,
    connections: &mut JoinSet<()>,
) -> Result<(), ElectrumServerError> {
    let connection_semaphore = Arc::new(Semaphore::new(max_connections as usize));
    let mut consecutive_accept_errors = 0;
    // Each select arm that ends the loop sets `outcome`.
    let mut outcome = None;
    while outcome.is_none() {
        tokio::select! {
            _ = shutdown.cancelled() => {
                outcome = Some(Ok(()));
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer_address)) => {
                    consecutive_accept_errors = 0;
                    accept_connection(
                        stream,
                        peer_address,
                        &connection_semaphore,
                        connection_shutdown,
                        connections,
                    );
                }
                Err(accept_error) => {
                    consecutive_accept_errors += 1;
                    error!("Electrum server accept failed: {accept_error}");
                    if consecutive_accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                        outcome = Some(Err(ElectrumServerError::Accept(accept_error)));
                    } else {
                        tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                    }
                }
            },
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                log_connection_result(joined);
            }
        }
    }
    outcome.unwrap_or(Ok(()))
}

/// Spawn a handler for an accepted stream if a connection permit is free,
/// otherwise drop the stream. The permit moves into the task, so it is
/// released when the connection closes.
fn accept_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    connection_semaphore: &Arc<Semaphore>,
    connection_shutdown: &CancellationToken,
    connections: &mut JoinSet<()>,
) {
    let Ok(permit) = connection_semaphore.clone().try_acquire_owned() else {
        warn!("Electrum server at connection limit, rejecting {peer_address}");
        return;
    };
    if let Err(error) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY for {peer_address}: {error}");
    }
    debug!("Electrum connection from {peer_address}");
    let (reader, writer) = stream.into_split();
    let shutdown = connection_shutdown.clone();
    connections.spawn(async move {
        let _permit = permit;
        handle_connection(reader, writer, peer_address, shutdown).await;
    });
}

/// Wait for every connection task to finish, aborting any still running
/// after `CONNECTION_DRAIN_TIMEOUT`.
async fn drain_connections(connections: &mut JoinSet<()>) {
    let drained = tokio::time::timeout(CONNECTION_DRAIN_TIMEOUT, async {
        while let Some(joined) = connections.join_next().await {
            log_connection_result(joined);
        }
    })
    .await;
    if drained.is_err() {
        warn!(
            "Electrum connections did not close within {CONNECTION_DRAIN_TIMEOUT:?}, aborting {}",
            connections.len()
        );
        connections.shutdown().await;
    }
}

/// A connection task only fails by panicking or being aborted. Log it; the
/// server keeps running.
fn log_connection_result(joined: Result<(), JoinError>) {
    if let Err(error) = joined {
        error!("Electrum connection task failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::MAX_LINE_LENGTH;
    use crate::test_utils::{TestClient, start_test_server, test_config};
    use serde_json::json;
    use std::net::TcpListener as StdTcpListener;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#;

    #[tokio::test]
    async fn ping_over_tcp_returns_null_result() {
        let shutdown = CancellationToken::new();
        let (address, _server) = start_test_server(shutdown.clone()).await;
        let mut client = TestClient::connect(address).await;

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn over_long_line_closes_only_that_connection() {
        let shutdown = CancellationToken::new();
        let (address, _server) = start_test_server(shutdown.clone()).await;
        let mut bystander = TestClient::connect(address).await;
        let mut offender = TestClient::connect(address).await;

        // The server may close before the whole line is written, so the
        // write itself is allowed to fail.
        let _ = offender.send(&"a".repeat(MAX_LINE_LENGTH + 1)).await;
        let after_long_line = offender.read_line().await;
        assert!(
            matches!(after_long_line, Ok(None) | Err(_)),
            "expected the connection to close, got {after_long_line:?}"
        );

        assert_eq!(
            bystander.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn connection_over_limit_is_dropped() {
        let shutdown = CancellationToken::new();
        let mut config = test_config();
        config.max_connections = 1;
        let (ready_tx, ready_rx) = oneshot::channel();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move { run_server(&config, server_shutdown, Some(ready_tx)).await });
        let address = ready_rx.await.unwrap();
        let mut first = TestClient::connect(address).await;
        assert_eq!(
            first.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );

        let mut second = TestClient::connect(address).await;
        let rejected = second.request(PING).await;
        assert!(
            matches!(rejected, Ok(None) | Err(_)),
            "expected the connection to be dropped, got {rejected:?}"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn cancelling_shutdown_returns_ok_and_closes_clients() {
        let shutdown = CancellationToken::new();
        let (address, server) = start_test_server(shutdown.clone()).await;
        let mut client = TestClient::connect(address).await;
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );

        shutdown.cancel();

        let result = timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
        assert!(result.is_ok(), "unexpected: {result:?}");
        assert_eq!(client.read_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn bind_to_held_port_returns_bind_error() {
        let held = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = test_config();
        config.port = held.local_addr().unwrap().port();

        let result = run_server(&config, CancellationToken::new(), None).await;

        assert!(
            matches!(result, Err(ElectrumServerError::Bind { .. })),
            "unexpected: {result:?}"
        );
    }
}
