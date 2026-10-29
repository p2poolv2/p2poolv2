// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::protocol::handle_line;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Longest request line accepted. A batch of a hundred scripthash requests
/// fits comfortably; a longer line closes the connection.
pub(crate) const MAX_LINE_LENGTH: usize = 64 * 1024;

/// Serve newline-delimited JSON-RPC on one connection until the client
/// disconnects or `shutdown` is cancelled.
///
/// Malformed JSON is answered with a parse error and the connection stays
/// open. An over-long line, a read or write error, or EOF closes this
/// connection only. Blank lines and notifications get no response.
pub(crate) async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    peer_address: SocketAddr,
    shutdown: CancellationToken,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE_LENGTH));
    let mut open = true;
    while open {
        open = tokio::select! {
            _ = shutdown.cancelled() => false,
            line = lines.next() => match line {
                Some(Ok(line)) => respond(&mut writer, &line, peer_address).await,
                Some(Err(error)) => {
                    debug!("Electrum connection {peer_address} read failed: {error}");
                    false
                }
                None => false,
            },
        };
    }
    if let Err(error) = writer.shutdown().await {
        debug!("Electrum connection {peer_address} close failed: {error}");
    }
    debug!("Electrum connection {peer_address} closed");
}

/// Answer one line, writing nothing for blank lines and notifications.
/// Returns whether the connection should stay open.
async fn respond<W>(writer: &mut W, line: &str, peer_address: SocketAddr) -> bool
where
    W: AsyncWrite + Unpin,
{
    if line.trim().is_empty() {
        return true;
    }
    let Some(response) = handle_line(line) else {
        return true;
    };
    let mut response = response.to_string();
    response.push('\n');
    match writer.write_all(response.as_bytes()).await {
        Ok(()) => true,
        Err(error) => {
            debug!("Electrum connection {peer_address} write failed: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::spawn_test_connection;
    use serde_json::json;
    use std::io;
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_test::io::Builder;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#;

    #[tokio::test]
    async fn request_line_gets_one_response_line() {
        let (mut client, _handler) = spawn_test_connection(CancellationToken::new());

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn invalid_json_gets_parse_error_and_connection_stays_open() {
        let (mut client, _handler) = spawn_test_connection(CancellationToken::new());

        let parse_error = client.call("{not json").await;
        assert_eq!(parse_error["error"]["code"], json!(-32700));
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn blank_line_gets_no_response() {
        let (mut client, _handler) = spawn_test_connection(CancellationToken::new());

        client.send("").await.unwrap();
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn notification_gets_no_response() {
        let (mut client, _handler) = spawn_test_connection(CancellationToken::new());

        client
            .send(r#"{"jsonrpc":"2.0","method":"server.ping","params":[]}"#)
            .await
            .unwrap();
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn over_long_line_closes_connection() {
        let (mut client, handler) = spawn_test_connection(CancellationToken::new());

        // The handler stops reading at the limit and closes, so the rest of
        // the write may fail.
        let _ = client.send(&"a".repeat(MAX_LINE_LENGTH + 1)).await;

        assert_eq!(client.read_line().await.unwrap(), None);
        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_eof_ends_handler() {
        let (client, handler) = spawn_test_connection(CancellationToken::new());

        drop(client);

        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_ends_handler_and_client_reads_eof() {
        let shutdown = CancellationToken::new();
        let (mut client, handler) = spawn_test_connection(shutdown.clone());
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );

        shutdown.cancel();

        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
        assert_eq!(client.read_line().await.unwrap(), None);
    }

    /// The reader keeps the connection idle after the request, so the
    /// handler can only finish this fast by closing on the write failure.
    #[tokio::test]
    async fn write_failure_ends_handler() {
        let reader = Builder::new()
            .read(format!("{PING}\n").as_bytes())
            .wait(Duration::from_secs(60))
            .build();
        let writer = Builder::new()
            .write_error(io::Error::from(io::ErrorKind::BrokenPipe))
            .build();
        let peer_address = SocketAddr::from(([127, 0, 0, 1], 0));

        timeout(
            TEST_TIMEOUT,
            handle_connection(reader, writer, peer_address, CancellationToken::new()),
        )
        .await
        .unwrap();
    }
}
