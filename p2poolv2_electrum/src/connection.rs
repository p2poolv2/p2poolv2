// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::methods::blockchain::scripthash::read_statuses;
use crate::protocol::handle_line;
use crate::session::Session;
use crate::tip::TipReceiver;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use serde_json::Value;
use std::mem;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

/// Longest request line accepted. A batch of a hundred scripthash requests
/// fits comfortably; a longer line closes the connection.
pub(crate) const MAX_LINE_LENGTH: usize = 64 * 1024;

/// Serve newline-delimited JSON-RPC on one connection until the client
/// disconnects or `shutdown` is cancelled.
///
/// Malformed JSON is answered with a parse error and the connection stays
/// open. An over-long line, a read or write error, or EOF closes this
/// connection only. Blank lines and notifications get no response.
///
/// Requests run through the connection's `Session`, which holds what the
/// client subscribed to. After every answered line and on every tip
/// published on `tip_receiver`, the session decides which notifications
/// are due, and the connection writes them (see `send_notifications`).
pub(crate) async fn handle_connection<R, W>(
    reader: R,
    mut writer: W,
    client_address: SocketAddr,
    chain_store_handle: ChainStoreHandle,
    mut tip_receiver: TipReceiver,
    shutdown: CancellationToken,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_LINE_LENGTH));
    let mut session = Session::default();
    let mut open = true;
    while open {
        // Biased so that a tip change already pending is pushed before the
        // next request is read: a client sees notifications in a fixed
        // order relative to its responses.
        open = tokio::select! {
            biased;
            _ = shutdown.cancelled() => false,
            // The tip sender outlives every connection of its server, so
            // an error here means the server is stopping.
            changed = tip_receiver.changed(), if session.has_subscriptions() => {
                match changed {
                    Ok(()) => {
                        send_notifications(
                            &mut writer,
                            &mut session,
                            &mut tip_receiver,
                            true,
                            &chain_store_handle,
                            client_address,
                        )
                        .await
                    }
                    Err(_) => false,
                }
            }
            line = lines.next() => match line {
                Some(Ok(line)) => {
                    let answered = respond(
                        &mut writer,
                        line,
                        &chain_store_handle,
                        &tip_receiver,
                        &mut session,
                        client_address,
                    )
                    .await;
                    // A tip published while the line was handled is sent
                    // straight after the response.
                    let tip_changed = tip_receiver.has_changed().unwrap_or(false);
                    answered
                        && send_notifications(
                            &mut writer,
                            &mut session,
                            &mut tip_receiver,
                            tip_changed,
                            &chain_store_handle,
                            client_address,
                        )
                        .await
                }
                Some(Err(error)) => {
                    debug!("Electrum connection {client_address} read failed: {error}");
                    false
                }
                None => false,
            },
        };
    }
    if let Err(error) = writer.shutdown().await {
        debug!("Electrum connection {client_address} close failed: {error}");
    }
    debug!("Electrum connection {client_address} closed");
}

/// Answer one line through `session`, writing nothing for blank lines and
/// notifications. Returns whether the connection should stay open.
///
/// Methods read RocksDB synchronously, so the line is handled on a blocking
/// thread rather than on a tokio worker shared with P2P and stratum. The
/// session moves to that thread and back. A failed blocking task or a
/// failed write closes this connection.
///
/// The watched tip is snapshotted before the request without marking it
/// seen, so a tip published while the line is handled is still reported
/// as a change afterwards.
async fn respond<W>(
    writer: &mut W,
    line: String,
    chain_store_handle: &ChainStoreHandle,
    tip_receiver: &TipReceiver,
    session: &mut Session,
    client_address: SocketAddr,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    if line.trim().is_empty() {
        return true;
    }
    let chain_store_handle = chain_store_handle.clone();
    let watched_tip = tip_receiver.borrow().clone();
    let mut lent_session = mem::take(session);
    let handled = tokio::task::spawn_blocking(move || {
        let response = handle_line(&line, |method, params| {
            lent_session.handle_method(&chain_store_handle, watched_tip.as_ref(), method, params)
        });
        (response, lent_session)
    })
    .await;
    let response = match handled {
        Ok((response, returned_session)) => {
            *session = returned_session;
            response
        }
        Err(join_error) => {
            error!("Electrum connection {client_address} request handling failed: {join_error}");
            return false;
        }
    };
    match response {
        Some(response) => write_message(writer, &response, client_address).await,
        None => true,
    }
}

/// Write the notifications `session` reports as due to be sent
/// out. This marks the watched tip as seen. The tip notification is
/// sent first, then, when `tip_changed`, one per scripthash whose
/// status changed. Returns whether the connection should stay open.
///
/// Scripthash statuses are read from the store only on a tip change, since
/// the history changes only with the confirmed chain, and only for a
/// session holding scripthash subscriptions.
async fn send_notifications<W>(
    writer: &mut W,
    session: &mut Session,
    tip_receiver: &mut TipReceiver,
    tip_changed: bool,
    chain_store_handle: &ChainStoreHandle,
    client_address: SocketAddr,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let watched_tip = tip_receiver.borrow_and_update().clone();
    let tip_sent = match session.tip_notification(watched_tip) {
        Some(notification) => write_message(writer, &notification, client_address).await,
        None => true,
    };
    if tip_sent && tip_changed && session.has_scripthash_subscriptions() {
        send_scripthash_notifications(writer, session, chain_store_handle, client_address).await
    } else {
        tip_sent
    }
}

/// Write a notification for each subscribed scripthash whose status
/// changed. Returns whether the connection should stay open.
///
/// Only the store reads run on a blocking thread, over a copy of the
/// subscribed scripthashes; the session compares the statuses afterwards.
/// A failed store read is logged and writes nothing, leaving the session's
/// statuses as they were, so the next tip change retries; a failed
/// blocking task or write closes the connection.
async fn send_scripthash_notifications<W>(
    writer: &mut W,
    session: &mut Session,
    chain_store_handle: &ChainStoreHandle,
    client_address: SocketAddr,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let scripthashes = session.subscribed_scripthashes();
    let chain_store_handle = chain_store_handle.clone();
    let read =
        tokio::task::spawn_blocking(move || read_statuses(&chain_store_handle, &scripthashes))
            .await;
    match read {
        Ok(Ok(statuses)) => {
            let mut open = true;
            for notification in &session.status_notifications(statuses) {
                open = open && write_message(writer, notification, client_address).await;
            }
            open
        }
        Ok(Err(error)) => {
            warn!("Electrum connection {client_address} scripthash status read failed: {error}");
            true
        }
        Err(join_error) => {
            error!(
                "Electrum connection {client_address} scripthash notifications failed: {join_error}"
            );
            false
        }
    }
}

/// Write `message` as one line. Returns whether the write succeeded.
async fn write_message<W>(writer: &mut W, message: &Value, client_address: SocketAddr) -> bool
where
    W: AsyncWrite + Unpin,
{
    let mut line = message.to_string();
    line.push('\n');
    match writer.write_all(line.as_bytes()).await {
        Ok(()) => true,
        Err(error) => {
            debug!("Electrum connection {client_address} write failed: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::blockchain::scripthash::scripthash_status;
    use crate::test_utils::{build_current_test_chain, electrum_scripthash, spawn_test_connection};
    use crate::tip::{Tip, read_tip};
    use bitcoin::consensus::encode::serialize_hex;
    use p2poolv2_lib::store::script_history::script_hash;
    use p2poolv2_lib::test_utils::{
        TestShareBlockBuilder, build_confirmed_test_chain, confirm_test_block,
        setup_test_chain_store_handle, test_funding_transaction,
    };
    use serde_json::json;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::watch;
    use tokio::time::timeout;
    use tokio_test::io::Builder;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#;
    const SUBSCRIBE: &str =
        r#"{"jsonrpc":"2.0","id":2,"method":"blockchain.headers.subscribe","params":[]}"#;

    #[tokio::test]
    async fn request_line_gets_one_response_line() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn invalid_json_gets_parse_error_and_connection_stays_open() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

        let parse_error = client.call("{not json").await;
        assert_eq!(parse_error["error"]["code"], json!(-32700));
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn blank_line_gets_no_response() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

        client.send("").await.unwrap();
        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn notification_gets_no_response() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

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
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

        // The handler stops reading at the limit and closes, so the rest of
        // the write may fail.
        let _ = client.send(&"a".repeat(MAX_LINE_LENGTH + 1)).await;

        assert_eq!(client.read_line().await.unwrap(), None);
        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_eof_ends_handler() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (client, handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());

        drop(client);

        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_ends_handler_and_client_reads_eof() {
        let shutdown = CancellationToken::new();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, shutdown.clone());
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
        let client_address = SocketAddr::from(([127, 0, 0, 1], 0));
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let (_tip_sender, tip_receiver) = watch::channel(None);

        timeout(
            TEST_TIMEOUT,
            handle_connection(
                reader,
                writer,
                client_address,
                chain_store_handle,
                tip_receiver,
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn subscribe_answers_watched_tip_and_pushes_new_tip() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let first_tip = read_tip(&chain_store_handle).unwrap();
        let (tip_sender, tip_receiver) = watch::channel(Some(Arc::new(first_tip.clone())));
        let (mut client, _handler) = spawn_test_connection(
            chain_store_handle.clone(),
            tip_receiver,
            CancellationToken::new(),
        );
        assert_eq!(
            client.call(SUBSCRIBE).await,
            json!({"jsonrpc": "2.0", "id": 2, "result": first_tip.to_json()})
        );

        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;
        let next_tip = read_tip(&chain_store_handle).unwrap();
        tip_sender.send_replace(Some(Arc::new(next_tip.clone())));

        let notification: Value =
            serde_json::from_str(&client.read_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            notification,
            json!({
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [next_tip.to_json()],
            })
        );
    }

    /// The next line after republishing is the ping reply, so no
    /// notification was written for the unchanged tip.
    #[tokio::test]
    async fn republished_same_tip_pushes_nothing() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let tip = read_tip(&chain_store_handle).unwrap();
        let (tip_sender, tip_receiver) = watch::channel(Some(Arc::new(tip.clone())));
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());
        assert_eq!(client.call(SUBSCRIBE).await["result"], tip.to_json());

        tip_sender.send_replace(Some(Arc::new(tip)));

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn unsubscribed_connection_gets_no_notification() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let (tip_sender, tip_receiver) = watch::channel(None);
        let (mut client, _handler) = spawn_test_connection(
            chain_store_handle.clone(),
            tip_receiver,
            CancellationToken::new(),
        );

        tip_sender.send_replace(Some(Arc::new(read_tip(&chain_store_handle).unwrap())));

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    /// On a stale chain the subscribe is refused, and a refused subscribe
    /// must not subscribe the connection.
    #[tokio::test]
    async fn refused_subscribe_gets_no_notification() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let tip = read_tip(&chain_store_handle).unwrap();
        let (tip_sender, tip_receiver) = watch::channel(Some(Arc::new(tip)));
        let (mut client, _handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());
        assert_eq!(client.call(SUBSCRIBE).await["error"]["code"], json!(-32000));

        tip_sender.send_replace(Some(Arc::new(Tip {
            height: 1,
            header_hex: serialize_hex(&blocks[1].header),
        })));

        assert_eq!(
            client.call(PING).await,
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
    }

    #[tokio::test]
    async fn closed_tip_channel_closes_subscribed_connection() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let tip = read_tip(&chain_store_handle).unwrap();
        let (tip_sender, tip_receiver) = watch::channel(Some(Arc::new(tip)));
        let (mut client, handler) =
            spawn_test_connection(chain_store_handle, tip_receiver, CancellationToken::new());
        assert!(client.call(SUBSCRIBE).await["result"].is_object());

        drop(tip_sender);

        assert_eq!(client.read_line().await.unwrap(), None);
        timeout(TEST_TIMEOUT, handler).await.unwrap().unwrap();
    }

    /// The connection holds no headers subscription, so only a guard that
    /// counts scripthash subscriptions wakes it on the tip change.
    #[tokio::test]
    async fn scripthash_subscription_alone_pushes_new_status() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let scripthash = electrum_scripthash(payout_script);
        let (tip_sender, tip_receiver) =
            watch::channel(Some(Arc::new(read_tip(&chain_store_handle).unwrap())));
        let (mut client, _handler) = spawn_test_connection(
            chain_store_handle.clone(),
            tip_receiver,
            CancellationToken::new(),
        );
        let subscribe = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"blockchain.scripthash.subscribe","params":["{scripthash}"]}}"#
        );
        assert!(client.call(&subscribe).await["result"].is_string());

        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;
        tip_sender.send_replace(Some(Arc::new(read_tip(&chain_store_handle).unwrap())));

        let notification: Value =
            serde_json::from_str(&client.read_line().await.unwrap().unwrap()).unwrap();
        let new_status = scripthash_status(&chain_store_handle, &script_hash(payout_script))
            .unwrap()
            .unwrap();
        assert_eq!(
            notification,
            json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [scripthash, new_status],
            })
        );
    }

    #[tokio::test]
    async fn tip_notification_is_pushed_before_scripthash_notification() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let scripthash = electrum_scripthash(payout_script);
        let (tip_sender, tip_receiver) =
            watch::channel(Some(Arc::new(read_tip(&chain_store_handle).unwrap())));
        let (mut client, _handler) = spawn_test_connection(
            chain_store_handle.clone(),
            tip_receiver,
            CancellationToken::new(),
        );
        assert!(client.call(SUBSCRIBE).await["result"].is_object());
        let subscribe = format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"blockchain.scripthash.subscribe","params":["{scripthash}"]}}"#
        );
        assert!(client.call(&subscribe).await["result"].is_string());

        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;
        let next_tip = read_tip(&chain_store_handle).unwrap();
        tip_sender.send_replace(Some(Arc::new(next_tip.clone())));

        let first: Value =
            serde_json::from_str(&client.read_line().await.unwrap().unwrap()).unwrap();
        let second: Value =
            serde_json::from_str(&client.read_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            first,
            json!({
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [next_tip.to_json()],
            })
        );
        assert_eq!(second["method"], json!("blockchain.scripthash.subscribe"));
        assert_eq!(second["params"][0], json!(scripthash));
    }
}
