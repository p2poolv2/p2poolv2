// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-connection Electrum state: what a client subscribed to and what it
//! was last sent.
//!
//! The connection owns one `Session` and runs every request through it.
//! Subscription methods change the session; every other method goes to
//! the stateless `dispatch`. After each request and on each tip change
//! the connection asks the session for the notifications to write, so the
//! connection itself only moves lines.

use crate::methods::{dispatch, not_synced_error, require_synced};
use crate::protocol::{JSONRPC_VERSION, RpcError};
use crate::tip::Tip;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use serde_json::{Value, json};
use std::sync::Arc;

/// Subscribes the session to tip notifications, which are sent under the
/// same method name.
pub(crate) const HEADERS_SUBSCRIBE_METHOD: &str = "blockchain.headers.subscribe";

#[derive(Debug, Default)]
pub(crate) struct Session {
    /// The tip last sent to the client, as a subscribe answer or a
    /// notification. `None` until the client subscribes to headers.
    sent_tip: Option<Arc<Tip>>,
}

impl Session {
    /// Whether tip changes can produce a notification for this session.
    pub(crate) fn is_subscribed_to_headers(&self) -> bool {
        self.sent_tip.is_some()
    }

    /// Run one request and return its result or a JSON-RPC error.
    ///
    /// `watched_tip` is the connection's snapshot of the tip watcher, taken
    /// before the request; only `blockchain.headers.subscribe` reads it.
    pub(crate) fn handle_method(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        watched_tip: Option<&Arc<Tip>>,
        method: &str,
        params: &Value,
    ) -> Result<Value, RpcError> {
        match method {
            HEADERS_SUBSCRIBE_METHOD => self.headers_subscribe(chain_store_handle, watched_tip),
            _ => dispatch(chain_store_handle, method, params),
        }
    }

    /// The notification to send for `watched_tip`, or `None` when the
    /// client has not subscribed to headers or already has this tip.
    /// A returned notification is recorded as sent.
    pub(crate) fn tip_notification(&mut self, watched_tip: Option<Arc<Tip>>) -> Option<Value> {
        let tip = watched_tip?;
        let changed = self.sent_tip.as_ref().is_some_and(|sent| *sent != tip);
        changed.then(|| {
            let notification = json!({
                "jsonrpc": JSONRPC_VERSION,
                "method": HEADERS_SUBSCRIBE_METHOD,
                "params": [tip.to_json()],
            });
            self.sent_tip = Some(tip);
            notification
        })
    }

    /// `blockchain.headers.subscribe []`: the confirmed tip as
    /// `{height, hex}`, `hex` encoded as for `blockchain.block.header`, and
    /// the session is subscribed from then on, even when the request was a
    /// notification.
    ///
    /// Gated on sync like every `blockchain.*` method. Answers with
    /// `watched_tip` rather than a store read, so the notifications that
    /// follow, which also come from the watcher, are never older than this
    /// answer. The server publishes the first tip before accepting
    /// connections, so `None` means the node has not been current since
    /// this server instance started.
    fn headers_subscribe(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        watched_tip: Option<&Arc<Tip>>,
    ) -> Result<Value, RpcError> {
        require_synced(chain_store_handle)?;
        let tip = watched_tip.ok_or_else(|| not_synced_error(chain_store_handle))?;
        self.sent_tip = Some(Arc::clone(tip));
        Ok(tip.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::NOT_SYNCED;
    use crate::test_utils::build_current_test_chain;
    use crate::tip::read_tip;
    use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
    use p2poolv2_lib::shares::share_block::ShareHeader;
    use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};

    #[tokio::test]
    async fn headers_subscribe_answers_watched_tip_and_subscribes() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 3).await;
        let watched_tip = Arc::new(read_tip(&chain_store_handle).unwrap());
        let mut session = Session::default();

        let result = session
            .handle_method(
                &chain_store_handle,
                Some(&watched_tip),
                HEADERS_SUBSCRIBE_METHOD,
                &json!([]),
            )
            .unwrap();

        assert_eq!(result["height"], json!(3));
        let decoded: ShareHeader = deserialize_hex(result["hex"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, blocks[3].header);
        assert!(session.is_subscribed_to_headers());
    }

    #[tokio::test]
    async fn headers_subscribe_before_watcher_publishes_is_not_synced() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let mut session = Session::default();

        let error = session
            .handle_method(
                &chain_store_handle,
                None,
                HEADERS_SUBSCRIBE_METHOD,
                &json!([]),
            )
            .unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        assert_eq!(error.data.unwrap()["confirmed_tip_height"], json!(2));
        assert!(!session.is_subscribed_to_headers());
    }

    /// A tip published while the node was current is not served once the
    /// node falls behind, and the refused subscribe does not subscribe.
    #[tokio::test]
    async fn headers_subscribe_on_stale_chain_is_not_synced() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;
        let watched_tip = Arc::new(read_tip(&chain_store_handle).unwrap());
        let mut session = Session::default();

        let error = session
            .handle_method(
                &chain_store_handle,
                Some(&watched_tip),
                HEADERS_SUBSCRIBE_METHOD,
                &json!([]),
            )
            .unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        assert!(!session.is_subscribed_to_headers());
    }

    #[tokio::test]
    async fn stateless_method_goes_to_dispatch() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let mut session = Session::default();

        let result = session
            .handle_method(&chain_store_handle, None, "server.ping", &json!([]))
            .unwrap();

        assert_eq!(result, Value::Null);
        assert!(!session.is_subscribed_to_headers());
    }

    #[tokio::test]
    async fn tip_notification_before_subscribe_is_none() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let watched_tip = Arc::new(read_tip(&chain_store_handle).unwrap());
        let mut session = Session::default();

        assert_eq!(session.tip_notification(Some(watched_tip)), None);
    }

    #[tokio::test]
    async fn tip_notification_for_new_tip_is_sent_once() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 3).await;
        let answered_tip = Arc::new(Tip {
            height: 2,
            header_hex: serialize_hex(&blocks[2].header),
        });
        let new_tip = Arc::new(read_tip(&chain_store_handle).unwrap());
        let mut session = Session::default();
        session
            .handle_method(
                &chain_store_handle,
                Some(&answered_tip),
                HEADERS_SUBSCRIBE_METHOD,
                &json!([]),
            )
            .unwrap();

        assert_eq!(
            session.tip_notification(Some(new_tip.clone())),
            Some(json!({
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [new_tip.to_json()],
            }))
        );
        assert_eq!(session.tip_notification(Some(new_tip)), None);
    }

    #[tokio::test]
    async fn tip_notification_for_answered_tip_is_none() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let watched_tip = Arc::new(read_tip(&chain_store_handle).unwrap());
        let mut session = Session::default();
        session
            .handle_method(
                &chain_store_handle,
                Some(&watched_tip),
                HEADERS_SUBSCRIBE_METHOD,
                &json!([]),
            )
            .unwrap();

        assert_eq!(session.tip_notification(Some(watched_tip)), None);
    }
}
