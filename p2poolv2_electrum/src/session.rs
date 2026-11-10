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
//! connection itself only moves lines. Scripthash notifications are
//! computed only on a tip change: the history changes only when the
//! confirmed chain does.
//!
//! The history window starts from the candidate tip, so an entry can drop
//! out of it while the confirmed tip stays put. That change is reported
//! with the next confirmed tip, seconds later on a current node.

use crate::methods::blockchain::scripthash::{parse_scripthash, scripthash_hex, scripthash_status};
use crate::methods::{dispatch, not_synced_error, param, require_synced, store_read_error};
use crate::protocol::{JSONRPC_VERSION, RpcError, TOO_MANY_SUBSCRIPTIONS};
use crate::tip::Tip;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::script_history::ScriptHash;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

/// Subscribes the session to tip notifications, which are sent under the
/// same method name.
pub(crate) const HEADERS_SUBSCRIBE_METHOD: &str = "blockchain.headers.subscribe";

/// Subscribes the session to status changes of one scripthash, which are
/// sent under the same method name.
pub(crate) const SCRIPTHASH_SUBSCRIBE_METHOD: &str = "blockchain.scripthash.subscribe";

/// Ends a scripthash subscription.
pub(crate) const SCRIPTHASH_UNSUBSCRIBE_METHOD: &str = "blockchain.scripthash.unsubscribe";

/// Most scripthash subscriptions one session may hold. Every tip change
/// recomputes the status of each, so this bounds the work a client can
/// cause.
pub(crate) const MAX_SCRIPTHASH_SUBSCRIPTIONS: usize = 1_000;

#[derive(Debug, Default)]
pub(crate) struct Session {
    /// The tip last sent to the client, as a subscribe answer or a
    /// notification. `None` until the client subscribes to headers.
    sent_tip: Option<Arc<Tip>>,
    /// Each subscribed scripthash, in store byte order, with the status
    /// last sent for it; `None` is the empty history.
    scripthash_statuses: HashMap<ScriptHash, Option<String>>,
}

impl Session {
    /// Whether tip changes can produce a notification for this session.
    pub(crate) fn has_subscriptions(&self) -> bool {
        self.sent_tip.is_some() || self.has_scripthash_subscriptions()
    }

    /// Whether a tip change needs scripthash statuses read from the store.
    pub(crate) fn has_scripthash_subscriptions(&self) -> bool {
        !self.scripthash_statuses.is_empty()
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
            SCRIPTHASH_SUBSCRIBE_METHOD => {
                self.scripthash_subscribe(chain_store_handle, params, MAX_SCRIPTHASH_SUBSCRIPTIONS)
            }
            SCRIPTHASH_UNSUBSCRIBE_METHOD => {
                self.scripthash_unsubscribe(chain_store_handle, params)
            }
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

    /// A copy of the subscribed scripthashes, so their statuses can be read
    /// on a blocking thread without the session.
    pub(crate) fn subscribed_scripthashes(&self) -> Vec<ScriptHash> {
        self.scripthash_statuses.keys().copied().collect()
    }

    /// A notification for each of `statuses` that differs from the status
    /// last sent for its scripthash, recording the new status as sent.
    /// Reads no store. A scripthash the session is not subscribed to is
    /// ignored rather than subscribed.
    pub(crate) fn status_notifications(
        &mut self,
        statuses: Vec<(ScriptHash, Option<String>)>,
    ) -> Vec<Value> {
        let mut notifications = Vec::with_capacity(statuses.len());
        for (scripthash, status) in statuses {
            if let Some(sent_status) = self.scripthash_statuses.get_mut(&scripthash)
                && *sent_status != status
            {
                notifications.push(json!({
                    "jsonrpc": JSONRPC_VERSION,
                    "method": SCRIPTHASH_SUBSCRIBE_METHOD,
                    "params": [scripthash_hex(&scripthash), status],
                }));
                *sent_status = status;
            }
        }
        notifications
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

    /// `blockchain.scripthash.subscribe [scripthash]`: the status of the
    /// script's history (`scripthash_status`), or null when it is empty,
    /// and the session is subscribed to it from then on.
    ///
    /// Gated on sync like every `blockchain.*` method. A new scripthash
    /// beyond `max_subscriptions` is refused with `TOO_MANY_SUBSCRIPTIONS`
    /// before its history is read; one already subscribed is answered
    /// again. The cap is a parameter so tests can reach it.
    fn scripthash_subscribe(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        params: &Value,
        max_subscriptions: usize,
    ) -> Result<Value, RpcError> {
        require_synced(chain_store_handle)?;
        let scripthash = parse_scripthash(param(params, 0, "scripthash"))?;
        let is_new = !self.scripthash_statuses.contains_key(&scripthash);
        if is_new && self.scripthash_statuses.len() >= max_subscriptions {
            return Err(RpcError::new(
                TOO_MANY_SUBSCRIPTIONS,
                format!("at most {max_subscriptions} scripthash subscriptions per connection"),
            ));
        }
        let status =
            scripthash_status(chain_store_handle, &scripthash).map_err(store_read_error)?;
        self.scripthash_statuses.insert(scripthash, status.clone());
        Ok(Value::from(status))
    }

    /// `blockchain.scripthash.unsubscribe [scripthash]`: true if the
    /// session was subscribed to the scripthash, false if not. Gated on
    /// sync like every `blockchain.*` method.
    fn scripthash_unsubscribe(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        params: &Value,
    ) -> Result<Value, RpcError> {
        require_synced(chain_store_handle)?;
        let scripthash = parse_scripthash(param(params, 0, "scripthash"))?;
        Ok(Value::Bool(
            self.scripthash_statuses.remove(&scripthash).is_some(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::blockchain::scripthash::read_statuses;
    use crate::protocol::{INVALID_PARAMS, NOT_SYNCED};
    use crate::test_utils::{build_current_test_chain, electrum_scripthash};
    use crate::tip::read_tip;
    use bitcoin::ScriptBuf;
    use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
    use p2poolv2_lib::shares::share_block::ShareHeader;
    use p2poolv2_lib::store::script_history::script_hash;
    use p2poolv2_lib::test_utils::{
        PUBKEY_2G, TestShareBlockBuilder, build_confirmed_test_chain, confirm_test_block,
        make_test_share_program, setup_test_chain_store_handle, test_funding_transaction,
    };

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
        assert!(session.has_subscriptions());
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
        assert!(!session.has_subscriptions());
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
        assert!(!session.has_subscriptions());
    }

    #[tokio::test]
    async fn stateless_method_goes_to_dispatch() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let mut session = Session::default();

        let result = session
            .handle_method(&chain_store_handle, None, "server.ping", &json!([]))
            .unwrap();

        assert_eq!(result, Value::Null);
        assert!(!session.has_subscriptions());
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

    #[tokio::test]
    async fn scripthash_subscribe_answers_status_and_subscribes() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let mut session = Session::default();

        let result = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([electrum_scripthash(payout_script)]),
            )
            .unwrap();

        let status = scripthash_status(&chain_store_handle, &script_hash(payout_script))
            .unwrap()
            .unwrap();
        assert_eq!(result, json!(status));
        assert_eq!(
            session.scripthash_statuses.get(&script_hash(payout_script)),
            Some(&Some(status))
        );
    }

    #[tokio::test]
    async fn scripthash_subscribe_to_empty_history_answers_null_and_subscribes() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let unused_script = ScriptBuf::new_witness_program(&make_test_share_program(2));
        let mut session = Session::default();

        let result = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([electrum_scripthash(&unused_script)]),
            )
            .unwrap();

        assert_eq!(result, Value::Null);
        assert_eq!(
            session
                .scripthash_statuses
                .get(&script_hash(&unused_script)),
            Some(&None)
        );
    }

    #[tokio::test]
    async fn scripthash_subscribe_on_stale_chain_is_not_synced() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let mut session = Session::default();

        let error = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([electrum_scripthash(payout_script)]),
            )
            .unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        assert!(session.scripthash_statuses.is_empty());
    }

    #[tokio::test]
    async fn scripthash_subscribe_with_bad_scripthash_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let mut session = Session::default();

        let error = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!(["z".repeat(64)]),
            )
            .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
        assert!(session.scripthash_statuses.is_empty());
    }

    #[tokio::test]
    async fn scripthash_subscribe_beyond_cap_is_refused_but_resubscribe_answers() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_scripthash =
            electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        let other_scripthash =
            electrum_scripthash(&ScriptBuf::new_witness_program(&make_test_share_program(2)));
        let mut session = Session::default();
        let first_answer = session
            .scripthash_subscribe(&chain_store_handle, &json!([payout_scripthash]), 1)
            .unwrap();

        let refused = session
            .scripthash_subscribe(&chain_store_handle, &json!([other_scripthash]), 1)
            .unwrap_err();
        let second_answer = session
            .scripthash_subscribe(&chain_store_handle, &json!([payout_scripthash]), 1)
            .unwrap();

        assert_eq!(refused.code, TOO_MANY_SUBSCRIPTIONS);
        assert_eq!(second_answer, first_answer);
        assert_eq!(session.scripthash_statuses.len(), 1);
    }

    #[tokio::test]
    async fn scripthash_unsubscribe_is_true_once_then_false() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        let mut session = Session::default();
        session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([scripthash]),
            )
            .unwrap();

        let first = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_UNSUBSCRIBE_METHOD,
                &json!([scripthash]),
            )
            .unwrap();
        let second = session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_UNSUBSCRIBE_METHOD,
                &json!([scripthash]),
            )
            .unwrap();

        assert_eq!(first, json!(true));
        assert_eq!(second, json!(false));
        assert!(session.scripthash_statuses.is_empty());
    }

    #[tokio::test]
    async fn new_block_paying_subscribed_script_notifies_once() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let mut session = Session::default();
        session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([electrum_scripthash(payout_script)]),
            )
            .unwrap();
        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;

        let statuses =
            read_statuses(&chain_store_handle, &session.subscribed_scripthashes()).unwrap();
        let notifications = session.status_notifications(statuses);
        let unchanged_statuses =
            read_statuses(&chain_store_handle, &session.subscribed_scripthashes()).unwrap();
        let repeated = session.status_notifications(unchanged_statuses);

        let new_status = scripthash_status(&chain_store_handle, &script_hash(payout_script))
            .unwrap()
            .unwrap();
        assert_eq!(
            notifications,
            vec![json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [electrum_scripthash(payout_script), new_status],
            })]
        );
        assert_eq!(repeated, Vec::<Value>::new());
    }

    #[tokio::test]
    async fn new_block_paying_another_script_does_not_notify() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let payout_script = &blocks[1].transactions[0].0.output[0].script_pubkey;
        let mut session = Session::default();
        session
            .handle_method(
                &chain_store_handle,
                None,
                SCRIPTHASH_SUBSCRIBE_METHOD,
                &json!([electrum_scripthash(payout_script)]),
            )
            .unwrap();
        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .miner_pubkey(PUBKEY_2G)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;

        let statuses =
            read_statuses(&chain_store_handle, &session.subscribed_scripthashes()).unwrap();
        let notifications = session.status_notifications(statuses);

        assert_ne!(
            &next_block.transactions[0].0.output[0].script_pubkey,
            payout_script
        );
        assert_eq!(notifications, Vec::<Value>::new());
    }

    #[test]
    fn status_for_unsubscribed_scripthash_is_ignored() {
        let mut session = Session::default();

        let notifications = session.status_notifications(vec![([9u8; 32], Some("ab".repeat(32)))]);

        assert_eq!(notifications, Vec::<Value>::new());
        assert!(session.scripthash_statuses.is_empty());
    }
}
