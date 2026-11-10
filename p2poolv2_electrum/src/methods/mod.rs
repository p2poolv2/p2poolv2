// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum method dispatch, laid out like the Electrum method names:
//! `server` for `server.*` and `blockchain::<namespace>` for
//! `blockchain.<namespace>.*`.
//!
//! `server.*` methods always answer. `blockchain.*` methods read the share
//! chain and answer only once the node is synced; before that they return
//! `NOT_SYNCED`, never partial data.
//!
//! `dispatch` routes the stateless methods. Subscription methods change
//! per-connection state and are routed by `Session` (`session.rs`), which
//! shares the sync gate `require_synced`.

pub(crate) mod blockchain;
mod server;

use crate::protocol::{INTERNAL_ERROR, METHOD_NOT_FOUND, NOT_SYNCED, RpcError};
use blockchain::block::block_header;
use blockchain::scripthash::scripthash_get_history;
use blockchain::transaction::transaction_get;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::writer::StoreError;
use serde_json::{Value, json};
use server::{BANNER, server_features, server_version};
use std::time::{SystemTime, UNIX_EPOCH};

/// Methods under this prefix read chain data and are gated on sync.
const BLOCKCHAIN_METHOD_PREFIX: &str = "blockchain.";

const NOT_SYNCED_MESSAGE: &str = "node is syncing the share chain; wallet \
methods are available once it is synced";

/// Run the named stateless method and return its result or a JSON-RPC
/// error.
///
/// A `blockchain.*` method on a node whose confirmed tip is not current
/// returns `NOT_SYNCED` (see `require_synced`) before its params are even
/// read, so a syncing node never serves a partial chain.
pub(crate) fn dispatch(
    chain_store_handle: &ChainStoreHandle,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    if method.starts_with(BLOCKCHAIN_METHOD_PREFIX) {
        require_synced(chain_store_handle)?;
    }
    match method {
        "server.version" => server_version(params),
        "server.ping" => Ok(Value::Null),
        "server.banner" => Ok(Value::from(BANNER)),
        "server.features" => server_features(chain_store_handle),
        "blockchain.block.header" => block_header(chain_store_handle, params),
        "blockchain.transaction.get" => transaction_get(chain_store_handle, params),
        "blockchain.scripthash.get_history" => scripthash_get_history(chain_store_handle, params),
        _ => Err(RpcError::new(
            METHOD_NOT_FOUND,
            format!("unknown method {method}"),
        )),
    }
}

/// `NOT_SYNCED` unless the node's confirmed tip is current
/// (`ChainStoreHandle::is_current`). The one sync gate for every
/// `blockchain.*` method, whichever layer routes it.
pub(crate) fn require_synced(chain_store_handle: &ChainStoreHandle) -> Result<(), RpcError> {
    if chain_store_handle.is_current() {
        Ok(())
    } else {
        Err(not_synced_error(chain_store_handle))
    }
}

/// The `NOT_SYNCED` error, with sync progress in its `data` member:
/// confirmed and candidate tip heights and the confirmed tip's age in
/// seconds. A field the store cannot supply is null; building the error
/// never fails.
pub(crate) fn not_synced_error(chain_store_handle: &ChainStoreHandle) -> RpcError {
    let confirmed_tip_height = chain_store_handle.get_tip_height().ok().flatten();
    let candidate_tip_height = chain_store_handle.get_candidate_tip_height().ok().flatten();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs());
    let tip_age_secs = chain_store_handle
        .get_chain_tip_header()
        .ok()
        .zip(now_secs)
        .map(|(tip_header, now_secs)| now_secs.saturating_sub(u64::from(tip_header.time)));
    RpcError::new(NOT_SYNCED, NOT_SYNCED_MESSAGE).with_data(json!({
        "confirmed_tip_height": confirmed_tip_height,
        "candidate_tip_height": candidate_tip_height,
        "tip_age_secs": tip_age_secs,
    }))
}

pub(crate) fn store_read_error(error: StoreError) -> RpcError {
    RpcError::new(INTERNAL_ERROR, format!("share chain read failed: {error}"))
}

/// A parameter by position, or by name when params are an object; the
/// Electrum protocol allows both.
pub(crate) fn param<'a>(params: &'a Value, index: usize, name: &str) -> Option<&'a Value> {
    match params {
        Value::Array(values) => values.get(index),
        Value::Object(fields) => fields.get(name),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_current_test_chain;
    use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};

    #[tokio::test]
    async fn unknown_server_method_is_not_found() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(&chain_store_handle, "server.no_such_method", &json!([])).unwrap_err();
        assert_eq!(error.code, METHOD_NOT_FOUND);
    }

    /// `build_confirmed_test_chain` stamps blocks in 2023, so its tip is
    /// stale and the node counts as syncing.
    #[tokio::test]
    async fn blockchain_method_on_stale_tip_is_not_synced_with_progress() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([1])).unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        let data = error.data.unwrap();
        assert_eq!(data["confirmed_tip_height"], json!(2));
        assert_eq!(data["candidate_tip_height"], json!(2));
        assert!(data["tip_age_secs"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn blockchain_method_on_empty_store_is_not_synced_with_null_progress() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([0])).unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        assert_eq!(
            error.data.unwrap(),
            json!({
                "confirmed_tip_height": null,
                "candidate_tip_height": null,
                "tip_age_secs": null,
            })
        );
    }

    #[tokio::test]
    async fn server_method_on_stale_tip_still_answers() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;

        assert!(dispatch(&chain_store_handle, "server.features", &json!([])).is_ok());
    }

    /// A current tip passes the gate, so an unknown blockchain method falls
    /// through to method not found.
    #[tokio::test]
    async fn blockchain_method_on_current_tip_passes_gate() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.no_such_method", &json!([])).unwrap_err();

        assert_eq!(error.code, METHOD_NOT_FOUND);
    }
}
