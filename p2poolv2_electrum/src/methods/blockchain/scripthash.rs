// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blockchain.scripthash.get_history`: the confirmed share chain history
//! of a script, with an optional p2pool `start_height` for paging. Also
//! the scripthash status, which `Session` answers and notifies for
//! `blockchain.scripthash.subscribe`.
//!
//! History covers only the history window (spendable depth, see
//! `p2poolv2_lib::store::script_history`), so every current node returns
//! the same entries.

use crate::methods::{param, store_read_error};
use crate::protocol::{HISTORY_TOO_LARGE, INVALID_PARAMS, RpcError};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::hex::{DisplayHex, FromHex};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::script_history::{ScriptHash, ScriptHistoryEntry};
use p2poolv2_lib::store::writer::StoreError;
use serde_json::{Value, json};
use std::fmt::Write;

/// Entries read per request. A page ends at a height boundary, so it may
/// hold a few more. Reported in `server.features` as
/// `p2pool.scripthash_history_page_size`.
pub(crate) const HISTORY_PAGE_SIZE: usize = 10_000;

/// Longest `"{tx_hash}:{height}:"`: 64 hex characters, two colons and
/// ten digits.
const STATUS_ENTRY_CAPACITY: usize = 76;

/// `blockchain.scripthash.get_history [scripthash, start_height]`.
///
/// Returns `[{"height", "tx_hash"}]` in height then block position order,
/// one entry per confirmed transaction that pays or spends the script.
/// There is no mempool, so no entry has height 0 or -1 for unconfirmed;
/// height 0 is the genesis share.
///
/// `start_height` is a p2pool extension to the standard method. Without
/// it the whole history is returned, or `HISTORY_TOO_LARGE` when that is
/// more than one page. With it, one page from that height is returned; the
/// wallet asks again from the last height plus one until it gets `[]`.
pub(crate) fn scripthash_get_history(
    chain_store_handle: &ChainStoreHandle,
    params: &Value,
) -> Result<Value, RpcError> {
    history_page(chain_store_handle, params, HISTORY_PAGE_SIZE)
}

/// `scripthash_get_history` with the page size as a parameter, so tests
/// can page through a short chain.
fn history_page(
    chain_store_handle: &ChainStoreHandle,
    params: &Value,
    page_size: usize,
) -> Result<Value, RpcError> {
    let scripthash = parse_scripthash(param(params, 0, "scripthash"))?;
    let start_height = parse_start_height(param(params, 1, "start_height"))?;
    let page = chain_store_handle
        .get_script_history(&scripthash, start_height.unwrap_or(0), page_size)
        .map_err(store_read_error)?;
    if page.has_more && start_height.is_none() {
        Err(RpcError::new(
            HISTORY_TOO_LARGE,
            "history too large; pass start_height to fetch it in pages",
        ))
    } else {
        Ok(Value::Array(
            page.entries.iter().map(history_entry_json).collect(),
        ))
    }
}

/// The Electrum status of `scripthash`: the sha256 of
/// `"{tx_hash}:{height}:"` joined over its whole history window, in
/// `get_history` order, as lowercase hex. `None` when the history is
/// empty. There is no mempool, so no unconfirmed part.
///
/// The status is the same size however long the history, so unlike
/// `get_history` it never needs paging by the client.
pub(crate) fn scripthash_status(
    chain_store_handle: &ChainStoreHandle,
    scripthash: &ScriptHash,
) -> Result<Option<String>, StoreError> {
    status_from_pages(chain_store_handle, scripthash, HISTORY_PAGE_SIZE)
}

/// The status of each of `scripthashes` (see `scripthash_status`), in the
/// same order. One failed read fails the whole call, so the caller records
/// every status or none.
pub(crate) fn read_statuses(
    chain_store_handle: &ChainStoreHandle,
    scripthashes: &[ScriptHash],
) -> Result<Vec<(ScriptHash, Option<String>)>, StoreError> {
    scripthashes
        .iter()
        .map(|scripthash| {
            scripthash_status(chain_store_handle, scripthash).map(|status| (*scripthash, status))
        })
        .collect()
}

/// `scripthash_status` with the page size as a parameter, so tests can
/// hash a short chain across pages.
///
/// Reads the history one page at a time and hashes each entry as it goes,
/// so the whole history is never held at once. Each page is its own store
/// read, so a block confirmed between two pages can give a status that
/// matches no single moment; the next tip change computes it again.
fn status_from_pages(
    chain_store_handle: &ChainStoreHandle,
    scripthash: &ScriptHash,
    page_size: usize,
) -> Result<Option<String>, StoreError> {
    let mut engine = sha256::Hash::engine();
    let mut entry_text = String::with_capacity(STATUS_ENTRY_CAPACITY);
    let mut entry_count = 0usize;
    let mut next_start = Some(0);
    while let Some(start_height) = next_start {
        let page = chain_store_handle.get_script_history(scripthash, start_height, page_size)?;
        for entry in &page.entries {
            entry_text.clear();
            // Writing to a String cannot fail.
            let _ = write!(entry_text, "{}:{}:", entry.txid, entry.height);
            engine.input(entry_text.as_bytes());
        }
        entry_count += page.entries.len();
        //* A page ends at a height boundary, so the next one starts at the
        //* height after its last entry.
        next_start = if page.has_more {
            page.entries
                .last()
                .and_then(|entry| entry.height.checked_add(1))
        } else {
            None
        };
    }
    Ok((entry_count > 0).then(|| {
        sha256::Hash::from_engine(engine)
            .to_byte_array()
            .to_lower_hex_string()
    }))
}

/// The Electrum hex form of a store scripthash, the inverse of
/// `parse_scripthash`: reversed byte order, lowercase hex.
pub(crate) fn scripthash_hex(scripthash: &ScriptHash) -> String {
    let mut reversed = *scripthash;
    reversed.reverse();
    reversed.to_lower_hex_string()
}

/// The store's scripthash from the Electrum hex form: 64 hex characters of
/// the script's sha256 in reversed byte order.
pub(crate) fn parse_scripthash(scripthash: Option<&Value>) -> Result<ScriptHash, RpcError> {
    scripthash
        .and_then(Value::as_str)
        .and_then(|scripthash| <ScriptHash as FromHex>::from_hex(scripthash).ok())
        .map(|mut scripthash| {
            scripthash.reverse();
            scripthash
        })
        .ok_or_else(|| {
            RpcError::new(
                INVALID_PARAMS,
                "scripthash must be 64 hex characters of a reversed script sha256",
            )
        })
}

/// Absent or null means no paging.
fn parse_start_height(start_height: Option<&Value>) -> Result<Option<u32>, RpcError> {
    match start_height {
        None | Some(Value::Null) => Ok(None),
        Some(start_height) => start_height
            .as_u64()
            .and_then(|start_height| u32::try_from(start_height).ok())
            .map(Some)
            .ok_or_else(|| {
                RpcError::new(
                    INVALID_PARAMS,
                    "start_height must be an integer from 0 to 4294967295",
                )
            }),
    }
}

fn history_entry_json(entry: &ScriptHistoryEntry) -> Value {
    json!({
        "height": entry.height,
        "tx_hash": entry.txid.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::dispatch;
    use crate::protocol::NOT_SYNCED;
    use crate::test_utils::{build_current_test_chain, electrum_scripthash};
    use p2poolv2_lib::store::script_history::script_hash;
    use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};

    #[tokio::test]
    async fn returns_payouts_in_height_order() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([scripthash]),
        )
        .unwrap();

        assert_eq!(
            history,
            json!([
                {"height": 0, "tx_hash": (blocks[0].transactions[0].0.compute_txid().to_string())},
                {"height": 1, "tx_hash": (blocks[1].transactions[0].0.compute_txid().to_string())},
                {"height": 2, "tx_hash": (blocks[2].transactions[0].0.compute_txid().to_string())},
            ])
        );
    }

    #[tokio::test]
    async fn named_params_with_start_height_return_history_from_that_height() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!({"scripthash": scripthash, "start_height": 2}),
        )
        .unwrap();

        assert_eq!(
            history,
            json!([
                {"height": 2, "tx_hash": (blocks[2].transactions[0].0.compute_txid().to_string())},
            ])
        );
    }

    #[tokio::test]
    async fn null_start_height_returns_whole_history() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 1).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([scripthash, null]),
        )
        .unwrap();

        assert_eq!(
            history,
            json!([
                {"height": 0, "tx_hash": (blocks[0].transactions[0].0.compute_txid().to_string())},
                {"height": 1, "tx_hash": (blocks[1].transactions[0].0.compute_txid().to_string())},
            ])
        );
    }

    #[tokio::test]
    async fn unknown_scripthash_is_empty() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let history = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([([9u8; 32].to_lower_hex_string())]),
        )
        .unwrap();

        assert_eq!(history, json!([]));
    }

    /// The store's internal byte order is not the Electrum form, so it
    /// names some other script.
    #[tokio::test]
    async fn scripthash_in_internal_byte_order_is_empty() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let internal_order = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([internal_order.to_lower_hex_string()]),
        )
        .unwrap();

        assert_eq!(history, json!([]));
    }

    #[tokio::test]
    async fn history_of_exactly_one_page_is_returned_without_start_height() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let history = history_page(&chain_store_handle, &json!([scripthash]), 3).unwrap();

        assert_eq!(history.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn history_over_one_page_without_start_height_is_too_large() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let error = history_page(&chain_store_handle, &json!([scripthash]), 2).unwrap_err();

        assert_eq!(error.code, HISTORY_TOO_LARGE);
    }

    /// The wallet's paging loop: ask from the last height plus one until
    /// the page is empty.
    #[tokio::test]
    async fn pages_walk_history_then_end_with_empty_page() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let first_page = history_page(&chain_store_handle, &json!([scripthash, 0]), 2).unwrap();
        let second_page = history_page(&chain_store_handle, &json!([scripthash, 2]), 2).unwrap();
        let last_page = history_page(&chain_store_handle, &json!([scripthash, 3]), 2).unwrap();

        assert_eq!(
            first_page,
            json!([
                {"height": 0, "tx_hash": (blocks[0].transactions[0].0.compute_txid().to_string())},
                {"height": 1, "tx_hash": (blocks[1].transactions[0].0.compute_txid().to_string())},
            ])
        );
        assert_eq!(
            second_page,
            json!([
                {"height": 2, "tx_hash": (blocks[2].transactions[0].0.compute_txid().to_string())},
            ])
        );
        assert_eq!(last_page, json!([]));
    }

    #[tokio::test]
    async fn short_scripthash_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([([9u8; 31].to_lower_hex_string())]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn non_hex_scripthash_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!(["z".repeat(64)]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn missing_scripthash_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn negative_start_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([([9u8; 32].to_lower_hex_string()), -1]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn string_start_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([([9u8; 32].to_lower_hex_string()), "1"]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn start_height_above_u32_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([([9u8; 32].to_lower_hex_string()), u64::from(u32::MAX) + 1]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn status_is_sha256_of_joined_history_entries() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);
        let joined_entries = format!(
            "{}:0:{}:1:{}:2:",
            blocks[0].transactions[0].0.compute_txid(),
            blocks[1].transactions[0].0.compute_txid(),
            blocks[2].transactions[0].0.compute_txid(),
        );

        let status = scripthash_status(&chain_store_handle, &scripthash).unwrap();

        assert_eq!(
            status,
            Some(
                sha256::Hash::hash(joined_entries.as_bytes())
                    .to_byte_array()
                    .to_lower_hex_string()
            )
        );
    }

    #[tokio::test]
    async fn status_of_unknown_scripthash_is_none() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let status = scripthash_status(&chain_store_handle, &[9u8; 32]).unwrap();

        assert_eq!(status, None);
    }

    /// One entry per page, so the status covers three pages.
    #[tokio::test]
    async fn status_read_across_pages_equals_status_of_one_page() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let scripthash = script_hash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let paged_status = status_from_pages(&chain_store_handle, &scripthash, 1).unwrap();

        assert_eq!(
            paged_status,
            scripthash_status(&chain_store_handle, &scripthash).unwrap()
        );
        assert!(paged_status.is_some());
    }

    #[tokio::test]
    async fn stale_tip_is_not_synced() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let scripthash = electrum_scripthash(&blocks[1].transactions[0].0.output[0].script_pubkey);

        let error = dispatch(
            &chain_store_handle,
            "blockchain.scripthash.get_history",
            &json!([scripthash]),
        )
        .unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
    }
}
