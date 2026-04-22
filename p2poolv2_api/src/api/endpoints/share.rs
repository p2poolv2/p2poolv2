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

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use bitcoin::BlockHash;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::block_tx_metadata::Status;
use p2poolv2_lib::store::dag_store::MAX_UNCLES_DEPTH;
use p2poolv2_lib::store::writer::StoreError;
use p2poolv2_lib::utils::time_provider::format_timestamp;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

/// Query parameters for the /share endpoint.
#[derive(Deserialize)]
pub struct ShareLookupQuery {
    /// Full blockhash of the share to look up.
    pub hash: Option<String>,
    /// Height to look up shares at.
    pub height: Option<u32>,
    /// Include full transaction list in the response.
    pub full: Option<bool>,
}

/// JSON output for the bitcoin block header embedded in a share.
#[derive(Serialize)]
pub struct BitcoinHeaderOutput {
    pub block_hash: String,
    pub version: i32,
    pub prev_blockhash: String,
    pub merkle_root: String,
    pub time: String,
    pub bits: String,
    pub nonce: u32,
}

/// JSON output for a share lookup result.
#[derive(Serialize)]
pub struct ShareLookupOutput {
    pub blockhash: String,
    pub height: Option<u32>,
    pub status: String,
    pub parent: String,
    pub uncles: Vec<String>,
    pub miner_address: String,
    pub merkle_root: String,
    pub bits: String,
    pub time: String,
    pub bitcoin_header: BitcoinHeaderOutput,
    pub template_merkle_branches_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<String>>,
}

/// Format a Status enum value as a human-readable string.
fn format_status(status: &Status) -> &'static str {
    match status {
        Status::Pending => "Pending",
        Status::HeaderValid => "HeaderValid",
        Status::Invalid => "Invalid",
        Status::Candidate => "Candidate",
        Status::BlockValid => "BlockValid",
        Status::Confirmed => "Confirmed",
    }
}

/// Build the JSON output for a single share identified by its blockhash.
fn build_share_output(
    chain_store_handle: &ChainStoreHandle,
    blockhash: &BlockHash,
    full: bool,
) -> Result<ShareLookupOutput, ApiError> {
    let store = chain_store_handle.store_handle().store();

    let share_header = store
        .get_share_header(blockhash)
        .map_err(|error| ApiError::ServerError(format!("Store error: {error}")))?
        .ok_or_else(|| ApiError::NotFound(format!("Share not found for blockhash {blockhash}")))?;

    let metadata = match chain_store_handle.get_block_metadata(blockhash) {
        Ok(metadata) => Some(metadata),
        Err(StoreError::NotFound(_)) => None,
        Err(error) => {
            return Err(ApiError::ServerError(format!(
                "Failed to get metadata for {blockhash}: {error}"
            )));
        }
    };

    let height = metadata
        .as_ref()
        .and_then(|metadata| metadata.expected_height);
    let status = metadata
        .as_ref()
        .map(|metadata| format_status(&metadata.status))
        .unwrap_or("Unknown");

    let bitcoin_header = &share_header.bitcoin_header;
    let bitcoin_header_output = BitcoinHeaderOutput {
        block_hash: bitcoin_header.block_hash().to_string(),
        version: bitcoin_header.version.to_consensus(),
        prev_blockhash: bitcoin_header.prev_blockhash.to_string(),
        merkle_root: bitcoin_header.merkle_root.to_string(),
        time: format_timestamp(bitcoin_header.time as u64),
        bits: format!("{:#x}", bitcoin_header.bits.to_consensus()),
        nonce: bitcoin_header.nonce,
    };

    let template_merkle_branches_count = store
        .get_template_merkle_branches(blockhash)
        .unwrap_or_default()
        .len();

    let transaction_ids = if full {
        let share_block = chain_store_handle.get_share(blockhash).ok_or_else(|| {
            ApiError::NotFound(format!("Full share not found for blockhash {blockhash}"))
        })?;

        let txids: Vec<String> = share_block
            .transactions
            .iter()
            .map(|transaction| transaction.compute_txid().to_string())
            .collect();

        Some(txids)
    } else {
        None
    };

    Ok(ShareLookupOutput {
        blockhash: blockhash.to_string(),
        height,
        status: status.to_string(),
        parent: share_header.prev_share_blockhash.to_string(),
        uncles: share_header
            .uncles
            .iter()
            .map(|uncle| uncle.to_string())
            .collect(),
        miner_address: share_header.miner_bitcoin_address.to_string(),
        merkle_root: share_header.merkle_root.to_string(),
        bits: format!("{:#x}", share_header.bits.to_consensus()),
        time: format_timestamp(share_header.time as u64),
        bitcoin_header: bitcoin_header_output,
        template_merkle_branches_count,
        transactions: transaction_ids,
    })
}

/// Look up shares by hash or height.
///
/// Returns a JSON array of share details. Hash lookup returns a single-element
/// array. Height lookup returns all shares (confirmed and uncles) at that height.
pub(crate) async fn share(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ShareLookupQuery>,
) -> Result<Json<Vec<ShareLookupOutput>>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;
    let full = query.full.unwrap_or(false);

    match (query.hash, query.height) {
        (Some(hash_string), None) => {
            let blockhash = BlockHash::from_str(&hash_string).map_err(|error| {
                ApiError::BadRequest(format!("Invalid blockhash '{hash_string}': {error}"))
            })?;
            let output = build_share_output(chain_store_handle, &blockhash, full)?;
            Ok(Json(vec![output]))
        }
        (None, Some(height)) => lookup_by_height(chain_store_handle, height, full),
        _ => Err(ApiError::BadRequest(
            "Exactly one of hash or height must be provided".to_string(),
        )),
    }
}

/// Look up the confirmed share at a given height and any uncles at that
/// height, then return as a JSON array.
fn lookup_by_height(
    chain_store_handle: &ChainStoreHandle,
    height: u32,
    full: bool,
) -> Result<Json<Vec<ShareLookupOutput>>, ApiError> {
    let store = chain_store_handle.store_handle().store();
    let mut blockhashes = Vec::with_capacity(4);

    if let Ok(confirmed_hash) = chain_store_handle.get_confirmed_at_height(height) {
        blockhashes.push(confirmed_hash);
    }

    let upper_height = height.saturating_add(MAX_UNCLES_DEPTH as u32);
    if let Some(start_height) = height.checked_add(1) {
        for scan_height in start_height..=upper_height {
            let Ok(scan_hash) = chain_store_handle.get_confirmed_at_height(scan_height) else {
                continue;
            };
            let Ok(Some(header)) = store.get_share_header(&scan_hash) else {
                continue;
            };
            for uncle_hash in &header.uncles {
                if blockhashes.contains(uncle_hash) {
                    continue;
                }
                let uncle_height = match chain_store_handle.get_block_metadata(uncle_hash) {
                    Ok(metadata) => metadata.expected_height,
                    Err(StoreError::NotFound(_)) => None,
                    Err(error) => {
                        return Err(ApiError::ServerError(format!(
                            "Failed to get metadata for uncle {uncle_hash}: {error}"
                        )));
                    }
                };
                if uncle_height == Some(height) {
                    blockhashes.push(*uncle_hash);
                }
            }
        }
    }

    if blockhashes.is_empty() {
        return Err(ApiError::NotFound(format!(
            "No shares found at height {height}"
        )));
    }

    let mut outputs = Vec::with_capacity(blockhashes.len());
    for blockhash in &blockhashes {
        outputs.push(build_share_output(chain_store_handle, blockhash, full)?);
    }
    Ok(Json(outputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::{Query, State};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::store::block_tx_metadata::Status;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::{genesis_for_tests, setup_test_chain_store_handle};

    async fn build_test_state(node_handle: NodeHandle) -> (Arc<AppState>, tempfile::TempDir) {
        let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let metrics_temp = tempfile::tempdir().unwrap();
        let metrics_handle =
            metrics::start_metrics(metrics_temp.path().to_str().unwrap().to_string())
                .await
                .unwrap();
        let tracker_handle = start_tracker_actor();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 0,
                network: bitcoin::Network::Signet,
                cors_allowed: false,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle,
            node_handle,
            monitoring_event_sender: create_monitoring_event_channel().0,
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[test]
    fn test_format_status_all_variants() {
        assert_eq!(format_status(&Status::Pending), "Pending");
        assert_eq!(format_status(&Status::HeaderValid), "HeaderValid");
        assert_eq!(format_status(&Status::Invalid), "Invalid");
        assert_eq!(format_status(&Status::Candidate), "Candidate");
        assert_eq!(format_status(&Status::BlockValid), "BlockValid");
        assert_eq!(format_status(&Status::Confirmed), "Confirmed");
    }

    #[tokio::test]
    async fn test_share_requires_hash_or_height() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(ShareLookupQuery {
            hash: None,
            height: None,
            full: None,
        });

        let result = share(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_rejects_both_hash_and_height() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(ShareLookupQuery {
            hash: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            height: Some(0),
            full: None,
        });

        let result = share(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_invalid_blockhash() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(ShareLookupQuery {
            hash: Some("not-a-valid-hash".to_string()),
            height: None,
            full: None,
        });

        let result = share(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_not_found_by_hash() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(ShareLookupQuery {
            hash: Some(
                "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            ),
            height: None,
            full: None,
        });

        let result = share(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_lookup_genesis_by_hash() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        let genesis_hash = genesis.block_hash().to_string();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(ShareLookupQuery {
            hash: Some(genesis_hash.clone()),
            height: None,
            full: Some(false),
        });

        let result = share(State(state), query).await;
        assert!(result.is_ok());

        let output = &result.unwrap().0;
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].blockhash, genesis_hash);
    }

    #[tokio::test]
    async fn test_share_lookup_genesis_by_height() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        let genesis_hash = genesis.block_hash().to_string();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(ShareLookupQuery {
            hash: None,
            height: Some(0),
            full: Some(false),
        });

        let result = share(State(state), query).await;
        assert!(result.is_ok());

        let output = &result.unwrap().0;
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].blockhash, genesis_hash);
    }

    #[tokio::test]
    async fn test_share_not_found_by_height() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(ShareLookupQuery {
            hash: None,
            height: Some(999),
            full: None,
        });

        let result = share(State(state), query).await;
        assert!(result.is_err());
    }
}
