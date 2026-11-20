// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use p2poolv2_lib::store::found_block::FoundBlock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Maximum number of found blocks that can be requested in a single query.
const MAX_NUM_FOUND_BLOCKS_IN_RESPONSE: u32 = 100;

/// Query parameters for the /found_blocks endpoint.
#[derive(Deserialize)]
pub struct FoundBlocksQuery {
    /// Number of most recent found blocks to return. Defaults to 10.
    pub num: Option<u32>,
}

/// A bitcoin block found by the pool, as returned by /found_blocks.
#[derive(Serialize)]
pub struct FoundBlockResponse {
    pub bitcoin_height: u64,
    pub bitcoin_blockhash: String,
    pub share_blockhash: String,
    pub bitcoin_time: u32,
    pub miner_bitcoin_address: String,
}

impl From<&FoundBlock> for FoundBlockResponse {
    fn from(found_block: &FoundBlock) -> Self {
        FoundBlockResponse {
            bitcoin_height: found_block.bitcoin_height,
            bitcoin_blockhash: found_block.bitcoin_blockhash.to_string(),
            share_blockhash: found_block.share_blockhash.to_string(),
            bitcoin_time: found_block.bitcoin_time,
            miner_bitcoin_address: found_block.miner_bitcoin_address.clone(),
        }
    }
}

/// JSON response for the /found_blocks endpoint.
#[derive(Serialize)]
pub struct FoundBlocksResponse {
    /// Bitcoin chain name as bitcoind spells it, so clients can pick a
    /// block explorer.
    pub network: &'static str,
    /// Total number of bitcoin blocks found by the pool.
    pub total: usize,
    /// The most recent found blocks, highest bitcoin height first.
    pub found_blocks: Vec<FoundBlockResponse>,
}

/// Returns the most recent bitcoin blocks found by the pool.
///
/// Found blocks are recorded when the share carrying them is confirmed
/// and are never deleted, so the list includes blocks that may since
/// have been orphaned on the bitcoin chain.
pub(crate) async fn found_blocks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FoundBlocksQuery>,
) -> Result<Json<FoundBlocksResponse>, ApiError> {
    let num = query.num.unwrap_or(10);

    if !(1..=MAX_NUM_FOUND_BLOCKS_IN_RESPONSE).contains(&num) {
        return Err(ApiError::BadRequest(format!(
            "num must be between 1 and {MAX_NUM_FOUND_BLOCKS_IN_RESPONSE}, got {num}"
        )));
    }

    let (total, latest_found_blocks) = state
        .chain_store_handle
        .get_latest_found_blocks(num as usize)
        .map_err(|error| ApiError::ServerError(format!("Failed to get found blocks: {error}")))?;

    let found_blocks = latest_found_blocks
        .iter()
        .map(FoundBlockResponse::from)
        .collect();

    Ok(Json(FoundBlocksResponse {
        network: state.app_config.chain.as_str(),
        total,
        found_blocks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::{Query, State};
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::config::Chain;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::{TestShareBlockBuilder, setup_test_chain_store_handle};

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
                chain: Chain::Signet,
                cors_allowed: false,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle,
            node_handle,
            monitoring_event_sender: create_monitoring_event_channel(),
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_found_blocks_rejects_num_zero() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = FoundBlocksQuery { num: Some(0) };
        let result = found_blocks(State(state), Query(query)).await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn test_found_blocks_rejects_num_above_max() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = FoundBlocksQuery {
            num: Some(MAX_NUM_FOUND_BLOCKS_IN_RESPONSE + 1),
        };
        let result = found_blocks(State(state), Query(query)).await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn test_found_blocks_empty_store_returns_no_blocks() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = FoundBlocksQuery { num: None };
        let response = found_blocks(State(state), Query(query)).await.unwrap().0;

        assert_eq!(response.network, "signet");
        assert_eq!(response.total, 0);
        assert!(response.found_blocks.is_empty());
    }

    #[tokio::test]
    async fn test_found_blocks_returns_newest_first_limited_by_num() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;
        let genesis = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // The regtest genesis header meets its own target, so confirming
        // these shares records found bitcoin blocks. The FoundBlocks key
        // includes the bitcoin height, so distinct heights give two entries.
        let mut first_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(0xe9695792)
            .build();
        first_share.header.bitcoin_header = genesis_block(Network::Regtest).header;
        first_share.header.bitcoin_height = 100;
        state
            .chain_store_handle
            .add_share_block_and_organise_header(first_share.clone())
            .await
            .unwrap();
        state
            .chain_store_handle
            .mark_block_valid(first_share.block_hash())
            .await
            .unwrap();
        state.chain_store_handle.organise_block().await.unwrap();

        let mut second_share = TestShareBlockBuilder::new()
            .prev_share_blockhash(first_share.block_hash().to_string())
            .nonce(0xe9695793)
            .build();
        //* A distinct bitcoin header, so blockhash and time tell the
        //* newest entry apart from the first. Nonce 0 at this time
        //* meets the regtest target.
        let mut second_bitcoin_header = genesis_block(Network::Regtest).header;
        second_bitcoin_header.time += 600;
        second_bitcoin_header.nonce = 0;
        second_share.header.bitcoin_header = second_bitcoin_header;
        second_share.header.bitcoin_height = 101;
        assert!(second_share.header.meets_bitcoin_difficulty());
        assert_ne!(
            second_bitcoin_header.block_hash(),
            first_share.header.bitcoin_header.block_hash()
        );
        state
            .chain_store_handle
            .add_share_block_and_organise_header(second_share.clone())
            .await
            .unwrap();
        state
            .chain_store_handle
            .mark_block_valid(second_share.block_hash())
            .await
            .unwrap();
        state.chain_store_handle.organise_block().await.unwrap();

        let query = FoundBlocksQuery { num: Some(1) };
        let response = found_blocks(State(state), Query(query)).await.unwrap().0;

        assert_eq!(response.total, 2);
        assert_eq!(response.found_blocks.len(), 1);
        let newest = &response.found_blocks[0];
        assert_eq!(newest.bitcoin_height, 101);
        assert_eq!(
            newest.bitcoin_blockhash,
            second_share.header.bitcoin_header.block_hash().to_string()
        );
        assert_eq!(
            newest.share_blockhash,
            second_share.block_hash().to_string()
        );
        assert_eq!(newest.bitcoin_time, second_share.header.bitcoin_header.time);
        assert_eq!(
            newest.miner_bitcoin_address,
            second_share.header.miner_bitcoin_address.to_string()
        );
    }
}
