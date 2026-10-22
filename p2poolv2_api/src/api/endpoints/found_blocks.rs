// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{Json, extract::State};
use p2poolv2_lib::store::found_block::FoundBlock;
use serde::Serialize;
use std::sync::Arc;

/// A bitcoin block found by the pool, as JSON.
#[derive(Serialize, Debug, PartialEq)]
pub struct FoundBlockResponse {
    pub bitcoin_height: u64,
    pub bitcoin_blockhash: String,
    pub share_blockhash: String,
    pub bitcoin_time: u32,
    pub miner_bitcoin_address: String,
}

impl From<&FoundBlock> for FoundBlockResponse {
    fn from(block: &FoundBlock) -> Self {
        Self {
            bitcoin_height: block.bitcoin_height,
            bitcoin_blockhash: block.bitcoin_blockhash.to_string(),
            share_blockhash: block.share_blockhash.to_string(),
            bitcoin_time: block.bitcoin_time,
            miner_bitcoin_address: block.miner_bitcoin_address.clone(),
        }
    }
}

/// Returns the bitcoin blocks found by the pool, newest first. The same data
/// `/metrics` exposes as `bitcoin_block_found_time_seconds`, as JSON.
pub(crate) async fn found_blocks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<FoundBlockResponse>>, ApiError> {
    let found_blocks = state
        .chain_store_handle
        .get_found_blocks()
        .map_err(|error| ApiError::ServerError(format!("Failed to read found blocks: {error}")))?;
    let mut response: Vec<FoundBlockResponse> =
        found_blocks.iter().map(FoundBlockResponse::from).collect();
    response.sort_by_key(|block| std::cmp::Reverse(block.bitcoin_height));
    Ok(Json(response))
}
