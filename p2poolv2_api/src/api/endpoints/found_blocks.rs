// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{Json, extract::State};
use p2poolv2_lib::address::bch_share::BchShareNetwork;
use p2poolv2_lib::address_display::payout_address_string;
use p2poolv2_lib::store::found_block::FoundBlock;
use serde::Serialize;
use std::str::FromStr;
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

impl FoundBlockResponse {
    /// The store keeps the payout address in Bitcoin's base58 spelling; on a
    /// Bitcoin Cash node it is shown as CashAddr, as everywhere else.
    fn new(block: &FoundBlock, cash_network: Option<BchShareNetwork>) -> Self {
        Self {
            bitcoin_height: block.bitcoin_height,
            bitcoin_blockhash: block.bitcoin_blockhash.to_string(),
            share_blockhash: block.share_blockhash.to_string(),
            bitcoin_time: block.bitcoin_time,
            miner_bitcoin_address: match bitcoin::Address::from_str(&block.miner_bitcoin_address) {
                Ok(address) => payout_address_string(&address.assume_checked(), cash_network),
                Err(_) => block.miner_bitcoin_address.clone(),
            },
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
    let cash_network = state.app_config.cash_network;
    let mut response: Vec<FoundBlockResponse> = found_blocks
        .iter()
        .map(|block| FoundBlockResponse::new(block, cash_network))
        .collect();
    response.sort_by_key(|block| std::cmp::Reverse(block.bitcoin_height));
    Ok(Json(response))
}
