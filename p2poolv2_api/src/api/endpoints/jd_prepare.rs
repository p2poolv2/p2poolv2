// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read-only preparation against this node's verified PPLNS snapshot. The
//! external miner keeps its transaction set and uses the resulting coinbase
//! in the standard SV2 Job Declaration messages on the public pool's listener.

use crate::api::{error::ApiError, server::AppState};
use axum::{Json, extract::State};
use p2poolv2_lib::address::{bch_share, share_owner::ShareOwner};
use p2poolv2_lib::config::{BitcoinCashNetwork, Chain, parse_payout_address};
use p2poolv2_lib::shares::{
    bch_coinbase::BchCoinbase, merge_mining::MergeMiningCommitment,
    share_commitment::ShareCommitment,
};
use p2poolv2_lib::stratum::sv2::preparation::prepare_coinbase;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrepareRequest {
    version: u8,
    token: String,
    payout: String,
    share_owner: String,
    height: u32,
    nbits: u32,
    previous_hash: String,
    coinbase_value: u64,
    script_prefix: String,
    auxiliary: MergeMiningCommitment,
}

#[derive(Serialize)]
pub(crate) struct PrepareResponse {
    version: u8,
    token_hash: String,
    anchor: String,
    height: u32,
    coinbase_value: u64,
    coinbase_prefix: String,
    coinbase_suffix: String,
    extranonce_size: u8,
}

pub(crate) async fn prepare(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ApiError> {
    if request.version != 1
        || request.token.len() > 510
        || request.payout.len() > 120
        || request.share_owner.len() > 120
        || request.script_prefix.len() > 176
    {
        return Err(ApiError::BadRequest(
            "unsupported or oversized preparation request".into(),
        ));
    }
    let cash_network = state
        .app_config
        .cash_network
        .ok_or_else(|| ApiError::BadRequest("BCH preparation requires a BCH share chain".into()))?;
    let network = match cash_network {
        bch_share::BchShareNetwork::Mainnet => BitcoinCashNetwork::Mainnet,
        bch_share::BchShareNetwork::Chipnet => BitcoinCashNetwork::Chipnet,
        bch_share::BchShareNetwork::Regtest => BitcoinCashNetwork::Regtest,
    };
    let invalid = |_| ApiError::BadRequest("invalid BCH identity or token".into());
    let payout = parse_payout_address(
        &request.payout,
        Chain::BitcoinCash,
        state.app_config.network,
        Some(network),
    )
    .map_err(invalid)?;
    let owner = bch_share::parse(&request.share_owner, cash_network)
        .map_err(|_| ApiError::BadRequest("invalid share owner for this network".into()))?;
    let token = hex::decode(&request.token)
        .map_err(|_| ApiError::BadRequest("invalid token encoding".into()))?;
    let commitment =
        ShareCommitment::from_mining_job_token(&token, payout, ShareOwner::CashP2pkh(owner.hash))
            .map_err(|_| ApiError::BadRequest("invalid BCH job token".into()))?;
    let anchor = commitment.prev_share_blockhash;
    let current = state
        .chain_store_handle
        .get_mining_base()
        .map_err(|_| ApiError::ServiceUnavailable("share-chain anchor unavailable".into()))?;
    if anchor != current {
        return Err(ApiError::ServiceUnavailable(
            "preparation node and pool token anchors differ; retry after synchronization".into(),
        ));
    }
    let current_job = state
        .tracker_handle
        .get_job(state.tracker_handle.get_latest_job_id())
        .ok_or_else(|| ApiError::ServiceUnavailable("BCH template unavailable".into()))?;
    if current_job.blocktemplate.bits != format!("{:08x}", request.nbits)
        || current_job.blocktemplate.height != request.height
        || current_job.blocktemplate.previousblockhash != request.previous_hash
    {
        return Err(ApiError::ServiceUnavailable(
            "preparation and selected BCH tips differ".into(),
        ));
    }
    let window = state
        .pplns_window
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("verified PPLNS window unavailable".into()))?;
    let weights = window
        .preparation_weights(anchor, request.nbits, &state.chain_store_handle)
        .await?;
    let descriptor = BchCoinbase {
        prefix: hex::decode(&request.script_prefix)
            .map_err(|_| ApiError::BadRequest("invalid script prefix".into()))?,
        merge_mining: request.auxiliary,
    };
    let prepared = prepare_coinbase(
        &token,
        commitment,
        &weights,
        request.coinbase_value,
        request.height,
        descriptor,
    )
    .map_err(ApiError::BadRequest)?;
    Ok(Json(PrepareResponse {
        version: 1,
        token_hash: hex::encode(prepared.token_hash),
        anchor: anchor.to_string(),
        height: request.height,
        coinbase_value: request.coinbase_value,
        coinbase_prefix: hex::encode(prepared.prefix),
        coinbase_suffix: hex::encode(prepared.suffix),
        extranonce_size: 12,
    }))
}
