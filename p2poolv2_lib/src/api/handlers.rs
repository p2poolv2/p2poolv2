// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use super::models::{
    ApiState, BlockTemplateResponse, DistributionEntry, ErrorResponse, PplnsDistributionResponse,
    ShareResponse, SharesQuery, TemplateTransactionResponse,
};
use crate::accounting::OutputPair;
use crate::accounting::simple_pplns::payout::Payout;
use crate::shares::chain::chain_store::ChainStore;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use bitcoin::Amount;
use rocksdb::{DB, Options};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{error, info};
// Conditional imports for ChainStore and MockChainStore
#[cfg(test)]
use crate::shares::chain::chain_store::MockChainStore;

/// Wrapper to call get_output_distribution with correct type in test and non-test builds
#[cfg(test)]
async fn call_output_distribution(
    payout: &Payout,
    store: &Arc<ChainStore>, // actually MockChainStore due to mockall_double
    difficulty: f64,
    amount: bitcoin::Amount,
    config: &crate::config::StratumConfig<crate::config::Parsed>,
) -> Result<Vec<OutputPair>, Box<dyn std::error::Error + Send + Sync>> {
    let store = unsafe { &*(store as *const Arc<ChainStore> as *const Arc<MockChainStore>) };
    payout
        .get_output_distribution(store, difficulty, amount, config)
        .await
}

#[cfg(not(test))]
async fn call_output_distribution(
    payout: &Payout,
    store: &Arc<ChainStore>,
    difficulty: f64,
    amount: bitcoin::Amount,
    config: &crate::config::StratumConfig<crate::config::Parsed>,
) -> Result<Vec<OutputPair>, Box<dyn std::error::Error + Send + Sync>> {
    payout
        .get_output_distribution(store, difficulty, amount, config)
        .await
}

/// Open a secondary read-only RocksDB for the API
fn open_secondary_db(
    path: &str,
    secondary_path: &str,
) -> Result<Arc<DB>, (StatusCode, Json<ErrorResponse>)> {
    let mut opts = Options::default();
    opts.create_if_missing(false);
    opts.create_missing_column_families(true);
    let cf_names = vec!["default", "share"];
    DB::open_cf_as_secondary(&opts, path, secondary_path, &cf_names)
        .map(Arc::new)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "DB error".into(),
                    message: format!("Failed to open secondary DB: {}", e),
                }),
            )
        })
}

/// Handler for getting shares
pub async fn get_shares(
    Query(params): Query<SharesQuery>,
) -> Result<Json<Vec<ShareResponse>>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting shares with params: {:?}", params);

    let db = open_secondary_db("./store.db", "/tmp/rocksdb_api_secondary")?;
    let cf = db.cf_handle("share").ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Missing 'share' CF".into(),
                message: "Column family 'share' not found in DB".into(),
            }),
        )
    })?;

    let mut shares = Vec::new();
    for (_key, value) in db.iterator_cf(cf, rocksdb::IteratorMode::Start).flatten() {
        if shares.len() >= params.limit.unwrap_or(100) {
            break;
        }
        shares.push(ShareResponse {
            difficulty: 0,
            btcaddress: hex::encode(&value),
            workername: "".into(),
            timestamp: 0,
            formatted_time: "".into(),
        });
    }

    Ok(Json(shares))
}

/// Handler for getting current block template
pub async fn get_block_template(
    State(state): State<ApiState>,
) -> Result<Json<BlockTemplateResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting current block template");

    let template_guard = state.current_template.read().await;
    let template = template_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "No template available".into(),
                message: "Block template is not available".into(),
            }),
        )
    })?;

    let transaction_responses: Vec<TemplateTransactionResponse> = template
        .transactions
        .iter()
        .map(|tx| TemplateTransactionResponse {
            data: tx.data.clone(),
            txid: tx.txid.clone(),
            hash: tx.hash.clone(),
            depends: tx.depends.clone(),
            fee: tx.fee,
            sigops: tx.sigops,
            weight: tx.weight,
        })
        .collect();

    let response = BlockTemplateResponse {
        version: template.version,
        rules: template.rules.clone(),
        vbavailable: template.vbavailable.clone(),
        vbrequired: template.vbrequired,
        previousblockhash: template.previousblockhash.clone(),
        transactions: transaction_responses,
        coinbaseaux: template.coinbaseaux.clone(),
        coinbasevalue: template.coinbasevalue,
        longpollid: template.longpollid.clone(),
        target: template.target.clone(),
        mintime: template.mintime,
        mutable: template.mutable.clone(),
        noncerange: template.noncerange.clone(),
        sigoplimit: template.sigoplimit,
        sizelimit: template.sizelimit,
        weightlimit: template.weightlimit,
        curtime: template.curtime,
        bits: template.bits.clone(),
        height: template.height,
        default_witness_commitment: template.default_witness_commitment.clone(),
    };

    Ok(Json(response))
}

/// Handler for getting current PPLNS distribution
pub async fn get_pplns_distribution(
    State(state): State<ApiState>,
) -> Result<Json<PplnsDistributionResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting current PPLNS distribution");

    let template_guard = state.current_template.read().await;
    let template = template_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "No template available".into(),
                message: "Block template is not available".into(),
            }),
        )
    })?;

    const DEFAULT_STEP_SIZE_SECONDS: u64 = 24 * 60 * 60; // 1 day
    let payout = Payout::new(DEFAULT_STEP_SIZE_SECONDS);
    let total_amount = Amount::from_sat(template.coinbasevalue);

    let compact_target =
        bitcoin::pow::CompactTarget::from_unprefixed_hex(&template.bits).map_err(|e| {
            error!("Failed to parse compact target: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Invalid target".into(),
                    message: format!("Failed to parse compact target: {}", e),
                }),
            )
        })?;

    let required_target = bitcoin::Target::from_compact(compact_target);
    let total_difficulty = required_target.difficulty_float() * state.config.difficulty_multiplier;

    let distribution = call_output_distribution(
        &payout,
        &state.chain_store,
        total_difficulty,
        total_amount,
        &state.config,
    )
    .await
    .map_err(|e| {
        error!("Failed to get output distribution: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Distribution calculation failed".into(),
                message: format!("Failed to calculate PPLNS distribution: {}", e),
            }),
        )
    })?;

    let total_amount_sat = total_amount.to_sat();
    let distribution_entries: Vec<DistributionEntry> = distribution
        .iter()
        .map(|entry| DistributionEntry {
            address: entry.address.to_string(),
            amount_sat: entry.amount.to_sat(),
            percentage: if total_amount_sat > 0 {
                (entry.amount.to_sat() as f64 / total_amount_sat as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let response = PplnsDistributionResponse {
        total_difficulty,
        total_amount_sat,
        distribution: distribution_entries,
        timestamp: current_time,
    };

    Ok(Json(response))
}

/// Handler for health check
pub async fn health_check()
-> Result<Json<HashMap<String, String>>, (StatusCode, Json<ErrorResponse>)> {
    let mut response = HashMap::new();
    response.insert("status".to_string(), "healthy".to_string());
    response.insert("service".to_string(), "p2poolv2-api".to_string());
    Ok(Json(response))
}
