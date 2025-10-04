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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Response model for shares endpoint
#[derive(Debug, Serialize)]
pub struct ShareResponse {
    pub difficulty: u64,
    pub btcaddress: String,
    pub workername: String,
    pub timestamp: u64,
    pub formatted_time: String,
}

/// Response model for block template endpoint
#[derive(Debug, Serialize)]
pub struct BlockTemplateResponse {
    pub version: i32,
    pub rules: Vec<String>,
    pub vbavailable: HashMap<String, i32>,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<TemplateTransactionResponse>,
    pub coinbaseaux: HashMap<String, String>,
    pub coinbasevalue: u64,
    pub longpollid: String,
    pub target: String,
    pub mintime: u32,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u32,
    pub sizelimit: u32,
    pub weightlimit: u32,
    pub curtime: u32,
    pub bits: String,
    pub height: u32,
    pub default_witness_commitment: Option<String>,
}

/// Response model for template transaction
#[derive(Debug, Serialize)]
pub struct TemplateTransactionResponse {
    pub data: String,
    pub txid: String,
    pub hash: String,
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u32,
    pub weight: u32,
}

/// Response model for PPLNS distribution endpoint
#[derive(Debug, Serialize)]
pub struct PplnsDistributionResponse {
    pub total_difficulty: f64,
    pub total_amount_sat: u64,
    pub distribution: Vec<DistributionEntry>,
    pub timestamp: u64,
}

/// Individual distribution entry
#[derive(Debug, Serialize)]
pub struct DistributionEntry {
    pub address: String,
    pub amount_sat: u64,
    pub percentage: f64,
}

/// Query parameters for shares endpoint
#[derive(Debug, Deserialize)]
pub struct SharesQuery {
    pub limit: Option<usize>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
}

/// Error response model
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Shared state for API handlers
#[derive(Clone)]
pub struct ApiState {
    pub chain_store: std::sync::Arc<crate::shares::chain::chain_store::ChainStore>,
    pub current_template: std::sync::Arc<
        tokio::sync::RwLock<Option<crate::stratum::work::block_template::BlockTemplate>>,
    >,
    pub config: crate::config::StratumConfig<crate::config::Parsed>,
}
