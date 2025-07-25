use ldk_node::bitcoin::Address;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use log::{info, error};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("HTTP request failed: {0}")]
    HttpRequestError(String),
    #[error("Failed to parse response: {0}")]
    ParseError(String),
    #[error("Broadcast failed with status {status}: {message}")]
    BroadcastError { status: reqwest::StatusCode, message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: u32,
    pub block_hash: String,
    pub block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub status: UtxoStatus,
    pub value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecommendedFeeRate {
    pub fastestFee: u64,
    pub halfHourFee: u64,
    pub hourFee: u64,
    pub economyFee: u64,
    pub minimumFee: u64,
}

pub async fn fetch_utxos_for_address(rpc_url: &str, address: &Address) -> Result<Vec<Utxo>, UtilsError> {
    let client = Client::new();
    let url = format!("{}/address/{}/utxo", rpc_url.trim_end_matches('/'), address);
    info!("Fetching UTXOs for address: {}", address);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to fetch UTXOs for address {}: {}", address, e);
            UtilsError::HttpRequestError(e.to_string())
        })?;

    let utxos = response
        .json::<Vec<Utxo>>()
        .await
        .map_err(|e| {
            error!("Failed to parse UTXO response for address {}: {}", address, e);
            UtilsError::ParseError(e.to_string())
        })?;

    info!("Fetched {} UTXOs for address {}", utxos.len(), address);
    Ok(utxos)
}

pub async fn broadcast_trx(rpc_url: &str, trx_raw_hex: &str) -> Result<String, UtilsError> {
    let client = Client::new();
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    info!("Broadcasting transaction: {}", trx_raw_hex);

    let response = client
        .post(&url)
        .body(trx_raw_hex.to_string())
        .header("Content-Type", "text/plain")
        .send()
        .await
        .map_err(|e| {
            error!("Failed to broadcast transaction: {}", e);
            UtilsError::HttpRequestError(e.to_string())
        })?;

    if response.status().is_success() {
        let txid = response
            .text()
            .await
            .map_err(|e| {
                error!("Failed to parse transaction ID: {}", e);
                UtilsError::ParseError(e.to_string())
            })?;
        info!("Successfully broadcast transaction, txid: {}", txid);
        Ok(txid)
    } else {
        let status = response.status();
        let error_message = response
            .text()
            .await
            .map_err(|e| {
                error!("Failed to parse broadcast error response: {}", e);
                UtilsError::ParseError(e.to_string())
            })?;
        error!("Broadcast failed with status {}: {}", status, error_message);
        Err(UtilsError::BroadcastError {
            status,
            message: error_message,
        })
    }
}

/// Fetches the current tip block height from the given RPC URL
pub async fn fetch_tip_block_height(rpc_url: &str) -> Result<u32, UtilsError> {
    let client = Client::new();
    let url = format!("{}/blocks/tip/height", rpc_url.trim_end_matches('/'));
    info!("Fetching tip block height from: {}", url);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to fetch tip block height: {}", e);
            UtilsError::HttpRequestError(e.to_string())
        })?;

    let height_text = response
        .text()
        .await
        .map_err(|e| {
            error!("Failed to parse tip block height response: {}", e);
            UtilsError::ParseError(e.to_string())
        })?;

    let height = height_text
        .trim()
        .parse::<u32>()
        .map_err(|e| {
            error!("Failed to parse block height '{}': {}", height_text, e);
            UtilsError::ParseError(e.to_string())
        })?;

    info!("Fetched tip block height: {}", height);
    Ok(height)
}

pub async fn fetch_recommended_fee_rate(base_url: &str) -> Result<RecommendedFeeRate, UtilsError> {
    let client = Client::new();
    let url = format!("{}/v1/fees/recommended", base_url.trim_end_matches('/'));
    info!("Fetching recommended fee rate from: {}", url);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to fetch recommended fee rate: {}", e);
            UtilsError::HttpRequestError(e.to_string())
        })?;

    let fee_rate = response
        .json::<RecommendedFeeRate>()
        .await
        .map_err(|e| {
            error!("Failed to parse recommended fee rate response: {}", e);
            UtilsError::ParseError(e.to_string())
        })?;

    info!("Fetched recommended fee rate: {:?}", fee_rate);
    Ok(fee_rate)
}