use ldk_node::bitcoin::Address;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::io::Error;

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

pub async fn fetch_utxos_for_address(rpc_url: &str, address: &Address) -> Result<Vec<Utxo>, Error> {
    let client = Client::new();
    let url = format!("{}/address/{}/utxo", rpc_url.trim_end_matches('/'), address);

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let utxos = response
        .json::<Vec<Utxo>>()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(utxos)
}

pub async fn broadcast_trx(rpc_url: &str, trx_raw_hex: &str) -> Result<String, Error> {
    let client = Client::new();
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));

    let response = client
        .post(url)
        .body(trx_raw_hex.to_string())
        .header("Content-Type", "text/plain")
        .send()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if response.status().is_success() {
        let txid = response
            .text()
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(txid)
    } else {
        let status = response.status();
        let error_message = response
            .text()
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Err(Error::new(
            std::io::ErrorKind::Other,
            format!("Broadcast failed with status {}: {}", status, error_message),
        ))
    }
}

/// Fetches the current tip block height from the given RPC URL
pub async fn fetch_tip_block_height(rpc_url: &str) -> Result<u32, Error> {
    let client = Client::new();
    let url = format!("{}/blocks/tip/height", rpc_url.trim_end_matches('/'));

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let height_text = response
        .text()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let height = height_text
        .trim()
        .parse::<u32>()
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(height)
}

pub async fn fetch_recommended_fee_rate(base_url: &str) -> Result<RecommendedFeeRate, Error> {
    let client = Client::new();
    let url = format!("{}/v1/fees/recommended", base_url.trim_end_matches('/'));

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let fee_rate = response
        .json::<RecommendedFeeRate>()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(fee_rate)
}
