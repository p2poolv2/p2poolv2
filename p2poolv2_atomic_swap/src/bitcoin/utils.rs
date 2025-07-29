use ldk_node::bitcoin::Address;
use log::{error, info};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("HTTP request failed: {0}")]
    HttpRequestError(String),
    #[error("Failed to parse response: {0}")]
    ParseError(String),
    #[error("Broadcast failed with status {status}: {message}")]
    BroadcastError {
        status: reqwest::StatusCode,
        message: String,
    },
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
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

pub async fn fetch_utxos_for_address(
    rpc_url: &str,
    address: &Address,
) -> Result<Vec<Utxo>, UtilsError> {
    let client = Client::new();
    let url = format!("{}/address/{}/utxo", rpc_url.trim_end_matches('/'), address);
    info!("Fetching UTXOs for address: {}", address);

    let response = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch UTXOs for address {}: {}", address, e);
        UtilsError::HttpRequestError(e.to_string())
    })?;

    let utxos = response.json::<Vec<Utxo>>().await.map_err(|e| {
        error!(
            "Failed to parse UTXO response for address {}: {}",
            address, e
        );
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
        let txid = response.text().await.map_err(|e| {
            error!("Failed to parse transaction ID: {}", e);
            UtilsError::ParseError(e.to_string())
        })?;
        let txid = txid.trim(); // Trim whitespace or newlines
        if txid.is_empty() || txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
            error!("Invalid transaction ID: '{}'", txid);
            return Err(UtilsError::ParseError(format!(
                "Invalid transaction ID: '{}'",
                txid
            )));
        }
        info!("Successfully broadcast transaction, txid: {}", txid);
        Ok(txid.to_string())
    } else {
        let status = response.status();
        let error_message = response.text().await.map_err(|e| {
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

    let response = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch tip block height: {}", e);
        UtilsError::HttpRequestError(e.to_string())
    })?;

    let height_text = response.text().await.map_err(|e| {
        error!("Failed to parse tip block height response: {}", e);
        UtilsError::ParseError(e.to_string())
    })?;

    let height = height_text.trim().parse::<u32>().map_err(|e| {
        error!("Failed to parse block height '{}': {}", height_text, e);
        UtilsError::ParseError(e.to_string())
    })?;

    info!("Fetched tip block height: {}", height);
    Ok(height)
}
#[allow(dead_code)]
pub async fn fetch_recommended_fee_rate(base_url: &str) -> Result<RecommendedFeeRate, UtilsError> {
    let client = Client::new();
    let url = format!("{}/v1/fees/recommended", base_url.trim_end_matches('/'));
    info!("Fetching recommended fee rate from: {}", url);

    let response = client.get(&url).send().await.map_err(|e| {
        error!("Failed to fetch recommended fee rate: {}", e);
        UtilsError::HttpRequestError(e.to_string())
    })?;

    let fee_rate = response.json::<RecommendedFeeRate>().await.map_err(|e| {
        error!("Failed to parse recommended fee rate response: {}", e);
        UtilsError::ParseError(e.to_string())
    })?;

    info!("Fetched recommended fee rate: {:?}", fee_rate);
    Ok(fee_rate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use ldk_node::bitcoin::{Address, Network};
    use log::info;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::str::FromStr;

    // Helper to create a mock Utxo
    fn create_mock_utxo() -> Utxo {
        Utxo {
            txid: "00".repeat(32),
            vout: 0,
            value: 10000,
            status: UtxoStatus {
                confirmed: true,
                block_height: 1234,
                block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                block_time: 1234567890,
            },
        }
    }

    // Helper to create a Bitcoin address
    fn create_address() -> Address {
        let addr_str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        Address::from_str(addr_str)
            .map_err(|e| panic!("Invalid address {}: {}", addr_str, e))
            .and_then(|addr| {
                addr.require_network(Network::Bitcoin)
                    .map_err(|e| panic!("Network mismatch for {}: {}", addr_str, e))
            })
            .unwrap()
    }

    // Helper to initialize logger
    fn init_logger() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();
    }

    #[tokio::test]
    async fn test_fetch_utxos_for_address_success() {
        init_logger();
        let mut server = Server::new_async().await;
        let address = create_address();
        let mock_utxos = vec![create_mock_utxo()];
        let mock_response = json!(mock_utxos).to_string();

        let mock = server
            .mock("GET", Matcher::Exact(format!("/address/{}/utxo", address)))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&mock_response)
            .create_async()
            .await;

        let result = fetch_utxos_for_address(&server.url(), &address).await;
        assert_eq!(result.is_ok(), true, "Expected Ok, got {:?}", result);
        let utxos = result.unwrap();
        assert_eq!(utxos.len(), 1, "Expected 1 UTXO");
        assert_eq!(utxos[0].txid, "00".repeat(32), "Unexpected txid");
        assert_eq!(utxos[0].value, 10000, "Unexpected value");
        assert_eq!(
            utxos[0].status.block_height, 1234,
            "Unexpected block height"
        );
        info!("Tested fetch_utxos_for_address success");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_utxos_for_address_parse_error() {
        init_logger();
        let mut server = Server::new_async().await;
        let address = create_address();

        let mock = server
            .mock("GET", Matcher::Exact(format!("/address/{}/utxo", address)))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("invalid json")
            .create_async()
            .await;

        let result = fetch_utxos_for_address(&server.url(), &address).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested fetch_utxos_for_address parse error");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_utxos_for_address_http_error() {
        init_logger();
        let mut server = Server::new_async().await;
        let address = create_address();

        let mock = server
            .mock("GET", Matcher::Exact(format!("/address/{}/utxo", address)))
            .with_status(500)
            .with_body("Server Error")
            .create_async()
            .await;

        let result = fetch_utxos_for_address(&server.url(), &address).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested fetch_utxos_for_address HTTP error");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_broadcast_trx_success() {
        init_logger();
        let mut server = Server::new_async().await;
        let tx_raw_hex = "0100000001abcdef...";
        let txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

        let mock = server
            .mock("POST", "/tx")
            .match_header("content-type", "text/plain")
            .with_status(200)
            .with_body(txid)
            .create_async()
            .await;

        let result = broadcast_trx(&server.url(), tx_raw_hex).await;
        info!("Raw result: {:?}", result); // Debug log
        assert_eq!(result.is_ok(), true, "Expected Ok, got {:?}", result);
        assert_eq!(
            result.as_ref().unwrap(),
            txid,
            "Expected txid {}, got {:?}",
            txid,
            result
        );
        info!("Tested broadcast_trx success");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_broadcast_trx_broadcast_error() {
        init_logger();
        let mut server = Server::new_async().await;
        let tx_raw_hex = "0100000001abcdef...";

        let mock = server
            .mock("POST", "/tx")
            .match_header("content-type", "text/plain")
            .with_status(400)
            .with_body("Invalid transaction")
            .create_async()
            .await;

        let result = broadcast_trx(&server.url(), tx_raw_hex).await;
        assert!(
            matches!(
                result,
                Err(UtilsError::BroadcastError { status, ref message }) if status == reqwest::StatusCode::BAD_REQUEST && message == "Invalid transaction"
            ),
            "Expected BroadcastError, got {:?}",
            result
        );
        info!("Tested broadcast_trx broadcast error");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_broadcast_trx_parse_error_empty() {
        init_logger();
        let mut server = Server::new_async().await;
        let tx_raw_hex = "0100000001abcdef...";

        let mock = server
            .mock("POST", "/tx")
            .match_header("content-type", "text/plain")
            .with_status(200)
            .with_body("")
            .create_async()
            .await;

        let result = broadcast_trx(&server.url(), tx_raw_hex).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested broadcast_trx parse error (empty)");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_broadcast_trx_parse_error_invalid() {
        init_logger();
        let mut server = Server::new_async().await;
        let tx_raw_hex = "0100000001abcdef...";

        let mock = server
            .mock("POST", "/tx")
            .match_header("content-type", "text/plain")
            .with_status(200)
            .with_body("invalid_txid")
            .create_async()
            .await;

        let result = broadcast_trx(&server.url(), tx_raw_hex).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested broadcast_trx parse error (invalid)");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_tip_block_height_success() {
        init_logger();
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("1234")
            .create_async()
            .await;

        let result = fetch_tip_block_height(&server.url()).await;
        assert_eq!(result.is_ok(), true, "Expected Ok, got {:?}", result);
        assert_eq!(
            *result.as_ref().unwrap(),
            1234,
            "Expected height 1234, got {:?}",
            result
        );
        info!("Tested fetch_tip_block_height success");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_tip_block_height_parse_error() {
        init_logger();
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("not_a_number")
            .create_async()
            .await;

        let result = fetch_tip_block_height(&server.url()).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested fetch_tip_block_height parse error");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_recommended_fee_rate_success() {
        init_logger();
        let mut server = Server::new_async().await;
        let mock_fee_rate = RecommendedFeeRate {
            fastest_fee: 100,
            half_hour_fee: 50,
            hour_fee: 25,
            economy_fee: 10,
            minimum_fee: 1,
        };
        let mock_response = json!(mock_fee_rate).to_string();

        let mock = server
            .mock("GET", "/v1/fees/recommended")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&mock_response)
            .create_async()
            .await;

        let result = fetch_recommended_fee_rate(&server.url()).await;
        assert_eq!(result.is_ok(), true, "Expected Ok, got {:?}", result);
        let fee_rate = result.unwrap();
        assert_eq!(fee_rate.fastest_fee, 100, "Unexpected fastest_fee");
        assert_eq!(fee_rate.half_hour_fee, 50, "Unexpected half_hour_fee");
        assert_eq!(fee_rate.hour_fee, 25, "Unexpected hour_fee");
        assert_eq!(fee_rate.economy_fee, 10, "Unexpected economy_fee");
        assert_eq!(fee_rate.minimum_fee, 1, "Unexpected minimum_fee");
        info!("Tested fetch_recommended_fee_rate success");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_recommended_fee_rate_parse_error() {
        init_logger();
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/fees/recommended")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("invalid json")
            .create_async()
            .await;

        let result = fetch_recommended_fee_rate(&server.url()).await;
        assert!(
            matches!(result, Err(UtilsError::ParseError(_))),
            "Expected ParseError, got {:?}",
            result
        );
        info!("Tested fetch_recommended_fee_rate parse error");
        mock.assert_async().await;
    }
}
