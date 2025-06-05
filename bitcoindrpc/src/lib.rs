// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::consensus::encode::serialize_hex;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HeaderMap, HttpClient, HttpClientBuilder};
use std::error::Error;
use std::fmt;

// Add mockall to make the trait mockable
#[cfg(any(test, feature = "mock"))]
pub use mockall::{automock, predicate::*};

/// Error type for the BitcoindRpcClient
#[derive(Debug)]
pub enum BitcoindRpcError {
    Other(String),
}

impl Error for BitcoindRpcError {
    fn description(&self) -> &str {
        match self {
            BitcoindRpcError::Other(msg) => msg,
        }
    }
}
impl fmt::Display for BitcoindRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoindRpcError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Define a trait for the BitcoindRpc functionality
/// All functions in the traits are desugred async functions so we can add Send as a bound.
#[cfg_attr(any(test, feature = "mock"), automock)]
#[warn(async_fn_in_trait)]
pub trait BitcoindRpc: Send + Sync + 'static {
    fn new(url: String, username: String, password: String) -> Result<Self, BitcoindRpcError>
    where
        Self: Sized;
    fn request<T: serde::de::DeserializeOwned + 'static>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> impl std::future::Future<Output = Result<T, BitcoindRpcError>> + Send;

    fn get_difficulty(
        &self,
    ) -> impl std::future::Future<Output = Result<f64, BitcoindRpcError>> + Send;

    fn getblocktemplate(
        &self,
        network: bitcoin::Network,
    ) -> impl std::future::Future<Output = Result<String, BitcoindRpcError>> + Send;

    fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> impl std::future::Future<Output = Result<bitcoin::Transaction, BitcoindRpcError>> + Send;

    fn submit_block(
        &self,
        block: &bitcoin::Block,
    ) -> impl std::future::Future<Output = Result<String, BitcoindRpcError>> + Send;
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BitcoindRpcClient {
    client: HttpClient,
}

impl BitcoindRpc for BitcoindRpcClient {
    fn new(url: String, username: String, password: String) -> Result<Self, BitcoindRpcError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", username, password))
            )
            .parse()
            .unwrap(),
        );
        let client = match HttpClientBuilder::default().set_headers(headers).build(url) {
            Ok(client) => client,
            Err(e) => {
                return Err(BitcoindRpcError::Other(format!(
                    "Failed to create HTTP client: {}",
                    e
                )))
            }
        };
        Ok(Self { client })
    }
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, BitcoindRpcError> {
        match self.client.request(method, params).await {
            Ok(response) => Ok(response),
            Err(e) => Err(BitcoindRpcError::Other(format!(
                "Failed to send RPC request: {}",
                e
            ))),
        }
    }

    /// Get current bitcoin difficulty from bitcoind rpc
    async fn get_difficulty(&self) -> Result<f64, BitcoindRpcError> {
        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = self.request("getdifficulty", params).await?;
        Ok(result.as_f64().unwrap())
    }

    /// Get current bitcoin block count from bitcoind rpc
    /// We use special rules for signet
    async fn getblocktemplate(
        &self,
        network: bitcoin::Network,
    ) -> Result<String, BitcoindRpcError> {
        let params = match network {
            bitcoin::Network::Signet => {
                vec![serde_json::json!({
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit", "signet"],
                })]
            }
            _ => {
                vec![serde_json::json!({
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit"],
                })]
            }
        };
        match self
            .request::<serde_json::Value>("getblocktemplate", params)
            .await
        {
            Ok(result) => Ok(result.to_string()),
            Err(e) => Err(BitcoindRpcError::Other(format!(
                "Failed to get block template: {}",
                e
            ))),
        }
    }

    /// Decode a raw transaction using bitcoind RPC
    ///
    /// Sends the transaction serialized as hex to the Bitcoin Core RPC,
    /// then receives and parses the decoded transaction information.
    async fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, BitcoindRpcError> {
        // Serialize the transaction to hex string
        let tx_hex = serialize_hex(tx);

        // Prepare params for the RPC call
        let params = vec![serde_json::Value::String(tx_hex)];

        // Make the RPC request
        match self
            .request::<serde_json::Value>("decoderawtransaction", params)
            .await
        {
            Ok(result) => {
                // Parse the response into a bitcoin::Transaction
                let tx: bitcoin::Transaction = match serde_json::from_value(result) {
                    Ok(tx) => tx,
                    Err(e) => {
                        return Err(BitcoindRpcError::Other(format!(
                            "Failed to decode raw transaction: {}",
                            e
                        )))
                    }
                };
                Ok(tx)
            }
            Err(e) => Err(BitcoindRpcError::Other(format!(
                "Failed to decode raw transaction: {}",
                e
            ))),
        }
    }

    async fn submit_block(&self, block: &bitcoin::Block) -> Result<String, BitcoindRpcError> {
        // Serialize the block to hex string
        let block_hex = serialize_hex(block);

        // Prepare params for the RPC call
        let params = vec![serde_json::Value::String(block_hex)];

        // Make the RPC request
        match self
            .request::<serde_json::Value>("submitblock", params)
            .await
        {
            Ok(result) => Ok(result.to_string()),
            Err(e) => Err(BitcoindRpcError::Other(format!(
                "Failed to submit block: {}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::CompactTarget;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_bitcoin_client() {
        // Start mock server
        let mock_server = MockServer::start().await;

        let auth_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", "testuser", "testpass"))
        );

        // Define expected request and response
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", auth_header))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "test",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": "test response",
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "testuser".to_string(),
            "testpass".to_string(),
        )
        .unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: String = client.request("test", params).await.unwrap();

        assert_eq!(result, "test response");
    }

    #[tokio::test]
    async fn test_bitcoin_client_with_invalid_credentials() {
        let mock_server = MockServer::start().await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "invaliduser".to_string(),
            "invalidpass".to_string(),
        )
        .unwrap();
        let params: Vec<serde_json::Value> = vec![];
        let result: Result<String, BitcoindRpcError> = client.request("test", params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore] // Ignore by default since we only use it to test the connection to a locally running bitcoind
    async fn test_bitcoin_client_real_connection() {
        let client = BitcoindRpcClient::new(
            "http://localhost:38332".to_string(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();

        let params: Vec<serde_json::Value> = vec![];
        let result: serde_json::Value = client.request("getblockchaininfo", params).await.unwrap();

        assert!(result.is_object());
        assert!(result.get("chain").is_some());
    }

    #[tokio::test]
    async fn test_get_difficulty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getdifficulty",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": 1234.56,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();
        let difficulty = client.get_difficulty().await.unwrap();

        assert_eq!(difficulty, 1234.56);
    }

    #[test_log::test(tokio::test)]
    async fn test_getblocktemplate_mainnet() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getblocktemplate",
                "params": [{
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit"],
                }],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "version": 536870912,
                    "previousblockhash": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "transactions": [],
                    "coinbaseaux": {},
                    "coinbasevalue": 625000000,
                    "longpollid": "mockid",
                    "target": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "mintime": 1610000000,
                    "mutable": ["time", "transactions", "prevblock"],
                    "noncerange": "00000000ffffffff",
                    "sigoplimit": 80000,
                    "sizelimit": 4000000,
                    "curtime": 1610000000,
                    "bits": "170d6d54",
                    "height": 1000000,
                    "default_witness_commitment": "6a24aa21a9ed"
                },
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();
        let result = client.getblocktemplate(bitcoin::Network::Bitcoin).await;
        let result = result.unwrap();

        let result = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert!(result.get("version").is_some());
        assert_eq!(result.get("height").unwrap(), 1000000);
    }

    #[tokio::test]
    async fn test_getblocktemplate_signet() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "getblocktemplate",
                "params": [{
                    "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                    "rules": ["segwit", "signet"],
                }],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "version": 536870912,
                    "previousblockhash": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "transactions": [],
                    "coinbaseaux": {},
                    "coinbasevalue": 625000000,
                    "longpollid": "mockid",
                    "target": "0000000000000000000b4d0b2e8e7e4e6b8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
                    "mintime": 1610000000,
                    "mutable": ["time", "transactions", "prevblock"],
                    "noncerange": "00000000ffffffff",
                    "sigoplimit": 80000,
                    "sizelimit": 4000000,
                    "curtime": 1610000000,
                    "bits": "170d6d54",
                    "height": 2000000,
                    "default_witness_commitment": "6a24aa21a9ed"
                },
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();
        let result = client
            .getblocktemplate(bitcoin::Network::Signet)
            .await
            .unwrap();

        let result = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert!(result.get("version").is_some());
        assert_eq!(result.get("height").unwrap(), 2000000);
    }

    #[tokio::test]
    async fn test_decoderawtransaction() {
        let mock_server = MockServer::start().await;
        let tx_hex = "0100000001000000000000000000000000000000000000000000000000000000\
                  0000000000ffffffff1c02fa01010004bdaf326804554ce1370c0101010101\
                  01010101010101ffffffff0300e1f50500000000160014fd8b1a0b2a4c387d\
                  0a418969c62f2812c76ee45d0011102401000000160014ca81d03f2707c355\
                  502622c7db77fdf79546926e0000000000000000266a24aa21a9eddd9e37e4\
                  20b1b58781dada016dfa5812f62133a381e1a58e83389735b2330ef700000000";
        let tx = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(
            hex::decode(tx_hex).unwrap().as_slice(),
        )
        .unwrap();

        // Setup mock for decoderawtransaction
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "decoderawtransaction",
                "params": [tx_hex],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": serde_json::to_value(tx.clone()).unwrap(),
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();

        let decoded_tx = client.decoderawtransaction(&tx).await.unwrap();

        assert_eq!(decoded_tx, tx);
    }

    #[tokio::test]
    async fn test_submit_block() {
        let mock_server = MockServer::start().await;

        // Create a simple block
        let block = bitcoin::Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: "5e9a183768460fbf56eab199a66057375b424bdca195e7ecc808374365a7ea67"
                    .parse()
                    .unwrap(),
                merkle_root: "277c298e9f1254a59411cfc29f1a88ec6ee12cf4c955044d8bb8a7242cfed919"
                    .parse()
                    .unwrap(),
                time: 1610000000,
                bits: CompactTarget::from_consensus(503543726),
                nonce: 12345,
            },
            txdata: vec![],
        };

        let block_hex = serialize_hex(&block);

        // Setup mock for submitblock
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("Authorization", "Basic cDJwb29sOnAycG9vbA=="))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "method": "submitblock",
                "params": [block_hex],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "result": null,  // null indicates success in Bitcoin Core
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(
            mock_server.uri(),
            "p2pool".to_string(),
            "p2pool".to_string(),
        )
        .unwrap();

        let result = client.submit_block(&block).await.unwrap();
        assert_eq!(result, "null"); // Successful submission returns null
    }
}
