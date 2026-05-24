// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use bitcoin::consensus::encode;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct TransactionQuery {
    pub txid: String,
    pub raw: Option<bool>,
}

#[derive(Serialize)]
pub struct TransactionOutput {
    pub txid: String,
    pub version: i32,
    pub lock_time: String,
    pub inputs: Vec<InputOutput>,
    pub outputs: Vec<OutputOutput>,
}

#[derive(Serialize)]
pub struct InputOutput {
    pub previous_output: String,
    pub script_sig: String,
    pub sequence: u32,
}

#[derive(Serialize)]
pub struct OutputOutput {
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Serialize)]
pub struct RawTransactionOutput {
    pub txid: String,
    pub hex: String,
}

pub async fn transaction(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TransactionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let txid = bitcoin::Txid::from_str(&query.txid)
        .map_err(|error| ApiError::BadRequest(format!("Invalid txid: {error}")))?;

    let store = state.chain_store_handle.store_handle().store();
    let tx = store
        .get_tx(&txid)
        .map_err(|error| ApiError::NotFound(format!("Transaction not found: {error}")))?;

    if query.raw.unwrap_or(false) {
        let raw_bytes = encode::serialize(&tx);
        let hex = hex::encode(raw_bytes);
        let output = RawTransactionOutput {
            txid: txid.to_string(),
            hex,
        };
        let value = serde_json::to_value(output).map_err(|error| {
            ApiError::ServerError(format!("Failed to serialize response: {error}"))
        })?;
        Ok(Json(value))
    } else {
        let inputs: Vec<InputOutput> = tx
            .input
            .iter()
            .map(|input| InputOutput {
                previous_output: format!(
                    "{}:{}",
                    input.previous_output.txid, input.previous_output.vout
                ),
                script_sig: input.script_sig.to_hex_string(),
                sequence: input.sequence.0,
            })
            .collect();

        let outputs: Vec<OutputOutput> = tx
            .output
            .iter()
            .map(|output| OutputOutput {
                value: output.value.to_sat(),
                script_pubkey: output.script_pubkey.to_hex_string(),
            })
            .collect();

        let output = TransactionOutput {
            txid: txid.to_string(),
            version: tx.version.0,
            lock_time: format!("{}", tx.lock_time),
            inputs,
            outputs,
        };
        let value = serde_json::to_value(output).map_err(|error| {
            ApiError::ServerError(format!("Failed to serialize response: {error}"))
        })?;
        Ok(Json(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::{Query, State};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::{
        TestShareBlockBuilder, genesis_for_tests, setup_test_chain_store_handle,
    };

    async fn build_test_state() -> (Arc<AppState>, tempfile::TempDir) {
        let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(chain_store_handle.get_chain_tip().unwrap().to_string())
            .nonce(1)
            .work(2)
            .build();
        chain_store_handle.add_share_block(share).await.unwrap();

        let metrics_temp = tempfile::tempdir().unwrap();
        let metrics_handle =
            metrics::start_metrics(metrics_temp.path().to_str().unwrap().to_string())
                .await
                .unwrap();
        let tracker_handle = start_tracker_actor();
        let node_handle = NodeHandle::new_for_test();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 0,
                network: bitcoin::Network::Signet,
                cors_allowed: false,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle,
            node_handle,
            monitoring_event_sender: create_monitoring_event_channel().0,
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_transaction_invalid_txid() {
        let (state, _temp_dir) = build_test_state().await;
        let query = Query(TransactionQuery {
            txid: "not_a_valid_txid".to_string(),
            raw: None,
        });
        let result = transaction(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transaction_not_found() {
        let (state, _temp_dir) = build_test_state().await;
        let query = Query(TransactionQuery {
            txid: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            raw: None,
        });
        let result = transaction(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_transaction_json_output() {
        let (state, _temp_dir) = build_test_state().await;
        let store = state.chain_store_handle.store_handle().store();
        let genesis_hash = state.chain_store_handle.get_chain_tip().unwrap();
        let txids = store.get_txids_for_blockhash(&genesis_hash);
        let txid = txids.0[0];

        let query = Query(TransactionQuery {
            txid: txid.to_string(),
            raw: None,
        });
        let result = transaction(State(state), query).await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert_eq!(json["txid"], txid.to_string());
        assert!(json["version"].is_number());
        assert!(json["inputs"].is_array());
        assert!(json["outputs"].is_array());
    }

    #[tokio::test]
    async fn test_transaction_raw_output() {
        let (state, _temp_dir) = build_test_state().await;
        let store = state.chain_store_handle.store_handle().store();
        let genesis_hash = state.chain_store_handle.get_chain_tip().unwrap();
        let txids = store.get_txids_for_blockhash(&genesis_hash);
        let txid = txids.0[0];

        let query = Query(TransactionQuery {
            txid: txid.to_string(),
            raw: Some(true),
        });
        let result = transaction(State(state), query).await;
        assert!(result.is_ok());
        let json = result.unwrap().0;
        assert_eq!(json["txid"], txid.to_string());
        assert!(json["hex"].is_string());
        let hex_str = json["hex"].as_str().unwrap();
        assert!(hex_str.len() > 0);
        assert!(hex::decode(hex_str).is_ok());
    }
}
