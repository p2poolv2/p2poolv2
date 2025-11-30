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

use crate::api::error::ApiError;
use axum::{
    Json, Router,
    extract::{Query, State},
    middleware::{self},
    routing::get,
};
use bitcoin::{Address, Network};
use chrono::DateTime;
use p2poolv2_lib::stratum::work::coinbase::extract_outputs_from_coinbase2;
use p2poolv2_lib::{
    accounting::{simple_pplns::SimplePplnsShare, stats::metrics::MetricsHandle},
    config::ApiConfig,
    shares::chain::chain_store::ChainStore,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use tracing::info;

use crate::api::auth::auth_middleware;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) chain_store: Arc<ChainStore>,
    pub(crate) metrics_handle: MetricsHandle,
    pub(crate) auth_user: Option<String>,
    pub(crate) auth_token: Option<String>,
    pub(crate) pool_signature_len: usize,
    pub(crate) network: Network,
}

#[derive(Deserialize)]
pub struct PplnsQuery {
    limit: Option<usize>,
    start_time: Option<String>,
    end_time: Option<String>,
}

/// Start the API server and return a shutdown channel
pub async fn start_api_server(
    config: ApiConfig,
    chain_store: Arc<ChainStore>,
    metrics_handle: MetricsHandle,
    pool_signature_len: usize,
    network: Network,
) -> Result<oneshot::Sender<()>, std::io::Error> {
    let app_state = Arc::new(AppState {
        chain_store,
        metrics_handle,
        auth_user: config.auth_user.clone(),
        auth_token: config.auth_token.clone(),
        pool_signature_len,
        network,
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let addr = SocketAddr::new(
        std::net::IpAddr::V4(config.hostname.parse().unwrap()),
        config.port,
    );
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics))
        .route("/pplns_shares", get(pplns_shares))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .with_state(app_state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => return Err(e),
    };

    info!("API server listening on {}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
                info!("API server shutdown signal received");
            })
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;

        info!("API server stopped");
        Ok::<(), ApiError>(())
    });
    Ok(shutdown_tx)
}

async fn health_check() -> String {
    "OK".into()
}

async fn metrics(State(state): State<Arc<AppState>>) -> String {
    //  Get base metrics
    let pool_metrics = state.metrics_handle.get_metrics().await;
    let mut exposition = pool_metrics.get_exposition();

    //  Get Tracker and Latest Job
    let tracker = &state.metrics_handle.tracker;
    let job_details = match tracker.get_latest_job_id().await {
        Ok(job_id) => tracker.get_job(job_id).await.ok().flatten(),
        _ => None,
    };

    if let Some(job) = job_details {
        //  Parse the coinbase2
        // We use the length stored in AppState
        match extract_outputs_from_coinbase2(&job.coinbase2, state.pool_signature_len) {
            Ok(outputs) => {
                let total_value = job.blocktemplate.coinbasevalue;

                let network = state.network;

                for tx_out in outputs.iter() {
                    let value_sats = tx_out.value;
                    // Avoid division by zero
                    let percentage = if total_value > 0 {
                        (value_sats.to_sat() as f64 / total_value as f64) * 100.0
                    } else {
                        0.0
                    };

                    let address = Address::from_script(&tx_out.script_pubkey, network)
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "unknown_script".to_string());

                    exposition.push_str(&format!(
                        "p2pool_coinbase_split{{address=\"{}\"}} {:.2}\n",
                        address, percentage
                    ));
                }
            }
            Err(e) => {
                tracing::error!("Failed to parse coinbase for metrics: {}", e);
                exposition.push_str("# p2pool_coinbase_split: error parsing coinbase\n");
            }
        }
    }

    exposition
}

async fn pplns_shares(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PplnsQuery>,
) -> Result<Json<Vec<SimplePplnsShare>>, ApiError> {
    // Convert ISO 8601 strings to Unix timestamps
    let start_time = match query.start_time.as_ref() {
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(dt) => dt.timestamp() as u64,
            Err(_) => {
                return Err(ApiError::ServerError("Invalid time format".into()));
            }
        },
        None => 0,
    };

    let end_time = match query.end_time.as_ref() {
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(dt) => dt.timestamp() as u64,
            Err(_) => {
                return Err(ApiError::ServerError("Invalid time format".into()));
            }
        },
        None => {
            // Default to current time
            let now = chrono::Utc::now();
            now.timestamp() as u64
        }
    };

    if end_time < start_time {
        return Err(ApiError::ServerError("Invalid date range".into()));
    }

    let shares =
        state
            .chain_store
            .get_pplns_shares_filtered(query.limit, Some(start_time), Some(end_time));

    Ok(Json(shares))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use bitcoin::consensus::serialize;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, Network, TxOut};
    use p2poolv2_lib::accounting::OutputPair;
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::shares::chain::chain_store::ChainStore;
    use p2poolv2_lib::shares::share_block::ShareBlock;
    use p2poolv2_lib::store::Store;
    use p2poolv2_lib::stratum::work::block_template::BlockTemplate;
    use p2poolv2_lib::stratum::work::coinbase::{parse_address, split_coinbase};
    use p2poolv2_lib::stratum::work::tracker::{JobId, start_tracker_actor};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_metrics_endpoint_exposes_coinbase_split() {
        let tracker_handle = start_tracker_actor();

        let temp_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(
            temp_dir.path().to_str().unwrap().to_string(),
            tracker_handle.clone(),
        )
        .await
        .unwrap();

        //  Use Signet Addresses
        let address = parse_address(
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d",
            Network::Signet,
        )
        .unwrap();

        let donation_address = parse_address(
            "tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f",
            Network::Signet,
        )
        .unwrap();

        // 50 BTC Total: 49 to miner, 1 to pool
        let output_pairs = vec![
            OutputPair {
                address: address.clone(),
                amount: Amount::from_str("49 BTC").unwrap(),
            },
            OutputPair {
                address: donation_address.clone(),
                amount: Amount::from_str("1 BTC").unwrap(),
            },
        ];

        let template = BlockTemplate {
            default_witness_commitment: Some(
                "6a24aa21a9ed010000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
            height: 100,
            version: 0x20000000,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            bits: "1d00ffff".to_string(),
            curtime: 1234567890,
            transactions: vec![],
            coinbasevalue: 50_0000_0000,
            coinbaseaux: HashMap::new(),
            rules: vec![],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            longpollid: "".to_string(),
            target: "".to_string(),
            mintime: 0,
            mutable: vec![],
            noncerange: "".to_string(),
            sigoplimit: 0,
            sizelimit: 0,
            weightlimit: 0,
        };

        let pool_signature = b"P2Poolv2";

        // Build outputs
        let outputs = vec![
            TxOut {
                value: Amount::from_str("49 BTC").unwrap(),
                script_pubkey: address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_str("1 BTC").unwrap(),
                script_pubkey: donation_address.script_pubkey(),
            },
        ];

        // Manually Construct `coinbase2` Hex
        let mut coinbase2_bytes = Vec::new();
        coinbase2_bytes.push(pool_signature.len() as u8);
        coinbase2_bytes.extend_from_slice(pool_signature);
        coinbase2_bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Sequence
        coinbase2_bytes.extend_from_slice(&bitcoin::consensus::serialize(&outputs)); // Outputs
        coinbase2_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // LockTime

        let coinbase2_hex = hex::encode(coinbase2_bytes);

        //  Insert Job into Tracker
        let job_id = tracker_handle.get_next_job_id().await.unwrap();
        tracker_handle
            .insert_job(
                Arc::new(template),
                "".to_string(),
                coinbase2_hex,
                None,
                job_id,
            )
            .await
            .expect("Failed to insert job");

        //  Mock ChainStore
        let temp_dir_store = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::new(temp_dir_store.path().to_str().unwrap().to_string(), false).unwrap(),
        );
        let genesis = ShareBlock::build_genesis_for_network(Network::Signet);
        let chain_store = Arc::new(ChainStore::new(store, genesis, Network::Signet));

        //  Prepare AppState
        let state = Arc::new(AppState {
            chain_store,
            metrics_handle,
            auth_user: None,
            auth_token: None,
            pool_signature_len: pool_signature.len(),
            network: Network::Signet,
        });

        let response_body = metrics(State(state)).await;

        println!("Metrics Response:\n{}", response_body);

        //  Verify Output
        assert!(response_body.contains(
            "p2pool_coinbase_split{address=\"tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d\"} 98.00"
        ));
        assert!(response_body.contains(
            "p2pool_coinbase_split{address=\"tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f\"} 2.00"
        ));
    }
}
