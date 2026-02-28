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

use crate::api::auth::auth_middleware;
use crate::api::error::ApiError;
use axum::{
    Extension, Json, Router,
    extract::{FromRef, Query, State},
    middleware::{self},
    routing::get,
};
use chrono::DateTime;
use p2poolv2_lib::node::actor::NodeHandle;
use p2poolv2_lib::stratum::work::tracker::{JobTracker, parse_coinbase};
use p2poolv2_lib::{
    accounting::{simple_pplns::SimplePplnsShare, stats::metrics::MetricsHandle},
    config::ApiConfig,
    shares::chain::chain_store_handle::ChainStoreHandle,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use tracing::info;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) app_config: AppConfig,
    pub(crate) chain_store_handle: ChainStoreHandle,
    pub(crate) metrics_handle: MetricsHandle,
    pub(crate) tracker_handle: Arc<JobTracker>,
    pub(crate) node_handle: NodeHandle,
    pub(crate) auth_user: Option<String>,
    pub(crate) auth_token: Option<String>,
}

/// Stores application config values that don't change across requests
/// Used with Extension axum framework
#[derive(Clone)]
pub struct AppConfig {
    pub pool_signature_length: usize,
    pub network: bitcoin::Network,
}

/// Get AppConfig from AppState ref
impl FromRef<AppState> for AppConfig {
    fn from_ref(state: &AppState) -> Self {
        state.app_config.clone()
    }
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
    chain_store_handle: ChainStoreHandle,
    metrics_handle: MetricsHandle,
    tracker_handle: Arc<JobTracker>,
    node_handle: NodeHandle,
    network: bitcoin::Network,
    pool_signature: Option<String>,
) -> Result<oneshot::Sender<()>, std::io::Error> {
    let app_config = AppConfig {
        pool_signature_length: pool_signature.unwrap_or_default().len(),
        network,
    };

    let app_state = Arc::new(AppState {
        app_config: app_config.clone(),
        chain_store_handle,
        metrics_handle,
        tracker_handle,
        node_handle,
        auth_user: config.auth_user.clone(),
        auth_token: config.auth_token.clone(),
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
        .route("/peers", get(peers))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .layer(Extension(app_config))
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

/// Returns pool metrics in grafana exposition format
///
/// The exposition also includes parsed coinbase outputs for showing
/// the current coinbase payout distribution
async fn metrics(State(state): State<Arc<AppState>>) -> String {
    //  Get base metrics
    let pool_metrics = state.metrics_handle.get_metrics().await;
    let mut exposition = pool_metrics.get_exposition();

    if let Some(coinbase_distribution) = parse_coinbase::get_distribution(
        &state.tracker_handle,
        state.app_config.pool_signature_length,
        state.app_config.network,
    ) {
        exposition.push_str("# HELP coinbase_rewards_distribution Current coinbase rewards distribution between users\n");
        exposition.push_str(&coinbase_distribution);
    }
    exposition
}

/// Response type for the /peers endpoint.
#[derive(Debug, Serialize)]
struct PeerResponse {
    peer_id: String,
}

/// Returns the list of currently connected peers.
async fn peers(State(state): State<Arc<AppState>>) -> Result<Json<Vec<PeerResponse>>, ApiError> {
    let peer_ids = state
        .node_handle
        .get_peers()
        .await
        .map_err(|error| ApiError::ServerError(format!("Failed to get peers: {error}")))?;

    let peers: Vec<PeerResponse> = peer_ids
        .into_iter()
        .map(|peer_id| PeerResponse {
            peer_id: peer_id.to_string(),
        })
        .collect();

    Ok(Json(peers))
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

    let shares = state.chain_store_handle.get_pplns_shares_filtered(
        query.limit,
        Some(start_time),
        Some(end_time),
    );

    Ok(Json(shares))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use bitcoin::{Amount, Network, TxOut};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::shares::share_block::ShareBlock;
    use p2poolv2_lib::stratum::work::block_template::BlockTemplate;
    use p2poolv2_lib::stratum::work::coinbase::parse_address;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::setup_test_chain_store_handle;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    /// Helper to build an AppState with the given NodeHandle for endpoint tests.
    async fn build_test_state(node_handle: NodeHandle) -> (Arc<AppState>, tempfile::TempDir) {
        let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let metrics_temp = tempfile::tempdir().unwrap();
        let metrics_handle =
            metrics::start_metrics(metrics_temp.path().to_str().unwrap().to_string())
                .await
                .unwrap();
        let tracker_handle = start_tracker_actor();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 0,
                network: bitcoin::Network::Signet,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle,
            node_handle,
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_peers_endpoint_returns_empty_list() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let response = peers(State(state)).await.unwrap();
        assert!(response.0.is_empty());
    }

    #[tokio::test]
    async fn test_peers_endpoint_returns_peer_list() {
        let (node_handle, expected_peer_ids) = NodeHandle::new_for_test_with_peer_count(3);
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let response = peers(State(state)).await.unwrap();
        let peer_responses = &response.0;

        assert_eq!(peer_responses.len(), 3);

        let returned_ids: Vec<&str> = peer_responses
            .iter()
            .map(|peer| peer.peer_id.as_str())
            .collect();
        for expected_id in &expected_peer_ids {
            assert!(
                returned_ids.contains(&expected_id.as_str()),
                "Expected peer ID {expected_id} not found in response"
            );
        }
    }

    #[tokio::test]
    async fn test_metrics_endpoint_exposes_coinbase_split() {
        let tracker_handle = start_tracker_actor();

        let temp_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(temp_dir.path().to_str().unwrap().to_string())
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
        let job_id = tracker_handle.get_next_job_id();
        tracker_handle.insert_job(
            Arc::new(template),
            "".to_string(),
            coinbase2_hex,
            None,
            job_id,
        );

        //  Mock ChainStore
        let _genesis = ShareBlock::build_genesis_for_network(Network::Signet);
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        //  Prepare AppState
        let node_handle = NodeHandle::new_for_test();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 8,
                network: bitcoin::Network::Signet,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle,
            node_handle,
            auth_user: None,
            auth_token: None,
        });

        let response_body = metrics(State(state)).await;

        println!("{}", response_body);

        //  Verify Output
        assert!(response_body.contains(
            "coinbase_output{index=\"0\",address=\"tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d\"} 4900000000"
        ));
        assert!(response_body.contains(
            "coinbase_output{index=\"1\",address=\"tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f\"} 100000000"
        ));
    }
}
