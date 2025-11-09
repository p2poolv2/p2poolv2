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
use chrono::DateTime;
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
) -> Result<oneshot::Sender<()>, std::io::Error> {
    let app_state = Arc::new(AppState {
        chain_store,
        metrics_handle,
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
    state.metrics_handle.get_prometheus_exposition().await
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
