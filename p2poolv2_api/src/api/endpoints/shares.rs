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

use crate::api::endpoints::MAX_NUM_SHARES_IN_RESPONSE;
use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use p2poolv2_lib::store::dag_store::ShareInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for the /shares endpoint.
#[derive(Deserialize)]
pub struct SharesQuery {
    /// Height to query up to (inclusive). Defaults to confirmed chain tip.
    pub to: Option<u32>,
    /// Number of shares going back from `to`. Defaults to 10.
    pub num: Option<u32>,
}

/// JSON response for the /shares endpoint.
#[derive(Serialize)]
pub struct SharesResponse {
    pub from_height: u32,
    pub to_height: u32,
    pub shares: Vec<ShareInfo>,
}

/// Returns confirmed shares and their uncles for a height range.
pub(crate) async fn shares(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SharesQuery>,
) -> Result<Json<SharesResponse>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;
    let num = query.num.unwrap_or(10);

    if num < 1 || num > MAX_NUM_SHARES_IN_RESPONSE {
        return Err(ApiError::BadRequest(format!(
            "num must be between 1 and {MAX_NUM_SHARES_IN_RESPONSE}, got {num}"
        )));
    }

    let tip_height = chain_store_handle
        .get_tip_height()
        .map_err(|error| ApiError::ServerError(format!("Failed to get tip height: {error}")))?
        .ok_or_else(|| ApiError::NotFound("No confirmed chain tip found".to_string()))?;

    let to_height = match query.to {
        Some(height) => {
            if height > tip_height {
                tip_height
            } else {
                height
            }
        }
        None => tip_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let store = chain_store_handle.store_handle().store();
    let shares = store
        .query_shares(from_height, to_height)
        .map_err(|error| ApiError::ServerError(format!("Failed to query shares: {error}")))?;

    Ok(Json(SharesResponse {
        from_height,
        to_height,
        shares,
    }))
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
    use p2poolv2_lib::test_utils::{genesis_for_tests, setup_test_chain_store_handle};

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
            monitoring_event_sender: create_monitoring_event_channel().0,
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_shares_rejects_num_zero() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(SharesQuery {
            to: None,
            num: Some(0),
        });

        let result = shares(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shares_rejects_num_above_max() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(SharesQuery {
            to: None,
            num: Some(1001),
        });

        let result = shares(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shares_accepts_num_at_max() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(SharesQuery {
            to: None,
            num: Some(100),
        });

        let result = shares(State(state), query).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shares_returns_not_found_on_empty_store() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(SharesQuery {
            to: None,
            num: None,
        });

        let result = shares(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shares_with_genesis() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(SharesQuery {
            to: Some(0),
            num: Some(1),
        });

        let result = shares(State(state), query).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.from_height, 0);
        assert_eq!(response.to_height, 0);
        assert!(!response.shares.is_empty());
    }

    #[tokio::test]
    async fn test_shares_defaults_num_to_ten() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(SharesQuery {
            to: None,
            num: None,
        });

        let result = shares(State(state), query).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.from_height, 0);
        assert_eq!(response.to_height, 0);
    }

    #[tokio::test]
    async fn test_shares_clamps_to_height_to_tip() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let query = Query(SharesQuery {
            to: Some(9999),
            num: Some(1),
        });

        let result = shares(State(state), query).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        // to_height should be clamped to tip (0)
        assert_eq!(response.to_height, 0);
    }
}
