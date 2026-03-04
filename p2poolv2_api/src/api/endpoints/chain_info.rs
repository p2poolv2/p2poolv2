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
use axum::{Json, extract::State};
use serde::Serialize;
use std::sync::Arc;

/// JSON response for the /chain_info endpoint.
#[derive(Serialize)]
pub struct ChainInfoResponse {
    pub genesis_blockhash: Option<String>,
    pub chain_tip_height: Option<u32>,
    pub total_work: String,
    pub chain_tip_blockhash: Option<String>,
    pub top_candidate_height: Option<u32>,
    pub top_candidate_blockhash: Option<String>,
}

/// Returns chain state information including tip height, total work, and candidate info.
pub(crate) async fn chain_info(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChainInfoResponse>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;

    let genesis_blockhash = chain_store_handle
        .get_genesis_blockhash()
        .map(|hash| hash.to_string());

    let chain_tip_height = chain_store_handle
        .get_tip_height()
        .map_err(|error| ApiError::ServerError(format!("Failed to get tip height: {error}")))?;

    let chain_tip_blockhash = chain_store_handle
        .get_chain_tip()
        .map(|hash| Some(hash.to_string()))
        .map_err(|error| ApiError::ServerError(format!("Failed to get chain tip: {error}")))?;

    let total_work = format!(
        "{:#x}",
        chain_store_handle
            .get_total_work()
            .map_err(|error| ApiError::ServerError(format!("Failed to get total work: {error}")))?
    );

    let top_candidate_height = chain_store_handle
        .get_candidate_tip_height()
        .map_err(|error| {
            ApiError::ServerError(format!("Failed to get candidate tip height: {error}"))
        })?;

    let top_candidate_blockhash = top_candidate_height.and_then(|height| {
        chain_store_handle
            .store_handle()
            .store()
            .get_candidate_at_height(height)
            .ok()
            .map(|hash| hash.to_string())
    });

    let response = ChainInfoResponse {
        genesis_blockhash,
        chain_tip_height,
        total_work,
        chain_tip_blockhash,
        top_candidate_height,
        top_candidate_blockhash,
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::State;
    use p2poolv2_lib::accounting::stats::metrics;
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
            auth_user: None,
            auth_token: None,
        });
        (state, temp_dir)
    }

    #[tokio::test]
    async fn test_chain_info_errors_on_empty_store() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let result = chain_info(State(state)).await;
        // Empty store has no total_work data, so handler returns ServerError
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_chain_info_after_genesis() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();

        let result = chain_info(State(state)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert!(response.genesis_blockhash.is_some());
        assert_eq!(response.chain_tip_height, Some(0));
        assert!(response.chain_tip_blockhash.is_some());
        assert!(!response.total_work.is_empty());
    }

    #[tokio::test]
    async fn test_chain_info_returns_none_when_no_genesis() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        // get_total_work errors on empty store, so this will return ServerError.
        // The key point is that it propagates the error rather than returning
        // fake defaults like height=0 and all-zero blockhash.
        let result = chain_info(State(state)).await;
        assert!(result.is_err());
    }
}
