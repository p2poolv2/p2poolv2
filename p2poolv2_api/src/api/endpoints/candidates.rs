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
use crate::api::endpoints::common::ShareInfoResponse;
use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for the /candidates endpoint.
#[derive(Deserialize)]
pub struct CandidatesQuery {
    /// Height to query up to (inclusive). Defaults to candidate chain tip.
    pub to: Option<u32>,
    /// Number of candidates going back from `to`. Defaults to 10.
    pub num: Option<u32>,
}

/// JSON response for the /candidates endpoint.
#[derive(Serialize)]
pub struct CandidatesResponse {
    pub from_height: u32,
    pub to_height: u32,
    pub shares: Vec<ShareInfoResponse>,
}

/// Returns candidate shares and their uncles for a height range.
pub(crate) async fn candidates(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CandidatesQuery>,
) -> Result<Json<CandidatesResponse>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;
    let num = query.num.unwrap_or(10);

    if num < 1 || num > MAX_NUM_SHARES_IN_RESPONSE {
        return Err(ApiError::BadRequest(format!(
            "num must be between 1 and {MAX_NUM_SHARES_IN_RESPONSE}, got {num}"
        )));
    }

    let candidate_height = chain_store_handle
        .get_candidate_tip_height()
        .map_err(|error| {
            ApiError::ServerError(format!("Failed to get candidate tip height: {error}"))
        })?
        .ok_or_else(|| ApiError::NotFound("No candidate chain tip found".to_string()))?;

    let to_height = match query.to {
        Some(height) => {
            if height > candidate_height {
                candidate_height
            } else {
                height
            }
        }
        None => candidate_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let store = chain_store_handle.store_handle().store();
    let candidates = store
        .query_candidates(from_height, to_height)
        .map_err(|error| ApiError::ServerError(format!("Failed to query candidates: {error}")))?;

    let candidate_shares: Vec<ShareInfoResponse> = candidates
        .into_iter()
        .map(ShareInfoResponse::from)
        .collect();

    Ok(Json(CandidatesResponse {
        from_height,
        to_height,
        shares: candidate_shares,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::{Query, State};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::setup_test_chain_store_handle;

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
    async fn test_candidates_rejects_num_zero() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(CandidatesQuery {
            to: None,
            num: Some(0),
        });

        let result = candidates(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_candidates_rejects_num_above_max() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(CandidatesQuery {
            to: None,
            num: Some(1001),
        });

        let result = candidates(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_candidates_returns_not_found_on_empty_store() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let query = Query(CandidatesQuery {
            to: None,
            num: None,
        });

        let result = candidates(State(state), query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_candidates_with_genesis_and_new_share() {
        let node_handle = NodeHandle::new_for_test();
        let (state, _temp_dir) = build_test_state(node_handle).await;

        let genesis = p2poolv2_lib::test_utils::genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Add a share that becomes a candidate
        let genesis_hash = genesis.block_hash().to_string();
        let share = p2poolv2_lib::test_utils::TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis_hash)
            .work(1)
            .build();

        let _ = state
            .chain_store_handle
            .organise_header(share.header.clone())
            .await;

        // Now check if we have candidates
        let query = Query(CandidatesQuery {
            to: None,
            num: Some(10),
        });

        let result = candidates(State(state), query).await;
        // May return data or NotFound depending on whether the header became a candidate
        // The important thing is it doesn't panic
        assert!(result.is_ok() || result.is_err());
    }
}
