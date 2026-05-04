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
use p2poolv2_lib::store::dag_store::DagEntry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Query parameters for the /dag endpoint.
#[derive(Deserialize)]
pub struct DagQuery {
    /// Height to query up to (inclusive). Defaults to confirmed chain tip.
    pub to: Option<u32>,
    /// Number of heights going back from `to`. Defaults to 10.
    pub num: Option<u32>,
}

/// JSON response for the /dag endpoint.
#[derive(Serialize)]
pub struct DagResponse {
    pub from_height: u32,
    pub to_height: u32,
    pub entries: Vec<DagEntry>,
}

/// Returns all share headers in the height index for a range of heights.
///
/// Unlike /shares and /candidates which only return confirmed or candidate
/// chain entries, this returns every block at each height regardless of
/// status (Confirmed, Candidate, HeaderValid, etc.).
pub(crate) async fn dag(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DagQuery>,
) -> Result<Json<DagResponse>, ApiError> {
    let chain_store_handle = &state.chain_store_handle;
    let num = query.num.unwrap_or(10);

    if !(1..=MAX_NUM_SHARES_IN_RESPONSE).contains(&num) {
        return Err(ApiError::BadRequest(format!(
            "num must be between 1 and {MAX_NUM_SHARES_IN_RESPONSE}, got {num}"
        )));
    }

    let tip_height = chain_store_handle
        .get_tip_height()
        .map_err(|error| ApiError::ServerError(format!("Failed to get tip height: {error}")))?
        .ok_or_else(|| ApiError::ServerError("No confirmed chain tip found".to_string()))?;

    let to_height = match query.to {
        Some(height) if height > tip_height => tip_height,
        Some(height) => height,
        None => tip_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let entries = chain_store_handle
        .store_handle()
        .store()
        .query_dag(from_height, to_height);

    Ok(Json(DagResponse {
        from_height,
        to_height,
        entries,
    }))
}
