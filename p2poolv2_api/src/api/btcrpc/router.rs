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

use crate::api::btcrpc::{
    auth::btcrpc_auth_middleware,
    handler::{BtcRpcState, btcrpc_handler},
};
use axum::{Router, middleware, routing::post};
use std::sync::Arc;

pub(crate) fn build_btcrpc_router(state: Arc<BtcRpcState>) -> Router {
    // v1: single POST / endpoint for all chain/mempool/fees/decode RPCs.
    // Extension point: add .route("/wallet/{name}", post(wallet_handler)) here
    // for v2 per-wallet routing without restructuring this router.
    Router::new()
        .route("/", post(btcrpc_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            btcrpc_auth_middleware,
        ))
        .with_state(state)
}
