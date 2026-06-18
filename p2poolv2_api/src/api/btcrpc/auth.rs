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

use crate::api::btcrpc::handler::BtcRpcState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::warn;

/// Constant-time string comparison via SHA-256 hashing.
/// Both inputs are hashed to a fixed-length digest before comparison,
/// preventing timing attacks regardless of input length.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a_hash = Sha256::digest(a.as_bytes());
    let b_hash = Sha256::digest(b.as_bytes());
    a_hash.ct_eq(&b_hash).into()
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
        "",
    )
        .into_response()
}

/// Bitcoin Core-style HTTP Basic Auth middleware.
/// If no credentials are configured in state, all requests are allowed through.
pub(crate) async fn btcrpc_auth_middleware(
    State(state): State<Arc<BtcRpcState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let (Some(expected_user), Some(expected_pass)) = (&state.rpcuser, &state.rpcpassword) else {
        return Ok(next.run(request).await);
    };

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(h) if h.starts_with("Basic ") => {
            let encoded = &h[6..];
            let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(b) => b,
                Err(_) => {
                    warn!("btcrpc: failed to decode base64 credentials");
                    return Err(unauthorized_response());
                }
            };
            let decoded_str = match String::from_utf8(decoded) {
                Ok(s) => s,
                Err(_) => {
                    warn!("btcrpc: invalid UTF-8 in credentials");
                    return Err(unauthorized_response());
                }
            };
            let mut parts = decoded_str.splitn(2, ':');
            let (user, pass) = match (parts.next(), parts.next()) {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    warn!("btcrpc: invalid credentials format");
                    return Err(unauthorized_response());
                }
            };
            if constant_time_eq_str(user, expected_user)
                && constant_time_eq_str(pass, expected_pass)
            {
                Ok(next.run(request).await)
            } else {
                warn!("btcrpc: invalid username or password");
                Err(unauthorized_response())
            }
        }
        _ => {
            warn!("btcrpc: missing or invalid Authorization header");
            Err(unauthorized_response())
        }
    }
}
