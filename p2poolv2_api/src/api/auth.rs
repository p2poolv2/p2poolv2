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

use crate::api::server::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use p2poolv2_lib::auth::password_to_hmac;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::warn;

/// Decode base64 credentials, parse `user:password`, and validate against
/// the expected username and stored token. Returns `Ok(())` on success or
/// `Err(UNAUTHORIZED)` on any validation failure.
pub(crate) fn validate_credentials(
    base64_credentials: &str,
    expected_user: &str,
    expected_token: &str,
) -> Result<(), StatusCode> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(base64_credentials)
        .map_err(|_| {
            warn!("Failed to decode base64 credentials");
            StatusCode::UNAUTHORIZED
        })?;

    let decoded_str = String::from_utf8(decoded).map_err(|_| {
        warn!("Invalid UTF-8 in credentials");
        StatusCode::UNAUTHORIZED
    })?;

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        warn!("Invalid credentials format");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (username, password) = (parts[0], parts[1]);
    if username == expected_user && validate_password(password, expected_token) {
        Ok(())
    } else {
        warn!("Invalid username or password");
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Validate password against stored salt$hmac token.
fn validate_password(password: &str, stored_token: &str) -> bool {
    // Parse stored token format: salt$hmac
    let parts: Vec<&str> = stored_token.split('$').collect();
    if parts.len() != 2 {
        warn!("Invalid auth_token format, expected salt$hmac");
        return false;
    }

    let salt = parts[0];
    let expected_hmac = parts[1];

    let computed_hmac = match password_to_hmac(salt, password) {
        Ok(hmac) => hmac,
        Err(error) => {
            warn!("Failed to compute HMAC: {error}");
            return false;
        }
    };

    computed_hmac
        .as_bytes()
        .ct_eq(expected_hmac.as_bytes())
        .into()
}

/// Authentication middleware that checks for valid Basic authentication
pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // If no auth is configured, allow all requests
    let (Some(expected_user), Some(expected_token)) = (&state.auth_user, &state.auth_token) else {
        return Ok(next.run(request).await);
    };

    // Get Authorization header
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Basic ") => {
            let credentials = &header[6..]; // Skip "Basic "
            validate_credentials(credentials, expected_user, expected_token)?;
            Ok(next.run(request).await)
        }
        Some(_) => {
            warn!("Invalid Authorization header format, expected Basic auth");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            warn!("Missing Authorization header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
