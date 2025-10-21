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

use crate::api::server::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Validate password against stored salt$hmac token
fn validate_password(password: &str, stored_token: &str) -> bool {
    // Parse stored token format: salt$hmac
    let parts: Vec<&str> = stored_token.split('$').collect();
    if parts.len() != 2 {
        warn!("Invalid auth_token format, expected salt$hmac");
        return false;
    }

    let salt = parts[0];
    let expected_hmac = parts[1];

    // Compute HMAC-SHA256 of password using salt as key
    let Ok(mut mac) = HmacSha256::new_from_slice(salt.as_bytes()) else {
        warn!("Failed to create HMAC");
        return false;
    };
    mac.update(password.as_bytes());
    let computed_hmac = hex::encode(mac.finalize().into_bytes());

    computed_hmac == expected_hmac
}

/// Authentication middleware that checks for valid Basic authentication
pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers().clone();
    // If no auth is configured, allow all requests
    let (Some(expected_user), Some(expected_token)) = (&state.auth_user, &state.auth_token) else {
        return Ok(next.run(request).await);
    };

    // Get Authorization header
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Basic ") => {
            let credentials = &header[6..]; // Skip "Basic "

            // Decode base64
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) else {
                warn!("Failed to decode Basic auth credentials");
                return Err(StatusCode::UNAUTHORIZED);
            };

            let Ok(decoded_str) = String::from_utf8(decoded) else {
                warn!("Invalid UTF-8 in Basic auth credentials");
                return Err(StatusCode::UNAUTHORIZED);
            };

            // Parse username:password
            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() != 2 {
                warn!("Invalid Basic auth format");
                return Err(StatusCode::UNAUTHORIZED);
            }

            let (username, password) = (parts[0], parts[1]);

            // Validate username and password
            if username == expected_user && validate_password(password, expected_token) {
                Ok(next.run(request).await)
            } else {
                warn!("Invalid username or password");
                Err(StatusCode::UNAUTHORIZED)
            }
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
