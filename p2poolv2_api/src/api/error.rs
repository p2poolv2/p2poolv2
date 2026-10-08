// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    ServerError(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::BadRequest(msg) => write!(f, "bad request: {msg}"),
            ApiError::NotFound(msg) => write!(f, "not found: {msg}"),
            ApiError::ServerError(msg) => write!(f, "axum server error: {msg}"),
        }
    }
}

impl Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::ServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}
