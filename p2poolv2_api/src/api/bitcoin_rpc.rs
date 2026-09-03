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
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient, BitcoindRpcError};
use p2poolv2_lib::config::BitcoinRpcApiConfig;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::oneshot;
use tracing::{info, warn};

const ALLOWED_METHODS: [&str; 16] = [
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockcount",
    "getblockfilter",
    "getblockhash",
    "getblockheader",
    "getmempoolentry",
    "getnetworkinfo",
    "getrawmempool",
    "getrawtransaction",
    "gettxout",
    "estimatesmartfee",
    "sendrawtransaction",
    "testmempoolaccept",
    "decoderawtransaction",
];

const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INVALID_PARAMS: i32 = -32602;
const INTERNAL_ERROR: i32 = -32603;

#[derive(Clone)]
struct BitcoinRpcState {
    client: BitcoindRpcClient,
    max_batch_size: usize,
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RpcVersion {
    Legacy,
    V2,
}

impl RpcVersion {
    fn from_request(request: &serde_json::Value) -> Self {
        if matches!(request.get("jsonrpc"), Some(serde_json::Value::String(version)) if version == "2.0")
        {
            Self::V2
        } else {
            Self::Legacy
        }
    }
}

fn make_success_response(
    version: RpcVersion,
    id: serde_json::Value,
    result: serde_json::Value,
) -> serde_json::Value {
    match version {
        RpcVersion::Legacy => json!({ "result": result, "error": null, "id": id }),
        RpcVersion::V2 => json!({ "jsonrpc": "2.0", "result": result, "id": id }),
    }
}

fn make_error_response(
    version: RpcVersion,
    id: serde_json::Value,
    error: RpcError,
) -> serde_json::Value {
    let error = json!({ "code": error.code, "message": error.message });
    match version {
        RpcVersion::Legacy => json!({ "result": null, "error": error, "id": id }),
        RpcVersion::V2 => json!({ "jsonrpc": "2.0", "error": error, "id": id }),
    }
}

fn bitcoind_error_to_rpc_error(error: BitcoindRpcError) -> RpcError {
    match error {
        BitcoindRpcError::RpcError { code, message } => RpcError { code, message },
        BitcoindRpcError::HttpError {
            status_code,
            message,
        } => RpcError {
            code: INTERNAL_ERROR,
            message: format!("HTTP error {status_code}: {message}"),
        },
        BitcoindRpcError::ParseError { message } => RpcError {
            code: INTERNAL_ERROR,
            message,
        },
        BitcoindRpcError::Other(message) => RpcError {
            code: INTERNAL_ERROR,
            message,
        },
    }
}

async fn handle_single(
    client: &BitcoindRpcClient,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let version = RpcVersion::from_request(request);
    let is_notification = version == RpcVersion::V2 && request.get("id").is_none();
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let response = if !request.is_object() {
        make_error_response(
            version,
            id,
            RpcError {
                code: INVALID_REQUEST,
                message: "Invalid Request".to_string(),
            },
        )
    } else if let Some(method) = request.get("method").and_then(serde_json::Value::as_str) {
        if !ALLOWED_METHODS.contains(&method) {
            make_error_response(
                version,
                id,
                RpcError {
                    code: METHOD_NOT_FOUND,
                    message: "Method not found".to_string(),
                },
            )
        } else {
            let invalid_params = request.get("params").is_some_and(|params| {
                !params.is_null() && !params.is_array() && !params.is_object()
            });
            if invalid_params {
                make_error_response(
                    version,
                    id,
                    RpcError {
                        code: INVALID_PARAMS,
                        message: "Params must be an array or object".to_string(),
                    },
                )
            } else {
                let params = request
                    .get("params")
                    .filter(|params| !params.is_null())
                    .cloned()
                    .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
                match client.call_value(method, params).await {
                    Ok(result) => make_success_response(version, id, result),
                    Err(error) => {
                        make_error_response(version, id, bitcoind_error_to_rpc_error(error))
                    }
                }
            }
        }
    } else {
        make_error_response(
            version,
            id,
            RpcError {
                code: INVALID_REQUEST,
                message: "Missing or invalid method field".to_string(),
            },
        )
    };

    (!is_notification).then_some(response)
}

async fn bitcoin_rpc_handler(State(state): State<Arc<BitcoinRpcState>>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            warn!("bitcoin_rpc: failed to parse request body: {error}");
            return Json(make_error_response(
                RpcVersion::Legacy,
                serde_json::Value::Null,
                RpcError {
                    code: PARSE_ERROR,
                    message: "Parse error".to_string(),
                },
            ))
            .into_response();
        }
    };

    match &value {
        serde_json::Value::Array(requests) => {
            if requests.is_empty() {
                return Json(make_error_response(
                    RpcVersion::Legacy,
                    serde_json::Value::Null,
                    RpcError {
                        code: INVALID_REQUEST,
                        message: "Invalid Request".to_string(),
                    },
                ))
                .into_response();
            }

            if requests.len() > state.max_batch_size {
                return Json(make_error_response(
                    RpcVersion::Legacy,
                    serde_json::Value::Null,
                    RpcError {
                        code: INVALID_REQUEST,
                        message: format!(
                            "Batch too large: {} requests, max {}",
                            requests.len(),
                            state.max_batch_size
                        ),
                    },
                ))
                .into_response();
            }

            let mut responses = Vec::with_capacity(requests.len());
            // ponytail: use bounded concurrency if sequential batches become measurable.
            for request in requests {
                if let Some(response) = handle_single(&state.client, request).await {
                    responses.push(response);
                }
            }
            if responses.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                Json(serde_json::Value::Array(responses)).into_response()
            }
        }
        _ => match handle_single(&state.client, &value).await {
            Some(response) => Json(response).into_response(),
            None => StatusCode::NO_CONTENT.into_response(),
        },
    }
}

fn constant_time_eq_str(left: &str, right: &str) -> bool {
    let left_hash = Sha256::digest(left.as_bytes());
    let right_hash = Sha256::digest(right.as_bytes());
    left_hash.ct_eq(&right_hash).into()
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
        "",
    )
        .into_response()
}

async fn bitcoin_rpc_auth_middleware(
    State(state): State<Arc<BitcoinRpcState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let (Some(expected_user), Some(expected_password)) = (&state.rpcuser, &state.rpcpassword)
    else {
        return next.run(request).await;
    };

    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Basic ") => {
            let encoded = &value[6..];
            let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => {
                    warn!("bitcoin_rpc: failed to decode base64 credentials");
                    return unauthorized_response();
                }
            };
            let credentials = match String::from_utf8(decoded) {
                Ok(credentials) => credentials,
                Err(_) => {
                    warn!("bitcoin_rpc: invalid UTF-8 in credentials");
                    return unauthorized_response();
                }
            };
            let mut parts = credentials.splitn(2, ':');
            let (username, password) = match (parts.next(), parts.next()) {
                (Some(username), Some(password)) => (username, password),
                _ => {
                    warn!("bitcoin_rpc: invalid credentials format");
                    return unauthorized_response();
                }
            };
            if constant_time_eq_str(username, expected_user)
                && constant_time_eq_str(password, expected_password)
            {
                next.run(request).await
            } else {
                warn!("bitcoin_rpc: invalid username or password");
                unauthorized_response()
            }
        }
        _ => {
            warn!("bitcoin_rpc: missing or invalid Authorization header");
            unauthorized_response()
        }
    }
}

fn build_router(state: Arc<BitcoinRpcState>) -> Router {
    Router::new()
        .route("/", post(bitcoin_rpc_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            bitcoin_rpc_auth_middleware,
        ))
        .with_state(state)
}

/// Start the Bitcoin Core compatible JSON-RPC gateway on its own listener.
///
/// Returns the shutdown sender and the actual bound port. The caller is
/// responsible for sending on the shutdown channel when the node stops.
pub async fn start_bitcoin_rpc_server(
    config: BitcoinRpcApiConfig,
    bitcoin_rpc: &BitcoinRpcConfig,
) -> Result<(oneshot::Sender<()>, u16), std::io::Error> {
    let client = BitcoindRpcClient::new(
        &bitcoin_rpc.url,
        &bitcoin_rpc.username,
        &bitcoin_rpc.password,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    let state = Arc::new(BitcoinRpcState {
        client,
        max_batch_size: config.max_batch_size,
        rpcuser: config.rpcuser.clone(),
        rpcpassword: config.rpcpassword.clone(),
    });

    let ip_address = config.host.parse().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid bitcoin_rpc bind host '{}': {error}", config.host),
        )
    })?;
    let address = SocketAddr::new(ip_address, config.port);

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let actual_port = listener.local_addr()?.port();

    info!(
        "Bitcoin RPC gateway listening on {}:{}",
        config.host, actual_port
    );

    let (shutdown_sender, shutdown_receiver) = oneshot::channel::<()>();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_receiver.await;
                info!("Bitcoin RPC gateway shutdown signal received");
            })
            .await
            .map_err(|error| ApiError::ServerError(error.to_string()))?;

        info!("Bitcoin RPC gateway stopped");
        Ok::<(), ApiError>(())
    });

    Ok((shutdown_sender, actual_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http};
    use base64::Engine;
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    #[test]
    fn allowlist_contains_exactly_v1_methods() {
        let cases = [
            ("getbestblockhash", true),
            ("getblock", true),
            ("getblockchaininfo", true),
            ("getblockcount", true),
            ("getblockfilter", true),
            ("getblockhash", true),
            ("getblockheader", true),
            ("getmempoolentry", true),
            ("getnetworkinfo", true),
            ("getrawmempool", true),
            ("getrawtransaction", true),
            ("gettxout", true),
            ("estimatesmartfee", true),
            ("sendrawtransaction", true),
            ("testmempoolaccept", true),
            ("decoderawtransaction", true),
            ("listunspent", false),
        ];

        assert_eq!(ALLOWED_METHODS.len(), 16);
        for (method_name, expected) in cases {
            assert_eq!(ALLOWED_METHODS.contains(&method_name), expected);
        }
    }

    #[test]
    fn only_exact_json_rpc_2_marker_selects_version_2() {
        assert!(RpcVersion::from_request(&json!({ "jsonrpc": "2.0" })) == RpcVersion::V2);
        for request in [
            json!({}),
            json!({ "jsonrpc": "1.0" }),
            json!({ "jsonrpc": "2" }),
            json!({ "jsonrpc": 2 }),
        ] {
            assert!(RpcVersion::from_request(&request) == RpcVersion::Legacy);
        }
    }

    #[tokio::test]
    async fn parameters_reach_upstream_unchanged() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockhash",
                "params": [42],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "positional",
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockhash",
                "params": { "height": 42 },
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "named",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblock",
                "params": { "args": ["000000000000abc"], "verbosity": 2 },
                "id": 2
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "args",
                "error": null,
                "id": 2
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 3
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 3
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockhash", "params": [42], "id": 7 },
                    {
                        "method": "getblockhash",
                        "params": { "height": 42 },
                        "id": 8
                    },
                    {
                        "method": "getblock",
                        "params": { "args": ["000000000000abc"], "verbosity": 2 },
                        "id": 9
                    },
                    { "method": "getblockcount", "id": 10 }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body[0]["result"], "positional");
        assert_eq!(body[1]["result"], "named");
        assert_eq!(body[2]["result"], "args");
        assert_eq!(body[3]["result"], 42);
    }

    #[tokio::test]
    async fn unlisted_method_returns_method_not_found() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "listunspent", "params": [], "id": 3}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(body["id"], 3);
    }

    #[tokio::test]
    async fn upstream_error_code_and_message_are_preserved() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "result": null,
                "error": {
                    "code": -5,
                    "message": "No such mempool or blockchain transaction"
                },
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({"method": "getrawtransaction", "params": ["deadbeef"], "id": 2}),
                )
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body.get("jsonrpc").is_none());
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], -5);
        assert_eq!(
            body["error"]["message"],
            "No such mempool or blockchain transaction"
        );
        assert_eq!(body["id"], 2);
    }

    #[tokio::test]
    async fn mixed_batch_omits_notifications_and_preserves_response_versions() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 100,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getbestblockhash",
                "params": [],
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "000000000000abc",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "getblockcount", "params": [], "id": 10},
                    {"jsonrpc": "2.0", "method": "getbestblockhash", "params": []},
                    {"jsonrpc": "2.0", "method": "listunspent", "params": [], "id": 12}
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let responses = body.as_array().unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["id"], 10);
        assert_eq!(responses[0]["result"], 100);
        assert!(responses[0].get("jsonrpc").is_none());
        assert_eq!(responses[1]["jsonrpc"], "2.0");
        assert_eq!(responses[1]["id"], 12);
        assert_eq!(responses[1]["error"]["code"], METHOD_NOT_FOUND);
        assert!(responses[1].get("result").is_none());
    }

    #[tokio::test]
    async fn json_rpc_2_success_contains_only_result() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount",
                    "id": 1
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "jsonrpc": "2.0", "result": 42, "id": 1 }));
    }

    #[tokio::test]
    async fn json_rpc_2_error_contains_only_error() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "listunspent",
                    "id": 2
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(body["id"], 2);
        assert!(body.get("result").is_none());
    }

    #[tokio::test]
    async fn single_notification_is_executed_without_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount"
                }))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn notification_only_batch_is_executed_without_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getbestblockhash",
                "params": [],
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "000000000000abc",
                "error": null,
                "id": 1
            })))
            .expect(1)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "jsonrpc": "2.0", "method": "getblockcount" },
                    { "jsonrpc": "2.0", "method": "getbestblockhash" }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn empty_batch_is_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("[]"))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
        assert!(body["result"].is_null());
        assert!(body["id"].is_null());
    }

    #[tokio::test]
    async fn invalid_top_level_values_are_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });

        for value in [json!(null), json!(true), json!(1), json!("request")] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap();
            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["error"]["code"], INVALID_REQUEST);
            assert!(body["result"].is_null());
            assert!(body["id"].is_null());
        }
    }

    #[tokio::test]
    async fn missing_and_invalid_methods_are_rejected() {
        let client = BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap();

        for request in [json!({ "id": 1 }), json!({ "method": 1, "id": 2 })] {
            let response = handle_single(&client, &request).await.unwrap();
            assert_eq!(response["error"]["code"], INVALID_REQUEST);
            assert!(response["result"].is_null());
        }
    }

    #[tokio::test]
    async fn invalid_params_are_rejected() {
        let client = BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap();
        let response = handle_single(
            &client,
            &json!({
                "jsonrpc": "2.0",
                "method": "getblockcount",
                "params": true,
                "id": 1
            }),
        )
        .await
        .unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("{"))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], PARSE_ERROR);
        assert!(body["result"].is_null());
        assert!(body["id"].is_null());
    }

    #[tokio::test]
    async fn malformed_upstream_response_returns_internal_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock_server)
            .await;
        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let response = handle_single(
            &client,
            &json!({ "jsonrpc": "2.0", "method": "getblockcount", "id": 1 }),
        )
        .await
        .unwrap();

        assert_eq!(response["error"]["code"], INTERNAL_ERROR);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn missing_credentials_return_unauthorized() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: Some("user".to_string()),
            rpcpassword: Some("pass".to_string()),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getblockcount", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_credentials_are_accepted() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: Some("alice".to_string()),
            rpcpassword: Some("secret".to_string()),
        });
        let credentials = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Basic {credentials}"))
            .body(Body::from(
                serde_json::to_vec(&json!({"method": "getblockcount", "params": [], "id": 1}))
                    .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["result"], 42);
    }

    #[tokio::test]
    async fn oversized_batch_is_rejected() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 2,
            rpcuser: None,
            rpcpassword: None,
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    {"method": "getblockcount", "params": [], "id": 1},
                    {"method": "getblockcount", "params": [], "id": 2},
                    {"method": "getblockcount", "params": [], "id": 3}
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
    }
}
