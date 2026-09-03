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
    rpcuser: String,
    rpcpassword: String,
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
                let params = request.get("params").cloned();
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
            if constant_time_eq_str(username, &state.rpcuser)
                & constant_time_eq_str(password, &state.rpcpassword)
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
    build_handler_router(state.clone()).layer(middleware::from_fn_with_state(
        state,
        bitcoin_rpc_auth_middleware,
    ))
}

fn build_handler_router(state: Arc<BitcoinRpcState>) -> Router {
    Router::new()
        .route("/", post(bitcoin_rpc_handler))
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
    config
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.message))?;
    if !config.enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bitcoin_rpc_api must be enabled before starting the listener",
        ));
    }

    let client = BitcoindRpcClient::new(
        &bitcoin_rpc.url,
        &bitcoin_rpc.username,
        &bitcoin_rpc.password,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    let state = Arc::new(BitcoinRpcState {
        client,
        max_batch_size: config.max_batch_size,
        rpcuser: config
            .rpcuser
            .expect("enabled bitcoin_rpc_api config was validated"),
        rpcpassword: config
            .rpcpassword
            .expect("enabled bitcoin_rpc_api config was validated"),
    });

    let ip_address = config
        .host
        .parse()
        .expect("bitcoin_rpc_api host was validated");
    let address = SocketAddr::new(
        ip_address,
        config
            .port
            .expect("enabled bitcoin_rpc_api config was validated"),
    );

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
    use std::{env, time::Duration};
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    #[tokio::test]
    async fn every_v1_method_is_forwarded() {
        let method_names = [
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
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .expect(method_names.len() as u64)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, method_name) in method_names.into_iter().enumerate() {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "method": method_name,
                        "params": [],
                        "id": request_id
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["result"], true, "method {method_name} was rejected");
            assert!(body["error"].is_null(), "method {method_name} failed");
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
                "params": null,
                "id": 3
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "null",
                "error": null,
                "id": 3
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
                "id": 4
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": "absent",
                "error": null,
                "id": 4
            })))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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
                    { "method": "getblockcount", "params": null, "id": 10 },
                    { "method": "getblockcount", "id": 11 }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body[0]["result"], "positional");
        assert_eq!(body[1]["result"], "named");
        assert_eq!(body[2]["result"], "args");
        assert_eq!(body[3]["result"], "null");
        assert_eq!(body[4]["result"], "absent");
    }

    #[tokio::test]
    async fn incorrect_method_names_are_rejected() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, method_name) in [
            "getblockcounts",
            "getblockcoun",
            "GetBlockCount",
            "getblockcount ",
            "getblock.count",
            "listunspent",
        ]
        .into_iter()
        .enumerate()
        {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(
                        &json!({"method": method_name, "params": [], "id": request_id}),
                    )
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert!(body["result"].is_null(), "method {method_name}");
            assert_eq!(
                body["error"]["code"], METHOD_NOT_FOUND,
                "method {method_name}"
            );
            assert_eq!(body["id"], request_id, "method {method_name}");
        }
    }

    #[tokio::test]
    async fn json_result_types_are_relayed() {
        let mock_server = MockServer::start().await;
        let results = [
            json!(42),
            json!({ "height": 42 }),
            json!(["transaction", 42]),
            json!("000000000000abc"),
            json!(true),
            json!(null),
        ];

        for (upstream_id, result) in results.iter().enumerate() {
            Mock::given(method("POST"))
                .and(path("/"))
                .and(body_json(json!({
                    "method": "getblockcount",
                    "params": [],
                    "id": upstream_id
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "result": result,
                    "error": null,
                    "id": upstream_id
                })))
                .expect(1)
                .mount(&mock_server)
                .await;
        }
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for (request_id, expected_result) in results.into_iter().enumerate() {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "method": "getblockcount",
                        "params": [],
                        "id": request_id
                    }))
                    .unwrap(),
                ))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["result"], expected_result, "result case {request_id}");
            assert!(body["error"].is_null(), "result case {request_id}");
        }
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
    async fn request_ids_are_preserved_without_batch_deduplication() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": true,
                "error": null,
                "id": 0
            })))
            .expect(8)
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockcount", "id": "string-id" },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": 42 },
                    { "method": "getblockcount", "id": null },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": null },
                    { "method": "getblockcount", "id": 7 },
                    { "jsonrpc": "2.0", "method": "getblockcount", "id": 7 },
                    { "method": "getblockcount" },
                    { "jsonrpc": "2.0", "method": "getblockcount" }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            body,
            json!([
                { "result": true, "error": null, "id": "string-id" },
                { "jsonrpc": "2.0", "result": true, "id": 42 },
                { "result": true, "error": null, "id": null },
                { "jsonrpc": "2.0", "result": true, "id": null },
                { "result": true, "error": null, "id": 7 },
                { "jsonrpc": "2.0", "result": true, "id": 7 },
                { "result": true, "error": null, "id": null }
            ])
        );
    }

    #[tokio::test]
    async fn json_rpc_2_success_contains_only_result() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
    async fn only_exact_json_rpc_2_marker_selects_version_2_envelope() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let cases = [
            (json!({ "method": "listunspent", "id": 1 }), false),
            (
                json!({ "jsonrpc": "1.0", "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": "2", "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": 2, "method": "listunspent", "id": 1 }),
                false,
            ),
            (
                json!({ "jsonrpc": "2.0", "method": "listunspent", "id": 1 }),
                true,
            ),
        ];

        for (request_body, is_version_2) in cases {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body.get("jsonrpc").is_some(), is_version_2);
            assert_eq!(body.get("result").is_none(), is_version_2);
            assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
            assert_eq!(body["id"], 1);
        }
    }

    #[tokio::test]
    async fn single_notification_is_executed_without_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(json!({
                "method": "getblockcount",
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn single_item_batch_returns_an_array() {
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!([
                    { "method": "getblockcount", "params": [], "id": 1 }
                ]))
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body, json!([{ "result": 42, "error": null, "id": 1 }]));
    }

    #[tokio::test]
    async fn empty_batch_is_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("[]"))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for value in [json!(null), json!(true), json!(1), json!("request")] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&value).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
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
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });

        for request in [json!({ "id": 1 }), json!({ "method": 1, "id": 2 })] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap();
            let response = build_handler_router(state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(body["error"]["code"], INVALID_REQUEST);
            assert!(body["result"].is_null());
        }
    }

    #[tokio::test]
    async fn invalid_params_are_rejected() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "method": "getblockcount",
                    "params": true,
                    "id": 1
                }))
                .unwrap(),
            ))
            .unwrap();
        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["error"]["code"], INVALID_PARAMS);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from("{"))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
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
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({ "jsonrpc": "2.0", "method": "getblockcount", "id": 1 }),
                )
                .unwrap(),
            ))
            .unwrap();
        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(response["error"]["code"], INTERNAL_ERROR);
        assert!(response.get("result").is_none());
    }

    #[tokio::test]
    async fn upstream_http_failure_returns_internal_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&mock_server)
            .await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
        });
        let request = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({ "jsonrpc": "2.0", "method": "getblockcount", "id": 1 }),
                )
                .unwrap(),
            ))
            .unwrap();

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"]["code"], INTERNAL_ERROR);
        assert!(body.get("result").is_none());
    }

    #[tokio::test]
    async fn missing_credentials_return_unauthorized() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
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
    async fn malformed_credentials_return_unauthorized() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
        });
        let credentials_without_separator =
            base64::engine::general_purpose::STANDARD.encode("userpass");

        for authorization in [
            "Bearer token".to_string(),
            "Basic !!!".to_string(),
            format!("Basic {credentials_without_separator}"),
        ] {
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .header("Authorization", authorization)
                .body(Body::from("{}"))
                .unwrap();

            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn wrong_credentials_return_unauthorized() {
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new("http://127.0.0.1:1", "p2pool", "p2pool").unwrap(),
            max_batch_size: 20,
            rpcuser: "user".to_string(),
            rpcpassword: "pass".to_string(),
        });

        for credentials in ["wrong:pass", "user:wrong"] {
            let credentials = base64::engine::general_purpose::STANDARD.encode(credentials);
            let request = http::Request::builder()
                .method("POST")
                .uri("/")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Basic {credentials}"))
                .body(Body::from("{}"))
                .unwrap();

            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
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
            rpcuser: "alice".to_string(),
            rpcpassword: "secret".to_string(),
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
    async fn listener_uses_ephemeral_port_and_shuts_down() {
        let config = BitcoinRpcApiConfig {
            enabled: true,
            port: Some(0),
            rpcuser: Some("user".to_string()),
            rpcpassword: Some("pass".to_string()),
            ..BitcoinRpcApiConfig::default()
        };
        let bitcoin_rpc = BitcoinRpcConfig {
            url: "http://127.0.0.1:1".to_string(),
            username: "upstream-user".to_string(),
            password: "upstream-password".to_string(),
        };

        let (shutdown_sender, port) = start_bitcoin_rpc_server(config, &bitcoin_rpc)
            .await
            .unwrap();
        assert_ne!(port, 0);
        shutdown_sender.send(()).unwrap();

        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let rebound_listener = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match tokio::net::TcpListener::bind(address).await {
                    Ok(listener) => return listener,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("Bitcoin RPC gateway did not shut down");
        drop(rebound_listener);
    }

    #[tokio::test]
    #[ignore = "requires a locally running Bitcoin Core regtest node"]
    async fn regtest_matches_bitcoin_core_contract() {
        const SETUP: &str = "set P2POOL_REGTEST_RPC_URL, P2POOL_REGTEST_RPC_USERNAME, and P2POOL_REGTEST_RPC_PASSWORD to run this ignored test";
        const GATEWAY_USERNAME: &str = "contract-user";
        const GATEWAY_PASSWORD: &str = "contract-password";

        let upstream_url = env::var("P2POOL_REGTEST_RPC_URL").expect(SETUP);
        let upstream_username = env::var("P2POOL_REGTEST_RPC_USERNAME").expect(SETUP);
        let upstream_password = env::var("P2POOL_REGTEST_RPC_PASSWORD").expect(SETUP);
        let gateway_config = BitcoinRpcApiConfig {
            enabled: true,
            port: Some(0),
            rpcuser: Some(GATEWAY_USERNAME.to_string()),
            rpcpassword: Some(GATEWAY_PASSWORD.to_string()),
            ..BitcoinRpcApiConfig::default()
        };
        let upstream_config = BitcoinRpcConfig {
            url: upstream_url.clone(),
            username: upstream_username.clone(),
            password: upstream_password.clone(),
        };
        let (shutdown_sender, gateway_port) =
            start_bitcoin_rpc_server(gateway_config, &upstream_config)
                .await
                .expect("failed to start the Bitcoin RPC gateway");
        let gateway_url = format!("http://127.0.0.1:{gateway_port}");
        let http_client = reqwest::Client::new();
        let normalize = |mut response: serde_json::Value| {
            let responses = response
                .as_array_mut()
                .expect("Bitcoin Core and the gateway must return batch arrays");
            responses.sort_by_key(|item| item["id"].as_u64());
            for item in responses.iter_mut() {
                let object = item
                    .as_object_mut()
                    .expect("every batch response must be an object");
                object.remove("id");
                object.remove("jsonrpc");
                if object.get("error").is_some_and(serde_json::Value::is_null) {
                    object.remove("error");
                } else {
                    object.remove("result");
                }
            }
            responses.clone()
        };

        let genesis_request = json!({
            "method": "getblockhash",
            "params": { "height": 0 },
            "id": 0
        });
        let direct_genesis: serde_json::Value = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&genesis_request)
            .send()
            .await
            .expect("failed to call Bitcoin Core directly")
            .error_for_status()
            .expect("Bitcoin Core returned an HTTP error")
            .json()
            .await
            .expect("Bitcoin Core returned invalid JSON");
        let gateway_genesis: serde_json::Value = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&genesis_request)
            .send()
            .await
            .expect("failed to call the Bitcoin RPC gateway")
            .error_for_status()
            .expect("the Bitcoin RPC gateway returned an HTTP error")
            .json()
            .await
            .expect("the Bitcoin RPC gateway returned invalid JSON");
        assert_eq!(
            normalize(json!([direct_genesis.clone()])),
            normalize(json!([gateway_genesis]))
        );
        let genesis_hash = direct_genesis["result"]
            .as_str()
            .expect("getblockhash for regtest genesis must return a hash");

        let requests = json!([
            { "method": "getblockcount", "params": [], "id": 1 },
            { "method": "getbestblockhash", "params": [], "id": 2 },
            { "method": "getblockchaininfo", "params": [], "id": 3 },
            { "method": "getrawmempool", "params": [], "id": 4 },
            { "method": "getnetworkinfo", "params": [], "id": 5 },
            {
                "method": "getblockheader",
                "params": { "blockhash": genesis_hash, "verbose": true },
                "id": 6
            },
            {
                "method": "getblock",
                "params": { "blockhash": genesis_hash, "verbosity": 1 },
                "id": 7
            },
            {
                "method": "gettxout",
                "params": ["0000000000000000000000000000000000000000000000000000000000000000", 0],
                "id": 8
            },
            {
                "method": "getrawtransaction",
                "params": ["0000000000000000000000000000000000000000000000000000000000000000"],
                "id": 9
            }
        ]);
        let direct_batch: serde_json::Value = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&requests)
            .send()
            .await
            .expect("failed to send a batch directly to Bitcoin Core")
            .error_for_status()
            .expect("Bitcoin Core returned an HTTP error for the batch")
            .json()
            .await
            .expect("Bitcoin Core returned invalid batch JSON");
        let gateway_batch: serde_json::Value = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&requests)
            .send()
            .await
            .expect("failed to send a batch to the Bitcoin RPC gateway")
            .error_for_status()
            .expect("the Bitcoin RPC gateway returned an HTTP error for the batch")
            .json()
            .await
            .expect("the Bitcoin RPC gateway returned invalid batch JSON");
        assert!(
            direct_batch.as_array().is_some_and(|responses| responses
                .iter()
                .any(|response| response["id"] == 3 && response["result"]["chain"] == "regtest")),
            "P2POOL_REGTEST_RPC_URL must point to a regtest node"
        );
        assert_eq!(normalize(direct_batch), normalize(gateway_batch));

        let notification = json!({ "jsonrpc": "2.0", "method": "getblockcount" });
        let direct_notification = http_client
            .post(&upstream_url)
            .basic_auth(&upstream_username, Some(&upstream_password))
            .json(&notification)
            .send()
            .await
            .expect("failed to send a notification directly to Bitcoin Core");
        let direct_notification_success = direct_notification.status().is_success();
        let direct_notification_body = direct_notification
            .bytes()
            .await
            .expect("failed to read Bitcoin Core's notification response");
        let gateway_notification = http_client
            .post(&gateway_url)
            .basic_auth(GATEWAY_USERNAME, Some(GATEWAY_PASSWORD))
            .json(&notification)
            .send()
            .await
            .expect("failed to send a notification to the Bitcoin RPC gateway");
        let gateway_notification_success = gateway_notification.status().is_success();
        let gateway_notification_body = gateway_notification
            .bytes()
            .await
            .expect("failed to read the gateway's notification response");
        assert_eq!(direct_notification_success, gateway_notification_success);
        assert_eq!(direct_notification_body, gateway_notification_body);
        assert!(gateway_notification_body.is_empty());

        shutdown_sender
            .send(())
            .expect("Bitcoin RPC gateway stopped before test shutdown");
    }

    #[tokio::test]
    async fn oversized_batch_is_rejected() {
        let mock_server = MockServer::start().await;
        let state = Arc::new(BitcoinRpcState {
            client: BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap(),
            max_batch_size: 2,
            rpcuser: "unused".to_string(),
            rpcpassword: "unused".to_string(),
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

        let response = build_handler_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
    }
}
