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

use crate::api::btcrpc::error::{
    INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, RpcError,
    bitcoind_error_to_rpc_error,
};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use bitcoindrpc::BitcoindRpcClient;
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

#[derive(Clone)]
pub(crate) struct BtcRpcState {
    pub(crate) client: Arc<BitcoindRpcClient>,
    pub(crate) max_batch_size: usize,
    pub(crate) rpcuser: Option<String>,
    pub(crate) rpcpassword: Option<String>,
}

fn make_success_response(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    json!({ "result": result, "error": null, "id": id })
}

fn make_error_response(id: serde_json::Value, error: RpcError) -> serde_json::Value {
    json!({
        "result": null,
        "error": { "code": error.code, "message": error.message },
        "id": id
    })
}

fn as_positional(
    method: &str,
    params: &serde_json::Value,
) -> Result<Vec<serde_json::Value>, RpcError> {
    match params {
        serde_json::Value::Array(arr) => Ok(arr.clone()),
        serde_json::Value::Object(obj) => Ok(normalize_named_params(method, obj)),
        serde_json::Value::Null => Ok(vec![]),
        _ => Err(RpcError {
            code: INVALID_PARAMS,
            message: "params must be an array or object".to_string(),
        }),
    }
}

fn normalize_named_params(
    method: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    let param_names: &[&str] = match method {
        "getblock" => &["blockhash", "verbosity"],
        "getblockfilter" => &["blockhash", "filtertype"],
        "getblockhash" => &["height"],
        "getblockheader" => &["blockhash", "verbose"],
        "getmempoolentry" => &["txid"],
        "getrawmempool" => &["verbose", "mempool_sequence"],
        "getrawtransaction" => &["txid", "verbose", "blockhash"],
        "gettxout" => &["txid", "n", "include_mempool"],
        "estimatesmartfee" => &["conf_target", "estimate_mode"],
        "sendrawtransaction" => &["hexstring", "maxfeerate"],
        "testmempoolaccept" => &["rawtxs", "maxfeerate"],
        "decoderawtransaction" => &["hexstring"],
        _ => &[],
    };

    let mut result: Vec<serde_json::Value> = param_names
        .iter()
        .map(|name| obj.get(*name).cloned().unwrap_or(serde_json::Value::Null))
        .collect();

    // Trim trailing nulls so optional params use their bitcoind defaults.
    while result.last() == Some(&serde_json::Value::Null) {
        result.pop();
    }
    result
}

fn require_str(params: &[serde_json::Value], idx: usize, name: &str) -> Result<String, RpcError> {
    params
        .get(idx)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: format!("Missing required parameter: {name}"),
        })
}

fn require_u64(params: &[serde_json::Value], idx: usize, name: &str) -> Result<u64, RpcError> {
    params
        .get(idx)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: format!("Missing required parameter: {name}"),
        })
}

fn require_str_array(
    params: &[serde_json::Value],
    idx: usize,
    name: &str,
) -> Result<Vec<String>, RpcError> {
    params
        .get(idx)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: format!("Missing required parameter: {name}"),
        })
}

async fn dispatch(
    client: &BitcoindRpcClient,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, RpcError> {
    let p = as_positional(method, params)?;

    match method {
        // Chain
        "getbestblockhash" => client
            .getbestblockhash()
            .await
            .map(serde_json::Value::String)
            .map_err(bitcoind_error_to_rpc_error),

        "getblock" => {
            let blockhash = require_str(&p, 0, "blockhash")?;
            let verbosity = p.get(1).and_then(|v| v.as_u64()).map(|v| v as u32);
            client
                .getblock(&blockhash, verbosity)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        "getblockchaininfo" => client
            .request::<serde_json::Value>("getblockchaininfo", vec![])
            .await
            .map_err(bitcoind_error_to_rpc_error),

        "getblockcount" => client
            .getblockcount()
            .await
            .map(|n| serde_json::Value::Number(n.into()))
            .map_err(bitcoind_error_to_rpc_error),

        "getblockfilter" => {
            let blockhash = require_str(&p, 0, "blockhash")?;
            let filtertype = p.get(1).and_then(|v| v.as_str()).map(String::from);
            client
                .getblockfilter(&blockhash, filtertype.as_deref())
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        "getblockhash" => {
            let height = require_u64(&p, 0, "height")?;
            client
                .getblockhash(height)
                .await
                .map(serde_json::Value::String)
                .map_err(bitcoind_error_to_rpc_error)
        }

        "getblockheader" => {
            let blockhash = require_str(&p, 0, "blockhash")?;
            let verbose = p.get(1).and_then(|v| v.as_bool());
            client
                .getblockheader(&blockhash, verbose)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        // Mempool
        "getmempoolentry" => {
            let txid = require_str(&p, 0, "txid")?;
            client
                .getmempoolentry(&txid)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        "getnetworkinfo" => client
            .getnetworkinfo()
            .await
            .map_err(bitcoind_error_to_rpc_error),

        "getrawmempool" => {
            let verbose = p.first().and_then(|v| v.as_bool());
            let mempool_sequence = p.get(1).and_then(|v| v.as_bool());
            client
                .getrawmempool(verbose, mempool_sequence)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        "getrawtransaction" => {
            let txid = require_str(&p, 0, "txid")?;
            let verbose = p.get(1).and_then(|v| v.as_bool());
            let blockhash = p.get(2).and_then(|v| v.as_str()).map(String::from);
            client
                .getrawtransaction(&txid, verbose, blockhash.as_deref())
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        "gettxout" => {
            let txid = require_str(&p, 0, "txid")?;
            let n = require_u64(&p, 1, "n")? as u32;
            let include_mempool = p.get(2).and_then(|v| v.as_bool());
            client
                .gettxout(&txid, n, include_mempool)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        // Fees / broadcast / validation
        "estimatesmartfee" => {
            let conf_target = require_u64(&p, 0, "conf_target")? as u32;
            let estimate_mode = p.get(1).and_then(|v| v.as_str()).map(String::from);
            let result = client
                .estimatesmartfee(conf_target, estimate_mode.as_deref())
                .await
                .map_err(bitcoind_error_to_rpc_error)?;
            serde_json::to_value(result).map_err(|e| RpcError {
                code: INTERNAL_ERROR,
                message: format!("Failed to serialize response: {e}"),
            })
        }

        "sendrawtransaction" => {
            let hexstring = require_str(&p, 0, "hexstring")?;
            let maxfeerate = p.get(1).and_then(|v| v.as_f64());
            client
                .sendrawtransaction(&hexstring, maxfeerate)
                .await
                .map(serde_json::Value::String)
                .map_err(bitcoind_error_to_rpc_error)
        }

        "testmempoolaccept" => {
            let rawtxs = require_str_array(&p, 0, "rawtxs")?;
            let maxfeerate = p.get(1).and_then(|v| v.as_f64());
            client
                .testmempoolaccept(rawtxs, maxfeerate)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        // Decode
        "decoderawtransaction" => {
            let hexstring = require_str(&p, 0, "hexstring")?;
            client
                .decoderawtransaction_hex(&hexstring)
                .await
                .map_err(bitcoind_error_to_rpc_error)
        }

        _ => Err(RpcError {
            code: METHOD_NOT_FOUND,
            message: format!("Method not found: {method}"),
        }),
    }
}

async fn handle_single(client: &BitcoindRpcClient, req: &serde_json::Value) -> serde_json::Value {
    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);

    let Some(method) = req.get("method").and_then(|v| v.as_str()) else {
        return make_error_response(
            id,
            RpcError {
                code: INVALID_REQUEST,
                message: "Missing or invalid method field".to_string(),
            },
        );
    };

    let params = req
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Array(vec![]));

    match dispatch(client, method, &params).await {
        Ok(result) => make_success_response(id, result),
        Err(e) => make_error_response(id, e),
    }
}

pub(crate) async fn btcrpc_handler(State(state): State<Arc<BtcRpcState>>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("btcrpc: failed to parse request body: {e}");
            return Json(make_error_response(
                serde_json::Value::Null,
                RpcError {
                    code: PARSE_ERROR,
                    message: format!("Parse error: {e}"),
                },
            ))
            .into_response();
        }
    };

    match &value {
        serde_json::Value::Array(requests) => {
            if requests.len() > state.max_batch_size {
                return Json(make_error_response(
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
            for req in requests {
                responses.push(handle_single(&state.client, req).await);
            }
            Json(serde_json::Value::Array(responses)).into_response()
        }
        _ => Json(handle_single(&state.client, &value).await).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::btcrpc::router::build_btcrpc_router;
    use axum::http;
    use bitcoindrpc::BitcoindRpcClient;
    use tower::ServiceExt;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    async fn make_request(
        app: axum::Router,
        body: serde_json::Value,
        auth: Option<&str>,
    ) -> http::Response<axum::body::Body> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json");
        if let Some(creds) = auth {
            builder = builder.header("Authorization", format!("Basic {creds}"));
        }
        let request = builder
            .body(http_body_util::Full::new(bytes::Bytes::from(
                serde_json::to_vec(&body).unwrap(),
            )))
            .unwrap();
        app.oneshot(request).await.unwrap()
    }

    async fn parse_body(response: http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn make_state(mock_uri: &str, max_batch_size: usize) -> Arc<BtcRpcState> {
        let client = BitcoindRpcClient::new(mock_uri, "p2pool", "p2pool").unwrap();
        Arc::new(BtcRpcState {
            client: Arc::new(client),
            max_batch_size,
            rpcuser: None,
            rpcpassword: None,
        })
    }

    // (a) Method forwards correctly and relays the result
    #[tokio::test]
    async fn test_dispatch_getblockcount_forwards_and_relays() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": 800000,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let state = make_state(&mock_server.uri(), 20);
        let app = build_btcrpc_router(state);

        let response = make_request(
            app,
            json!({"method": "getblockcount", "params": [], "id": 1}),
            None,
        )
        .await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        assert_eq!(body["result"], 800000);
        assert!(body["error"].is_null());
        assert_eq!(body["id"], 1);
    }

    // (b) Upstream error is relayed with code and message preserved
    #[tokio::test]
    async fn test_upstream_error_code_and_message_preserved() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": {
                    "code": -5,
                    "message": "No such mempool or blockchain transaction"
                },
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let state = make_state(&mock_server.uri(), 20);
        let app = build_btcrpc_router(state);

        let response = make_request(
            app,
            json!({"method": "getrawtransaction", "params": ["deadbeef"], "id": 2}),
            None,
        )
        .await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], -5);
        assert_eq!(
            body["error"]["message"],
            "No such mempool or blockchain transaction"
        );
        assert_eq!(body["id"], 2);
    }

    // (c) Unknown / wallet method returns -32601
    #[tokio::test]
    async fn test_unknown_method_returns_method_not_found() {
        let mock_server = MockServer::start().await;
        let state = make_state(&mock_server.uri(), 20);
        let app = build_btcrpc_router(state);

        let response = make_request(
            app,
            json!({"method": "listunspent", "params": [], "id": 3}),
            None,
        )
        .await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(body["id"], 3);
    }

    // (d) Batch request returns ordered array of responses
    #[tokio::test]
    async fn test_batch_returns_ordered_responses() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": 100,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "method": "getbestblockhash",
                "params": [],
                "id": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": "000000000000abc",
                "error": null,
                "id": 1
            })))
            .mount(&mock_server)
            .await;

        let state = make_state(&mock_server.uri(), 20);
        let app = build_btcrpc_router(state);

        let batch = json!([
            {"method": "getblockcount", "params": [], "id": 10},
            {"method": "getbestblockhash", "params": [], "id": 11}
        ]);

        let response = make_request(app, batch, None).await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        let arr = body.as_array().expect("expected array response");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], 10);
        assert_eq!(arr[0]["result"], 100);
        assert_eq!(arr[1]["id"], 11);
        assert_eq!(arr[1]["result"], "000000000000abc");
    }

    // (e) Bad credentials return 401
    #[tokio::test]
    async fn test_missing_credentials_return_401() {
        let mock_server = MockServer::start().await;
        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let state = Arc::new(BtcRpcState {
            client: Arc::new(client),
            max_batch_size: 20,
            rpcuser: Some("user".to_string()),
            rpcpassword: Some("pass".to_string()),
        });
        let app = build_btcrpc_router(state);

        let response = make_request(
            app,
            json!({"method": "getblockcount", "params": [], "id": 1}),
            None,
        )
        .await;

        assert_eq!(response.status(), 401);
    }

    // (f) Oversized batch is rejected before dispatch
    #[tokio::test]
    async fn test_oversized_batch_rejected() {
        let mock_server = MockServer::start().await;
        let state = make_state(&mock_server.uri(), 2);
        let app = build_btcrpc_router(state);

        let batch = json!([
            {"method": "getblockcount", "params": [], "id": 1},
            {"method": "getblockcount", "params": [], "id": 2},
            {"method": "getblockcount", "params": [], "id": 3}
        ]);

        let response = make_request(app, batch, None).await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        assert!(body["result"].is_null());
        assert_eq!(body["error"]["code"], INVALID_REQUEST);
    }

    // Auth: valid credentials are accepted
    #[tokio::test]
    async fn test_valid_credentials_accepted() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "method": "getblockcount",
                "params": [],
                "id": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": 42,
                "error": null,
                "id": 0
            })))
            .mount(&mock_server)
            .await;

        let client = BitcoindRpcClient::new(&mock_server.uri(), "p2pool", "p2pool").unwrap();
        let state = Arc::new(BtcRpcState {
            client: Arc::new(client),
            max_batch_size: 20,
            rpcuser: Some("alice".to_string()),
            rpcpassword: Some("secret".to_string()),
        });
        let app = build_btcrpc_router(state);

        // base64("alice:secret")
        use base64::Engine;
        let creds = base64::engine::general_purpose::STANDARD.encode("alice:secret");

        let response = make_request(
            app,
            json!({"method": "getblockcount", "params": [], "id": 1}),
            Some(&creds),
        )
        .await;

        assert_eq!(response.status(), 200);
        let body = parse_body(response).await;
        assert_eq!(body["result"], 42);
    }
}
