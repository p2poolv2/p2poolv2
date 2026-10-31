// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON-RPC 2.0 envelope for the Electrum protocol.
//!
//! Only JSON-RPC 2.0 is accepted, strictly: a request without
//! `"jsonrpc": "2.0"` is an invalid request. Electrum clients (aiorpcx
//! based) speak 2.0, so dropping 1.0 costs no target client. Requests
//! without an `id` are notifications and get no response.

use serde_json::{Map, Value, json};

/// JSON-RPC 2.0 error code: the line is not valid JSON
pub(crate) const PARSE_ERROR: i64 = -32700;
/// JSON-RPC 2.0 error code: the JSON is not a valid request object
pub(crate) const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC 2.0 error code: the method does not exist
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC 2.0 error code: the params do not fit the method
pub(crate) const INVALID_PARAMS: i64 = -32602;
/// JSON-RPC 2.0 error code: the server failed to answer a valid request
pub(crate) const INTERNAL_ERROR: i64 = -32603;
/// Server error (JSON-RPC 2.0 reserves -32000 to -32099 for these): the
/// node is still syncing, so chain data would be partial
pub(crate) const NOT_SYNCED: i64 = -32000;

/// Largest batch request answered. Larger batches get a single
/// invalid request error rather than a truncated answer.
pub(crate) const MAX_BATCH_SIZE: usize = 100;

const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC error object, with the optional `data` member for
/// structured detail.
#[derive(Debug)]
pub(crate) struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attach structured detail, sent as the error's `data` member.
    pub(crate) fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Handle one received line, which is either a single request or a batch,
/// running each valid request through `dispatch`.
///
/// Returns the response to write, or `None` when the line held only
/// notifications. A parse failure or an invalid request is answered with
/// an error object, never by closing the connection. The envelope layer
/// knows no methods: `dispatch` maps a method name and params to a result.
pub(crate) fn handle_line<D>(line: &str, dispatch: &D) -> Option<Value>
where
    D: Fn(&str, &Value) -> Result<Value, RpcError>,
{
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Array(requests)) => handle_batch(requests, dispatch),
        Ok(request) => handle_request(request, dispatch),
        Err(error) => Some(error_message(
            Value::Null,
            RpcError::new(PARSE_ERROR, format!("parse error: {error}")),
        )),
    }
}

/// Answer each request of a batch in order, as an array of responses.
/// Notifications contribute no entry; a batch of only notifications gets
/// no response at all.
fn handle_batch<D>(requests: Vec<Value>, dispatch: &D) -> Option<Value>
where
    D: Fn(&str, &Value) -> Result<Value, RpcError>,
{
    if requests.is_empty() {
        return Some(error_message(
            Value::Null,
            RpcError::new(INVALID_REQUEST, "empty batch"),
        ));
    }
    if requests.len() > MAX_BATCH_SIZE {
        return Some(error_message(
            Value::Null,
            RpcError::new(
                INVALID_REQUEST,
                format!("batch larger than {MAX_BATCH_SIZE} requests"),
            ),
        ));
    }
    let responses: Vec<Value> = requests
        .into_iter()
        .filter_map(|request| handle_request(request, dispatch))
        .collect();
    if responses.is_empty() {
        None
    } else {
        Some(Value::Array(responses))
    }
}

/// Validate a single request and dispatch it to its method.
///
/// An invalid request is always answered, with a null id when its id is
/// absent or not a string, number or null. A valid request without an id
/// is a notification: it runs but gets no response.
fn handle_request<D>(request: Value, dispatch: &D) -> Option<Value>
where
    D: Fn(&str, &Value) -> Result<Value, RpcError>,
{
    let Value::Object(fields) = request else {
        return Some(error_message(
            Value::Null,
            RpcError::new(INVALID_REQUEST, "request must be an object"),
        ));
    };
    let id = match fields.get("id") {
        None => None,
        Some(id @ (Value::String(_) | Value::Number(_) | Value::Null)) => Some(id.clone()),
        Some(_) => {
            return Some(error_message(
                Value::Null,
                RpcError::new(INVALID_REQUEST, "id must be a string, number or null"),
            ));
        }
    };
    match parse_call(&fields) {
        Err(error) => Some(error_message(id.unwrap_or(Value::Null), error)),
        Ok((method, params)) => {
            let outcome = dispatch(method, params);
            id.map(|id| response_message(id, outcome))
        }
    }
}

/// Check the version, method and params members of a request object.
/// Absent params are passed to the method as null.
fn parse_call(fields: &Map<String, Value>) -> Result<(&str, &Value), RpcError> {
    if fields.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(RpcError::new(
            INVALID_REQUEST,
            "jsonrpc must be \"2.0\"; JSON-RPC 1.0 is not supported",
        ));
    }
    let Some(method) = fields.get("method").and_then(Value::as_str) else {
        return Err(RpcError::new(INVALID_REQUEST, "method must be a string"));
    };
    let params = match fields.get("params") {
        None => &Value::Null,
        Some(params @ (Value::Array(_) | Value::Object(_))) => params,
        Some(_) => {
            return Err(RpcError::new(
                INVALID_REQUEST,
                "params must be an array or object",
            ));
        }
    };
    Ok((method, params))
}

fn response_message(id: Value, outcome: Result<Value, RpcError>) -> Value {
    match outcome {
        Ok(result) => json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "result": result }),
        Err(error) => error_message(id, error),
    }
}

fn error_message(id: Value, error: RpcError) -> Value {
    let mut error_object = json!({ "code": error.code, "message": error.message });
    if let Some(data) = error.data {
        error_object["data"] = data;
    }
    json!({ "jsonrpc": JSONRPC_VERSION, "id": id, "error": error_object })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::ping_only_dispatch;

    #[test]
    fn ping_returns_null_result() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]}"#,
            &ping_only_dispatch,
        );
        assert_eq!(
            response,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": null}))
        );
    }

    #[test]
    fn string_id_is_echoed() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":"a","method":"server.ping"}"#,
            &ping_only_dispatch,
        );
        assert_eq!(
            response,
            Some(json!({"jsonrpc": "2.0", "id": "a", "result": null}))
        );
    }

    #[test]
    fn unknown_method_returns_method_not_found_without_result() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":4,"method":"blockchain.scripthash.get_balance","params":[]}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], json!(4));
        assert!(response.get("result").is_none());
        assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
    }

    #[test]
    fn invalid_json_returns_parse_error_with_null_id() {
        let response = handle_line("{not json", &ping_only_dispatch).unwrap();
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], json!(PARSE_ERROR));
    }

    #[test]
    fn request_without_jsonrpc_member_is_invalid() {
        let response = handle_line(
            r#"{"id":5,"method":"server.ping","params":[]}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], json!(5));
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn request_with_jsonrpc_1_0_is_invalid() {
        let response = handle_line(
            r#"{"jsonrpc":"1.0","id":6,"method":"server.ping","params":[]}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], json!(6));
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn request_without_method_is_invalid() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":7,"params":[]}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], json!(7));
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn scalar_params_are_invalid() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":8,"method":"server.ping","params":1}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], json!(8));
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn object_id_is_invalid_and_answered_with_null_id() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"server.ping"}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn non_object_request_is_invalid() {
        let response = handle_line("42", &ping_only_dispatch).unwrap();
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn notification_gets_no_response() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","method":"server.ping","params":[]}"#,
            &ping_only_dispatch,
        );
        assert_eq!(response, None);
    }

    #[test]
    fn invalid_notification_is_answered_with_null_id() {
        let response = handle_line(
            r#"{"method":"server.ping","params":[]}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn batch_is_answered_in_order_as_an_array() {
        let response = handle_line(
            r#"[{"jsonrpc":"2.0","id":1,"method":"server.ping"},{"jsonrpc":"2.0","id":2,"method":"no.such.method"}]"#, &ping_only_dispatch)
        .unwrap();
        assert_eq!(response.as_array().unwrap().len(), 2);
        assert_eq!(
            response[0],
            json!({"jsonrpc": "2.0", "id": 1, "result": null})
        );
        assert_eq!(response[1]["id"], json!(2));
        assert_eq!(response[1]["error"]["code"], json!(METHOD_NOT_FOUND));
    }

    #[test]
    fn batch_omits_notifications() {
        let response = handle_line(
            r#"[{"jsonrpc":"2.0","method":"server.ping"},{"jsonrpc":"2.0","id":2,"method":"server.ping"}]"#, &ping_only_dispatch)
        .unwrap();
        assert_eq!(
            response,
            json!([{"jsonrpc": "2.0", "id": 2, "result": null}])
        );
    }

    #[test]
    fn batch_of_only_notifications_gets_no_response() {
        let response = handle_line(
            r#"[{"jsonrpc":"2.0","method":"server.ping"},{"jsonrpc":"2.0","method":"server.ping"}]"#,
            &ping_only_dispatch,
        );
        assert_eq!(response, None);
    }

    #[test]
    fn batch_answers_non_object_entry_with_invalid_request() {
        let response = handle_line(
            r#"[1,{"jsonrpc":"2.0","id":2,"method":"server.ping"}]"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert_eq!(response[0]["error"]["code"], json!(INVALID_REQUEST));
        assert_eq!(
            response[1],
            json!({"jsonrpc": "2.0", "id": 2, "result": null})
        );
    }

    #[test]
    fn error_data_is_sent_as_data_member() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":9,"method":"server.ping"}"#,
            &|_method, _params| Err(RpcError::new(-32000, "busy").with_data(json!({"height": 7}))),
        )
        .unwrap();
        assert_eq!(
            response["error"],
            json!({"code": -32000, "message": "busy", "data": {"height": 7}})
        );
    }

    #[test]
    fn error_without_data_has_no_data_member() {
        let response = handle_line(
            r#"{"jsonrpc":"2.0","id":10,"method":"no.such.method"}"#,
            &ping_only_dispatch,
        )
        .unwrap();
        assert!(response["error"].get("data").is_none());
    }

    #[test]
    fn empty_batch_is_invalid() {
        let response = handle_line("[]", &ping_only_dispatch).unwrap();
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }

    #[test]
    fn batch_over_cap_returns_single_invalid_request() {
        let requests =
            vec![json!({"jsonrpc": "2.0", "id": 1, "method": "server.ping"}); MAX_BATCH_SIZE + 1];
        let response =
            handle_line(&Value::Array(requests).to_string(), &ping_only_dispatch).unwrap();
        assert!(response.is_object());
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
    }
}
