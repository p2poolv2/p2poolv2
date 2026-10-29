// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum method dispatch. Only the `server.*` methods exist so far;
//! wallet methods arrive with the share chain scripthash indexes.

use crate::protocol::{METHOD_NOT_FOUND, RpcError};
use serde_json::{Value, json};

/// Electrum protocol version this server reports.
pub(crate) const PROTOCOL_VERSION: &str = "1.4";

/// Shown by the wallet on connect. States the deployment requirement and
/// the share UTXO expiry rule.
const BANNER: &str = "P2Poolv2 share chain Electrum server. Use only your own \
fully synced p2poolv2 node: there are no public servers, and a wallet trusts \
the node it connects to completely. Share outputs expire about 14 days after \
the coinbase that created them, and trading them does not reset their expiry.";

/// Run the named method and return its result or a JSON-RPC error.
pub(crate) fn dispatch(method: &str, _params: &Value) -> Result<Value, RpcError> {
    match method {
        "server.version" => Ok(server_version()),
        "server.ping" => Ok(Value::Null),
        "server.banner" => Ok(Value::from(BANNER)),
        _ => Err(RpcError::new(
            METHOD_NOT_FOUND,
            format!("unknown method {method}"),
        )),
    }
}

/// Returns `[software_version, protocol_version]`.
///
/// The client's requested version is not negotiated yet. Rejecting
/// unknown versions will land with the wallet methods, once there are
/// semantics a client could misunderstand.
fn server_version() -> Value {
    json!([
        format!("P2Poolv2 {}", env!("CARGO_PKG_VERSION")),
        PROTOCOL_VERSION
    ])
}
