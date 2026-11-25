// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `server.*` methods: protocol version negotiation, banner and features.
//! They answer whether or not the node is synced.

use crate::methods::blockchain::scripthash::HISTORY_PAGE_SIZE;
use crate::methods::param;
use crate::protocol::{INTERNAL_ERROR, INVALID_PARAMS, RpcError};
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    COINBASE_MATURITY, PAYOUT_DEPTH, PRUNE_DEPTH,
};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use serde_json::{Value, json};

/// Electrum protocol version this server speaks.
pub(crate) const PROTOCOL_VERSION: &str = "1.4";

/// `PROTOCOL_VERSION` as dotted numeric parts, for range comparison.
const SUPPORTED_PROTOCOL: [u32; 2] = [1, 4];

/// Shown by the wallet on connect. States the deployment requirement and
/// the share UTXO expiry rule.
pub(crate) const BANNER: &str = "P2Poolv2 share chain Electrum server. Use only your own \
fully synced p2poolv2 node: there are no public servers, and a wallet trusts \
the node it connects to completely. Share outputs expire about 14 days after \
the coinbase that created them, and trading them does not reset their expiry.";

/// `server.version [client_name, protocol_version]`.
///
/// `protocol_version` is absent, a version string, or a `[min, max]` pair
/// of version strings. The request is accepted when `PROTOCOL_VERSION`
/// falls in the range; a single string is a range of one. Returns
/// `[software_version, PROTOCOL_VERSION]`; anything else is
/// `INVALID_PARAMS`, so a client never runs against semantics it does not
/// know.
pub(crate) fn server_version(params: &Value) -> Result<Value, RpcError> {
    match param(params, 0, "client_name") {
        None | Some(Value::Null | Value::String(_)) => {}
        Some(_) => {
            return Err(RpcError::new(
                INVALID_PARAMS,
                "client_name must be a string",
            ));
        }
    }
    let (minimum, maximum) = requested_protocol_range(param(params, 1, "protocol_version"))?;
    let supported = SUPPORTED_PROTOCOL.as_slice();
    if minimum.as_slice() <= supported && supported <= maximum.as_slice() {
        Ok(json!([software_version(), PROTOCOL_VERSION]))
    } else {
        Err(RpcError::new(
            INVALID_PARAMS,
            format!("unsupported protocol version; this server speaks {PROTOCOL_VERSION}"),
        ))
    }
}

/// The `[min, max]` protocol range a client asked for. Absent means the
/// supported version.
fn requested_protocol_range(
    protocol_version: Option<&Value>,
) -> Result<(Vec<u32>, Vec<u32>), RpcError> {
    let malformed = || {
        RpcError::new(
            INVALID_PARAMS,
            "protocol_version must be a version string or a [min, max] pair of them",
        )
    };
    match protocol_version {
        None | Some(Value::Null) => Ok((SUPPORTED_PROTOCOL.to_vec(), SUPPORTED_PROTOCOL.to_vec())),
        Some(Value::String(version)) => {
            let version = parse_protocol_version(version).ok_or_else(malformed)?;
            Ok((version.clone(), version))
        }
        Some(Value::Array(range)) => match range.as_slice() {
            [Value::String(minimum), Value::String(maximum)] => Ok((
                parse_protocol_version(minimum).ok_or_else(malformed)?,
                parse_protocol_version(maximum).ok_or_else(malformed)?,
            )),
            _ => Err(malformed()),
        },
        Some(_) => Err(malformed()),
    }
}

/// Dotted numeric version, trailing zero parts dropped so `1.4` and
/// `1.4.0` compare equal. `None` unless every part is a number.
fn parse_protocol_version(version: &str) -> Option<Vec<u32>> {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    while parts.last() == Some(&0) {
        parts.pop();
    }
    Some(parts)
}

/// `server.features`: the standard Electrum fields plus a `p2pool` object
/// with the network, the depths a wallet needs to judge output maturity
/// and expiry without hardcoding consensus constants, and the
/// `blockchain.scripthash.get_history` page size.
pub(crate) fn server_features(chain_store_handle: &ChainStoreHandle) -> Result<Value, RpcError> {
    let genesis_hash = chain_store_handle
        .get_genesis_blockhash()
        .ok_or_else(|| RpcError::new(INTERNAL_ERROR, "share chain genesis is not stored"))?;
    Ok(json!({
        "genesis_hash": genesis_hash.to_string(),
        "hosts": {},
        "protocol_min": PROTOCOL_VERSION,
        "protocol_max": PROTOCOL_VERSION,
        "server_version": software_version(),
        "hash_function": "sha256",
        "pruning": null,
        "p2pool": {
            "network": chain_store_handle.network().to_string(),
            "payout_depth": PAYOUT_DEPTH,
            "coinbase_maturity": COINBASE_MATURITY,
            "prune_depth": PRUNE_DEPTH,
            "scripthash_history_page_size": HISTORY_PAGE_SIZE,
        },
    }))
}

fn software_version() -> String {
    format!("P2Poolv2 {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::dispatch;
    use p2poolv2_lib::test_utils::{
        build_confirmed_test_chain, genesis_for_tests, setup_test_chain_store_handle,
    };

    #[test]
    fn supported_protocol_matches_protocol_version() {
        assert_eq!(
            parse_protocol_version(PROTOCOL_VERSION),
            Some(SUPPORTED_PROTOCOL.to_vec())
        );
    }

    #[tokio::test]
    async fn version_without_protocol_version_is_accepted() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let result = dispatch(&chain_store_handle, "server.version", &Value::Null).unwrap();
        assert_eq!(result, json!([software_version(), "1.4"]));
    }

    #[tokio::test]
    async fn version_matching_string_is_accepted() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let result = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", "1.4"]),
        )
        .unwrap();
        assert_eq!(result, json!([software_version(), "1.4"]));
    }

    #[tokio::test]
    async fn version_with_trailing_zero_is_accepted() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let result = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", "1.4.0"]),
        );
        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[tokio::test]
    async fn version_range_including_supported_is_accepted() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let result = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", ["1.2", "1.6"]]),
        );
        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[tokio::test]
    async fn version_named_params_are_accepted() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let params = json!({"client_name": "cli", "protocol_version": "1.4"});
        let result = dispatch(&chain_store_handle, "server.version", &params);
        assert!(result.is_ok(), "unexpected: {result:?}");
    }

    #[tokio::test]
    async fn version_older_than_supported_is_rejected() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", "1.2"]),
        )
        .unwrap_err();
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn version_range_above_supported_is_rejected() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", ["1.5", "1.6"]]),
        )
        .unwrap_err();
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn version_non_numeric_is_rejected() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(
            &chain_store_handle,
            "server.version",
            &json!(["cli", "x.y"]),
        )
        .unwrap_err();
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn version_as_number_is_rejected() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error =
            dispatch(&chain_store_handle, "server.version", &json!(["cli", 1.4])).unwrap_err();
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn version_with_non_string_client_name_is_rejected() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error =
            dispatch(&chain_store_handle, "server.version", &json!([5, "1.4"])).unwrap_err();
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn ping_returns_null() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        assert_eq!(
            dispatch(&chain_store_handle, "server.ping", &json!([])).unwrap(),
            Value::Null
        );
    }

    #[tokio::test]
    async fn banner_states_own_node_requirement_and_expiry() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let banner = dispatch(&chain_store_handle, "server.banner", &json!([])).unwrap();
        let banner = banner.as_str().unwrap();
        assert!(banner.contains("your own"));
        assert!(banner.contains("expire"));
    }

    #[tokio::test]
    async fn features_report_genesis_hash_p2pool_depths_and_page_size() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;

        let features = dispatch(&chain_store_handle, "server.features", &json!([])).unwrap();

        assert_eq!(
            features["genesis_hash"],
            json!(genesis_for_tests().block_hash().to_string())
        );
        assert_eq!(features["protocol_min"], json!("1.4"));
        assert_eq!(features["protocol_max"], json!("1.4"));
        assert_eq!(
            features["p2pool"],
            json!({
                "network": "signet",
                "payout_depth": PAYOUT_DEPTH,
                "coinbase_maturity": COINBASE_MATURITY,
                "prune_depth": PRUNE_DEPTH,
                "scripthash_history_page_size": HISTORY_PAGE_SIZE,
            })
        );
    }

    #[tokio::test]
    async fn features_without_genesis_is_internal_error() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(&chain_store_handle, "server.features", &json!([])).unwrap_err();
        assert_eq!(error.code, INTERNAL_ERROR);
    }
}
