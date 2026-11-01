// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum method dispatch.
//!
//! `server.*` methods always answer. `blockchain.*` methods read the share
//! chain and answer only once the node is synced; before that they return
//! `NOT_SYNCED`, never partial data.

use crate::protocol::{INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND, NOT_SYNCED, RpcError};
use bitcoin::consensus::encode::serialize_hex;
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    COINBASE_MATURITY, PAYOUT_DEPTH, PRUNE_DEPTH,
};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::writer::StoreError;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// Electrum protocol version this server speaks.
pub(crate) const PROTOCOL_VERSION: &str = "1.4";

/// `PROTOCOL_VERSION` as dotted numeric parts, for range comparison.
const SUPPORTED_PROTOCOL: [u32; 2] = [1, 4];

/// Methods under this prefix read chain data and are gated on sync.
const BLOCKCHAIN_METHOD_PREFIX: &str = "blockchain.";

/// Shown by the wallet on connect. States the deployment requirement and
/// the share UTXO expiry rule.
const BANNER: &str = "P2Poolv2 share chain Electrum server. Use only your own \
fully synced p2poolv2 node: there are no public servers, and a wallet trusts \
the node it connects to completely. Share outputs expire about 14 days after \
the coinbase that created them, and trading them does not reset their expiry.";

const NOT_SYNCED_MESSAGE: &str = "node is syncing the share chain; wallet \
methods are available once it is synced";

/// Run the named method and return its result or a JSON-RPC error.
///
/// A `blockchain.*` method on a node whose confirmed tip is not current
/// (`ChainStoreHandle::is_current`) returns `NOT_SYNCED` before its params
/// are even read, so a syncing node never serves a partial chain.
pub(crate) fn dispatch(
    chain_store_handle: &ChainStoreHandle,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    if method.starts_with(BLOCKCHAIN_METHOD_PREFIX) && !chain_store_handle.is_current() {
        return Err(not_synced_error(chain_store_handle));
    }
    match method {
        "server.version" => server_version(params),
        "server.ping" => Ok(Value::Null),
        "server.banner" => Ok(Value::from(BANNER)),
        "server.features" => server_features(chain_store_handle),
        "blockchain.block.header" => block_header(chain_store_handle, params),
        _ => Err(RpcError::new(
            METHOD_NOT_FOUND,
            format!("unknown method {method}"),
        )),
    }
}

/// The `NOT_SYNCED` error, with sync progress in its `data` member:
/// confirmed and candidate tip heights and the confirmed tip's age in
/// seconds. A field the store cannot supply is null; building the error
/// never fails.
fn not_synced_error(chain_store_handle: &ChainStoreHandle) -> RpcError {
    let confirmed_tip_height = chain_store_handle.get_tip_height().ok().flatten();
    let candidate_tip_height = chain_store_handle.get_candidate_tip_height().ok().flatten();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs());
    let tip_age_secs = chain_store_handle
        .get_chain_tip_header()
        .ok()
        .zip(now_secs)
        .map(|(tip_header, now_secs)| now_secs.saturating_sub(u64::from(tip_header.time)));
    RpcError::new(NOT_SYNCED, NOT_SYNCED_MESSAGE).with_data(json!({
        "confirmed_tip_height": confirmed_tip_height,
        "candidate_tip_height": candidate_tip_height,
        "tip_age_secs": tip_age_secs,
    }))
}

/// `server.version [client_name, protocol_version]`.
///
/// `protocol_version` is absent, a version string, or a `[min, max]` pair
/// of version strings. The request is accepted when `PROTOCOL_VERSION`
/// falls in the range; a single string is a range of one. Returns
/// `[software_version, PROTOCOL_VERSION]`; anything else is
/// `INVALID_PARAMS`, so a client never runs against semantics it does not
/// know.
fn server_version(params: &Value) -> Result<Value, RpcError> {
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
/// with the network and the depths a wallet needs to judge output maturity
/// and expiry without hardcoding consensus constants.
fn server_features(chain_store_handle: &ChainStoreHandle) -> Result<Value, RpcError> {
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
        },
    }))
}

/// `blockchain.block.header [height, cp_height]`: hex of the
/// consensus-encoded `ShareHeader` of the confirmed block at `height`.
///
/// This is the variable-width share header (uncles, addresses, coinbase
/// proof), not an 80-byte bitcoin header; decode it with `ShareHeader`'s
/// `Decodable`. A height above the confirmed tip is `INVALID_PARAMS`; a
/// failed store read is `INTERNAL_ERROR`.
///
/// `cp_height` must be absent or 0. A checkpoint proof (a merkle branch
/// from the header to a root over all headers up to `cp_height`) lets an
/// SPV client check headers from an untrusted server against a root
/// hardcoded in the client. Wallets here talk only to their operator's own
/// fully synced node, which they trust completely, so a proof against a
/// root that same node computed adds no security. Serving one would also
/// need a merkle tree over every confirmed share header, maintained across
/// reorgs.
fn block_header(chain_store_handle: &ChainStoreHandle, params: &Value) -> Result<Value, RpcError> {
    let Some(height) = param(params, 0, "height")
        .and_then(Value::as_u64)
        .and_then(|height| u32::try_from(height).ok())
    else {
        return Err(RpcError::new(
            INVALID_PARAMS,
            "height must be an integer from 0 to 4294967295",
        ));
    };
    match param(params, 1, "cp_height") {
        None | Some(Value::Null) => {}
        Some(cp_height) if cp_height.as_u64() == Some(0) => {}
        Some(_) => {
            return Err(RpcError::new(
                INVALID_PARAMS,
                "checkpoint proofs are not supported; cp_height must be 0",
            ));
        }
    }
    let tip_height = chain_store_handle
        .get_tip_height()
        .map_err(store_read_error)?
        .ok_or_else(|| RpcError::new(INTERNAL_ERROR, "no confirmed share chain"))?;
    if height > tip_height {
        return Err(RpcError::new(
            INVALID_PARAMS,
            format!("height {height} is above the confirmed tip {tip_height}"),
        ));
    }
    let header = chain_store_handle
        .get_confirmed_at_height(height)
        .and_then(|blockhash| chain_store_handle.get_share_header(&blockhash))
        .map_err(store_read_error)?;
    Ok(Value::from(serialize_hex(&header)))
}

fn store_read_error(error: StoreError) -> RpcError {
    RpcError::new(INTERNAL_ERROR, format!("share chain read failed: {error}"))
}

fn software_version() -> String {
    format!("P2Poolv2 {}", env!("CARGO_PKG_VERSION"))
}

/// A parameter by position, or by name when params are an object; the
/// Electrum protocol allows both.
fn param<'a>(params: &'a Value, index: usize, name: &str) -> Option<&'a Value> {
    match params {
        Value::Array(values) => values.get(index),
        Value::Object(fields) => fields.get(name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::build_current_test_chain;
    use bitcoin::consensus::encode::deserialize_hex;
    use p2poolv2_lib::shares::share_block::ShareHeader;
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
    async fn unknown_server_method_is_not_found() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(&chain_store_handle, "server.no_such_method", &json!([])).unwrap_err();
        assert_eq!(error.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn features_report_genesis_hash_and_p2pool_depths() {
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
            })
        );
    }

    #[tokio::test]
    async fn features_without_genesis_is_internal_error() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;
        let error = dispatch(&chain_store_handle, "server.features", &json!([])).unwrap_err();
        assert_eq!(error.code, INTERNAL_ERROR);
    }

    /// `build_confirmed_test_chain` stamps blocks in 2023, so its tip is
    /// stale and the node counts as syncing.
    #[tokio::test]
    async fn blockchain_method_on_stale_tip_is_not_synced_with_progress() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([1])).unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        let data = error.data.unwrap();
        assert_eq!(data["confirmed_tip_height"], json!(2));
        assert_eq!(data["candidate_tip_height"], json!(2));
        assert!(data["tip_age_secs"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn blockchain_method_on_empty_store_is_not_synced_with_null_progress() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(false).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([0])).unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
        assert_eq!(
            error.data.unwrap(),
            json!({
                "confirmed_tip_height": null,
                "candidate_tip_height": null,
                "tip_age_secs": null,
            })
        );
    }

    #[tokio::test]
    async fn server_method_on_stale_tip_still_answers() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;

        assert!(dispatch(&chain_store_handle, "server.features", &json!([])).is_ok());
    }

    /// A current tip passes the gate, so an unknown blockchain method falls
    /// through to method not found.
    #[tokio::test]
    async fn blockchain_method_on_current_tip_passes_gate() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.no_such_method", &json!([])).unwrap_err();

        assert_eq!(error.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn block_header_returns_encoded_confirmed_header() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 3).await;

        let header_hex =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([2])).unwrap();

        let decoded: ShareHeader = deserialize_hex(header_hex.as_str().unwrap()).unwrap();
        assert_eq!(decoded, blocks[2].header);
    }

    #[tokio::test]
    async fn block_header_at_height_zero_is_genesis() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let header_hex =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([0])).unwrap();

        let decoded: ShareHeader = deserialize_hex(header_hex.as_str().unwrap()).unwrap();
        assert_eq!(decoded, genesis_for_tests().header);
    }

    #[tokio::test]
    async fn block_header_accepts_named_params_and_zero_cp_height() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;

        let header_hex = dispatch(
            &chain_store_handle,
            "blockchain.block.header",
            &json!({"height": 1, "cp_height": 0}),
        )
        .unwrap();

        let decoded: ShareHeader = deserialize_hex(header_hex.as_str().unwrap()).unwrap();
        assert_eq!(decoded, blocks[1].header);
    }

    #[tokio::test]
    async fn block_header_above_tip_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([3])).unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn block_header_with_nonzero_cp_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.block.header",
            &json!([1, 1]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn block_header_with_negative_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([-1])).unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn block_header_with_string_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.block.header",
            &json!(["1"]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn block_header_without_height_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error =
            dispatch(&chain_store_handle, "blockchain.block.header", &json!([])).unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn block_header_with_height_above_u32_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.block.header",
            &json!([u64::from(u32::MAX) + 1]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }
}
