// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blockchain.block.*`: confirmed share headers by height.

use crate::methods::{param, store_read_error};
use crate::protocol::{INTERNAL_ERROR, INVALID_PARAMS, RpcError};
use bitcoin::consensus::encode::serialize_hex;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use serde_json::Value;

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
pub(crate) fn block_header(
    chain_store_handle: &ChainStoreHandle,
    params: &Value,
) -> Result<Value, RpcError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::dispatch;
    use crate::test_utils::build_current_test_chain;
    use bitcoin::consensus::encode::deserialize_hex;
    use p2poolv2_lib::shares::share_block::ShareHeader;
    use p2poolv2_lib::test_utils::{genesis_for_tests, setup_test_chain_store_handle};
    use serde_json::json;

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
