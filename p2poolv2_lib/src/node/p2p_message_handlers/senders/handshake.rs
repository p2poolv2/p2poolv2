// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::messages::{HandshakeData, Message};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::writer::StoreError;
use tracing::error;

/// Build a handshake message carrying our confirmed tip height and hash.
///
/// Both sides of a connection send this on establishment so each can determine
/// whether it needs to sync headers from the other. Synchronous so the node's
/// event loop can build and send it on the swarm directly, without awaiting a
/// send on `swarm_tx`.
pub fn build_handshake_message(
    chain_store_handle: &ChainStoreHandle,
) -> Result<Message, StoreError> {
    let tip_height = chain_store_handle
        .get_tip_height()
        .map_err(|error| {
            error!("Failed to read tip height from store: {error}");
            error
        })?
        .unwrap_or(0);

    let tip_hash = chain_store_handle.get_chain_tip().map_err(|error| {
        error!("Failed to read chain tip from store: {error}");
        error
    })?;

    Ok(Message::Handshake(HandshakeData {
        tip_height,
        tip_hash,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use std::str::FromStr;

    #[test]
    fn test_build_handshake_with_existing_chain() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let tip_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(42)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(tip_hash));

        match build_handshake_message(&chain_store_handle) {
            Ok(Message::Handshake(data)) => {
                assert_eq!(data.tip_height, 42);
                assert_eq!(data.tip_hash, tip_hash);
            }
            other => panic!("Expected Handshake message, got {other:?}"),
        }
    }

    #[test]
    fn test_build_handshake_fresh_node_with_genesis() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let genesis_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .unwrap();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(0)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(move || Ok(genesis_hash));

        match build_handshake_message(&chain_store_handle) {
            Ok(Message::Handshake(data)) => {
                assert_eq!(data.tip_height, 0);
                assert_eq!(data.tip_hash, genesis_hash);
            }
            other => panic!("Expected Handshake message, got {other:?}"),
        }
    }

    #[test]
    fn test_build_handshake_tip_height_error_propagates() {
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Err(StoreError::Database("disk failure".into())));

        let result = build_handshake_message(&chain_store_handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disk failure"));
    }

    #[test]
    fn test_build_handshake_chain_tip_error_propagates() {
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_get_tip_height()
            .times(1)
            .return_once(|| Ok(Some(5)));

        chain_store_handle
            .expect_get_chain_tip()
            .times(1)
            .return_once(|| Err(StoreError::Database("corrupt store".into())));

        let result = build_handshake_message(&chain_store_handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("corrupt store"));
    }
}
