// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use crate::node::request_response_handler::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::validation_worker::{ValidationEvent, ValidationSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation;
use std::error::Error;
use tracing::{debug, error, info, warn};

/// Handle a ShareBlock received from a peer.
///
/// Called both when a peer broadcasts a new share directly (inbound request)
/// and when we receive a share in response to a GetData request (response).
///
/// Before storing, checks that the block is not a duplicate and that
/// the header is already on the candidate chain or has valid proof of
/// work.
///
/// This prevents peers from flooding the database with invalid
/// headers. During sync, headers arrive before full blocks so the
/// candidate chain check passes. For broadcast blocks, PoW is
/// verified.
///
/// After storing, notifies the block fetcher and sends the block to
/// the validation worker for full asynchronous validation. On
/// successful validation the worker emits OrganiseEvent::Block and
/// SwarmSend::Inv.
pub async fn handle_share_block(
    _peer_id: libp2p::PeerId,
    share_block: ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received share block: {:?}", share_block);

    let block_hash = share_block.block_hash();

    // Skip blocks we already have in the store (cheap key-existence check,
    // avoids deserializing the full share block).
    if chain_store_handle.share_block_exists(&block_hash) {
        debug!("Share block {block_hash} already in store, skipping");
        return Ok(());
    }

    // Allow blocks whose header is already on the candidate chain (synced
    // headers arrive before full blocks). Otherwise require valid proof of
    // work to prevent peers from flooding our database with garbage headers.
    if !chain_store_handle.is_candidate(&block_hash) {
        if let Err(validation_error) =
            validation::validate_share_header(&share_block.header, chain_store_handle)
        {
            warn!("Rejecting share block {block_hash} with invalid header: {validation_error}");
            return Err(format!("Invalid share header: {validation_error}").into());
        }
    }

    // TODO: Check if this will be an uncle, for now add to main chain
    if let Err(store_error) = chain_store_handle
        .add_share_block(share_block.clone(), true)
        .await
    {
        error!("Failed to add share: {}", store_error);
        return Err("Error adding share to chain".into());
    }

    // Notify block fetcher that this block was received (removes from in-flight)
    if let Err(send_error) = block_fetcher_handle
        .send(BlockFetcherEvent::BlockReceived(block_hash))
        .await
    {
        error!(
            "Failed to send BlockReceived to block fetcher: {}",
            send_error
        );
    }

    // Send to validation worker for async validation, organise, and inv relay
    info!("Sending block {block_hash} to validation worker");
    if let Err(send_error) = validation_tx
        .send(ValidationEvent::ValidateBlock(block_hash))
        .await
    {
        error!("Failed to send block to validation worker: {send_error}");
    }

    debug!("Successfully added share block to chain");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_response_handler::block_fetcher;
    use crate::node::validation_worker;
    use crate::shares::share_block::ShareHeader;
    use crate::store::writer::StoreError;
    use crate::test_utils::{empty_share_block_from_header, load_share_headers_test_data};
    use mockall::predicate::*;

    /// Create test block fetcher and validation handles.
    fn test_handles() -> (
        BlockFetcherHandle,
        ValidationSender,
        crate::node::validation_worker::ValidationReceiver,
    ) {
        let (block_fetcher_tx, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, validation_rx) = validation_worker::create_validation_channel();
        (block_fetcher_tx, validation_tx, validation_rx)
    }

    #[tokio::test]
    async fn test_handle_share_block_success() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        // Not on candidate chain, so PoW will be checked (valid_header passes)
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Ok(()));

        let (block_fetcher_handle, validation_tx, mut validation_rx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
        .await;
        assert!(result.is_ok());

        // Verify validation event was sent
        if let Some(ValidationEvent::ValidateBlock(sent_hash)) = validation_rx.recv().await {
            assert_eq!(sent_hash, block_hash);
        } else {
            panic!("Expected ValidationEvent::ValidateBlock after successful store");
        }
    }

    #[tokio::test]
    async fn test_handle_share_block_add_share_error() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        // Not on candidate chain, so PoW will be checked (valid_header passes)
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Err(StoreError::Database("Failed to add share".to_string())));

        let (block_fetcher_handle, validation_tx, mut validation_rx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );

        // No validation event should be sent on store error
        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected on store error"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_duplicate_skips() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        // Block already in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| true);

        // add_share_block should NOT be called for a duplicate
        let (block_fetcher_handle, validation_tx, mut validation_rx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
        .await;
        assert!(result.is_ok());

        // No validation event should be sent for a duplicate
        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected for duplicate block"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_invalid_header_rejected() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["tight_target_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        // Not on candidate chain, so PoW will be checked (tight_target fails)
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        // add_share_block should NOT be called for invalid header
        let (block_fetcher_handle, validation_tx, mut validation_rx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
        .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid share header"),
            "Expected invalid share header error"
        );

        // No validation event should be sent for invalid header
        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected for invalid header"
        );
    }
}
