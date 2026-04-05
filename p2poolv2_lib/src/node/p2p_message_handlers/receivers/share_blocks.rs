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

use crate::node::request_response_handler::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::validation_worker::{ValidationEvent, ValidationSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation::ShareValidator;
use crate::store::block_tx_metadata::Status;
use bitcoin::{BlockHash, hashes::Hash};
use std::collections::HashSet;
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
/// After storing, notifies the block fetcher and checks for missing
/// dependencies (uncles and parent). If any are missing, requests
/// them from the block fetcher and defers validation. Otherwise
/// sends the block to the validation worker for full asynchronous
/// validation. On successful validation the worker emits
/// OrganiseEvent::Block and SwarmSend::Inv.
pub async fn handle_share_block(
    peer_id: libp2p::PeerId,
    share_block: ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
    share_validator: &(dyn ShareValidator + Send + Sync),
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received ShareBlock: {:?}", share_block);

    let block_hash = share_block.block_hash();

    // Block already stored: skip the add but re-trigger validation if
    // the block has not been confirmed yet. This handles the case where
    // the process restarted after storing a block but before validation
    // completed.
    if chain_store_handle.share_block_exists(&block_hash) {
        if !chain_store_handle.has_status(&block_hash, Status::Confirmed) {
            debug!("Share block {block_hash} in store but not confirmed, re-sending to validation");
            if let Err(send_error) = validation_tx
                .send(ValidationEvent::ValidateBlock(block_hash))
                .await
            {
                error!("Failed to re-send block to validation worker: {send_error}");
            }
        } else {
            debug!("Share block {block_hash} already confirmed, skipping");
        }
        return Ok(());
    }

    // If new block not in store, run minimal PoW check for dos prevention
    if let Err(validation_error) = share_validator.validate_share_header(&share_block.header) {
        warn!("Rejecting share block {block_hash} with invalid header: {validation_error}");
        return Err(format!("Invalid share header: {validation_error}").into());
    }

    // We can't save block just after validate_share_header
    //
    // we buffer blocks in a queue and wait till all parents are
    // received. we could still use missing dependencies through the
    // block fetcher to avoid duplicate fetching.
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

    // Fetch missing dependencies and defer validation if any are absent
    if fetch_missing_dependencies(
        peer_id,
        &share_block,
        chain_store_handle,
        &block_fetcher_handle,
    )
    .await
    {
        debug!("Deferring validation of block {block_hash} until dependencies arrive");
        return Ok(());
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

/// Check for missing parent and uncle dependencies. If any are
/// missing, send a FetchBlocks request to the block fetcher and
/// return true to signal that validation should be deferred.
/// Returns false when all dependencies are present.
async fn fetch_missing_dependencies(
    peer_id: libp2p::PeerId,
    share_block: &ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: &BlockFetcherHandle,
) -> bool {
    let block_hash = share_block.block_hash();
    let mut missing = HashSet::with_capacity(share_block.header.uncles.len() + 1);

    // Check parent (skip all-zeros sentinel used by genesis)
    let parent_hash = share_block.header.prev_share_blockhash;
    if parent_hash != BlockHash::all_zeros() && !chain_store_handle.share_block_exists(&parent_hash)
    {
        missing.insert(parent_hash);
    }

    for uncle_hash in &share_block.header.uncles {
        if !chain_store_handle.share_block_exists(uncle_hash) {
            missing.insert(*uncle_hash);
        }
    }

    if missing.is_empty() {
        return false;
    }

    info!(
        "Block {block_hash} has {} missing dependencies, requesting fetch",
        missing.len()
    );
    match block_fetcher_handle
        .send(BlockFetcherEvent::FetchBlocks {
            blockhashes: missing.into_iter().collect(),
            peer_id,
        })
        .await
    {
        Ok(()) => true,
        Err(send_error) => {
            error!("Failed to send FetchBlocks for missing dependencies: {send_error}");
            // Proceed with validation rather than leaving the block permanently stalled
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_response_handler::block_fetcher;
    use crate::node::validation_worker;
    use crate::shares::share_block::ShareHeader;
    use crate::shares::validation::{MockDefaultShareValidator, ValidationError};
    use crate::store::writer::StoreError;
    use crate::test_utils::{empty_share_block_from_header, load_share_headers_test_data};
    use mockall::predicate::*;

    /// Create test block fetcher and validation handles, returning
    /// all receivers so tests can inspect sent events.
    fn test_handles() -> (
        BlockFetcherHandle,
        tokio::sync::mpsc::Receiver<BlockFetcherEvent>,
        ValidationSender,
        crate::node::validation_worker::ValidationReceiver,
    ) {
        let (block_fetcher_tx, block_fetcher_rx) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, validation_rx) = validation_worker::create_validation_channel();
        (
            block_fetcher_tx,
            block_fetcher_rx,
            validation_tx,
            validation_rx,
        )
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

        // Not on candidate chain, so PoW will be checked
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| Ok(()));
        mock_validator
            .expect_validate_with_pool_difficulty()
            .returning(|_, _| Ok(()));

        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Ok(()));

        let (block_fetcher_handle, _block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
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

        // Not on candidate chain, so PoW will be checked
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| Ok(()));
        mock_validator
            .expect_validate_with_pool_difficulty()
            .returning(|_, _| Ok(()));

        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Err(StoreError::Database("Failed to add share".to_string())));

        let (block_fetcher_handle, _block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
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
    async fn test_handle_share_block_confirmed_duplicate_skips() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| true);
        chain_store_handle
            .expect_has_status()
            .with(eq(block_hash), eq(Status::Confirmed))
            .returning(|_, _| true);

        let mock_validator = MockDefaultShareValidator::default();

        let (block_fetcher_handle, _block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected for confirmed duplicate block"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_unconfirmed_duplicate_triggers_validation() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();
        let share_block = empty_share_block_from_header(header);
        let block_hash = share_block.block_hash();

        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| true);
        chain_store_handle
            .expect_has_status()
            .with(eq(block_hash), eq(Status::Confirmed))
            .returning(|_, _| false);

        let mock_validator = MockDefaultShareValidator::default();

        let (block_fetcher_handle, _block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        let event = validation_rx
            .try_recv()
            .expect("Expected validation event for unconfirmed stored block");
        match event {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, block_hash),
        }
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

        // Not on candidate chain, so PoW will be checked
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| false);

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| {
                Err(ValidationError::new(
                    "Insufficient work: block hash does not meet share target",
                ))
            });

        // add_share_block should NOT be called for invalid header
        let (block_fetcher_handle, _block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
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

    #[tokio::test]
    async fn test_handle_share_block_fetches_missing_uncles() {
        use crate::test_utils::TestShareBlockBuilder;

        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a share block that references two uncles
        let uncle_hash_a = BlockHash::from_byte_array([0xaa; 32]);
        let uncle_hash_b = BlockHash::from_byte_array([0xbb; 32]);
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash_a, uncle_hash_b])
            .build();
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        // Already on candidate chain so PoW check is skipped
        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| true);

        chain_store_handle
            .expect_add_share_block()
            .returning(|_, _| Ok(()));

        // Parent is all-zeros (genesis sentinel) so no parent check.
        // Uncles are not in store.
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(uncle_hash_a))
            .returning(|_| false);
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(uncle_hash_b))
            .returning(|_| false);

        let mock_validator = MockDefaultShareValidator::default();
        let (block_fetcher_handle, mut block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        // Should have sent BlockReceived followed by FetchBlocks
        let received_event = block_fetcher_rx.try_recv().expect("expected BlockReceived");
        assert!(
            matches!(received_event, BlockFetcherEvent::BlockReceived(hash) if hash == block_hash)
        );

        let fetch_event = block_fetcher_rx.try_recv().expect("expected FetchBlocks");
        match fetch_event {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id: event_peer_id,
            } => {
                assert_eq!(event_peer_id, peer_id);
                assert!(blockhashes.contains(&uncle_hash_a));
                assert!(blockhashes.contains(&uncle_hash_b));
                assert_eq!(blockhashes.len(), 2);
            }
            other => panic!("expected FetchBlocks, got: {other}"),
        }

        // Validation should be deferred (no event sent)
        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected when dependencies are missing"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_skips_known_uncles() {
        use crate::test_utils::TestShareBlockBuilder;

        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a share block that references an uncle already in store
        let uncle_hash = BlockHash::from_byte_array([0xcc; 32]);
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| true);

        chain_store_handle
            .expect_add_share_block()
            .returning(|_, _| Ok(()));

        // Uncle IS in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(uncle_hash))
            .returning(|_| true);

        let mock_validator = MockDefaultShareValidator::default();
        let (block_fetcher_handle, mut block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        // BlockReceived should be sent, but no FetchBlocks
        let received_event = block_fetcher_rx.try_recv().expect("expected BlockReceived");
        assert!(
            matches!(received_event, BlockFetcherEvent::BlockReceived(hash) if hash == block_hash)
        );
        assert!(
            block_fetcher_rx.try_recv().is_err(),
            "No FetchBlocks expected when all dependencies are present"
        );

        // Validation should proceed since all dependencies are present
        let validation_event = validation_rx.try_recv().expect("expected validation event");
        assert!(
            matches!(validation_event, ValidationEvent::ValidateBlock(hash) if hash == block_hash)
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_fetches_missing_parent() {
        use crate::test_utils::TestShareBlockBuilder;

        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a parent block so we can reference its hash
        let parent_block = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let parent_hash = parent_block.block_hash();

        // Build a share block whose parent is not in the store
        let share_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let block_hash = share_block.block_hash();

        // Block not yet in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(block_hash))
            .returning(|_| false);

        chain_store_handle
            .expect_is_candidate()
            .with(eq(block_hash))
            .returning(|_| true);

        chain_store_handle
            .expect_add_share_block()
            .returning(|_, _| Ok(()));

        // Parent is NOT in store
        chain_store_handle
            .expect_share_block_exists()
            .with(eq(parent_hash))
            .returning(|_| false);

        let mock_validator = MockDefaultShareValidator::default();
        let (block_fetcher_handle, mut block_fetcher_rx, validation_tx, mut validation_rx) =
            test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            validation_tx,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        // BlockReceived then FetchBlocks with parent hash
        let received_event = block_fetcher_rx.try_recv().expect("expected BlockReceived");
        assert!(
            matches!(received_event, BlockFetcherEvent::BlockReceived(hash) if hash == block_hash)
        );

        let fetch_event = block_fetcher_rx.try_recv().expect("expected FetchBlocks");
        match fetch_event {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id: event_peer_id,
            } => {
                assert_eq!(event_peer_id, peer_id);
                assert_eq!(blockhashes, vec![parent_hash]);
            }
            other => panic!("expected FetchBlocks, got: {other}"),
        }

        // Validation deferred
        assert!(
            validation_rx.try_recv().is_err(),
            "No validation event expected when parent is missing"
        );
    }
}
