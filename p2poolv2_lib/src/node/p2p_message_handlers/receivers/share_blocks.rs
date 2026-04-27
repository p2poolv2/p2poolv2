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

use crate::node::p2p_message_handlers::receivers::block_receiver::{
    BlockReceiverEvent, BlockReceiverHandle,
};
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
use std::error::Error;
use tokio::sync::oneshot;
use tracing::{debug, error, warn};

/// Handle a ShareBlock received from a peer.
///
/// Called both when a peer broadcasts a new share directly (inbound request)
/// and when we receive a share in response to a GetData request (response).
///
/// Duplicates already in the store are handled directly: confirmed blocks
/// are skipped, unconfirmed blocks are re-sent to validation. New blocks
/// pass a minimal PoW check (DoS gate) then are forwarded to the
/// BlockReceiver actor which buffers them until their dependency DAG is
/// complete, validates ASERT difficulty, stores them, and sends them to
/// the validation worker.
pub async fn handle_share_block(
    share_block: ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    validation_tx: ValidationSender,
    block_receiver_handle: &BlockReceiverHandle,
    block_fetcher_handle: &BlockFetcherHandle,
    share_validator: &(dyn ShareValidator + Send + Sync),
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received ShareBlock: {:?}", share_block);

    let block_hash = share_block.block_hash();

    // Notify the block fetcher unconditionally so it clears any
    // in-flight request for this hash. This must happen regardless of
    // whether the block is new, duplicate, or invalid -- otherwise
    // the fetcher times out and retries forever.
    let _ = block_fetcher_handle
        .send(BlockFetcherEvent::BlockReceived(block_hash))
        .await;

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

    // Send to BlockReceiver actor for dependency buffering, ASERT
    // validation, storage, and forwarding to the validation worker.
    let (result_tx, result_rx) = oneshot::channel();
    if let Err(send_error) = block_receiver_handle
        .send(BlockReceiverEvent::ShareBlockReceived {
            share_block,
            result_tx,
        })
        .await
    {
        error!("Failed to send block to BlockReceiver: {send_error}");
        return Err(format!("BlockReceiver channel closed: {send_error}").into());
    }

    match result_rx.await {
        Ok(result) => result,
        Err(recv_error) => {
            error!("BlockReceiver dropped result channel: {recv_error}");
            Err(format!("BlockReceiver dropped result: {recv_error}").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    use crate::node::request_response_handler::block_fetcher::{
        BlockFetcherReceiver, create_block_fetcher_channel,
    };
    use crate::node::validation_worker;
    use crate::node::validation_worker::ValidationReceiver;
    use crate::shares::share_block::ShareHeader;
    use crate::shares::validation::{MockDefaultShareValidator, ValidationError};
    use crate::test_utils::{empty_share_block_from_header, load_share_headers_test_data};
    use mockall::predicate::*;

    /// Create test validation, block receiver, and block fetcher handles.
    fn test_handles() -> (
        ValidationSender,
        ValidationReceiver,
        BlockReceiverHandle,
        BlockFetcherHandle,
        BlockFetcherReceiver,
    ) {
        let (validation_tx, validation_rx) = validation_worker::create_validation_channel();
        let (block_receiver_handle, _block_receiver_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, block_fetcher_rx) = create_block_fetcher_channel();
        (
            validation_tx,
            validation_rx,
            block_receiver_handle,
            block_fetcher_handle,
            block_fetcher_rx,
        )
    }

    #[tokio::test]
    async fn test_handle_share_block_success() {
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

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| Ok(()));

        let (validation_tx, _validation_rx) = validation_worker::create_validation_channel();
        let (block_receiver_handle, mut block_receiver_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, mut block_fetcher_rx) = create_block_fetcher_channel();

        // Spawn a task to respond Ok on the oneshot
        tokio::spawn(async move {
            if let Some(BlockReceiverEvent::ShareBlockReceived { result_tx, .. }) =
                block_receiver_rx.recv().await
            {
                let _ = result_tx.send(Ok(()));
            }
        });

        let result = handle_share_block(
            share_block,
            &chain_store_handle,
            validation_tx,
            &block_receiver_handle,
            &block_fetcher_handle,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        let fetcher_event = block_fetcher_rx
            .try_recv()
            .expect("Expected BlockReceived event for new block");
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, block_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_handle_share_block_confirmed_duplicate_skips() {
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

        let (
            validation_tx,
            mut validation_rx,
            block_receiver_handle,
            block_fetcher_handle,
            _block_fetcher_rx,
        ) = test_handles();
        let result = handle_share_block(
            share_block,
            &chain_store_handle,
            validation_tx,
            &block_receiver_handle,
            &block_fetcher_handle,
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

        let (
            validation_tx,
            mut validation_rx,
            block_receiver_handle,
            block_fetcher_handle,
            _block_fetcher_rx,
        ) = test_handles();
        let result = handle_share_block(
            share_block,
            &chain_store_handle,
            validation_tx,
            &block_receiver_handle,
            &block_fetcher_handle,
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

        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_validate_share_header()
            .returning(|_| {
                Err(ValidationError::new(
                    "Insufficient work: block hash does not meet share target",
                ))
            });

        let (
            validation_tx,
            mut validation_rx,
            block_receiver_handle,
            block_fetcher_handle,
            mut block_fetcher_rx,
        ) = test_handles();
        let result = handle_share_block(
            share_block,
            &chain_store_handle,
            validation_tx,
            &block_receiver_handle,
            &block_fetcher_handle,
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

        let fetcher_event = block_fetcher_rx
            .try_recv()
            .expect("Expected BlockReceived event even for invalid block");
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, block_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_handle_share_block_confirmed_duplicate_notifies_block_fetcher() {
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

        let (
            validation_tx,
            _validation_rx,
            block_receiver_handle,
            block_fetcher_handle,
            mut block_fetcher_rx,
        ) = test_handles();
        let result = handle_share_block(
            share_block,
            &chain_store_handle,
            validation_tx,
            &block_receiver_handle,
            &block_fetcher_handle,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok());

        let fetcher_event = block_fetcher_rx
            .try_recv()
            .expect("Expected BlockReceived event for confirmed duplicate");
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, block_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }
    }
}
