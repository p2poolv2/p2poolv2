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

//! Validation worker that validates share blocks in capped concurrent tasks.
//!
//! Receives `ValidationEvent` values containing blockhash to validate. It reads the
//! corresponding share block from the chain store, validates them using
//! `shares::validation::validate_share_block`, and on success emits
//! `OrganiseEvent::Block` and `SwarmSend::Inv` events. Runs in a dedicated
//! tokio task, decoupled from the P2P message handler hot path.

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::organise_worker::{OrganiseEvent, OrganiseSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::validation;
use bitcoin::BlockHash;
use libp2p::request_response::ResponseChannel;
use std::fmt;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info};

/// Channel capacity for blocks pending validation.
const VALIDATION_CHANNEL_CAPACITY: usize = 256;

/// Maximum number of concurrent validation tasks.
const MAX_CONCURRENT_VALIDATIONS: usize = 4;

/// Events for the validation worker.
pub enum ValidationEvent {
    /// Validate a stored ShareBlock by its hash.
    ValidateBlock(BlockHash),
}

/// Sender half of the validation channel.
pub type ValidationSender = mpsc::Sender<ValidationEvent>;
/// Receiver half of the validation channel.
pub type ValidationReceiver = mpsc::Receiver<ValidationEvent>;

/// Create a validation channel with bounded capacity.
pub fn create_validation_channel() -> (ValidationSender, ValidationReceiver) {
    mpsc::channel(VALIDATION_CHANNEL_CAPACITY)
}

/// Fatal error from the validation worker.
///
/// Returned when the worker encounters an unrecoverable failure,
/// indicating the node should shut down.
#[derive(Debug)]
pub struct ValidationWorkerError {
    message: String,
}

impl fmt::Display for ValidationWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ValidationWorkerError: {}", self.message)
    }
}

impl std::error::Error for ValidationWorkerError {}

/// Worker that validates share blocks in capped concurrent tasks.
///
/// Receives `ValidationEvent` values containing block hashes, reads
/// the share block from the chain store, validates it, and on success
/// emits `OrganiseEvent::Block` for confirmed promotion and
/// `SwarmSend::Inv` for inventory relay to peers.
pub struct ValidationWorker {
    validation_rx: ValidationReceiver,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    semaphore: Arc<Semaphore>,
}

impl ValidationWorker {
    /// Creates a new validation worker.
    pub fn new(
        validation_rx: ValidationReceiver,
        chain_store_handle: ChainStoreHandle,
        organise_tx: OrganiseSender,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    ) -> Self {
        Self {
            validation_rx,
            chain_store_handle,
            organise_tx,
            swarm_tx,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_VALIDATIONS)),
        }
    }

    /// Runs the validation worker until the channel closes.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(ValidationWorkerError)` on fatal failure.
    pub async fn run(mut self) -> Result<(), ValidationWorkerError> {
        info!("Validation worker started");
        while let Some(event) = self.validation_rx.recv().await {
            match event {
                ValidationEvent::ValidateBlock(block_hash) => {
                    let permit = match self.semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            error!("Validation semaphore closed");
                            return Err(ValidationWorkerError {
                                message: "Validation semaphore closed".to_string(),
                            });
                        }
                    };
                    let chain_store_handle = self.chain_store_handle.clone();
                    let organise_tx = self.organise_tx.clone();
                    let swarm_tx = self.swarm_tx.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        Self::validate_and_emit(
                            block_hash,
                            chain_store_handle,
                            organise_tx,
                            swarm_tx,
                        )
                        .await;
                    });
                }
            }
        }
        info!("Validation worker stopped - channel closed");
        Ok(())
    }

    /// Read a share block from the store, validate it, and emit events on success.
    async fn validate_and_emit(
        block_hash: BlockHash,
        chain_store_handle: ChainStoreHandle,
        organise_tx: OrganiseSender,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    ) {
        let share_block = match chain_store_handle.get_share(&block_hash) {
            Some(share_block) => share_block,
            None => {
                error!("Share block {block_hash} not found in store for validation");
                return;
            }
        };

        if let Err(validation_error) =
            validation::validate_share_block(&share_block, &chain_store_handle)
        {
            error!("Share block {block_hash} validation failed: {validation_error}");
            return;
        }

        info!("Share block {block_hash} validated successfully");

        if let Err(send_error) = organise_tx.send(OrganiseEvent::Block(share_block)).await {
            error!("Failed to send validated block to organise worker: {send_error}");
        }

        if let Err(send_error) = swarm_tx.send(SwarmSend::Inv(block_hash)).await {
            error!("Failed to send inv relay for validated block {block_hash}: {send_error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::organise_worker;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;

    #[tokio::test]
    async fn test_validation_worker_stops_on_channel_close() {
        let (_validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        let (organise_tx, _organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        drop(_validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validation_worker_validates_and_sends_organise_event() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        // Mock clone for spawned task
        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Allow spawned task in run to complete
        tokio::task::yield_now().await;

        if let Some(OrganiseEvent::Block(received_block)) = organise_rx.recv().await {
            assert_eq!(received_block.block_hash(), block_hash);
        } else {
            panic!("Expected OrganiseEvent::Block after successful validation");
        }
    }

    #[tokio::test]
    async fn test_validation_worker_sends_inv_on_success() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, _organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Allow spawned task to complete
        tokio::task::yield_now().await;

        if let Some(SwarmSend::Inv(sent_block_hash)) = swarm_rx.recv().await {
            assert_eq!(sent_block_hash, block_hash);
        } else {
            panic!("Expected SwarmSend::Inv after successful validation");
        }
    }

    #[tokio::test]
    async fn test_validation_worker_skips_missing_block() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let block_hash = TestShareBlockBuilder::new().build().block_hash();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone.expect_get_share().returning(|_| None);
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Allow spawned task to complete
        tokio::task::yield_now().await;

        assert!(
            organise_rx.try_recv().is_err(),
            "No OrganiseEvent expected for missing block"
        );
        assert!(
            swarm_rx.try_recv().is_err(),
            "No SwarmSend expected for missing block"
        );
    }

    #[tokio::test]
    async fn test_validation_worker_skips_invalid_block() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        // Build a share with an uncle that does not exist in the store
        let uncle_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse::<BlockHash>()
            .unwrap();
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .withf(move |hash| *hash == block_hash)
            .returning(move |_| Some(share_block_clone.clone()));
        mock_clone
            .expect_get_share()
            .withf(move |hash| *hash == uncle_hash)
            .returning(|_| None);
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Allow spawned task to complete
        tokio::task::yield_now().await;

        assert!(
            organise_rx.try_recv().is_err(),
            "No OrganiseEvent expected for invalid block"
        );
        assert!(
            swarm_rx.try_recv().is_err(),
            "No SwarmSend expected for invalid block"
        );
    }
}
