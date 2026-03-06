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
use crate::utils::cpu::available_cpus;
use bitcoin::BlockHash;
use libp2p::request_response::ResponseChannel;
use std::fmt;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info};

/// Channel capacity for blocks pending validation.
const VALIDATION_CHANNEL_CAPACITY: usize = 256;

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
///
/// After successful validation, spawns new tasks for stored children
/// and nephews so the chain advances when a hole is filled. Each
/// child/nephew task acquires its own semaphore permit.
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
            semaphore: Arc::new(Semaphore::new(available_cpus())),
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
                    let semaphore = self.semaphore.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        validate_and_emit(
                            block_hash,
                            chain_store_handle,
                            organise_tx,
                            swarm_tx,
                            semaphore,
                        )
                        .await;
                    });
                }
            }
        }
        info!("Validation worker stopped - channel closed");
        Ok(())
    }
}

/// Read a share block from the store, validate it, and emit events
/// on success. After organising, spawn tasks for stored children and
/// nephews so the chain advances when a hole is filled.
///
/// Blocks that are already BlockValid are skipped entirely. During
/// initial download a block can be scheduled for validation twice:
/// once when it arrives via handle_share_block, and again when its
/// parent validates and schedule_dependents spawns a child task.
/// This early return avoids duplicate organise/inv events in that
/// race. There is a small window where two concurrent tasks both
/// see Candidate status and both proceed, but that duplication is
/// harmless since organise_block is idempotent.
async fn validate_and_emit(
    block_hash: BlockHash,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    semaphore: Arc<Semaphore>,
) {
    // Skip blocks already validated by a concurrent task to avoid
    // duplicate organise/inv events during initial download.
    if chain_store_handle.has_status(
        &block_hash,
        crate::store::block_tx_metadata::Status::BlockValid,
    ) {
        return;
    }

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

    // Relay block once context free validations are run. If later
    // the block is not confirmed, peers should have a copy anyway.
    if let Err(send_error) = swarm_tx.send(SwarmSend::Inv(block_hash)).await {
        error!("Failed to send inv relay for validated block {block_hash}: {send_error}");
    }

    // Spawn tasks for stored children and nephews so the chain
    // advances when a missing block arrives.
    schedule_dependents(
        &block_hash,
        &chain_store_handle,
        &organise_tx,
        &swarm_tx,
        &semaphore,
    );
}

/// Collect stored children and nephews and spawn a validation task
/// for each. Each task acquires its own semaphore permit so
/// concurrency stays capped.
fn schedule_dependents(
    block_hash: &BlockHash,
    chain_store_handle: &ChainStoreHandle,
    organise_tx: &OrganiseSender,
    swarm_tx: &mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    semaphore: &Arc<Semaphore>,
) {
    let mut dependent_hashes = Vec::with_capacity(4);

    if let Ok(Some(children)) = chain_store_handle.get_children_blockhashes(block_hash) {
        for child_hash in children {
            if chain_store_handle.share_block_exists(&child_hash) {
                info!("Scheduling child {child_hash} for validation after {block_hash}");
                dependent_hashes.push(child_hash);
            }
        }
    }

    if let Some(nephews) = chain_store_handle.get_nephews(block_hash) {
        for nephew_hash in nephews {
            if chain_store_handle.share_block_exists(&nephew_hash) {
                info!("Scheduling nephew {nephew_hash} for validation after uncle {block_hash}");
                dependent_hashes.push(nephew_hash);
            }
        }
    }

    for dependent_hash in dependent_hashes {
        let chain_store_handle = chain_store_handle.clone();
        let organise_tx = organise_tx.clone();
        let swarm_tx = swarm_tx.clone();
        let semaphore = semaphore.clone();

        tokio::spawn(async move {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    error!(
                        "Validation semaphore closed while scheduling dependent {dependent_hash}"
                    );
                    return;
                }
            };
            let _permit = permit;
            validate_and_emit(
                dependent_hash,
                chain_store_handle,
                organise_tx,
                swarm_tx,
                semaphore,
            )
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::organise_worker;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;
    use std::time::Duration;

    /// Add mock expectations needed for validate_and_emit (has_status)
    /// and schedule_dependents (get_children_blockhashes, get_nephews) on a
    /// mock clone that will handle a successful validation path with no
    /// children or nephews.
    fn setup_validation_expectations(mock_clone: &mut MockChainStoreHandle) {
        // validate_and_emit and validate_share_block both call has_status
        // to check for BlockValid early return
        mock_clone.expect_has_status().returning(|_, _| false);

        // schedule_dependents checks children and nephews
        mock_clone
            .expect_get_children_blockhashes()
            .returning(|_| Ok(None));
        mock_clone.expect_get_nephews().returning(|_| None);
    }

    #[tokio::test]
    async fn test_validation_worker_stops_on_channel_close() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mock_chain_handle = MockChainStoreHandle::new();
        let (organise_tx, _organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        drop(validation_tx);

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
        setup_validation_expectations(&mut mock_clone);
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
        setup_validation_expectations(&mut mock_clone);
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

        // Block not found in store -- no events should be produced.
        let organise_result =
            tokio::time::timeout(Duration::from_millis(500), organise_rx.recv()).await;
        assert!(
            matches!(organise_result, Ok(None)),
            "No OrganiseEvent expected for missing block"
        );

        let swarm_result = tokio::time::timeout(Duration::from_millis(500), swarm_rx.recv()).await;
        assert!(
            matches!(swarm_result, Ok(None)),
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
        // validate_and_emit and validate_share_block both call has_status
        mock_clone.expect_has_status().returning(|_, _| false);
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

        // Validation fails (uncle not found) -- no events should be produced.
        let organise_result =
            tokio::time::timeout(Duration::from_millis(500), organise_rx.recv()).await;
        assert!(
            matches!(organise_result, Ok(None)),
            "No OrganiseEvent expected for invalid block"
        );

        let swarm_result = tokio::time::timeout(Duration::from_millis(500), swarm_rx.recv()).await;
        assert!(
            matches!(swarm_result, Ok(None)),
            "No SwarmSend expected for invalid block"
        );
    }

    #[tokio::test]
    async fn test_validation_worker_schedules_children() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let parent_block = TestShareBlockBuilder::new().build();
        let parent_hash = parent_block.block_hash();
        let parent_clone = parent_block.clone();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .build();
        let child_hash = child_block.block_hash();

        // The mock clone will be used for both the parent validation
        // and the spawned child validation task (via clone).
        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(parent_clone.clone()));
        mock_clone.expect_has_status().returning(|_, _| false);
        // schedule_dependents: parent has one child
        mock_clone
            .expect_get_children_blockhashes()
            .returning(move |_| Ok(Some(vec![child_hash])));
        mock_clone.expect_share_block_exists().returning(|_| true);
        mock_clone.expect_get_nephews().returning(|_| None);
        // The spawned child task clones the handle. Return the child
        // block so validation succeeds and produces a second organise event.
        let child_clone = child_block.clone();
        mock_clone.expect_clone().return_once(move || {
            let mut inner = MockChainStoreHandle::new();
            inner
                .expect_get_share()
                .returning(move |_| Some(child_clone.clone()));
            setup_validation_expectations(&mut inner);
            inner
        });
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(parent_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // First organise event from parent validation.
        let first_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv())
            .await
            .expect("Timed out waiting for parent OrganiseEvent");
        assert!(
            matches!(first_event, Some(OrganiseEvent::Block(_))),
            "Expected OrganiseEvent::Block for parent"
        );

        // Second organise event from the spawned child validation task.
        let second_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv())
            .await
            .expect("Timed out waiting for child OrganiseEvent");
        if let Some(OrganiseEvent::Block(received_block)) = second_event {
            assert_eq!(received_block.block_hash(), child_hash);
        } else {
            panic!("Expected OrganiseEvent::Block for child");
        }
    }

    #[tokio::test]
    async fn test_validation_worker_schedules_nephews() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let uncle_block = TestShareBlockBuilder::new().build();
        let uncle_hash = uncle_block.block_hash();
        let uncle_clone = uncle_block.clone();

        let nephew_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();
        let nephew_hash = nephew_block.block_hash();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(uncle_clone.clone()));
        mock_clone.expect_has_status().returning(|_, _| false);
        // schedule_dependents: no children, one nephew
        mock_clone
            .expect_get_children_blockhashes()
            .returning(|_| Ok(None));
        mock_clone
            .expect_get_nephews()
            .returning(move |_| Some(vec![nephew_hash]));
        mock_clone.expect_share_block_exists().returning(|_| true);
        // The spawned nephew task clones the handle. Return the nephew
        // block (which references the uncle) so validation succeeds.
        let nephew_clone = nephew_block.clone();
        let uncle_for_nephew = uncle_block.clone();
        mock_clone.expect_clone().return_once(move || {
            let mut inner = MockChainStoreHandle::new();
            // nephew's get_share returns itself; uncle lookup returns uncle
            let nephew_for_inner = nephew_clone.clone();
            let nephew_hash_inner = nephew_for_inner.block_hash();
            inner
                .expect_get_share()
                .withf(move |hash| *hash == nephew_hash_inner)
                .returning(move |_| Some(nephew_for_inner.clone()));
            inner
                .expect_get_share()
                .returning(move |_| Some(uncle_for_nephew.clone()));
            setup_validation_expectations(&mut inner);
            inner
        });
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(validation_rx, mock_chain_handle, organise_tx, swarm_tx);

        validation_tx
            .send(ValidationEvent::ValidateBlock(uncle_hash))
            .await
            .unwrap();
        drop(validation_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // First organise event from uncle validation.
        let first_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv())
            .await
            .expect("Timed out waiting for uncle OrganiseEvent");
        assert!(
            matches!(first_event, Some(OrganiseEvent::Block(_))),
            "Expected OrganiseEvent::Block for uncle"
        );

        // Second organise event from the spawned nephew validation task.
        let second_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv())
            .await
            .expect("Timed out waiting for nephew OrganiseEvent");
        if let Some(OrganiseEvent::Block(received_block)) = second_event {
            assert_eq!(received_block.block_hash(), nephew_hash);
        } else {
            panic!("Expected OrganiseEvent::Block for nephew");
        }
    }
}
