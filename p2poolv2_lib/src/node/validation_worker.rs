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

#[cfg(test)]
#[mockall_double::double]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
#[cfg(not(test))]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::organise_worker::{OrganiseEvent, OrganiseSender};
#[cfg(test)]
#[mockall_double::double]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(not(test))]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::validation::{DefaultShareValidator, ShareValidator};
use crate::utils::cpu::available_cpus;
use bitcoin::BlockHash;
use libp2p::request_response::ResponseChannel;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::{Semaphore, mpsc};
use tracing::{error, info};

/// Channel capacity for blocks pending validation.
const VALIDATION_CHANNEL_CAPACITY: usize = 8192;

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
/// After successful validation, the organise worker handles PPLNS
/// updates and dependent scheduling.
pub struct ValidationWorker {
    validation_rx: ValidationReceiver,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    semaphore: Arc<Semaphore>,
    pplns_window: Arc<RwLock<PplnsWindow>>,
    difficulty_multiplier: u128,
    pool_signature: Vec<u8>,
}

impl ValidationWorker {
    /// Creates a new validation worker.
    pub fn new(
        validation_rx: ValidationReceiver,
        chain_store_handle: ChainStoreHandle,
        organise_tx: OrganiseSender,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        pplns_window: Arc<RwLock<PplnsWindow>>,
        difficulty_multiplier: u128,
        pool_signature: Vec<u8>,
    ) -> Self {
        Self {
            validation_rx,
            chain_store_handle,
            organise_tx,
            swarm_tx,
            semaphore: Arc::new(Semaphore::new(available_cpus())),
            pplns_window,
            difficulty_multiplier,
            pool_signature,
        }
    }

    /// Runs the validation worker until the channel closes.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(ValidationWorkerError)` on fatal failure.
    pub async fn run(mut self) -> Result<(), ValidationWorkerError> {
        info!("Validation worker started");

        let pool_difficulty = PoolDifficulty::build(&self.chain_store_handle).map_err(|error| {
            ValidationWorkerError {
                message: format!("Failed to build pool difficulty: {error}"),
            }
        })?;
        let share_validator = Arc::new(DefaultShareValidator::new(
            pool_difficulty,
            self.difficulty_multiplier,
            self.pool_signature.clone(),
        ));

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
                    let validator = Arc::clone(&share_validator);
                    let pplns_window = Arc::clone(&self.pplns_window);

                    tokio::spawn(async move {
                        let _permit = permit;
                        validate_and_emit(
                            block_hash,
                            validator,
                            chain_store_handle,
                            organise_tx,
                            swarm_tx,
                            pplns_window,
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
/// on success.
///
/// Duplicate validation of already-confirmed blocks is handled by
/// `validate_share_block` which returns Ok immediately for blocks
/// with `BlockValid` status.
async fn validate_and_emit(
    block_hash: BlockHash,
    share_validator: Arc<DefaultShareValidator>,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    pplns_window: Arc<RwLock<PplnsWindow>>,
) {
    let share_block = match chain_store_handle.get_share(&block_hash) {
        Some(share_block) => share_block,
        None => {
            error!("Share block {block_hash} not found in store for validation");
            return;
        }
    };

    if let Err(validation_error) =
        share_validator.validate_share_block(&share_block, &chain_store_handle, pplns_window)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::organise_worker;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;
    use std::collections::HashMap;
    use std::time::Duration;

    #[tokio::test]
    async fn test_validation_worker_validates_and_sends_organise_event() {
        let _pool_difficulty_build_ctx = PoolDifficulty::build_context();
        _pool_difficulty_build_ctx
            .expect()
            .returning(|_| Ok(PoolDifficulty::default()));

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
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(
            validation_rx,
            mock_chain_handle,
            organise_tx,
            swarm_tx,
            {
                let mut mock_window = PplnsWindow::default();
                mock_window
                    .expect_network()
                    .return_const(bitcoin::Network::Signet);
                mock_window
                    .expect_get_distribution_from_start_hash()
                    .returning(|_, _| Some(HashMap::new()));
                Arc::new(RwLock::new(mock_window))
            },
            1,
            b"P2Poolv2".to_vec(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();

        let organise_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv()).await;
        if let Ok(Some(OrganiseEvent::Block(received_block))) = organise_event {
            assert_eq!(received_block.block_hash(), block_hash);
        } else {
            panic!("Expected OrganiseEvent::Block after successful validation");
        }

        worker_handle.abort();
    }

    #[tokio::test]
    async fn test_validation_worker_sends_inv_on_success() {
        let _pool_difficulty_build_ctx = PoolDifficulty::build_context();
        _pool_difficulty_build_ctx
            .expect()
            .returning(|_| Ok(PoolDifficulty::default()));

        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, _organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(
            validation_rx,
            mock_chain_handle,
            organise_tx,
            swarm_tx,
            {
                let mut mock_window = PplnsWindow::default();
                mock_window
                    .expect_network()
                    .return_const(bitcoin::Network::Signet);
                mock_window
                    .expect_get_distribution_from_start_hash()
                    .returning(|_, _| Some(HashMap::new()));
                Arc::new(RwLock::new(mock_window))
            },
            1,
            b"P2Poolv2".to_vec(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();

        let swarm_event = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv()).await;
        if let Ok(Some(SwarmSend::Inv(sent_block_hash))) = swarm_event {
            assert_eq!(sent_block_hash, block_hash);
        } else {
            panic!("Expected SwarmSend::Inv after successful validation");
        }

        worker_handle.abort();
    }

    #[tokio::test]
    async fn test_validation_worker_skips_missing_block() {
        let _pool_difficulty_build_ctx = PoolDifficulty::build_context();
        _pool_difficulty_build_ctx
            .expect()
            .returning(|_| Ok(PoolDifficulty::default()));

        let _pplns_new_ctx = PplnsWindow::new_context();
        _pplns_new_ctx.expect().returning(|_network| {
            let mut mock = PplnsWindow::default();
            mock.expect_network().return_const(bitcoin::Network::Signet);
            mock.expect_get_distribution_from_start_hash()
                .returning(|_, _| Some(HashMap::new()));
            mock
        });

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

        let worker = ValidationWorker::new(
            validation_rx,
            mock_chain_handle,
            organise_tx,
            swarm_tx,
            {
                let mut mock_window = PplnsWindow::default();
                mock_window
                    .expect_network()
                    .return_const(bitcoin::Network::Signet);
                mock_window
                    .expect_get_distribution_from_start_hash()
                    .returning(|_, _| Some(HashMap::new()));
                Arc::new(RwLock::new(mock_window))
            },
            1,
            b"P2Poolv2".to_vec(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();

        // Block not found in store -- no events should be produced.
        let organise_result =
            tokio::time::timeout(Duration::from_millis(500), organise_rx.recv()).await;
        assert!(
            organise_result.is_err(),
            "No OrganiseEvent expected for missing block"
        );

        let swarm_result = tokio::time::timeout(Duration::from_millis(500), swarm_rx.recv()).await;
        assert!(
            swarm_result.is_err(),
            "No SwarmSend expected for missing block"
        );

        worker_handle.abort();
    }

    #[tokio::test]
    async fn test_validation_worker_skips_invalid_block() {
        let _pool_difficulty_build_ctx = PoolDifficulty::build_context();
        _pool_difficulty_build_ctx
            .expect()
            .returning(|_| Ok(PoolDifficulty::default()));

        let _pplns_new_ctx = PplnsWindow::new_context();
        _pplns_new_ctx.expect().returning(|_network| {
            let mut mock = PplnsWindow::default();
            mock.expect_network().return_const(bitcoin::Network::Signet);
            mock.expect_get_distribution_from_start_hash()
                .returning(|_, _| Some(HashMap::new()));
            mock
        });

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
        // validate_share_block calls has_status
        mock_clone.expect_has_status().returning(|_, _| false);
        mock_chain_handle
            .expect_clone()
            .return_once(move || mock_clone);

        let (organise_tx, mut organise_rx) = organise_worker::create_organise_channel();
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);

        let worker = ValidationWorker::new(
            validation_rx,
            mock_chain_handle,
            organise_tx,
            swarm_tx,
            {
                let mut mock_window = PplnsWindow::default();
                mock_window
                    .expect_network()
                    .return_const(bitcoin::Network::Signet);
                mock_window
                    .expect_get_distribution_from_start_hash()
                    .returning(|_, _| Some(HashMap::new()));
                Arc::new(RwLock::new(mock_window))
            },
            1,
            b"P2Poolv2".to_vec(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlock(block_hash))
            .await
            .unwrap();

        // Validation fails (uncle not found) -- no events should be produced.
        let organise_result =
            tokio::time::timeout(Duration::from_millis(500), organise_rx.recv()).await;
        assert!(
            organise_result.is_err(),
            "No OrganiseEvent expected for invalid block"
        );

        let swarm_result = tokio::time::timeout(Duration::from_millis(500), swarm_rx.recv()).await;
        assert!(
            swarm_result.is_err(),
            "No SwarmSend expected for invalid block"
        );

        worker_handle.abort();
    }
}
