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
//! `OrganiseEvent::Block` and `SwarmSend::BroadcastBlock` events. Runs in a dedicated
//! tokio task, decoupled from the P2P message handler hot path.

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
use crate::shares::share_block::ShareBlock;
use crate::shares::validation::check_pplns_zone;
use crate::shares::validation::{DefaultShareValidator, ShareValidator};
use crate::utils::cpu::available_cpus;
use bitcoin::BlockHash;
use libp2p::request_response::ResponseChannel;
use std::fmt;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, error, info};

/// Channel capacity for blocks pending validation.
const VALIDATION_CHANNEL_CAPACITY: usize = 8192;

/// Events for the validation worker.
pub enum ValidationEvent {
    /// Validate a stored ShareBlock by its hash (reads from store).
    ValidateBlockHash(BlockHash),
    /// Validate a ShareBlock already in memory (avoids redundant store read).
    ValidateShareBlock(ShareBlock),
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
/// `SwarmSend::BroadcastBlock` for block relay to peers.
///
/// After successful validation, the organise worker handles PPLNS
/// updates and dependent scheduling.
pub struct ValidationWorker {
    validation_rx: ValidationReceiver,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    semaphore: Arc<Semaphore>,
    difficulty_multiplier: u128,
    pool_signature: Vec<u8>,
    pool_difficulty: PoolDifficulty,
}

impl ValidationWorker {
    /// Creates a new validation worker.
    pub fn new(
        validation_rx: ValidationReceiver,
        chain_store_handle: ChainStoreHandle,
        organise_tx: OrganiseSender,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        difficulty_multiplier: u128,
        pool_signature: Vec<u8>,
        pool_difficulty: PoolDifficulty,
    ) -> Self {
        Self {
            validation_rx,
            chain_store_handle,
            organise_tx,
            swarm_tx,
            semaphore: Arc::new(Semaphore::new(available_cpus())),
            difficulty_multiplier,
            pool_signature,
            pool_difficulty,
        }
    }

    /// Runs the validation worker until the channel closes.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(ValidationWorkerError)` on fatal failure.
    pub async fn run(mut self) -> Result<(), ValidationWorkerError> {
        info!("Validation worker started");

        let share_validator = Arc::new(DefaultShareValidator::new(
            self.pool_difficulty,
            self.difficulty_multiplier,
            self.pool_signature.clone(),
        ));

        while let Some(event) = self.validation_rx.recv().await {
            let (block_hash, prefetched_block) = match event {
                ValidationEvent::ValidateBlockHash(hash) => (hash, None),
                ValidationEvent::ValidateShareBlock(share_block) => {
                    (share_block.block_hash(), Some(share_block))
                }
            };

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

            tokio::spawn(async move {
                let _permit = permit;
                validate_and_emit(
                    block_hash,
                    prefetched_block,
                    validator,
                    chain_store_handle,
                    organise_tx,
                    swarm_tx,
                )
                .await;
            });
        }
        info!("Validation worker stopped - channel closed");
        Ok(())
    }
}

/// Validate a share block and emit events on success.
///
/// When `prefetched_block` is `Some`, uses the provided block directly
/// (avoids a redundant store read for locally mined shares). Otherwise
/// reads the block from the chain store by hash.
///
/// Sends `OrganiseEvent::Block` for chain promotion. Locally mined
/// blocks (prefetched) are always broadcast to peers. Blocks received
/// from peers are only broadcast when the chain is current,
/// suppressing relay of historic blocks during initial sync or catchup.
///
/// Duplicate validation of already-confirmed blocks is handled by
/// `validate_share_block` which returns Ok immediately for blocks
/// with `BlockValid` status.
async fn validate_and_emit(
    block_hash: BlockHash,
    prefetched_block: Option<ShareBlock>,
    share_validator: Arc<DefaultShareValidator>,
    chain_store_handle: ChainStoreHandle,
    organise_tx: OrganiseSender,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
) {
    let locally_mined = prefetched_block.is_some();
    let share_block = match prefetched_block {
        Some(block) => block,
        None => match chain_store_handle.get_share(&block_hash) {
            Some(share_block) => share_block,
            None => {
                error!("Share block {block_hash} not found in store for validation");
                return;
            }
        },
    };

    let in_pplns_zone = match check_pplns_zone(&block_hash, &chain_store_handle) {
        Ok(result) => result,
        Err(error_message) => {
            error!("Error checking for pplns zone: {error_message}");
            return;
        }
    };

    let validation_result = if in_pplns_zone {
        share_validator.validate_share_block(&share_block, &chain_store_handle)
    } else {
        share_validator.validate_below_pplns_depth(&share_block, &chain_store_handle)
    };

    if let Err(validation_error) = validation_result {
        let error_message = validation_error.to_string();
        if error_message.contains("is on confirmed chain") {
            debug!("Share block {block_hash} validation: {error_message}");
        } else {
            error!("Share block {block_hash} validation failed: {error_message}");
        }
        return;
    }

    debug!("Share block {block_hash} validated successfully");

    if let Err(send_error) = organise_tx
        .send(OrganiseEvent::Block(share_block.clone()))
        .await
    {
        error!("Failed to send validated block to organise worker: {send_error}");
    }

    // Always broadcast locally mined blocks. For blocks received from
    // peers, only broadcast when the chain is current to avoid relaying
    // historic blocks during initial sync or catchup.
    if locally_mined || chain_store_handle.is_current() {
        #[cfg(not(feature = "sim"))]
        {
            if let Err(send_error) = swarm_tx.send(SwarmSend::BroadcastBlock(share_block)).await {
                error!("Failed to send broadcast for validated block {block_hash}: {send_error}");
            }
        }
        #[cfg(feature = "sim")]
        {
            crate::sim_overrides::spawn_delayed_broadcast(swarm_tx, share_block);
        }
    } else {
        debug!("Skipping broadcast for {block_hash} - chain not current");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::organise_worker;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::TestShareBlockBuilder;

    use bitcoin::Work;
    use std::time::Duration;

    /// Build a BlockMetadata value that places the block inside the PPLNS zone.
    ///
    /// Uses height 1 so that `is_in_pplns_zone(1, candidate_tip=1)` returns true,
    /// causing `validate_share_block` (not `validate_below_pplns_depth`) to run.
    fn pplns_zone_metadata() -> BlockMetadata {
        BlockMetadata {
            expected_height: Some(1),
            chain_work: Work::from_be_bytes([0u8; 32]),
            status: Status::Candidate,
        }
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
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| true);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
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
    async fn test_validation_worker_sends_broadcast_on_success() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| true);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
            .await
            .unwrap();

        let swarm_event = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv()).await;
        if let Ok(Some(SwarmSend::BroadcastBlock(broadcast_block))) = swarm_event {
            assert_eq!(broadcast_block.block_hash(), block_hash);
        } else {
            panic!("Expected SwarmSend::BroadcastBlock after successful validation");
        }

        worker_handle.abort();
    }

    #[tokio::test]
    async fn test_validation_worker_skips_broadcast_when_not_current() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| false);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
            .await
            .unwrap();

        // Organisation event should still be sent
        let organise_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv()).await;
        if let Ok(Some(OrganiseEvent::Block(received_block))) = organise_event {
            assert_eq!(received_block.block_hash(), block_hash);
        } else {
            panic!("Expected OrganiseEvent::Block even when not current");
        }

        // Broadcast should NOT be sent during sync
        let swarm_result = tokio::time::timeout(Duration::from_millis(500), swarm_rx.recv()).await;
        assert!(
            swarm_result.is_err(),
            "No SwarmSend expected when chain is not current"
        );

        worker_handle.abort();
    }

    #[tokio::test]
    async fn test_locally_mined_block_broadcasts_when_not_current() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone.expect_get_share().never();
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| false);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateShareBlock(share_block))
            .await
            .unwrap();

        let swarm_event = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv()).await;
        if let Ok(Some(SwarmSend::BroadcastBlock(broadcast_block))) = swarm_event {
            assert_eq!(broadcast_block.block_hash(), block_hash);
        } else {
            panic!(
                "Expected SwarmSend::BroadcastBlock for locally mined block even when not current"
            );
        }

        worker_handle.abort();
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

        let worker = ValidationWorker::new(
            validation_rx,
            mock_chain_handle,
            organise_tx,
            swarm_tx,
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
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
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
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

    #[tokio::test]
    async fn test_validate_share_block_skips_store_read() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone.expect_get_share().never();
        mock_clone
            .expect_get_block_metadata()
            .returning(|_| Ok(pplns_zone_metadata()));
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| true);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateShareBlock(share_block))
            .await
            .unwrap();

        let organise_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv()).await;
        if let Ok(Some(OrganiseEvent::Block(received_block))) = organise_event {
            assert_eq!(received_block.block_hash(), block_hash);
        } else {
            panic!("Expected OrganiseEvent::Block for prefetched share block");
        }

        let swarm_event = tokio::time::timeout(Duration::from_secs(2), swarm_rx.recv()).await;
        if let Ok(Some(SwarmSend::BroadcastBlock(broadcast_block))) = swarm_event {
            assert_eq!(broadcast_block.block_hash(), block_hash);
        } else {
            panic!("Expected SwarmSend::BroadcastBlock for prefetched share block");
        }

        worker_handle.abort();
    }

    /// Prune-zone block (height 100, candidate tip 300000) is validated
    /// via the below-PPLNS path. The BlockValid shortcut fires (same as
    /// PPLNS-zone tests) because test fixture blocks don't carry valid
    /// PoW against pool difficulty. The test verifies the block reaches
    /// the organise worker, confirming the below-PPLNS path returns Ok.
    #[tokio::test]
    async fn test_validation_worker_successfully_validates_blocks_in_prune_zone() {
        let (validation_tx, validation_rx) = create_validation_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();
        let share_block_clone = share_block.clone();

        let mut mock_clone = MockChainStoreHandle::new();
        mock_clone
            .expect_get_share()
            .returning(move |_| Some(share_block_clone.clone()));
        mock_clone.expect_get_block_metadata().returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(100),
                chain_work: Work::from_be_bytes([0u8; 32]),
                status: Status::Candidate,
            })
        });
        mock_clone
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(300_000)));
        // BlockValid shortcut fires in validate_below_pplns_depth
        mock_clone.expect_has_status().returning(|_, _| true);
        mock_clone.expect_is_current().returning(|| false);
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
            1,
            b"P2Poolv2".to_vec(),
            PoolDifficulty::default(),
        );

        let worker_handle = tokio::spawn(worker.run());

        validation_tx
            .send(ValidationEvent::ValidateBlockHash(block_hash))
            .await
            .unwrap();

        let organise_event = tokio::time::timeout(Duration::from_secs(2), organise_rx.recv()).await;
        if let Ok(Some(OrganiseEvent::Block(received_block))) = organise_event {
            assert_eq!(received_block.block_hash(), block_hash);
        } else {
            panic!("Expected OrganiseEvent::Block for prune-zone block");
        }

        worker_handle.abort();
    }
}
