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

//! Organisation worker that updates candidate and confirmed indexes.
//!
//! Receives OrganiseEvent values and triggers atomic organisation of the
//! candidate/confirmed indexes in the chain store. Runs in a dedicated
//! tokio task, decoupled from share producers (emission worker, peer
//! handler, future validation worker).
//!
//! After promoting a block to confirmed, updates the PplnsWindow cache
//! and schedules stored children and nephews for validation so the
//! chain advances with a fresh PPLNS state.

#[cfg(test)]
#[mockall_double::double]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
#[cfg(not(test))]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
use crate::monitoring_events::{MonitoringEvent, MonitoringEventSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::shares::validation::ShareValidator;
use crate::store::dag_store::ShareInfo;
use crate::store::writer::StoreError;
use crate::stratum::work::notify::{NotifyCmd, NotifySender};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Channel capacity for shares pending organisation.
const ORGANISE_CHANNEL_CAPACITY: usize = 8192;

/// Maximum number of blocks buffered while waiting for ancestor
/// confirmation during sync.
const PENDING_BLOCKS_CAPACITY: usize = 16384;

/// Events for the organise worker.
pub enum OrganiseEvent {
    /// Organise a header into the candidate chain.
    Header(ShareHeader),
    /// Promote candidates to confirmed after a block is validated.
    Block(ShareBlock),
}

/// Sender half of the organise channel.
pub type OrganiseSender = mpsc::Sender<OrganiseEvent>;
/// Receiver half of the organise channel.
pub type OrganiseReceiver = mpsc::Receiver<OrganiseEvent>;

/// Create an organise channel with bounded capacity.
pub fn create_organise_channel() -> (OrganiseSender, OrganiseReceiver) {
    mpsc::channel(ORGANISE_CHANNEL_CAPACITY)
}

/// Fatal error from the organise worker.
///
/// Returned when the worker encounters an unrecoverable failure,
/// indicating the node should shut down.
#[derive(Debug)]
pub struct OrganiseError {
    message: String,
}

impl fmt::Display for OrganiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OrganiseError: {}", self.message)
    }
}

impl std::error::Error for OrganiseError {}

/// Worker that triggers organisation of headers and blocks.
///
/// Receives `OrganiseEvent` values that have already been stored in the
/// chain and triggers atomic updates to the candidate/confirmed indexes
/// via `ChainStoreHandle`. After promoting a block, updates the shared
/// PplnsWindow cache and schedules stored children/nephews for
/// validation.
pub struct OrganiseWorker {
    organise_rx: OrganiseReceiver,
    chain_store_handle: ChainStoreHandle,
    monitoring_event_sender: MonitoringEventSender,
    notify_tx: NotifySender,
    pplns_window: Arc<RwLock<PplnsWindow>>,
    share_validator: Arc<dyn ShareValidator + Send + Sync>,
    /// Blocks whose parent height exceeds the confirmed tip, keyed by the
    /// parent's expected height. One block per height since the confirmed
    /// chain has exactly one block per height.
    pending_blocks: BTreeMap<u32, ShareBlock>,
}

impl OrganiseWorker {
    /// Creates a new organise worker.
    pub fn new(
        organise_rx: OrganiseReceiver,
        chain_store_handle: ChainStoreHandle,
        monitoring_event_sender: MonitoringEventSender,
        notify_tx: NotifySender,
        pplns_window: Arc<RwLock<PplnsWindow>>,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> Self {
        Self {
            organise_rx,
            chain_store_handle,
            monitoring_event_sender,
            notify_tx,
            pplns_window,
            share_validator,
            pending_blocks: BTreeMap::new(),
        }
    }

    /// Runs the organise worker until the channel closes or a fatal error occurs.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(OrganiseError)` on fatal failure (store writer dead).
    pub async fn run(mut self) -> Result<(), OrganiseError> {
        info!("Organise worker started");

        // Make sure pplns window is warmed up with current chain state in store
        self.update_pplns_window();

        while let Some(event) = self.organise_rx.recv().await {
            match event {
                OrganiseEvent::Header(header) => {
                    let blockhash = header.block_hash();
                    debug!("Organising header: {blockhash:?}");
                    match self.chain_store_handle.organise_header(header).await {
                        Ok(Some(_height)) => {}
                        Ok(None) => {}
                        Err(StoreError::ChannelClosed) => {
                            error!("Store writer channel closed during organise header");
                            return Err(OrganiseError {
                                message: "Store writer channel closed".to_string(),
                            });
                        }
                        Err(error) => {
                            error!("Error organising header {error}");
                        }
                    }
                }
                OrganiseEvent::Block(share_block) => {
                    self.handle_organise_block_event(share_block).await?;
                }
            }
        }
        info!("Organise worker stopped - channel closed");
        Ok(())
    }

    /// Validate, promote, and follow up on a single share block.
    ///
    /// Validation failures and non-fatal store errors are logged and
    /// dropped so the worker keeps running. Only `StoreError::ChannelClosed`
    /// during promotion is propagated as a fatal `OrganiseError`.
    async fn handle_organise_block_event(
        &mut self,
        share_block: ShareBlock,
    ) -> Result<(), OrganiseError> {
        if let Some(parent_height) = self.should_buffer_block(&share_block) {
            self.buffer_block(parent_height, share_block);
            return Ok(());
        }

        let promoted_height = self.validate_and_promote_block(&share_block).await?;

        if let Some(height) = promoted_height {
            self.post_promote(&share_block, height).await;
            self.drain_pending_blocks().await?;
        }

        Ok(())
    }

    /// Validate a block with chain context and promote it to confirmed.
    ///
    /// Returns the confirmed height on successful promotion, None when
    /// validation fails or the block is not promoted, or a fatal error
    /// when the store channel is closed.
    async fn validate_and_promote_block(
        &self,
        share_block: &ShareBlock,
    ) -> Result<Option<u32>, OrganiseError> {
        let blockhash = share_block.block_hash();
        debug!("Organising block: {blockhash:?}");

        if let Err(validation_error) = self
            .share_validator
            .validate_with_chain_context(share_block, &self.chain_store_handle)
        {
            error!("Chain-context validation failed for {blockhash}: {validation_error}");
            return Ok(None);
        }

        match self
            .chain_store_handle
            .promote_block(share_block.header.clone())
            .await
        {
            Ok(Some(height)) => Ok(Some(height)),
            Ok(None) => Ok(None),
            Err(StoreError::ChannelClosed) => {
                error!("Store writer channel closed during promote block");
                Err(OrganiseError {
                    message: "Store writer channel closed".to_string(),
                })
            }
            Err(error) => {
                error!("Error promoting block {blockhash}: {error}");
                Ok(None)
            }
        }
    }

    /// Run post-promotion actions: update PPLNS, optionally send new
    /// notify, and emit a monitoring event.
    async fn post_promote(&self, share_block: &ShareBlock, height: u32) {
        self.update_pplns_window();

        match self.chain_store_handle.get_candidate_tip_height() {
            Ok(Some(candidate_tip_height)) if height >= candidate_tip_height => {
                self.send_new_notify(height, candidate_tip_height).await;
            }
            Ok(Some(_)) => {}
            _ => debug!("No candidate tip found"),
        }

        self.emit_share_monitoring_event(share_block, height);
    }

    /// Check whether a block's parent height exceeds the confirmed tip.
    ///
    /// Returns `Some(parent_height)` when the block should be buffered
    /// because the confirmed chain has not yet reached the parent's
    /// height. Returns `None` when the block can proceed to validation
    /// immediately.
    fn should_buffer_block(&self, share_block: &ShareBlock) -> Option<u32> {
        let parent_hash = share_block.header.prev_share_blockhash;
        let parent_metadata = match self.chain_store_handle.get_block_metadata(&parent_hash) {
            Ok(metadata) => metadata,
            Err(_) => return None,
        };
        let parent_height = parent_metadata.expected_height?;
        let confirmed_tip = match self.chain_store_handle.get_tip_height() {
            Ok(Some(tip)) => tip,
            Ok(None) => 0,
            Err(_) => return None,
        };
        if parent_height > confirmed_tip {
            return Some(parent_height);
        }
        None
    }

    /// Insert a block into the pending buffer, keyed by its parent height.
    ///
    /// Drops the block with an error log if the buffer is at capacity.
    fn buffer_block(&mut self, parent_height: u32, share_block: ShareBlock) {
        if self.pending_blocks.len() >= PENDING_BLOCKS_CAPACITY {
            error!(
                "Pending block buffer full ({PENDING_BLOCKS_CAPACITY}), dropping block {}",
                share_block.block_hash()
            );
            return;
        }
        info!(
            "Buffering block {} at parent height {parent_height} (confirmed tip not yet reached)",
            share_block.block_hash()
        );
        self.pending_blocks.insert(parent_height, share_block);
    }

    /// Process buffered blocks whose parent height is now at or below the
    /// confirmed tip.
    ///
    /// After each successful promotion the confirmed tip advances, so
    /// additional buffered blocks may become processable. Uses an
    /// iterative loop that terminates when no more buffered blocks are
    /// ready or no promotions occurred in the last pass.
    async fn drain_pending_blocks(&mut self) -> Result<(), OrganiseError> {
        loop {
            let confirmed_tip = match self.chain_store_handle.get_tip_height() {
                Ok(Some(tip)) => tip,
                Ok(None) => return Ok(()),
                Err(error) => {
                    error!("Failed to get confirmed tip during drain: {error}");
                    return Ok(());
                }
            };

            // split_off returns entries with key >= confirmed_tip + 1,
            // leaving entries with key <= confirmed_tip in self.pending_blocks.
            let not_ready = self.pending_blocks.split_off(&(confirmed_tip + 1));
            // Move not_ready into pending_blocks and return the current pending_blocks as processable
            let processable = std::mem::replace(&mut self.pending_blocks, not_ready);

            if processable.is_empty() {
                return Ok(());
            }

            info!(
                "Draining {} buffered blocks with parent height <= confirmed tip {confirmed_tip}",
                processable.len()
            );

            let mut promoted_any = false;
            for (_parent_height, share_block) in processable {
                let promoted_height = self.validate_and_promote_block(&share_block).await?;
                if let Some(height) = promoted_height {
                    self.post_promote(&share_block, height).await;
                    promoted_any = true;
                }
            }

            if !promoted_any {
                return Ok(());
            }
        }
    }

    /// Update the shared PplnsWindow cache after a block is promoted.
    ///
    /// Acquires a write lock, calls update, and releases the lock before
    /// returning. This ensures the window reflects the latest confirmed
    /// chain state before dependents are scheduled for validation.
    fn update_pplns_window(&self) {
        let mut window = self
            .pplns_window
            .write()
            .expect("PPLNS window lock poisoned on write");
        if let Err(error) = window.update(&self.chain_store_handle) {
            error!("Failed to update PPLNS window: {error}");
        }
    }

    /// Send new notify message to workers after share chain is
    /// extended. This is important to keep uncles from being generated.
    ///
    /// Sends a NewNotify command to the notifier when the confirmed chain
    /// catches up to the candidate tip.
    async fn send_new_notify(&self, confirmed_height: u32, candidate_tip_height: u32) {
        debug!(
            "Confirmed height {confirmed_height} caught up to candidate tip {candidate_tip_height}. Sending new work to miners."
        );
        if self.notify_tx.send(NotifyCmd::NewNotify).await.is_err() {
            error!("Notify channel closed. Cannot send new work to miners.");
        }
    }

    /// Emits a Share monitoring event for a confirmed share.
    ///
    /// Looks up uncle details from the store so that subscribers receive
    /// full uncle information in a single event.
    fn emit_share_monitoring_event(&self, share_block: &ShareBlock, height: u32) {
        let uncle_infos = self
            .chain_store_handle
            .get_uncle_infos(&share_block.header.uncles);

        let share_info = ShareInfo {
            blockhash: share_block.block_hash(),
            prev_blockhash: share_block.header.prev_share_blockhash,
            height,
            miner_address: share_block.header.miner_bitcoin_address.to_string(),
            timestamp: share_block.header.time,
            bits: share_block.header.bits,
            uncles: uncle_infos,
        };
        let event = MonitoringEvent::Share(share_info);
        if self.monitoring_event_sender.send(event).is_err() {
            debug!("No monitoring subscribers for Share event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring_events::create_monitoring_event_channel;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::store::block_tx_metadata::BlockMetadata;
    use crate::stratum::work::notify::{NotifyCmd, NotifyReceiver};

    /// Create a notify channel for tests, returning the sender and receiver.
    fn create_test_notify_channel() -> (NotifySender, NotifyReceiver) {
        tokio::sync::mpsc::channel::<NotifyCmd>(10)
    }

    /// Create a mock PplnsWindow wrapped in Arc<RwLock<>> for tests.
    /// The mock expects `update` to succeed and return false (no change).
    fn create_test_pplns_window() -> Arc<RwLock<PplnsWindow>> {
        let mut mock_window = PplnsWindow::default();
        mock_window.expect_update().returning(|_| Ok(false));
        Arc::new(RwLock::new(mock_window))
    }

    /// Build a stub share validator that approves every chain-context check.
    fn stub_share_validator_with_success() -> Arc<dyn ShareValidator + Send + Sync> {
        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _| Ok(()));
        Arc::new(mock_validator)
    }

    #[tokio::test]
    async fn test_organise_worker_stops_on_channel_close() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Drop sender so recv() returns None immediately
        drop(_organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_calls_organise_header() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_organise_header()
            .returning(|_| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx
            .send(OrganiseEvent::Header(share.header))
            .await
            .unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_calls_organise_block() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_skips_promote_when_validator_rejects() {
        use crate::shares::validation::ValidationError;

        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        // promote_block must NOT be called when chain-context validation fails.
        mock_chain_handle.expect_promote_block().never();

        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _| Err(ValidationError::new("rejected for test")));
        let share_validator: Arc<dyn ShareValidator + Send + Sync> = Arc::new(mock_validator);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            share_validator,
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_fatal_on_channel_closed() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Err(StoreError::ChannelClosed));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_organise_worker_continues_on_non_fatal_error() {
        let (tx, rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Err(StoreError::Database("test error".to_string())));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(tx);

        // Worker should continue past the non-fatal error and exit cleanly
        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_sends_new_notify_when_confirmed_catches_up() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(None));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(5)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Verify NewNotify was sent on the notify channel
        let cmd = notify_rx.try_recv();
        assert!(cmd.is_ok());
        assert!(matches!(cmd.unwrap(), NotifyCmd::NewNotify));
    }

    #[tokio::test]
    async fn test_organise_worker_no_new_notify_when_confirmed_below_candidate() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(None));
        // Confirmed height 3 is below candidate tip 5
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(3)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // No NewNotify should have been sent
        assert!(notify_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_organise_worker_buffers_block_when_parent_above_confirmed_tip() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(10),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: crate::store::block_tx_metadata::Status::Candidate,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle.expect_promote_block().never();

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_does_not_buffer_when_parent_at_confirmed_tip() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: crate::store::block_tx_metadata::Status::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(6)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_drains_buffered_block_after_promotion() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);

        // First call: block A has parent at height 100, tip is 5 -> buffer.
        // Second call: block B has parent at height 5, tip is 5 -> proceed.
        // Third call (during drain): block A re-checked, parent at 100 still.
        let metadata_call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let metadata_counter = metadata_call_count.clone();
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(move |_| {
                let count = metadata_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let height = if count == 0 { 100 } else { 5 };
                Ok(BlockMetadata {
                    expected_height: Some(height),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: crate::store::block_tx_metadata::Status::Confirmed,
                })
            });

        // First call (should_buffer for block A): tip is 5 -> buffer.
        // Second call (should_buffer for block B): tip is 5 -> proceed.
        // Third call (drain after B promotes): tip is 100 -> drain A.
        // Fourth call (drain loop re-check): tip is 100 -> empty, stop.
        let tip_call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let tip_counter = tip_call_count.clone();
        mock_chain_handle
            .expect_get_tip_height()
            .returning(move || {
                let count = tip_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tip = if count < 2 { 5 } else { 100 };
                Ok(Some(tip))
            });

        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(100)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(100)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Block A: parent height 100, will be buffered
        let share_a = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx
            .send(OrganiseEvent::Block(share_a))
            .await
            .unwrap();

        // Block B: parent height 5, will proceed and promote
        let share_b = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695792)
            .build();
        organise_tx
            .send(OrganiseEvent::Block(share_b))
            .await
            .unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // promote_block was called at least twice: once for B, once for
        // drained A. The mock allows unlimited calls.
    }
}
