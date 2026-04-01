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
use crate::node::validation_worker::{ValidationEvent, ValidationSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::dag_store::ShareInfo;
use crate::store::writer::StoreError;
use crate::stratum::work::notify::{NotifyCmd, NotifySender};
use bitcoin::BlockHash;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Channel capacity for shares pending organisation.
const ORGANISE_CHANNEL_CAPACITY: usize = 256;

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
    validation_tx: ValidationSender,
}

impl OrganiseWorker {
    /// Creates a new organise worker.
    pub fn new(
        organise_rx: OrganiseReceiver,
        chain_store_handle: ChainStoreHandle,
        monitoring_event_sender: MonitoringEventSender,
        notify_tx: NotifySender,
        pplns_window: Arc<RwLock<PplnsWindow>>,
        validation_tx: ValidationSender,
    ) -> Self {
        Self {
            organise_rx,
            chain_store_handle,
            monitoring_event_sender,
            notify_tx,
            pplns_window,
            validation_tx,
        }
    }

    /// Runs the organise worker until the channel closes or a fatal error occurs.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(OrganiseError)` on fatal failure (store writer dead).
    pub async fn run(mut self) -> Result<(), OrganiseError> {
        info!("Organise worker started");
        while let Some(event) = self.organise_rx.recv().await {
            match event {
                OrganiseEvent::Header(header) => {
                    let blockhash = header.block_hash();
                    debug!("Organising header: {blockhash:?}");
                    match self.chain_store_handle.organise_header(header).await {
                        Ok(Some((_height, _valid_blocks))) => {}
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
                    let blockhash = share_block.block_hash();
                    debug!("Organising block: {blockhash:?}");
                    match self
                        .chain_store_handle
                        .promote_block(share_block.header.clone())
                        .await
                    {
                        Ok(Some(height)) => {
                            self.update_pplns_window();
                            self.schedule_dependents(&blockhash).await;

                            if let Ok(Some(candidate_tip_height)) =
                                self.chain_store_handle.get_candidate_tip_height()
                            {
                                if height >= candidate_tip_height {
                                    self.send_new_notify(height, candidate_tip_height).await;
                                }
                            } else {
                                debug!("No candidate tip found");
                            }
                            self.emit_share_monitoring_event(&share_block, height);
                        }
                        Ok(None) => {}
                        Err(StoreError::ChannelClosed) => {
                            error!("Store writer channel closed during promote block");
                            return Err(OrganiseError {
                                message: "Store writer channel closed".to_string(),
                            });
                        }
                        Err(error) => {
                            error!("Error promoting block {blockhash}: {error}");
                        }
                    }
                }
            }
        }
        info!("Organise worker stopped - channel closed");
        Ok(())
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

    /// Schedule stored children and nephews for validation.
    ///
    /// Called after promote_block and PPLNS update so that dependents
    /// validate against the freshly updated window.
    async fn schedule_dependents(&self, block_hash: &BlockHash) {
        let mut dependent_hashes = Vec::with_capacity(4);

        if let Ok(Some(children)) = self.chain_store_handle.get_children_blockhashes(block_hash) {
            for child_hash in children {
                if self.chain_store_handle.share_block_exists(&child_hash) {
                    dependent_hashes.push(child_hash);
                }
            }
        }

        if let Some(nephews) = self.chain_store_handle.get_nephews(block_hash) {
            for nephew_hash in nephews {
                if self.chain_store_handle.share_block_exists(&nephew_hash) {
                    dependent_hashes.push(nephew_hash);
                }
            }
        }

        for dependent_hash in dependent_hashes {
            info!("Scheduling dependent {dependent_hash} for validation after {block_hash}");
            if let Err(send_error) = self
                .validation_tx
                .send(ValidationEvent::ValidateBlock(dependent_hash))
                .await
            {
                error!(
                    "Failed to schedule dependent {dependent_hash} for validation: {send_error}"
                );
            }
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
    use crate::node::validation_worker::create_validation_channel;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
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

    /// Add mock expectations for schedule_dependents: no children, no nephews.
    fn setup_no_dependents(mock: &mut MockChainStoreHandle) {
        mock.expect_get_children_blockhashes()
            .returning(|_| Ok(None));
        mock.expect_get_nephews().returning(|_| None);
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
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
            .expect_promote_block()
            .returning(|_| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
            .expect_promote_block()
            .returning(|_| Err(StoreError::ChannelClosed));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
            .expect_promote_block()
            .returning(|_| Err(StoreError::Database("test error".to_string())));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
            .expect_promote_block()
            .returning(|_| Ok(Some(5)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());
        setup_no_dependents(&mut mock_chain_handle);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
        setup_no_dependents(&mut mock_chain_handle);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_pplns_window(),
            validation_tx,
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
    async fn test_organise_worker_updates_pplns_and_schedules_dependents() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(5)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let child_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse::<BlockHash>()
            .unwrap();
        mock_chain_handle
            .expect_get_children_blockhashes()
            .returning(move |_| Ok(Some(vec![child_hash])));
        mock_chain_handle
            .expect_share_block_exists()
            .returning(|_| true);
        mock_chain_handle.expect_get_nephews().returning(|_| None);

        let mut mock_window = PplnsWindow::default();
        mock_window.expect_update().returning(|_| Ok(true));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let (validation_tx, mut validation_rx) = create_validation_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            pplns_window,
            validation_tx,
        );

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // Verify the child was scheduled for validation
        let event = validation_rx.try_recv();
        assert!(event.is_ok());
        let ValidationEvent::ValidateBlock(hash) = event.unwrap();
        assert_eq!(hash, child_hash);
    }
}
