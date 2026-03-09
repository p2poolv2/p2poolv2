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

use crate::monitoring_events::{MonitoringEvent, MonitoringEventSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::dag_store::ShareInfo;
use crate::store::writer::StoreError;
use std::fmt;
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
/// via `ChainStoreHandle`.
pub struct OrganiseWorker {
    organise_rx: OrganiseReceiver,
    chain_store_handle: ChainStoreHandle,
    monitoring_event_sender: MonitoringEventSender,
}

impl OrganiseWorker {
    /// Creates a new organise worker.
    pub fn new(
        organise_rx: OrganiseReceiver,
        chain_store_handle: ChainStoreHandle,
        monitoring_event_sender: MonitoringEventSender,
    ) -> Self {
        Self {
            organise_rx,
            chain_store_handle,
            monitoring_event_sender,
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
            miner_address: share_block.header.miner_address.to_string(),
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

    #[tokio::test]
    async fn test_organise_worker_stops_on_channel_close() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let worker = OrganiseWorker::new(organise_rx, mock_chain_handle, monitoring_tx);

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
        let worker = OrganiseWorker::new(organise_rx, mock_chain_handle, monitoring_tx);

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
        let worker = OrganiseWorker::new(organise_rx, mock_chain_handle, monitoring_tx);

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
        let worker = OrganiseWorker::new(organise_rx, mock_chain_handle, monitoring_tx);

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
        let worker = OrganiseWorker::new(rx, mock_chain_handle, monitoring_tx);

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(tx);

        // Worker should continue past the non-fatal error and exit cleanly
        let result = worker.run().await;
        assert!(result.is_ok());
    }
}
