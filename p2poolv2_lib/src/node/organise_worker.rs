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

//! Organisation worker that updates candidate and confirmed indexes.
//!
//! Receives stored ShareBlocks and triggers atomic organisation of the
//! candidate/confirmed indexes in the chain store. Runs in a dedicated
//! tokio task, decoupled from share producers (emission worker, peer
//! handler, future validation worker).

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::store::writer::StoreError;
use std::fmt;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Channel capacity for shares pending organisation.
const ORGANISE_CHANNEL_CAPACITY: usize = 256;

/// Sender half of the organise channel.
pub type OrganiseSender = mpsc::Sender<ShareBlock>;
/// Receiver half of the organise channel.
pub type OrganiseReceiver = mpsc::Receiver<ShareBlock>;

/// Create an organise channel with bounded capacity.
pub fn organise_channel() -> (OrganiseSender, OrganiseReceiver) {
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

/// Worker that triggers organisation of stored shares.
///
/// Receives `ShareBlock` values that have already been stored in the
/// chain and triggers atomic updates to the candidate/confirmed indexes
/// via `ChainStoreHandle`.
pub struct OrganiseWorker {
    organise_rx: OrganiseReceiver,
    chain_store_handle: ChainStoreHandle,
}

impl OrganiseWorker {
    /// Creates a new organise worker.
    pub fn new(organise_rx: OrganiseReceiver, chain_store_handle: ChainStoreHandle) -> Self {
        Self {
            organise_rx,
            chain_store_handle,
        }
    }

    /// Runs the organise worker until the channel closes or a fatal error occurs.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(OrganiseError)` on fatal failure (store writer dead).
    pub async fn run(mut self) -> Result<(), OrganiseError> {
        info!("Organise worker started");
        while let Some(share_block) = self.organise_rx.recv().await {
            debug!("Organising share: {:?}", share_block.block_hash());
            match self.chain_store_handle.organise_share(share_block).await {
                Ok(()) => {
                    debug!("Organised share");
                }
                Err(StoreError::ChannelClosed) => {
                    error!("Store writer channel closed during organise");
                    return Err(OrganiseError {
                        message: "Store writer channel closed".to_string(),
                    });
                }
                Err(e) => {
                    error!("Error organising share {e}");
                }
            }
        }
        info!("Organise worker stopped - channel closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;

    #[tokio::test]
    async fn test_organise_worker_stops_on_channel_close() {
        let (_tx, rx) = organise_channel();
        let mut mock = MockChainStoreHandle::new();
        mock.expect_clone().return_once(MockChainStoreHandle::new);
        let worker = OrganiseWorker::new(rx, mock);

        // Drop sender so recv() returns None immediately
        drop(_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_calls_organise_share() {
        let (tx, rx) = organise_channel();
        let mut mock = MockChainStoreHandle::new();
        mock.expect_clone().return_once(MockChainStoreHandle::new);
        mock.expect_organise_share().returning(|_| Ok(()));

        let worker = OrganiseWorker::new(rx, mock);

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        tx.send(share).await.unwrap();
        drop(tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_fatal_on_channel_closed() {
        let (tx, rx) = organise_channel();
        let mut mock = MockChainStoreHandle::new();
        mock.expect_clone().return_once(MockChainStoreHandle::new);
        mock.expect_organise_share()
            .returning(|_| Err(StoreError::ChannelClosed));

        let worker = OrganiseWorker::new(rx, mock);

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        tx.send(share).await.unwrap();
        drop(tx);

        let result = worker.run().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_organise_worker_continues_on_non_fatal_error() {
        let (tx, rx) = organise_channel();
        let mut mock = MockChainStoreHandle::new();
        mock.expect_clone().return_once(MockChainStoreHandle::new);
        mock.expect_organise_share()
            .returning(|_| Err(StoreError::Database("test error".to_string())));

        let worker = OrganiseWorker::new(rx, mock);

        let share = crate::test_utils::TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build();
        tx.send(share).await.unwrap();
        drop(tx);

        // Worker should continue past the non-fatal error and exit cleanly
        let result = worker.run().await;
        assert!(result.is_ok());
    }
}
