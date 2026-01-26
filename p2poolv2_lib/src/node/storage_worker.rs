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

//! Storage worker processes database writes in a dedicated task.
//!
//! This serializes all database writes to ensure consistent ordering and
//! offloads I/O-bound operations from the main swarm event loop.
//!
//! # Future Optimizations
//!
//! The current implementation processes items one by one. Potential optimizations:
//! - Batch multiple writes into a single RocksDB WriteBatch for better throughput
//! - Use multi-threaded batch processing for parallel writes when safe
//! - Implement write-ahead logging for crash recovery

use crate::accounting::simple_pplns::SimplePplnsShare;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::share_block::ShareBlock;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Items that can be stored by the storage worker.
#[derive(Debug)]
pub enum StorageItem {
    /// A share block to store in the chain (with confirm_txs flag)
    ShareBlock {
        share: ShareBlock,
        confirm_txs: bool,
    },
    /// A PPLNS share for accounting
    PplnsShare(SimplePplnsShare),
}

/// Sender type for the storage channel.
pub type StorageSender = mpsc::Sender<StorageItem>;

/// Receiver type for the storage channel.
pub type StorageReceiver = mpsc::Receiver<StorageItem>;

/// Creates a new storage channel with the specified buffer capacity.
pub fn storage_channel(capacity: usize) -> (StorageSender, StorageReceiver) {
    mpsc::channel(capacity)
}

/// Worker that processes database writes in a dedicated task.
///
/// Receives `ShareBlock` and `SimplePplnsShare` items over a channel
/// and stores them one by one to the database. This serializes all
/// writes and avoids using blocking spawsn.
///
/// We can use micro batching later to optimise writes, especially the
/// pplns writes - if need be.
pub struct StorageWorker {
    storage_rx: StorageReceiver,
    chain_store: Arc<ChainStore>,
}

impl StorageWorker {
    /// Creates a new storage worker.
    pub fn new(storage_rx: StorageReceiver, chain_store: Arc<ChainStore>) -> Self {
        Self {
            storage_rx,
            chain_store,
        }
    }

    /// Runs the storage worker until the storage channel is closed.
    ///
    /// Processes items sequentially for now. This avoids using
    /// blocking spawns.  Errors are logged but do not stop the
    /// worker.
    pub async fn run(mut self) {
        info!("Storage worker started");

        while let Some(item) = self.storage_rx.recv().await {
            self.store_item(item);
        }

        info!("Storage worker stopped - channel closed");
    }

    /// Process a single storage item.
    fn store_item(&self, item: StorageItem) {
        match item {
            StorageItem::ShareBlock { share, confirm_txs } => {
                debug!("Storing share block: {:?}", share.block_hash());
                if let Err(e) = self.chain_store.add_share(&share, confirm_txs) {
                    error!("Failed to store share block: {e}");
                }
            }
            StorageItem::PplnsShare(pplns) => {
                debug!("Storing PPLNS share for user: {}", pplns.user_id);
                if let Err(e) = self.chain_store.add_pplns_share(pplns) {
                    error!("Failed to store PPLNS share: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store::MockChainStore;
    use crate::test_utils::TestShareBlockBuilder;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_storage_worker_processes_share_block() {
        let (tx, rx) = storage_channel(10);

        let share_block = TestShareBlockBuilder::new().build();
        let share_clone = share_block.clone();

        let mut mock_store = MockChainStore::default();
        mock_store
            .expect_add_share()
            .with(eq(share_clone), eq(true))
            .times(1)
            .returning(|_, _| Ok(()));

        let worker = StorageWorker::new(rx, Arc::new(mock_store));

        // Send item and drop sender to close channel
        tx.send(StorageItem::ShareBlock {
            share: share_block,
            confirm_txs: true,
        })
        .await
        .unwrap();
        drop(tx);

        // Run worker - it will process the item and exit when channel closes
        worker.run().await;
    }

    #[tokio::test]
    async fn test_storage_worker_processes_pplns_share() {
        let (tx, rx) = storage_channel(10);

        let pplns = SimplePplnsShare {
            user_id: 42,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };
        let pplns_clone = pplns.clone();

        let mut mock_store = MockChainStore::default();
        mock_store
            .expect_add_pplns_share()
            .withf(move |p: &SimplePplnsShare| p.user_id == pplns_clone.user_id)
            .times(1)
            .returning(|_| Ok(()));

        let worker = StorageWorker::new(rx, Arc::new(mock_store));

        tx.send(StorageItem::PplnsShare(pplns)).await.unwrap();
        drop(tx);

        worker.run().await;
    }

    #[tokio::test]
    async fn test_storage_worker_handles_share_error() {
        let (tx, rx) = storage_channel(10);

        let share_block = TestShareBlockBuilder::new().build();
        let share_clone = share_block.clone();

        let mut mock_store = MockChainStore::default();
        mock_store
            .expect_add_share()
            .with(eq(share_clone), eq(true))
            .times(1)
            .returning(|_, _| Err("Database error".into()));

        let worker = StorageWorker::new(rx, Arc::new(mock_store));

        tx.send(StorageItem::ShareBlock {
            share: share_block,
            confirm_txs: true,
        })
        .await
        .unwrap();
        drop(tx);

        // Worker should not panic on error, just log it
        worker.run().await;
    }

    #[tokio::test]
    async fn test_storage_worker_handles_pplns_error() {
        let (tx, rx) = storage_channel(10);

        let pplns = SimplePplnsShare {
            user_id: 42,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let mut mock_store = MockChainStore::default();
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Err("PPLNS storage error".into()));

        let worker = StorageWorker::new(rx, Arc::new(mock_store));

        tx.send(StorageItem::PplnsShare(pplns)).await.unwrap();
        drop(tx);

        // Worker should not panic on error, just log it
        worker.run().await;
    }

    #[tokio::test]
    async fn test_storage_worker_processes_multiple_items() {
        let (tx, rx) = storage_channel(10);

        let share1 = TestShareBlockBuilder::new().nonce(1).build();
        let share2 = TestShareBlockBuilder::new().nonce(2).build();
        let pplns = SimplePplnsShare {
            user_id: 42,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let mut mock_store = MockChainStore::default();
        mock_store
            .expect_add_share()
            .times(2)
            .returning(|_, _| Ok(()));
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        let worker = StorageWorker::new(rx, Arc::new(mock_store));

        tx.send(StorageItem::ShareBlock {
            share: share1,
            confirm_txs: true,
        })
        .await
        .unwrap();
        tx.send(StorageItem::PplnsShare(pplns)).await.unwrap();
        tx.send(StorageItem::ShareBlock {
            share: share2,
            confirm_txs: false,
        })
        .await
        .unwrap();
        drop(tx);

        worker.run().await;
    }
}
