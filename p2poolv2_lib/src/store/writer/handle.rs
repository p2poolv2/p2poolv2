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

//! Store handle providing direct reads and serialized writes.
//!
//! `StoreHandle` combines an `Arc<Store>` for direct read access with a
//! write channel for serialized database writes. This allows fast reads
//! while ensuring all writes are processed sequentially.

use super::{StoreError, WriteCommand, WriteSender};
use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::store::Store;
use crate::store::stored_user::StoredUser;
use bitcoin::{BlockHash, Work};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Handle for interacting with the store.
///
/// Provides direct read access via `Arc<Store>` and serialized write
/// access through a channel to the `StoreWriter` task.
#[derive(Clone)]
pub struct StoreHandle {
    store: Arc<Store>,
    write_tx: WriteSender,
}

impl StoreHandle {
    /// Create a new store handle.
    pub fn new(store: Arc<Store>, write_tx: WriteSender) -> Self {
        Self { store, write_tx }
    }

    /// Get direct access to the underlying store for read operations.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    // ========================================================================
    // DIRECT READS - These delegate directly to Store (may block briefly)
    // ========================================================================

    /// Get a share from the store.
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock> {
        self.store.get_share(blockhash)
    }

    /// Get the share at the current chain tip.
    pub fn get_share_at_tip(&self) -> Option<ShareBlock> {
        self.store.get_share_at_tip()
    }

    /// Get share headers for multiple blockhashes.
    pub fn get_share_headers(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<Vec<ShareHeader>, StoreError> {
        self.store.get_share_headers(blockhashes)
    }

    /// Get a share header from the store.
    pub fn get_share_header(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<ShareHeader>, StoreError> {
        self.store.get_share_header(blockhash)
    }

    /// Get multiple shares from the store.
    pub fn get_shares(
        &self,
        blockhashes: &[BlockHash],
    ) -> Result<HashMap<BlockHash, ShareBlock>, StoreError> {
        self.store.get_shares(blockhashes)
    }

    /// Get shares at a specific height.
    pub fn get_shares_at_height(
        &self,
        height: u32,
    ) -> Result<HashMap<BlockHash, ShareBlock>, StoreError> {
        self.store.get_shares_at_height(height)
    }

    /// Get blockhashes for a specific height.
    pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash> {
        self.store.get_blockhashes_for_height(height)
    }

    /// Check which blockhashes are missing from the store.
    pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash> {
        self.store.get_missing_blockhashes(blockhashes)
    }

    /// Get the genesis blockhash from the chain.
    pub fn get_genesis_blockhash(&self) -> Option<BlockHash> {
        self.store.get_genesis_blockhash()
    }

    /// Get the current chain tip.
    pub fn get_chain_tip(&self) -> BlockHash {
        self.store.get_chain_tip()
    }

    /// Get all tips from chain state.
    pub fn get_tips(&self) -> HashSet<BlockHash> {
        self.store.get_tips()
    }

    /// Get the total work of the chain.
    pub fn get_total_work(&self) -> Result<Work, StoreError> {
        self.store.get_total_work()
    }

    /// Get all PPLNS shares.
    pub fn get_pplns_shares(&self) -> Vec<SimplePplnsShare> {
        self.store.get_pplns_shares()
    }

    /// Get PPLNS shares with filtering.
    pub fn get_pplns_shares_filtered(
        &self,
        limit: Option<usize>,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        self.store
            .get_pplns_shares_filtered(limit, start_time, end_time)
    }

    /// Get jobs within a time range.
    pub fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, StoreError> {
        self.store.get_jobs(start_time, end_time, limit)
    }

    /// Get user by user ID.
    pub fn get_user_by_id(&self, user_id: u64) -> Result<Option<StoredUser>, StoreError> {
        self.store.get_user_by_id(user_id)
    }

    /// Get user by btcaddress.
    pub fn get_user_by_btcaddress(
        &self,
        btcaddress: &str,
    ) -> Result<Option<StoredUser>, StoreError> {
        self.store.get_user_by_btcaddress(btcaddress)
    }

    /// Get bitcoin addresses for multiple user IDs.
    pub fn get_btcaddresses_for_user_ids(
        &self,
        user_ids: &[u64],
    ) -> Result<Vec<(u64, String)>, StoreError> {
        self.store.get_btcaddresses_for_user_ids(user_ids)
    }

    /// Get children blockhashes for a given blockhash.
    pub fn get_children_blockhashes(
        &self,
        blockhash: &BlockHash,
    ) -> Result<Option<Vec<BlockHash>>, StoreError> {
        self.store.get_children_blockhashes(blockhash)
    }

    // ========================================================================
    // SERIALIZED WRITES - These go through the channel to StoreWriter
    //
    // The reason to use serialized writes through a worker is to
    // avoid rocksdb write stalls to block all tokio threads. This
    // pattern comes highly recommended in the tokio/rocksdb
    // users community.
    // ========================================================================

    /// Add a share to the store.
    pub async fn add_share(
        &self,
        share: ShareBlock,
        height: u32,
        chain_work: Work,
        confirm_txs: bool,
    ) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::AddShare {
                share,
                height,
                chain_work,
                confirm_txs,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Setup genesis block.
    pub async fn setup_genesis(&self, genesis: ShareBlock) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::SetupGenesis {
                genesis,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Initialize chain state from store.
    pub async fn init_chain_state_from_store(
        &self,
        genesis_hash: BlockHash,
    ) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::InitChainStateFromStore {
                genesis_hash,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Add a job to the store.
    pub async fn add_job(
        &self,
        timestamp: u64,
        serialized_notify: String,
    ) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::AddJob {
                timestamp,
                serialized_notify,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Add a user to the store. Returns the user ID.
    pub async fn add_user(&self, btcaddress: String) -> Result<u64, StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::AddUser {
                btcaddress,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Organise a share: update candidate and confirmed indexes atomically.
    pub async fn organise_share(&self, share: ShareBlock) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::OrganiseShare {
                share,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    /// Add a PPLNS share for accounting.
    pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteCommand::AddPplnsShare {
                pplns_share,
                reply: reply_tx,
            })
            .map_err(|_| StoreError::ChannelClosed)?;
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?
    }

    // ========================================================================
    // SYNC CHAIN STATE UPDATES - Direct in-memory operations (no serialization needed)
    // ========================================================================

    /// Set the chain tip (sync, in-memory RwLock update).
    pub fn set_chain_tip(&self, hash: BlockHash) {
        self.store.set_chain_tip(hash);
    }

    /// Set the genesis block hash (sync, in-memory RwLock update).
    pub fn set_genesis_blockhash(&self, hash: BlockHash) {
        self.store.set_genesis_blockhash(hash);
    }

    /// Update all tips (sync, in-memory RwLock update).
    pub fn update_tips(&self, tips: HashSet<BlockHash>) {
        self.store.update_tips(tips);
    }

    /// Add a tip (sync, in-memory RwLock update).
    pub fn add_tip(&self, hash: BlockHash) {
        self.store.add_tip(hash);
    }

    /// Remove a tip (sync, in-memory RwLock update).
    pub fn remove_tip(&self, hash: &BlockHash) {
        self.store.remove_tip(hash);
    }
}

// Mock for StoreHandle using mockall
// This allows tests to create specific scenarios without real storage
#[cfg(test)]
mockall::mock! {
    pub StoreHandle {
        // Constructor
        pub fn new(store: Arc<Store>, write_tx: WriteSender) -> Self;

        // Direct reads
        pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock>;
        pub fn get_share_at_tip(&self) -> Option<ShareBlock>;
        pub fn get_share_headers(&self, blockhashes: &[BlockHash]) -> Result<Vec<ShareHeader>, StoreError>;
        pub fn get_share_header(&self, blockhash: &BlockHash) -> Result<Option<ShareHeader>, StoreError>;
        pub fn get_shares(&self, blockhashes: &[BlockHash]) -> Result<HashMap<BlockHash, ShareBlock>, StoreError>;
        pub fn get_shares_at_height(&self, height: u32) -> Result<HashMap<BlockHash, ShareBlock>, StoreError>;
        pub fn get_blockhashes_for_height(&self, height: u32) -> Vec<BlockHash>;
        pub fn get_missing_blockhashes(&self, blockhashes: &[BlockHash]) -> Vec<BlockHash>;
        pub fn get_genesis_blockhash(&self) -> Option<BlockHash>;
        pub fn get_chain_tip(&self) -> BlockHash;
        pub fn get_tips(&self) -> HashSet<BlockHash>;
        pub fn get_total_work(&self) -> Result<Work, StoreError>;
        pub fn get_pplns_shares(&self) -> Vec<SimplePplnsShare>;
        pub fn get_pplns_shares_filtered(&self, limit: Option<usize>, start_time: Option<u64>, end_time: Option<u64>) -> Vec<SimplePplnsShare>;
        pub fn get_jobs(&self, start_time: Option<u64>, end_time: Option<u64>, limit: usize) -> Result<Vec<(u64, String)>, StoreError>;
        pub fn get_user_by_id(&self, user_id: u64) -> Result<Option<StoredUser>, StoreError>;
        pub fn get_user_by_btcaddress(&self, btcaddress: &str) -> Result<Option<StoredUser>, StoreError>;
        pub fn get_btcaddresses_for_user_ids(&self, user_ids: &[u64]) -> Result<Vec<(u64, String)>, StoreError>;
        pub fn get_children_blockhashes(&self, blockhash: &BlockHash) -> Result<Option<Vec<BlockHash>>, StoreError>;

        // Serialized writes (async)
        pub async fn organise_share(&self, blockhash: BlockHash) -> Result<(), StoreError>;
        pub async fn add_share(&self, share: ShareBlock, height: u32, chain_work: Work, confirm_txs: bool) -> Result<(), StoreError>;
        pub async fn setup_genesis(&self, genesis: ShareBlock) -> Result<(), StoreError>;
        pub async fn init_chain_state_from_store(&self, genesis_hash: BlockHash) -> Result<(), StoreError>;
        pub async fn add_job(&self, timestamp: u64, serialized_notify: String) -> Result<(), StoreError>;
        pub async fn add_user(&self, btcaddress: String) -> Result<u64, StoreError>;
        pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), StoreError>;

        // Sync chain state updates
        pub fn set_chain_tip(&self, hash: BlockHash);
        pub fn set_genesis_blockhash(&self, hash: BlockHash);
        pub fn update_tips(&self, tips: HashSet<BlockHash>);
        pub fn add_tip(&self, hash: BlockHash);
        pub fn remove_tip(&self, hash: &BlockHash);
    }

    impl Clone for StoreHandle {
        fn clone(&self) -> Self;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::writer::write_channel;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_store_handle_creation() {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let (write_tx, _write_rx) = write_channel();

        let handle = StoreHandle::new(store.clone(), write_tx);

        // Verify we can access the store
        assert!(handle.store().get_tips().is_empty());
    }

    #[tokio::test]
    async fn test_store_handle_direct_reads() {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let (write_tx, _write_rx) = write_channel();

        let handle = StoreHandle::new(store, write_tx);

        // Test various read methods
        assert!(handle.get_genesis_blockhash().is_none());
        assert!(handle.get_tips().is_empty());
        assert!(handle.get_pplns_shares().is_empty());
    }

    #[tokio::test]
    async fn test_store_handle_clone() {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let (write_tx, _write_rx) = write_channel();

        let handle1 = StoreHandle::new(store, write_tx);
        let handle2 = handle1.clone();

        // Both handles should read the same data
        assert_eq!(handle1.get_tips(), handle2.get_tips());
    }
}
