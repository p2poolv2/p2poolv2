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

use crate::node::request_response_handler::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::validation_worker::{ValidationEvent, ValidationSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation::ShareValidator;
use crate::store::block_tx_metadata::Status;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

/// Maximum number of blocks held in the pending set.
const PENDING_CAPACITY: usize = 2000;

/// Channel capacity for block receiver events.
const BLOCK_RECEIVER_CHANNEL_CAPACITY: usize = 8192;

/// Interval for evicting stale pending blocks.
const EVICTION_TICK_SECONDS: u64 = 60;

/// Maximum age of a pending block before eviction.
const STALE_THRESHOLD_SECONDS: u64 = 300;

/// Events sent to the BlockReceiver actor.
pub enum BlockReceiverEvent {
    /// A new share block arrived from a peer, after passing DoS
    /// validation (validate_share_header) in handle_share_block.
    ShareBlockReceived {
        share_block: ShareBlock,
        result_tx: oneshot::Sender<Result<(), Box<dyn Error + Send + Sync>>>,
    },
}

pub type BlockReceiverHandle = mpsc::Sender<BlockReceiverEvent>;
pub type BlockReceiverReceiver = mpsc::Receiver<BlockReceiverEvent>;

/// Create a block receiver channel with bounded capacity.
pub fn create_block_receiver_channel() -> (BlockReceiverHandle, BlockReceiverReceiver) {
    mpsc::channel(BLOCK_RECEIVER_CHANNEL_CAPACITY)
}

/// A share block waiting in the pending set for its ancestors to reach
/// HeaderValid in the store.
struct PendingBlock {
    share_block: ShareBlock,
    received_at: Instant,
}

/// Buffers incoming ShareBlocks until their direct parent and uncles are
/// at status HeaderValid (or better) in the store, then validates ASERT
/// difficulty, persists the block, and queues it for full validation.
///
/// Each block is processed in isolation against its parent's metadata
/// from the store. When a block becomes ready and is committed, any
/// previously-buffered descendants whose ancestry is now complete are
/// driven to commit via an iterative descendant worklist.
pub struct BlockReceiver {
    event_rx: BlockReceiverReceiver,
    /// Pending blocks indexed by their block hash.
    pending: HashMap<BlockHash, PendingBlock>,
    /// Reverse index: ancestor_hash -> pending blocks that declared it
    /// as parent or uncle. Used to drive descendants when an ancestor
    /// reaches HeaderValid.
    descendants: HashMap<BlockHash, Vec<BlockHash>>,
    share_validator: Arc<dyn ShareValidator + Send + Sync>,
    chain_store_handle: ChainStoreHandle,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
}

/// True iff the given status means the block has been admitted to the
/// chain at least at the HeaderValid level (so its metadata can be used
/// to validate descendants).
fn is_at_least_header_valid(status: Status) -> bool {
    matches!(
        status,
        Status::HeaderValid | Status::Candidate | Status::Confirmed | Status::BlockValid
    )
}

impl BlockReceiver {
    /// Create a new BlockReceiver actor.
    pub fn new(
        event_rx: BlockReceiverReceiver,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
        chain_store_handle: ChainStoreHandle,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
    ) -> Self {
        Self {
            event_rx,
            pending: HashMap::with_capacity(PENDING_CAPACITY),
            descendants: HashMap::with_capacity(PENDING_CAPACITY),
            share_validator,
            chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        }
    }

    /// Number of blocks currently in the pending set.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Add a block to the pending set. Evicts the oldest entry if at
    /// capacity. Updates the descendants index for parent and uncles.
    fn add_to_pending(&mut self, block_hash: BlockHash, share_block: ShareBlock) {
        if self.pending.contains_key(&block_hash) {
            return;
        }
        if self.pending.len() >= PENDING_CAPACITY {
            self.evict_oldest();
        }

        let parent_hash = share_block.header.prev_share_blockhash;
        if parent_hash != BlockHash::all_zeros() {
            self.descendants
                .entry(parent_hash)
                .or_insert_with(|| Vec::with_capacity(2))
                .push(block_hash);
        }
        for uncle_hash in &share_block.header.uncles {
            self.descendants
                .entry(*uncle_hash)
                .or_insert_with(|| Vec::with_capacity(2))
                .push(block_hash);
        }

        self.pending.insert(
            block_hash,
            PendingBlock {
                share_block,
                received_at: Instant::now(),
            },
        );
    }

    /// Remove a block from the pending set and clean up its entries
    /// in the descendants index.
    fn remove_from_pending(&mut self, block_hash: &BlockHash) -> Option<ShareBlock> {
        let pending_block = self.pending.remove(block_hash)?;

        let parent_hash = pending_block.share_block.header.prev_share_blockhash;
        if parent_hash != BlockHash::all_zeros() {
            if let Some(descendants_list) = self.descendants.get_mut(&parent_hash) {
                descendants_list.retain(|hash| hash != block_hash);
                if descendants_list.is_empty() {
                    self.descendants.remove(&parent_hash);
                }
            }
        }
        for uncle_hash in &pending_block.share_block.header.uncles {
            if let Some(descendants_list) = self.descendants.get_mut(uncle_hash) {
                descendants_list.retain(|hash| hash != block_hash);
                if descendants_list.is_empty() {
                    self.descendants.remove(uncle_hash);
                }
            }
        }

        Some(pending_block.share_block)
    }

    /// Evict the oldest pending block by received_at timestamp.
    fn evict_oldest(&mut self) {
        let oldest_hash = self
            .pending
            .iter()
            .min_by_key(|(_, pending_block)| pending_block.received_at)
            .map(|(hash, _)| *hash);

        if let Some(hash) = oldest_hash {
            debug!("Evicting oldest pending block {hash} to maintain capacity");
            self.remove_from_pending(&hash);
        }
    }

    /// Evict pending blocks older than the stale threshold.
    fn evict_stale_pending(&mut self) {
        let threshold = Instant::now() - std::time::Duration::from_secs(STALE_THRESHOLD_SECONDS);

        let stale_hashes: Vec<BlockHash> = self
            .pending
            .iter()
            .filter(|(_, pending_block)| pending_block.received_at < threshold)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in stale_hashes {
            info!("Evicting stale pending block {hash}");
            self.remove_from_pending(&hash);
        }
    }

    /// Look up parent (time, expected_height) for ASERT.
    fn get_parent_time_and_height(
        &self,
        parent_hash: &BlockHash,
    ) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
        let header = self.chain_store_handle.get_share_header(parent_hash)?;
        let metadata = self.chain_store_handle.get_block_metadata(parent_hash)?;
        let expected_height = metadata.expected_height.ok_or_else(|| {
            format!("Parent block {parent_hash} is missing expected_height metadata")
        })?;
        Ok((header.time, expected_height))
    }

    /// Return parent and uncle hashes that are not yet HeaderValid in
    /// the store. The returned list is what needs to be fetched before
    /// this block can be processed.
    fn collect_ancestors_not_ready(&self, share_block: &ShareBlock) -> Vec<BlockHash> {
        let header = &share_block.header;
        let mut not_ready: Vec<BlockHash> = Vec::with_capacity(1 + header.uncles.len());
        let parent_hash = header.prev_share_blockhash;
        if parent_hash != BlockHash::all_zeros() && !self.ancestor_ready(&parent_hash) {
            not_ready.push(parent_hash);
        }
        for uncle_hash in &header.uncles {
            if !self.ancestor_ready(uncle_hash) {
                not_ready.push(*uncle_hash);
            }
        }
        not_ready
    }

    /// Check whether a single ancestor hash is at status HeaderValid or
    /// better in the store.
    fn ancestor_ready(&self, hash: &BlockHash) -> bool {
        match self.chain_store_handle.get_block_metadata(hash) {
            Ok(metadata) => is_at_least_header_valid(metadata.status),
            Err(_) => false,
        }
    }

    /// ASERT difficulty check against the parent's stored time and height.
    fn validate_asert(&self, share_block: &ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        let parent_hash = share_block.header.prev_share_blockhash;
        let (parent_time, parent_height) = self.get_parent_time_and_height(&parent_hash)?;
        let expected_bits = self
            .share_validator
            .pool_difficulty()
            .calculate_target_clamped(parent_time, parent_height);
        if share_block.header.bits != expected_bits {
            let block_hash = share_block.block_hash();
            return Err(format!(
                "ASERT mismatch for {block_hash}: declared bits {:#010x}, expected {:#010x}",
                share_block.header.bits.to_consensus(),
                expected_bits.to_consensus()
            )
            .into());
        }
        Ok(())
    }

    /// Persist a committed block, organise its header, and queue it
    /// for full validation by the validation worker.
    ///
    /// The persist + organise step is performed in a single RocksDB
    /// write batch so a crash cannot leave the share stored but not
    /// organised on the candidate chain.
    async fn store_and_emit_validation(
        &self,
        block_hash: &BlockHash,
        share_block: ShareBlock,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Err(error) = self
            .chain_store_handle
            .add_share_block_and_organise_header(share_block)
            .await
        {
            error!("Failed to store and organise block {block_hash}: {error}");
            return Err(error.into());
        }

        if let Err(error) = self
            .validation_tx
            .send(ValidationEvent::ValidateBlock(*block_hash))
            .await
        {
            error!("Failed to send ValidateBlock for {block_hash}: {error}");
            return Err(error.into());
        }

        info!("Committed and queued validation for block {block_hash}");
        Ok(())
    }

    /// Process an incoming share block.
    ///
    /// Fast path: if the block is already known to the store, drop or
    /// re-emit validation as appropriate.
    ///
    /// Otherwise, if the block's direct parent and all uncles are at
    /// HeaderValid+, validate ASERT, persist, then drive any
    /// descendants buffered in pending. If the parent or uncles are
    /// not yet ready, buffer in pending. The headers-first pipeline
    /// will supply ancestors via header sync and block fetch.
    async fn process_share_block(
        &mut self,
        share_block: ShareBlock,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_hash = share_block.block_hash();

        // Already-known fast path: only skip work for terminal states.
        // For HeaderValid / Candidate / Confirmed, the header may have
        // been organised during header sync but the block body was not
        // stored, so we still need to call add_share_block via the
        // normal flow below.
        if let Ok(metadata) = self.chain_store_handle.get_block_metadata(&block_hash) {
            match metadata.status {
                Status::BlockValid => {
                    debug!("Block {block_hash} already BlockValid, ignoring");
                    return Ok(());
                }
                Status::Invalid => {
                    debug!("Block {block_hash} already marked Invalid, dropping");
                    return Ok(());
                }
                _ => {}
            }
        }

        if self.pending.contains_key(&block_hash) {
            debug!("Block {block_hash} already pending, ignoring duplicate");
            return Ok(());
        }

        // Notify block fetcher that we received this block so it can
        // clear any in-flight request.
        let _ = self
            .block_fetcher_handle
            .send(BlockFetcherEvent::BlockReceived(block_hash))
            .await;

        let ancestors_not_ready = self.collect_ancestors_not_ready(&share_block);
        if !ancestors_not_ready.is_empty() {
            debug!(
                "Block {block_hash} has {} unready ancestors, buffering",
                ancestors_not_ready.len()
            );
            self.add_to_pending(block_hash, share_block);
            return Ok(());
        }

        // Ancestry is ready: ASERT-check and persist this block.
        if let Err(error) = self.validate_asert(&share_block) {
            warn!("Dropping block {block_hash}: {error}");
            return Ok(());
        }
        self.store_and_emit_validation(&block_hash, share_block)
            .await?;

        // Drive any pending descendants now unblocked by this commit.
        self.drive_descendants(block_hash).await
    }

    /// Iteratively re-process pending descendants of `just_committed`,
    /// then descendants of those that successfully commit, etc. Each
    /// descendant is re-checked against the full ancestry-ready
    /// predicate; if it is still waiting on a different parent or
    /// uncle, it remains in pending untouched.
    async fn drive_descendants(
        &mut self,
        just_committed: BlockHash,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut queue: VecDeque<BlockHash> = VecDeque::with_capacity(4);
        if let Some(descendants_list) = self.descendants.get(&just_committed) {
            queue.extend(descendants_list.iter().copied());
        }

        while let Some(descendant_hash) = queue.pop_front() {
            let Some(pending_block) = self.pending.get(&descendant_hash) else {
                continue;
            };
            let share_block = pending_block.share_block.clone();

            let unready = self.collect_ancestors_not_ready(&share_block);
            if !unready.is_empty() {
                // Still waiting on a different ancestor; leave in pending.
                continue;
            }

            if let Err(error) = self.validate_asert(&share_block) {
                warn!("Dropping cascaded block {descendant_hash}: {error}");
                self.remove_from_pending(&descendant_hash);
                continue;
            }

            // remove_from_pending before storing so we don't keep a
            // duplicate copy in memory while the store write runs.
            self.remove_from_pending(&descendant_hash);
            self.store_and_emit_validation(&descendant_hash, share_block)
                .await?;

            if let Some(next_descendants) = self.descendants.get(&descendant_hash) {
                queue.extend(next_descendants.iter().copied());
            }
        }

        Ok(())
    }

    /// Run the BlockReceiver event loop.
    ///
    /// Processes incoming share blocks and periodically evicts stale
    /// pending blocks. Runs until the event channel is closed.
    pub async fn run(mut self) {
        let mut eviction_interval =
            tokio::time::interval(std::time::Duration::from_secs(EVICTION_TICK_SECONDS));

        loop {
            tokio::select! {
                event = self.event_rx.recv() => {
                    match event {
                        Some(BlockReceiverEvent::ShareBlockReceived {
                            share_block,
                            result_tx,
                        }) => {
                            let result = self.process_share_block(share_block).await;
                            let _ = result_tx.send(result);
                        }
                        None => {
                            info!("BlockReceiver channel closed, shutting down");
                            return;
                        }
                    }
                }
                _ = eviction_interval.tick() => {
                    self.evict_stale_pending();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_response_handler::block_fetcher;
    use crate::node::validation_worker;
    #[mockall_double::double]
    use crate::pool_difficulty::PoolDifficulty;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::store::block_tx_metadata::BlockMetadata;
    use crate::store::writer::StoreError;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::CompactTarget;

    #[test]
    fn test_add_to_pending_inserts_block() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        assert_eq!(receiver.pending_count(), 1);
        assert!(receiver.pending.contains_key(&block_hash));
    }

    #[test]
    fn test_add_to_pending_updates_descendants_index() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        let parent_block = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let parent_hash = parent_block.block_hash();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        assert_eq!(
            receiver.descendants.get(&parent_hash).unwrap(),
            &[child_hash]
        );
    }

    #[test]
    fn test_add_to_pending_uncle_descendants() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        let uncle_hash = BlockHash::from_byte_array([0xaa; 32]);
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        assert_eq!(
            receiver.descendants.get(&uncle_hash).unwrap(),
            &[block_hash]
        );
    }

    #[test]
    fn test_remove_from_pending_cleans_descendants() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        let parent_block = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let parent_hash = parent_block.block_hash();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);
        assert!(receiver.descendants.contains_key(&parent_hash));

        let removed = receiver.remove_from_pending(&child_hash);
        assert!(removed.is_some());
        assert!(!receiver.descendants.contains_key(&parent_hash));
        assert_eq!(receiver.pending_count(), 0);
    }

    #[test]
    fn test_evict_oldest_at_capacity() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        for nonce in 0..PENDING_CAPACITY {
            let share_block = TestShareBlockBuilder::new().nonce(nonce as u32).build();
            let block_hash = share_block.block_hash();
            receiver.add_to_pending(block_hash, share_block);
        }
        assert_eq!(receiver.pending_count(), PENDING_CAPACITY);

        let extra_block = TestShareBlockBuilder::new()
            .nonce(PENDING_CAPACITY as u32)
            .build();
        let extra_hash = extra_block.block_hash();
        receiver.add_to_pending(extra_hash, extra_block);

        assert_eq!(receiver.pending_count(), PENDING_CAPACITY);
        assert!(receiver.pending.contains_key(&extra_hash));
    }

    #[test]
    fn test_genesis_parent_not_tracked_in_descendants_key() {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        // Default TestShareBlockBuilder has all-zeros parent (genesis)
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        assert!(!receiver.descendants.contains_key(&BlockHash::all_zeros()));
    }

    #[test]
    fn test_collect_unready_ancestors_returns_missing_parent() {
        let missing_parent_hash = BlockHash::from_byte_array([0x55; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();

        let not_ready = receiver.collect_ancestors_not_ready(&child_block);
        assert_eq!(not_ready, vec![missing_parent_hash]);
    }

    #[test]
    fn test_collect_not_ready_ancestors_empty_when_parent_header_valid() {
        let parent_hash = BlockHash::from_byte_array([0x66; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(parent_hash))
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::HeaderValid,
                })
            });

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();

        assert!(
            receiver
                .collect_ancestors_not_ready(&child_block)
                .is_empty()
        );
    }

    #[test]
    fn test_collect_not_ready_ancestors_includes_not_ready_uncle() {
        let parent_hash = BlockHash::from_byte_array([0x77; 32]);
        let uncle_hash = BlockHash::from_byte_array([0x78; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(parent_hash))
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(uncle_hash))
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .uncles(vec![uncle_hash])
            .nonce(0xe9695791)
            .build();

        assert_eq!(
            receiver.collect_ancestors_not_ready(&child_block),
            vec![uncle_hash]
        );
    }

    #[tokio::test]
    async fn test_process_share_block_with_ready_parent_commits() {
        let parent_hash = BlockHash::from_byte_array([0x88; 32]);
        let parent_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let parent_header_clone = parent_header.clone();

        let mut mock_store = ChainStoreHandle::default();
        // The new block's own metadata lookup (fast path) returns NotFound.
        // The parent is at status Confirmed.
        mock_store
            .expect_get_block_metadata()
            .returning(move |hash| {
                if hash == &parent_hash {
                    Ok(BlockMetadata {
                        expected_height: Some(0),
                        chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                        status: Status::Confirmed,
                    })
                } else {
                    Err(StoreError::NotFound("not found".to_string()))
                }
            });
        mock_store
            .expect_get_share_header()
            .with(mockall::predicate::eq(parent_hash))
            .returning(move |_| Ok(parent_header_clone.clone()));
        mock_store
            .expect_add_share_block_and_organise_header()
            .returning(|_| Ok(None));

        let mut mock_validator = MockDefaultShareValidator::default();
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| {
                CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });
        mock_validator
            .expect_pool_difficulty()
            .return_const(pool_difficulty);

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, mut block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(mock_validator),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        child_block.header.bits =
            CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let child_hash = child_block.block_hash();

        let result = receiver.process_share_block(child_block).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        assert_eq!(receiver.pending_count(), 0);

        let fetcher_event = block_fetcher_rx.try_recv().unwrap();
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, child_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }

        let validation_event = validation_rx.try_recv().unwrap();
        match validation_event {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, child_hash),
        }
    }

    #[tokio::test]
    async fn test_process_share_block_missing_parent_buffers_without_fetching() {
        let missing_parent_hash = BlockHash::from_byte_array([0x99; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, mut block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        let result = receiver.process_share_block(child_block).await;
        assert!(result.is_ok());

        assert_eq!(receiver.pending_count(), 1);
        assert!(receiver.pending.contains_key(&child_hash));

        let fetcher_event = block_fetcher_rx.try_recv().unwrap();
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, child_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }

        assert!(
            block_fetcher_rx.try_recv().is_err(),
            "No FetchBlocks should be sent; headers-first pipeline supplies ancestors"
        );
    }

    #[tokio::test]
    async fn test_process_share_block_already_block_valid_is_noop() {
        let mut mock_store = ChainStoreHandle::default();
        mock_store.expect_get_block_metadata().returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                status: Status::BlockValid,
            })
        });

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, mut block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let result = receiver.process_share_block(block).await;
        assert!(result.is_ok());

        assert!(block_fetcher_rx.try_recv().is_err());
        assert!(validation_rx.try_recv().is_err());
        assert_eq!(receiver.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_process_share_block_already_header_valid_still_stores_body() {
        // When the header was synced ahead of the body (organise_header
        // during share-header sync), the block's status is already
        // HeaderValid but add_share_block was never called. Receiving
        // the body must still persist it via add_share_block and emit
        // a validation event.
        let parent_hash = BlockHash::from_byte_array([0x71; 32]);
        let parent_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let parent_header_clone = parent_header.clone();

        let mut mock_store = ChainStoreHandle::default();
        // Both the new block (already HeaderValid) and its parent are
        // HeaderValid in the store.
        mock_store.expect_get_block_metadata().returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                status: Status::HeaderValid,
            })
        });
        mock_store
            .expect_get_share_header()
            .returning(move |_| Ok(parent_header_clone.clone()));
        mock_store
            .expect_add_share_block_and_organise_header()
            .with(mockall::predicate::always())
            .times(1)
            .returning(|_| Ok(None));

        let mut mock_validator = MockDefaultShareValidator::default();
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| {
                CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });
        mock_validator
            .expect_pool_difficulty()
            .return_const(pool_difficulty);

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(mock_validator),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        child_block.header.bits =
            CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let child_hash = child_block.block_hash();

        let result = receiver.process_share_block(child_block).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        let event = validation_rx.try_recv().unwrap();
        match event {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, child_hash),
        }
    }

    #[tokio::test]
    async fn test_process_share_block_asert_mismatch_dropped() {
        let parent_hash = BlockHash::from_byte_array([0xab; 32]);
        let parent_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let parent_header_clone = parent_header.clone();

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .returning(move |hash| {
                if hash == &parent_hash {
                    Ok(BlockMetadata {
                        expected_height: Some(0),
                        chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                        status: Status::Confirmed,
                    })
                } else {
                    Err(StoreError::NotFound("not found".to_string()))
                }
            });
        mock_store
            .expect_get_share_header()
            .returning(move |_| Ok(parent_header_clone.clone()));

        let mut mock_pool_difficulty = PoolDifficulty::default();
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| CompactTarget::from_consensus(0x1d00ffff));
        let mut mock_validator = MockDefaultShareValidator::default();
        mock_validator
            .expect_pool_difficulty()
            .return_const(mock_pool_difficulty);

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(mock_validator),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        child_block.header.bits =
            CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);

        let result = receiver.process_share_block(child_block).await;
        assert!(result.is_ok());

        // Block must NOT enter the store and validation must NOT be emitted.
        assert!(validation_rx.try_recv().is_err());
        assert_eq!(receiver.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_cascade_commits_child_when_parent_arrives() {
        let root_hash = BlockHash::from_byte_array([0xcc; 32]);
        let root_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let root_header_clone = root_header.clone();

        // Build parent -> child chain
        let mut parent_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        parent_block.header.bits =
            CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let parent_hash = parent_block.block_hash();

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();
        child_block.header.bits =
            CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let child_hash = child_block.block_hash();

        let mut mock_store = ChainStoreHandle::default();
        // root_hash always Confirmed (it is the anchor in the store).
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });
        // child_hash: always NotFound (never reaches the store via the
        // fast path; the new design only persists via add_share_block,
        // which the mock here is a no-op for).
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(child_hash))
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));
        // parent_hash: NotFound on the first 2 calls (collect_not_ready
        // for the buffered child + parent's own fast-path lookup), then
        // Confirmed for cascade collect_not_ready and validate_asert
        // lookups.
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(parent_hash))
            .times(2)
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(parent_hash))
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });
        mock_store
            .expect_get_share_header()
            .returning(move |_| Ok(root_header_clone.clone()));
        mock_store
            .expect_add_share_block_and_organise_header()
            .returning(|_| Ok(None));

        let mut mock_validator = MockDefaultShareValidator::default();
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| {
                CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });
        mock_validator
            .expect_pool_difficulty()
            .return_const(pool_difficulty);

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, mut validation_rx) = validation_worker::create_validation_channel();
        let mut receiver = BlockReceiver::new(
            event_rx,
            Arc::new(mock_validator),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        // Child arrives first -- parent is missing in store, so child
        // is buffered.
        let result = receiver.process_share_block(child_block).await;
        assert!(result.is_ok());
        assert_eq!(receiver.pending_count(), 1);

        // Parent arrives -- commits itself, then cascade commits the
        // buffered child.
        let result = receiver.process_share_block(parent_block).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        assert_eq!(receiver.pending_count(), 0);

        let event1 = validation_rx
            .try_recv()
            .expect("expected first validation event");
        match event1 {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, parent_hash),
        }
        let event2 = validation_rx
            .try_recv()
            .expect("expected second validation event");
        match event2 {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, child_hash),
        }
    }

    #[tokio::test]
    async fn test_run_processes_event_and_shuts_down() {
        let missing_parent_hash = BlockHash::from_byte_array([0xbb; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".to_string())));

        let (event_tx, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _validation_rx) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            Arc::new(MockDefaultShareValidator::default()),
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();

        let (result_tx, result_rx) = oneshot::channel();
        event_tx
            .send(BlockReceiverEvent::ShareBlockReceived {
                share_block: child_block,
                result_tx,
            })
            .await
            .unwrap();

        drop(event_tx);

        receiver.run().await;

        let result = result_rx.await.unwrap();
        assert!(result.is_ok());
    }
}
