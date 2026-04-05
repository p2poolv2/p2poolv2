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

use crate::node::p2p_message_handlers::receivers::share_headers::validate_asert_chain;
use crate::node::request_response_handler::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::validation_worker::{ValidationEvent, ValidationSender};
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
use crate::store::block_tx_metadata::Status;
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
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
        peer_id: libp2p::PeerId,
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

/// A share block waiting in the pending set for its dependencies.
struct PendingBlock {
    share_block: ShareBlock,
    received_at: Instant,
}

/// Buffers incoming ShareBlocks until their dependency DAG is
/// well-formed and rooted at a confirmed or candidate block in the
/// store, then validates ASERT difficulty in topological order,
/// commits blocks to the store, and sends them to the validation
/// worker.
pub struct BlockReceiver {
    event_rx: BlockReceiverReceiver,
    /// Pending blocks indexed by their block hash.
    pending: HashMap<BlockHash, PendingBlock>,
    /// Reverse index: dependency hash -> pending blocks that need it.
    /// Used to efficiently find which pending blocks become unblocked
    /// when a dependency is committed.
    dependents: HashMap<BlockHash, Vec<BlockHash>>,
    pool_difficulty: PoolDifficulty,
    chain_store_handle: ChainStoreHandle,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
}

impl BlockReceiver {
    /// Create a new BlockReceiver actor.
    pub fn new(
        event_rx: BlockReceiverReceiver,
        pool_difficulty: PoolDifficulty,
        chain_store_handle: ChainStoreHandle,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
    ) -> Self {
        Self {
            event_rx,
            pending: HashMap::with_capacity(PENDING_CAPACITY),
            dependents: HashMap::with_capacity(PENDING_CAPACITY),
            pool_difficulty,
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
    /// capacity. Updates the dependents reverse index.
    fn add_to_pending(&mut self, block_hash: BlockHash, share_block: ShareBlock) {
        if self.pending.len() >= PENDING_CAPACITY {
            self.evict_oldest();
        }

        // Build reverse index entries for parent and uncles
        let parent_hash = share_block.header.prev_share_blockhash;
        if parent_hash != BlockHash::all_zeros() {
            self.dependents
                .entry(parent_hash)
                .or_insert_with(|| Vec::with_capacity(2))
                .push(block_hash);
        }
        for uncle_hash in &share_block.header.uncles {
            self.dependents
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
    /// in the dependents reverse index.
    fn remove_from_pending(&mut self, block_hash: &BlockHash) -> Option<ShareBlock> {
        let pending_block = self.pending.remove(block_hash)?;

        // Clean up dependents entries for this block's dependencies
        let parent_hash = pending_block.share_block.header.prev_share_blockhash;
        if parent_hash != BlockHash::all_zeros() {
            if let Some(dependent_list) = self.dependents.get_mut(&parent_hash) {
                dependent_list.retain(|hash| hash != block_hash);
                if dependent_list.is_empty() {
                    self.dependents.remove(&parent_hash);
                }
            }
        }
        for uncle_hash in &pending_block.share_block.header.uncles {
            if let Some(dependent_list) = self.dependents.get_mut(uncle_hash) {
                dependent_list.retain(|hash| hash != block_hash);
                if dependent_list.is_empty() {
                    self.dependents.remove(uncle_hash);
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

    /// Check if a block hash is a valid root for chain building.
    ///
    /// A valid root has status HeaderValid or better in the store
    /// (HeaderValid, Candidate, Confirmed, or BlockValid).
    fn is_valid_root(&self, block_hash: &BlockHash) -> bool {
        match self.chain_store_handle.get_block_metadata(block_hash) {
            Ok(metadata) => matches!(
                metadata.status,
                Status::HeaderValid | Status::Candidate | Status::Confirmed | Status::BlockValid
            ),
            Err(_) => false,
        }
    }

    /// Collect all dependency hashes (parent + uncles) for a pending block.
    fn dependency_hashes(&self, block_hash: &BlockHash) -> Vec<BlockHash> {
        let pending_block = match self.pending.get(block_hash) {
            Some(pending_block) => pending_block,
            None => return Vec::new(),
        };
        let header = &pending_block.share_block.header;
        let mut dependencies = Vec::with_capacity(1 + header.uncles.len());
        if header.prev_share_blockhash != BlockHash::all_zeros() {
            dependencies.push(header.prev_share_blockhash);
        }
        for uncle_hash in &header.uncles {
            dependencies.push(*uncle_hash);
        }
        dependencies
    }

    /// Walk the pending DAG from a starting block, collecting all
    /// reachable pending block hashes. Returns None if any leaf
    /// dependency is neither pending nor a valid root in the store.
    /// Stops traversal at valid roots without exploring further.
    fn collect_pending_subgraph(&self, start_hash: &BlockHash) -> Option<Vec<BlockHash>> {
        let mut pending_blocks = Vec::with_capacity(16);
        let mut visited = HashSet::with_capacity(16);
        let mut stack = Vec::with_capacity(16);
        stack.push(*start_hash);

        while let Some(current_hash) = stack.pop() {
            if !visited.insert(current_hash) {
                continue;
            }
            if !self.pending.contains_key(&current_hash) {
                if self.is_valid_root(&current_hash) {
                    continue;
                }
                return None;
            }
            pending_blocks.push(current_hash);
            for dep_hash in self.dependency_hashes(&current_hash) {
                if !visited.contains(&dep_hash) {
                    stack.push(dep_hash);
                }
            }
        }

        Some(pending_blocks)
    }

    /// Topologically sort pending blocks using Kahn's algorithm.
    ///
    /// Produces parent/uncle-before-child ordering. Only counts edges
    /// within the pending subgraph (edges to store roots contribute
    /// zero in-degree). Returns None if a cycle is detected.
    fn topological_sort(&self, pending_hashes: &[BlockHash]) -> Option<Vec<BlockHash>> {
        let pending_set: HashSet<BlockHash> = pending_hashes.iter().copied().collect();
        let mut in_degree: HashMap<BlockHash, usize> = HashMap::with_capacity(pending_hashes.len());
        for hash in pending_hashes {
            in_degree.insert(*hash, 0);
        }
        for hash in pending_hashes {
            for dep_hash in self.dependency_hashes(hash) {
                if pending_set.contains(&dep_hash) {
                    *in_degree.entry(*hash).or_insert(0) += 1;
                }
            }
        }

        let mut queue: VecDeque<BlockHash> = VecDeque::with_capacity(pending_hashes.len());
        for (hash, degree) in &in_degree {
            if *degree == 0 {
                queue.push_back(*hash);
            }
        }

        let mut sorted = Vec::with_capacity(pending_hashes.len());
        while let Some(ready_hash) = queue.pop_front() {
            sorted.push(ready_hash);
            if let Some(dependent_list) = self.dependents.get(&ready_hash) {
                for dependent_hash in dependent_list {
                    if let Some(degree) = in_degree.get_mut(dependent_hash) {
                        *degree = degree.saturating_sub(1);
                        if *degree == 0 {
                            queue.push_back(*dependent_hash);
                        }
                    }
                }
            }
        }

        if sorted.len() != pending_hashes.len() {
            warn!(
                "Cycle detected in pending DAG, sorted {} of {} blocks",
                sorted.len(),
                pending_hashes.len()
            );
            return None;
        }

        Some(sorted)
    }

    /// Try to build a ready chain rooted at valid store blocks.
    ///
    /// Starting from start_hash, walks the pending DAG via parent and
    /// uncle edges. If every leaf dependency is a valid root in the
    /// store, returns a topologically sorted Vec of pending block
    /// hashes (parent/uncle before child). Returns None if any leaf
    /// dependency is missing or a cycle exists.
    fn try_build_ready_chain(&self, start_hash: &BlockHash) -> Option<Vec<BlockHash>> {
        let pending_hashes = self.collect_pending_subgraph(start_hash)?;
        self.topological_sort(&pending_hashes)
    }

    /// Find dependencies missing from both the pending set and the store.
    ///
    /// Walks the pending DAG from start_hash, collecting any
    /// dependency that is neither pending nor a valid root in the
    /// store. These are the blocks that need to be fetched.
    fn find_missing_dependencies(&self, start_hash: &BlockHash) -> HashSet<BlockHash> {
        let mut missing = HashSet::with_capacity(4);
        let mut visited = HashSet::with_capacity(16);
        let mut stack = Vec::with_capacity(16);
        stack.push(*start_hash);

        while let Some(current_hash) = stack.pop() {
            if !visited.insert(current_hash) {
                continue;
            }
            if !self.pending.contains_key(&current_hash) {
                if !self.is_valid_root(&current_hash) {
                    missing.insert(current_hash);
                }
                continue;
            }
            for dep_hash in self.dependency_hashes(&current_hash) {
                if !visited.contains(&dep_hash) {
                    stack.push(dep_hash);
                }
            }
        }

        missing
    }

    /// Look up the anchor time and height for the root block that
    /// the ready chain is rooted at.
    fn get_anchor_info(
        &self,
        ordered_hashes: &[BlockHash],
    ) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
        let first_hash = ordered_hashes
            .first()
            .ok_or("Empty ordered hashes in commit_ready_chain")?;
        let first_pending = self
            .pending
            .get(first_hash)
            .ok_or_else(|| format!("First block {first_hash} not in pending"))?;
        let root_hash = first_pending.share_block.header.prev_share_blockhash;

        if root_hash == BlockHash::all_zeros() {
            return Err("Genesis block should not arrive via BlockReceiver".into());
        }

        let root_header = self.chain_store_handle.get_share_header(&root_hash)?;
        let root_metadata = self.chain_store_handle.get_block_metadata(&root_hash)?;
        let anchor_height = root_metadata.expected_height.ok_or_else(|| {
            std::io::Error::other(format!(
                "Missing expected_height for anchor block {root_hash}"
            ))
        })?;
        Ok((root_header.time, anchor_height))
    }

    /// Validate ASERT difficulty and commit a ready chain to the store.
    ///
    /// Blocks are removed from pending, stored via add_share_block and
    /// organise_header, and sent to the validation worker.
    async fn commit_ready_chain(
        &mut self,
        ordered_hashes: Vec<BlockHash>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (anchor_time, anchor_height) = self.get_anchor_info(&ordered_hashes)?;

        // Collect headers for ASERT validation
        let headers: Vec<_> = ordered_hashes
            .iter()
            .filter_map(|hash| {
                self.pending
                    .get(hash)
                    .map(|pending_block| pending_block.share_block.header.clone())
            })
            .collect();
        let header_refs: Vec<_> = headers.iter().collect();

        validate_asert_chain(
            &header_refs,
            &self.pool_difficulty,
            anchor_time,
            anchor_height,
        )?;

        // Remove from pending, store, and send to validation
        for block_hash in &ordered_hashes {
            let share_block = self
                .remove_from_pending(block_hash)
                .ok_or_else(|| format!("Block {block_hash} disappeared from pending"))?;

            let header = share_block.header.clone();

            if let Err(error) = self
                .chain_store_handle
                .add_share_block(share_block, false)
                .await
            {
                error!("Failed to store block {block_hash}: {error}");
                return Err(error.into());
            }

            if let Err(error) = self.chain_store_handle.organise_header(header).await {
                error!("Failed to organise header {block_hash}: {error}");
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
        }

        Ok(())
    }

    /// After committing blocks, collect all transitively unblocked
    /// pending dependents and commit them. Walks the dependents index
    /// breadth-first to find all pending blocks whose dependencies
    /// are now satisfied, then commits them in topological order.
    async fn cascade_committed(
        &mut self,
        committed_hashes: &[BlockHash],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut queue: VecDeque<BlockHash> = VecDeque::with_capacity(8);
        for committed_hash in committed_hashes {
            if let Some(dependent_list) = self.dependents.get(committed_hash) {
                for dependent_hash in dependent_list {
                    if self.pending.contains_key(dependent_hash) {
                        queue.push_back(*dependent_hash);
                    }
                }
            }
        }

        while let Some(dependent_hash) = queue.pop_front() {
            if !self.pending.contains_key(&dependent_hash) {
                // Already committed in an earlier iteration
                continue;
            }
            let ordered = vec![dependent_hash];
            self.commit_ready_chain(ordered).await?;

            // Check if this newly committed block unblocks further dependents
            if let Some(next_dependents) = self.dependents.get(&dependent_hash) {
                for next_hash in next_dependents {
                    if self.pending.contains_key(next_hash) {
                        queue.push_back(*next_hash);
                    }
                }
            }
        }

        Ok(())
    }

    /// Process an incoming share block: buffer or commit.
    ///
    /// If the block's dependency DAG is complete and rooted at valid
    /// store blocks, validates ASERT and commits the chain. Otherwise,
    /// buffers the block and requests missing dependencies.
    async fn process_share_block(
        &mut self,
        peer_id: libp2p::PeerId,
        share_block: ShareBlock,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let block_hash = share_block.block_hash();

        if self.pending.contains_key(&block_hash) {
            debug!("Block {block_hash} already pending, ignoring duplicate");
            return Ok(());
        }

        // Notify block fetcher that we received this block
        let _ = self
            .block_fetcher_handle
            .send(BlockFetcherEvent::BlockReceived(block_hash))
            .await;

        self.add_to_pending(block_hash, share_block);

        if let Some(ordered) = self.try_build_ready_chain(&block_hash) {
            let committed: Vec<BlockHash> = ordered.clone();
            self.commit_ready_chain(ordered).await?;
            self.cascade_committed(&committed).await?;
        } else {
            let missing = self.find_missing_dependencies(&block_hash);
            if !missing.is_empty() {
                let missing_vec: Vec<BlockHash> = missing.into_iter().collect();
                debug!(
                    "Block {block_hash} has {} missing dependencies, requesting fetch",
                    missing_vec.len()
                );
                let _ = self
                    .block_fetcher_handle
                    .send(BlockFetcherEvent::FetchBlocks {
                        blockhashes: missing_vec,
                        peer_id,
                    })
                    .await;
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
                            peer_id,
                            share_block,
                            result_tx,
                        }) => {
                            let result = self.process_share_block(peer_id, share_block).await;
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
    use crate::test_utils::TestShareBlockBuilder;

    fn create_test_block_receiver() -> BlockReceiver {
        let (_, event_rx) = create_block_receiver_channel();
        let pool_difficulty = PoolDifficulty::default();
        let chain_store_handle = ChainStoreHandle::default();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        BlockReceiver::new(
            event_rx,
            pool_difficulty,
            chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
    }

    #[test]
    fn test_add_to_pending_inserts_block() {
        let mut receiver = create_test_block_receiver();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        assert_eq!(receiver.pending_count(), 1);
        assert!(receiver.pending.contains_key(&block_hash));
    }

    #[test]
    fn test_add_to_pending_updates_dependents_index() {
        let mut receiver = create_test_block_receiver();

        let parent_block = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let parent_hash = parent_block.block_hash();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        assert_eq!(
            receiver.dependents.get(&parent_hash).unwrap(),
            &[child_hash]
        );
    }

    #[test]
    fn test_add_to_pending_uncle_dependents() {
        let mut receiver = create_test_block_receiver();

        let uncle_hash = BlockHash::from_byte_array([0xaa; 32]);
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        assert_eq!(receiver.dependents.get(&uncle_hash).unwrap(), &[block_hash]);
    }

    #[test]
    fn test_remove_from_pending_cleans_dependents() {
        let mut receiver = create_test_block_receiver();

        let parent_block = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let parent_hash = parent_block.block_hash();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);
        assert!(receiver.dependents.contains_key(&parent_hash));

        let removed = receiver.remove_from_pending(&child_hash);
        assert!(removed.is_some());
        assert!(!receiver.dependents.contains_key(&parent_hash));
        assert_eq!(receiver.pending_count(), 0);
    }

    #[test]
    fn test_evict_oldest_at_capacity() {
        let mut receiver = create_test_block_receiver();

        // Fill to capacity with blocks
        let mut block_hashes = Vec::with_capacity(PENDING_CAPACITY + 1);
        for nonce in 0..PENDING_CAPACITY {
            let share_block = TestShareBlockBuilder::new().nonce(nonce as u32).build();
            let block_hash = share_block.block_hash();
            block_hashes.push(block_hash);
            receiver.add_to_pending(block_hash, share_block);
        }
        assert_eq!(receiver.pending_count(), PENDING_CAPACITY);

        // Add one more, should evict the oldest
        let extra_block = TestShareBlockBuilder::new()
            .nonce(PENDING_CAPACITY as u32)
            .build();
        let extra_hash = extra_block.block_hash();
        receiver.add_to_pending(extra_hash, extra_block);

        assert_eq!(receiver.pending_count(), PENDING_CAPACITY);
        assert!(receiver.pending.contains_key(&extra_hash));
    }

    #[test]
    fn test_duplicate_add_to_pending_overwrites() {
        let mut receiver = create_test_block_receiver();
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block.clone());
        receiver.add_to_pending(block_hash, share_block);

        assert_eq!(receiver.pending_count(), 1);
    }

    #[test]
    fn test_genesis_parent_not_tracked_in_dependents() {
        let mut receiver = create_test_block_receiver();

        // Default TestShareBlockBuilder has all-zeros parent (genesis)
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        // All-zeros parent should not appear in dependents
        assert!(!receiver.dependents.contains_key(&BlockHash::all_zeros()));
    }

    fn create_block_receiver_with_mock(chain_store_handle: ChainStoreHandle) -> BlockReceiver {
        let (_, event_rx) = create_block_receiver_channel();
        let pool_difficulty = PoolDifficulty::default();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        BlockReceiver::new(
            event_rx,
            pool_difficulty,
            chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        )
    }

    #[test]
    fn test_try_build_ready_chain_single_block_with_valid_root() {
        let root_hash = BlockHash::from_byte_array([0x11; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        let result = receiver.try_build_ready_chain(&child_hash);
        assert!(result.is_some());
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0], child_hash);
    }

    #[test]
    fn test_try_build_ready_chain_missing_leaf_returns_none() {
        let missing_parent_hash = BlockHash::from_byte_array([0x22; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store.expect_get_block_metadata().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".to_string(),
            ))
        });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        let result = receiver.try_build_ready_chain(&child_hash);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_build_ready_chain_parent_before_child_ordering() {
        let root_hash = BlockHash::from_byte_array([0x33; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        // Build parent -> child chain, both pending
        let parent_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695790)
            .build();
        let parent_hash = parent_block.block_hash();

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(parent_hash, parent_block);
        receiver.add_to_pending(child_hash, child_block);

        let result = receiver.try_build_ready_chain(&child_hash);
        assert!(result.is_some());
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 2);

        let parent_pos = sorted.iter().position(|h| *h == parent_hash).unwrap();
        let child_pos = sorted.iter().position(|h| *h == child_hash).unwrap();
        assert!(parent_pos < child_pos, "Parent must come before child");
    }

    #[test]
    fn test_try_build_ready_chain_uncle_before_nephew() {
        let root_hash = BlockHash::from_byte_array([0x44; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        // Uncle block: parent is root
        let uncle_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695790)
            .build();
        let uncle_hash = uncle_block.block_hash();

        // Nephew block: parent is root, uncle is uncle_block
        let nephew_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .uncles(vec![uncle_hash])
            .nonce(0xe9695791)
            .build();
        let nephew_hash = nephew_block.block_hash();

        receiver.add_to_pending(uncle_hash, uncle_block);
        receiver.add_to_pending(nephew_hash, nephew_block);

        let result = receiver.try_build_ready_chain(&nephew_hash);
        assert!(result.is_some());
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 2);

        let uncle_pos = sorted.iter().position(|h| *h == uncle_hash).unwrap();
        let nephew_pos = sorted.iter().position(|h| *h == nephew_hash).unwrap();
        assert!(uncle_pos < nephew_pos, "Uncle must come before nephew");
    }

    #[test]
    fn test_find_missing_dependencies_returns_missing_hashes() {
        let missing_hash = BlockHash::from_byte_array([0x55; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store.expect_get_block_metadata().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".to_string(),
            ))
        });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        let missing = receiver.find_missing_dependencies(&child_hash);
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&missing_hash));
    }

    #[test]
    fn test_find_missing_dependencies_empty_when_all_rooted() {
        let root_hash = BlockHash::from_byte_array([0x66; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Candidate,
                })
            });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        receiver.add_to_pending(child_hash, child_block);

        let missing = receiver.find_missing_dependencies(&child_hash);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_collect_pending_subgraph_genesis_parent_block() {
        // A block with all-zeros parent (genesis) has no parent
        // dependency to check, so it is immediately collectible.
        let mock_store = ChainStoreHandle::default();
        let mut receiver = create_block_receiver_with_mock(mock_store);

        let genesis_child = TestShareBlockBuilder::new().build();
        let block_hash = genesis_child.block_hash();
        receiver.add_to_pending(block_hash, genesis_child);

        let result = receiver.collect_pending_subgraph(&block_hash);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_get_anchor_info_returns_root_time_and_height() {
        let root_hash = BlockHash::from_byte_array([0x11; 32]);
        let root_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let root_time = root_header.time;

        let root_header_clone = root_header.clone();
        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_share_header()
            .with(mockall::predicate::eq(root_hash))
            .returning(move |_| Ok(root_header_clone.clone()));
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let mut receiver = create_block_receiver_with_mock(mock_store);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();
        receiver.add_to_pending(child_hash, child_block);

        let result = receiver.get_anchor_info(&[child_hash]);
        assert!(result.is_ok());
        let (anchor_time, anchor_height) = result.unwrap();
        assert_eq!(anchor_time, root_time);
        assert_eq!(anchor_height, 5);
    }

    #[test]
    fn test_get_anchor_info_errors_on_genesis_parent() {
        let mock_store = ChainStoreHandle::default();
        let mut receiver = create_block_receiver_with_mock(mock_store);

        // Default TestShareBlockBuilder has all-zeros parent (genesis)
        let genesis_child = TestShareBlockBuilder::new().build();
        let child_hash = genesis_child.block_hash();
        receiver.add_to_pending(child_hash, genesis_child);

        let result = receiver.get_anchor_info(&[child_hash]);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("Genesis"),
            "Error should mention genesis"
        );
    }

    #[test]
    fn test_get_anchor_info_errors_on_empty_hashes() {
        let mock_store = ChainStoreHandle::default();
        let receiver = create_block_receiver_with_mock(mock_store);

        let result = receiver.get_anchor_info(&[]);
        assert!(result.is_err());
    }

    /// Build a BlockReceiver with full access to fetcher and validation
    /// receivers for verifying events sent by process_share_block.
    fn create_full_block_receiver(
        chain_store_handle: ChainStoreHandle,
        pool_difficulty: PoolDifficulty,
    ) -> (
        BlockReceiver,
        block_fetcher::BlockFetcherReceiver,
        validation_worker::ValidationReceiver,
    ) {
        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, validation_rx) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            pool_difficulty,
            chain_store_handle,
            block_fetcher_handle,
            validation_tx,
        );
        (receiver, block_fetcher_rx, validation_rx)
    }

    #[tokio::test]
    async fn test_process_share_block_with_ready_deps_commits() {
        let root_hash = BlockHash::from_byte_array([0x88; 32]);
        let root_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let root_header_clone = root_header.clone();

        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(root_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(0),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });
        mock_store
            .expect_get_share_header()
            .with(mockall::predicate::eq(root_hash))
            .returning(move |_| Ok(root_header_clone.clone()));
        mock_store.expect_add_share_block().returning(|_, _| Ok(()));
        mock_store.expect_organise_header().returning(|_| Ok(None));

        let mut mock_pool_difficulty = PoolDifficulty::default();
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| {
                bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });

        let (mut receiver, mut block_fetcher_rx, mut validation_rx) =
            create_full_block_receiver(mock_store, mock_pool_difficulty);

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        child_block.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let child_hash = child_block.block_hash();

        let peer_id = libp2p::PeerId::random();
        let result = receiver.process_share_block(peer_id, child_block).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        // Block should be removed from pending after commit
        assert_eq!(receiver.pending_count(), 0);

        // BlockReceived event should have been sent to block fetcher
        let fetcher_event = block_fetcher_rx.try_recv();
        assert!(fetcher_event.is_ok());
        match fetcher_event.unwrap() {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, child_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }

        // ValidateBlock event should have been sent
        let validation_event = validation_rx.try_recv();
        assert!(validation_event.is_ok());
        match validation_event.unwrap() {
            ValidationEvent::ValidateBlock(hash) => assert_eq!(hash, child_hash),
        }
    }

    #[tokio::test]
    async fn test_process_share_block_missing_deps_fetches() {
        let missing_parent_hash = BlockHash::from_byte_array([0x99; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store.expect_get_block_metadata().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".to_string(),
            ))
        });

        let mock_pool_difficulty = PoolDifficulty::default();
        let (mut receiver, mut block_fetcher_rx, _validation_rx) =
            create_full_block_receiver(mock_store, mock_pool_difficulty);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let child_hash = child_block.block_hash();

        let peer_id = libp2p::PeerId::random();
        let result = receiver.process_share_block(peer_id, child_block).await;
        assert!(result.is_ok());

        // Block should remain in pending
        assert_eq!(receiver.pending_count(), 1);
        assert!(receiver.pending.contains_key(&child_hash));

        // BlockReceived sent first
        let fetcher_event = block_fetcher_rx.try_recv().unwrap();
        match fetcher_event {
            BlockFetcherEvent::BlockReceived(hash) => assert_eq!(hash, child_hash),
            other => panic!("Expected BlockReceived, got: {other}"),
        }

        // FetchBlocks should have been sent for the missing parent
        let fetch_event = block_fetcher_rx.try_recv().unwrap();
        match fetch_event {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id: event_peer_id,
            } => {
                assert_eq!(blockhashes, vec![missing_parent_hash]);
                assert_eq!(event_peer_id, peer_id);
            }
            other => panic!("Expected FetchBlocks, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_process_share_block_duplicate_pending_ignored() {
        let missing_parent_hash = BlockHash::from_byte_array([0xaa; 32]);

        let mut mock_store = ChainStoreHandle::default();
        mock_store.expect_get_block_metadata().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".to_string(),
            ))
        });

        let mock_pool_difficulty = PoolDifficulty::default();
        let (mut receiver, _block_fetcher_rx, _validation_rx) =
            create_full_block_receiver(mock_store, mock_pool_difficulty);

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();

        let peer_id = libp2p::PeerId::random();
        // First call adds to pending
        let result = receiver
            .process_share_block(peer_id, child_block.clone())
            .await;
        assert!(result.is_ok());
        assert_eq!(receiver.pending_count(), 1);

        // Second call with same block is ignored
        let result = receiver.process_share_block(peer_id, child_block).await;
        assert!(result.is_ok());
        assert_eq!(receiver.pending_count(), 1);
    }

    #[tokio::test]
    async fn test_cascade_commits_child_when_parent_arrives() {
        let root_hash = BlockHash::from_byte_array([0xcc; 32]);
        let root_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let root_header_clone = root_header.clone();

        let mut mock_store = ChainStoreHandle::default();

        let confirmed_metadata = crate::store::block_tx_metadata::BlockMetadata {
            expected_height: Some(0),
            chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
            status: Status::Confirmed,
        };
        let not_found = crate::store::writer::StoreError::NotFound("not found".to_string());

        let mut seq = mockall::Sequence::new();

        // 1. Child arrives: collect_pending_subgraph checks parent_hash -> NotFound
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Err(not_found.clone()));

        // 2. Child: find_missing_dependencies checks parent_hash -> NotFound
        let not_found2 = crate::store::writer::StoreError::NotFound("not found".to_string());
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Err(not_found2.clone()));

        // 3. Parent arrives: collect_pending_subgraph checks root_hash -> Confirmed
        let meta3 = confirmed_metadata.clone();
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(meta3.clone()));

        // 4. Parent commit: get_anchor_info checks root_hash -> Confirmed
        let meta4 = confirmed_metadata.clone();
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(meta4.clone()));

        // 5. Cascade child: get_anchor_info checks parent_hash -> Confirmed
        let meta5 = confirmed_metadata.clone();
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(meta5.clone()));

        mock_store
            .expect_get_share_header()
            .returning(move |_| Ok(root_header_clone.clone()));
        mock_store.expect_add_share_block().returning(|_, _| Ok(()));
        mock_store.expect_organise_header().returning(|_| Ok(None));

        let mut mock_pool_difficulty = PoolDifficulty::default();
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| {
                bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });

        let (mut receiver, _block_fetcher_rx, mut validation_rx) =
            create_full_block_receiver(mock_store, mock_pool_difficulty);

        // Build parent -> child chain
        let mut parent_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695791)
            .build();
        parent_block.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let parent_hash = parent_block.block_hash();

        let mut child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent_hash.to_string())
            .nonce(0xe9695792)
            .build();
        child_block.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let child_hash = child_block.block_hash();

        let peer_id = libp2p::PeerId::random();

        // Child arrives first -- parent is missing, goes to pending
        let result = receiver.process_share_block(peer_id, child_block).await;
        assert!(result.is_ok());
        assert_eq!(receiver.pending_count(), 1);

        // Parent arrives -- commits itself, then cascade commits child
        let result = receiver.process_share_block(peer_id, parent_block).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        // Both blocks should be committed (removed from pending)
        assert_eq!(receiver.pending_count(), 0);

        // Two ValidateBlock events should have been sent
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
        mock_store.expect_get_block_metadata().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".to_string(),
            ))
        });

        let mock_pool_difficulty = PoolDifficulty::default();

        let (event_tx, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _validation_rx) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            mock_pool_difficulty,
            mock_store,
            block_fetcher_handle,
            validation_tx,
        );

        let child_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(missing_parent_hash.to_string())
            .nonce(0xe9695791)
            .build();

        let peer_id = libp2p::PeerId::random();
        let (result_tx, result_rx) = oneshot::channel();
        event_tx
            .send(BlockReceiverEvent::ShareBlockReceived {
                peer_id,
                share_block: child_block,
                result_tx,
            })
            .await
            .unwrap();

        // Drop sender to close channel and trigger shutdown
        drop(event_tx);

        // Run the actor -- it will process the event then shut down
        receiver.run().await;

        // The oneshot should have received the result
        let result = result_rx.await.unwrap();
        assert!(result.is_ok());
    }
}
