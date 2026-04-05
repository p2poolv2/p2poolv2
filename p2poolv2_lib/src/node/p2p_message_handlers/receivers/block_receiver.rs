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
}
