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
}
