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
use tracing::{debug, error, info};

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

/// A share block waiting in the pending set for its ancestors to be organised.
struct PendingBlock {
    share_block: ShareBlock,
    received_at: Instant,
}

/// A subgraph of pending blocks that is ready for validation and commit.
///
/// `chain` is the linear main chain in parent-first order, walked via
/// `prev_share_blockhash` from the start hash up to (but excluding)
/// the anchor in the store. `uncles` maps each chain block to its
/// uncles that are still in pending. Uncles already in the store are
/// omitted because they have already been validated.
struct ReadyChain {
    chain: Vec<BlockHash>,
    uncles: HashMap<BlockHash, Vec<BlockHash>>,
}

/// Buffers incoming ShareBlocks until their ancestory DAG is
/// well-formed and rooted at a confirmed or candidate block in the
/// store, then validates ASERT difficulty in topological order,
/// commits blocks to the store, and sends them to the validation
/// worker.
pub struct BlockReceiver {
    event_rx: BlockReceiverReceiver,
    /// Pending blocks indexed by their block hash.
    pending: HashMap<BlockHash, PendingBlock>,
    /// Reverse index: hash -> pending blocks that need it.
    /// Used to efficiently find which pending descendant blocks become unblocked
    /// when a hash is committed.
    descendants: HashMap<BlockHash, Vec<BlockHash>>,
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
            descendants: HashMap::with_capacity(PENDING_CAPACITY),
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
    /// capacity. Updates the descendants index.
    fn add_to_pending(&mut self, block_hash: BlockHash, share_block: ShareBlock) {
        if self.pending.len() >= PENDING_CAPACITY {
            self.evict_oldest();
        }

        // Build reverse index entries for parent and uncles
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

        // Clean up entries for this block's descendants
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

    /// Walk parent links starting from `start_hash`, producing the
    /// linear main chain in parent-first order.
    ///
    /// Returns `None` if the first non-pending ancestor is not a valid
    /// root in the store, or if the walk reaches the genesis sentinel
    /// (which should not arrive via BlockReceiver).
    fn walk_pending_parent_chain(&self, start_hash: &BlockHash) -> Option<Vec<BlockHash>> {
        let mut chain_reversed: Vec<BlockHash> = Vec::with_capacity(8);
        let mut current = *start_hash;
        while let Some(pending_block) = self.pending.get(&current) {
            let parent = pending_block.share_block.header.prev_share_blockhash;
            if parent == BlockHash::all_zeros() {
                // Genesis sentinel - should not arrive via BlockReceiver
                return None;
            }
            chain_reversed.push(current);
            current = parent;
        }
        // The walk exited because `current` is not in pending. It must
        // be a valid anchor in the store; otherwise the chain is
        // incomplete.
        if !self.is_valid_root(&current) {
            return None;
        }
        chain_reversed.reverse();
        Some(chain_reversed)
    }

    /// Collect the pending uncles declared by each block in `chain`.
    ///
    /// Uncles already in the store are skipped (already validated).
    /// Returns `None` if any declared uncle is missing from both
    /// pending and the store.
    fn collect_pending_uncles(
        &self,
        chain: &[BlockHash],
    ) -> Option<HashMap<BlockHash, Vec<BlockHash>>> {
        let mut uncles: HashMap<BlockHash, Vec<BlockHash>> = HashMap::with_capacity(chain.len());
        for chain_hash in chain {
            let header = &self.pending.get(chain_hash)?.share_block.header;
            let mut pending_uncles: Vec<BlockHash> = Vec::with_capacity(header.uncles.len());
            for uncle_hash in &header.uncles {
                if self.pending.contains_key(uncle_hash) {
                    pending_uncles.push(*uncle_hash);
                } else if !self.is_valid_root(uncle_hash) {
                    // Uncle missing from both pending and store
                    return None;
                }
                // else: uncle is in store, skip
            }
            if !pending_uncles.is_empty() {
                uncles.insert(*chain_hash, pending_uncles);
            }
        }
        Some(uncles)
    }

    /// Walk parent links from start_hash to build the linear main
    /// chain (parent-first order) and collect pending uncles for each
    /// chain block.
    ///
    /// Returns None if the chain's anchor (first non-pending ancestor)
    /// is not a valid root in the store, or if any declared uncle is
    /// missing from both pending and the store.
    fn collect_pending_subgraph(&self, start_hash: &BlockHash) -> Option<ReadyChain> {
        let chain = self.walk_pending_parent_chain(start_hash)?;
        let uncles = self.collect_pending_uncles(&chain)?;
        Some(ReadyChain { chain, uncles })
    }

    /// Find ancestors missing from both the pending set and the store.
    ///
    /// Walks the parent chain from start_hash. For each pending block,
    /// collects declared uncles that are missing. When the walk reaches
    /// a hash that is not in pending and not a valid root, adds it and
    /// stops.
    fn find_missing_ancestors(&self, start_hash: &BlockHash) -> HashSet<BlockHash> {
        let mut missing: HashSet<BlockHash> = HashSet::with_capacity(4);
        let mut current = *start_hash;
        while let Some(pending_block) = self.pending.get(&current) {
            let header = &pending_block.share_block.header;
            for uncle_hash in &header.uncles {
                if !self.pending.contains_key(uncle_hash) && !self.is_valid_root(uncle_hash) {
                    missing.insert(*uncle_hash);
                }
            }
            let parent = header.prev_share_blockhash;
            if parent == BlockHash::all_zeros() {
                return missing;
            }
            current = parent;
        }
        // `current` is not in pending. If it is also not a valid root
        // in the store, record it as a missing ancestor
        if !self.is_valid_root(&current) {
            missing.insert(current);
        }
        missing
    }

    /// Pure ASERT check given a parent's time and height.
    fn validate_asert(
        &self,
        share_block: &ShareBlock,
        parent_time: u32,
        parent_height: u32,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let expected_bits = self.pool_difficulty.calculate_target_clamped(
            parent_time,
            parent_height,
            share_block.header.bitcoin_header.bits,
        );
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

    /// Look up `(time, expected_height)` for a parent hash. Returns
    /// the cached value if present; otherwise queries the store. Used
    /// for uncles whose parent may be older than the chain's anchor.
    fn lookup_parent_params(
        &self,
        parent_hash: &BlockHash,
        cache: &HashMap<BlockHash, (u32, u32)>,
    ) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
        if let Some(&params) = cache.get(parent_hash) {
            return Ok(params);
        }
        let header = self.chain_store_handle.get_share_header(parent_hash)?;
        let metadata = self.chain_store_handle.get_block_metadata(parent_hash)?;
        Ok((header.time, metadata.expected_height.unwrap_or(0)))
    }

    /// Store a committed block and queue it for validation.
    async fn store_and_emit_validation(
        &self,
        block_hash: &BlockHash,
        share_block: ShareBlock,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
        Ok(())
    }

    /// Validate ASERT difficulty and commit a ready chain to the store.
    ///
    /// Walks the parent-first chain, validating each block against its
    /// parent's time and height from an in-memory cache (seeded with a
    /// single store lookup for the anchor). Uncles of each chain block
    /// are committed before the chain block itself, so the uncle
    /// references a parent that is either in the cache or, in the rare
    /// case it is older than the anchor, available via a store lookup.
    async fn commit_ready_chain(
        &mut self,
        ready: ReadyChain,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let ReadyChain { chain, mut uncles } = ready;
        let first_chain_hash = chain
            .first()
            .ok_or("commit_ready_chain called with empty chain")?;

        // Seed cache with the chain's anchor (one store lookup).
        let anchor_hash = self
            .pending
            .get(first_chain_hash)
            .ok_or_else(|| format!("First chain block {first_chain_hash} not in pending"))?
            .share_block
            .header
            .prev_share_blockhash;
        if anchor_hash == BlockHash::all_zeros() {
            return Err("Genesis block should not arrive via BlockReceiver".into());
        }
        let anchor_header = self.chain_store_handle.get_share_header(&anchor_hash)?;
        let anchor_metadata = self.chain_store_handle.get_block_metadata(&anchor_hash)?;
        let mut cache: HashMap<BlockHash, (u32, u32)> = HashMap::with_capacity(chain.len() + 1);
        cache.insert(
            anchor_hash,
            (
                anchor_header.time,
                anchor_metadata.expected_height.unwrap_or(0),
            ),
        );

        for chain_hash in &chain {
            // Commit pending uncles for this chain block first so
            // they are in the store when the nephew is organised.
            if let Some(uncle_hashes) = uncles.remove(chain_hash) {
                for uncle_hash in uncle_hashes {
                    let uncle_block = self
                        .remove_from_pending(&uncle_hash)
                        .ok_or_else(|| format!("Uncle {uncle_hash} disappeared from pending"))?;
                    let uncle_parent_hash = uncle_block.header.prev_share_blockhash;
                    let (parent_time, parent_height) =
                        self.lookup_parent_params(&uncle_parent_hash, &cache)?;
                    self.validate_asert(&uncle_block, parent_time, parent_height)?;
                    cache.insert(uncle_hash, (uncle_block.header.time, parent_height + 1));
                    self.store_and_emit_validation(&uncle_hash, uncle_block)
                        .await?;
                }
            }

            // Commit the chain block.
            let share_block = self
                .remove_from_pending(chain_hash)
                .ok_or_else(|| format!("Block {chain_hash} disappeared from pending"))?;
            let parent_hash = share_block.header.prev_share_blockhash;
            let (parent_time, parent_height) = self.lookup_parent_params(&parent_hash, &cache)?;
            self.validate_asert(&share_block, parent_time, parent_height)?;
            cache.insert(*chain_hash, (share_block.header.time, parent_height + 1));
            self.store_and_emit_validation(chain_hash, share_block)
                .await?;
        }

        Ok(())
    }

    /// After committing blocks, collect all transitively unblocked
    /// pending descendants and commit them. For each unblocked descendant
    /// we build a fresh `ReadyChain` so its own uncles are picked up.
    async fn cascade_descendants(
        &mut self,
        committed_hashes: &[BlockHash],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut queue: VecDeque<BlockHash> = VecDeque::with_capacity(8);
        for committed_hash in committed_hashes {
            if let Some(descendants_list) = self.descendants.get(committed_hash) {
                for descendant_hash in descendants_list {
                    if self.pending.contains_key(descendant_hash) {
                        queue.push_back(*descendant_hash);
                    }
                }
            }
        }

        while let Some(descendant_hash) = queue.pop_front() {
            if !self.pending.contains_key(&descendant_hash) {
                // Already committed as an uncle of an earlier chain block
                continue;
            }
            let Some(ready) = self.collect_pending_subgraph(&descendant_hash) else {
                continue;
            };
            let committed_chain: Vec<BlockHash> = ready.chain.clone();
            self.commit_ready_chain(ready).await?;

            // Enqueue next-level descendants for each newly committed block
            for committed_hash in &committed_chain {
                if let Some(next_descendant) = self.descendants.get(committed_hash) {
                    for next_hash in next_descendant {
                        if self.pending.contains_key(next_hash) {
                            queue.push_back(*next_hash);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process an incoming share block: buffer or commit.
    ///
    /// If the block's DAG is complete and rooted at valid store
    /// blocks, validates ASERT and commits the chain. Otherwise,
    /// buffers the block and requests missing ancestors.
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

        if let Some(ready) = self.collect_pending_subgraph(&block_hash) {
            let committed: Vec<BlockHash> = ready.chain.clone();
            self.commit_ready_chain(ready).await?;
            self.cascade_descendants(&committed).await?;
        } else {
            // iterate over the in-memory chain again, we can optimise this to be returned with collect_pending_subgraph if needed
            let missing = self.find_missing_ancestors(&block_hash);
            if !missing.is_empty() {
                let missing_vec: Vec<BlockHash> = missing.into_iter().collect();
                debug!(
                    "Block {block_hash} has {} missing ancestors, requesting fetch",
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
    fn test_add_to_pending_updates_descendants_index() {
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
            receiver.descendants.get(&parent_hash).unwrap(),
            &[child_hash]
        );
    }

    #[test]
    fn test_add_to_pending_uncle_descendants() {
        let mut receiver = create_test_block_receiver();

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
        let mut receiver = create_test_block_receiver();

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
    fn test_genesis_parent_not_tracked_in_descendants_key() {
        let mut receiver = create_test_block_receiver();

        // Default TestShareBlockBuilder has all-zeros parent (genesis)
        let share_block = TestShareBlockBuilder::new().build();
        let block_hash = share_block.block_hash();

        receiver.add_to_pending(block_hash, share_block);

        // All-zeros parent should not appear in descendants
        assert!(!receiver.descendants.contains_key(&BlockHash::all_zeros()));
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
    fn test_collect_pending_subgraph_single_block_with_valid_root() {
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

        let result = receiver.collect_pending_subgraph(&child_hash);
        assert!(result.is_some());
        let ready = result.unwrap();
        assert_eq!(ready.chain.len(), 1);
        assert_eq!(ready.chain[0], child_hash);
        assert!(ready.uncles.is_empty());
    }

    #[test]
    fn test_collect_pending_subgraph_missing_leaf_returns_none() {
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

        let result = receiver.collect_pending_subgraph(&child_hash);
        assert!(result.is_none());
    }

    #[test]
    fn test_collect_pending_subgraph_parent_before_child_ordering() {
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

        let result = receiver.collect_pending_subgraph(&child_hash);
        assert!(result.is_some());
        let ready = result.unwrap();
        assert_eq!(ready.chain.len(), 2);
        // Parent-first ordering guaranteed by collect_pending_subgraph
        assert_eq!(ready.chain[0], parent_hash);
        assert_eq!(ready.chain[1], child_hash);
        assert!(ready.uncles.is_empty());
    }

    #[test]
    fn test_collect_pending_subgraph_uncle_before_nephew() {
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

        let result = receiver.collect_pending_subgraph(&nephew_hash);
        assert!(result.is_some());
        let ready = result.unwrap();
        // Nephew's main chain is just [nephew] -- its parent is the
        // root (in store). The uncle is recorded in the uncles map.
        assert_eq!(ready.chain, vec![nephew_hash]);
        assert_eq!(ready.uncles.get(&nephew_hash).unwrap(), &vec![uncle_hash]);
    }

    #[test]
    fn test_find_missing_ancestors_returns_missing_hashes() {
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

        let missing = receiver.find_missing_ancestors(&child_hash);
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&missing_hash));
    }

    #[test]
    fn test_find_missing_ancestors_empty_when_all_rooted() {
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

        let missing = receiver.find_missing_ancestors(&child_hash);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_collect_pending_subgraph_genesis_parent_block() {
        // A block with all-zeros parent (genesis) has no
        // ancestor to check, so it is immediately collectible.
        let mock_store = ChainStoreHandle::default();
        let mut receiver = create_block_receiver_with_mock(mock_store);

        let genesis_child = TestShareBlockBuilder::new().build();
        let block_hash = genesis_child.block_hash();
        receiver.add_to_pending(block_hash, genesis_child);

        let result = receiver.collect_pending_subgraph(&block_hash);
        // Default builder has all-zeros parent (genesis sentinel) so
        // collect_pending_subgraph returns None.
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_asert_ok_when_bits_match() {
        let mut mock_pool_difficulty = PoolDifficulty::default();
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| {
                bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            mock_pool_difficulty,
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        let mut child_block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        child_block.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);

        let result = receiver.validate_asert(&child_block, 1700000000, 5);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_asert_mismatch_rejected() {
        let mut mock_pool_difficulty = PoolDifficulty::default();
        // Return a target different from the block's declared bits.
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| bitcoin::CompactTarget::from_consensus(0x1d00ffff));

        let (_, event_rx) = create_block_receiver_channel();
        let (block_fetcher_handle, _) = block_fetcher::create_block_fetcher_channel();
        let (validation_tx, _) = validation_worker::create_validation_channel();
        let receiver = BlockReceiver::new(
            event_rx,
            mock_pool_difficulty,
            ChainStoreHandle::default(),
            block_fetcher_handle,
            validation_tx,
        );

        let mut child_block = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        child_block.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);

        let result = receiver.validate_asert(&child_block, 1700000000, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASERT mismatch"));
    }

    #[test]
    fn test_lookup_parent_params_uses_cache() {
        let parent_hash = BlockHash::from_byte_array([0x11; 32]);
        // Store has NO expectations -- if the function hits the store,
        // the test will panic.
        let receiver = create_block_receiver_with_mock(ChainStoreHandle::default());

        let mut cache: HashMap<BlockHash, (u32, u32)> = HashMap::new();
        cache.insert(parent_hash, (1700001234, 42));

        let result = receiver.lookup_parent_params(&parent_hash, &cache);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1700001234, 42));
    }

    #[test]
    fn test_lookup_parent_params_falls_back_to_store() {
        let parent_hash = BlockHash::from_byte_array([0x12; 32]);
        let parent_header = TestShareBlockBuilder::new()
            .nonce(0xe9695790)
            .build()
            .header;
        let parent_time = parent_header.time;

        let parent_header_clone = parent_header.clone();
        let mut mock_store = ChainStoreHandle::default();
        mock_store
            .expect_get_share_header()
            .with(mockall::predicate::eq(parent_hash))
            .returning(move |_| Ok(parent_header_clone.clone()));
        mock_store
            .expect_get_block_metadata()
            .with(mockall::predicate::eq(parent_hash))
            .returning(|_| {
                Ok(crate::store::block_tx_metadata::BlockMetadata {
                    expected_height: Some(7),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let receiver = create_block_receiver_with_mock(mock_store);

        let cache: HashMap<BlockHash, (u32, u32)> = HashMap::new();
        let result = receiver.lookup_parent_params(&parent_hash, &cache);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (parent_time, 7));
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
    async fn test_commit_ready_chain_uses_cache_for_multi_block_chain() {
        // Build a 3-block chain A -> B -> C rooted at root_hash in store.
        // Assert that get_share_header is called exactly ONCE (for the
        // anchor); subsequent blocks should use the in-memory cache
        // seeded by the previous chain block's (time, height).
        let root_hash = BlockHash::from_byte_array([0xdd; 32]);
        let root_header = TestShareBlockBuilder::new()
            .nonce(0xdeadbeef)
            .build()
            .header;
        let root_header_clone = root_header.clone();

        let mut mock_store = ChainStoreHandle::default();
        // is_valid_root check during collect_pending_subgraph walks all
        // three pending blocks then hits root_hash in the store.
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
        // Anchor lookup in commit_ready_chain: exactly one call for root_hash.
        mock_store
            .expect_get_share_header()
            .with(mockall::predicate::eq(root_hash))
            .times(1)
            .returning(move |_| Ok(root_header_clone.clone()));
        mock_store.expect_add_share_block().returning(|_, _| Ok(()));
        mock_store.expect_organise_header().returning(|_| Ok(None));

        let mut mock_pool_difficulty = PoolDifficulty::default();
        mock_pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| {
                bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
            });

        let (mut receiver, _block_fetcher_rx, _validation_rx) =
            create_full_block_receiver(mock_store, mock_pool_difficulty);

        let mut block_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(root_hash.to_string())
            .nonce(0xe9695790)
            .build();
        block_a.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let a_hash = block_a.block_hash();

        let mut block_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(a_hash.to_string())
            .nonce(0xe9695791)
            .build();
        block_b.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let b_hash = block_b.block_hash();

        let mut block_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(b_hash.to_string())
            .nonce(0xe9695792)
            .build();
        block_c.header.bits =
            bitcoin::CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET);
        let c_hash = block_c.block_hash();

        receiver.add_to_pending(a_hash, block_a);
        receiver.add_to_pending(b_hash, block_b);
        receiver.add_to_pending(c_hash, block_c);

        let ready = receiver.collect_pending_subgraph(&c_hash).unwrap();
        assert_eq!(ready.chain, vec![a_hash, b_hash, c_hash]);

        let result = receiver.commit_ready_chain(ready).await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
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

        // 2. Child: find_missing_ancestors checks parent_hash -> NotFound
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

        // 5. Cascade: collect_pending_subgraph(child) walks child -> parent.
        //    parent is now in store -> is_valid_root(parent) -> Confirmed.
        let meta5 = confirmed_metadata.clone();
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(meta5.clone()));

        // 6. Cascade commit: anchor lookup for parent_hash -> Confirmed
        let meta6 = confirmed_metadata.clone();
        mock_store
            .expect_get_block_metadata()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(meta6.clone()));

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
