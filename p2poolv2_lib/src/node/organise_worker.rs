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
//! After promoting a block to confirmed, updates the PplnsWindow cache.

#[cfg(test)]
#[mockall_double::double]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
#[cfg(not(test))]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
use crate::accounting::stats::metrics::MetricsHandle;
use crate::monitoring_events::{MonitoringEvent, MonitoringEventSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation::FailureKind;
use crate::shares::validation::ShareValidator;
use crate::shares::validation::check_pplns_zone;
use crate::store::block_tx_metadata::{ChainMembership, Status};
use crate::store::dag_store::ShareInfo;
use crate::store::writer::StoreError;
use crate::stratum::work::notify::{NotifyCmd, NotifySender};
use bitcoin::BlockHash;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Channel capacity for shares pending organisation.
///
/// Both this and `PENDING_BLOCKS_CAPACITY` hold whole `ShareBlock`s, which
/// `handle_share_block` bounds at `BLOCK_TXS_SIZE_LIMIT` (200 KB) each, so the
/// capacities set the worst-case memory of the organise path. They are kept
/// small deliberately: this channel is pure backpressure between the parallel
/// validation tasks and the serial organise worker, so a deeper queue buys no
/// throughput -- the organise worker is the bottleneck either way -- and only
/// adds latency between a block's two `check_pplns_zone` reads, which is the
/// window in which its validation tier can flip (see the PPLNS zone tiering
/// notes in docs/architecture/share-processing-pipeline.md).
const ORGANISE_CHANNEL_CAPACITY: usize = 512;

/// Maximum number of blocks buffered while waiting for ancestor
/// confirmation during sync.
///
/// Sized against the channel rather than picked independently: a block is
/// buffered when its parent is not yet `BlockValid`, and a child can sit at
/// most a full channel ahead of its parent, so the buffer must be able to hold
/// a channel's worth of out-of-order arrivals. The headroom matters because
/// overflow drops a block that is already stored, which nothing re-fetches.
const PENDING_BLOCKS_CAPACITY: usize = 2 * ORGANISE_CHANNEL_CAPACITY;

/// Events for the organise worker.
// Block dominates the traffic and InvalidBlock is rare, so allow variant.
#[allow(clippy::large_enum_variant)]
pub enum OrganiseEvent {
    /// Promote candidates to confirmed after a block is validated.
    Block(ShareBlock),
    /// Mark a block that failed pre-context validation Invalid.
    ///
    /// The validation worker detects these failures but does not mutate chain
    /// state, so it reports the verdict here.
    InvalidBlock(BlockHash),
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
/// PplnsWindow cache.
pub struct OrganiseWorker {
    organise_rx: OrganiseReceiver,
    chain_store_handle: ChainStoreHandle,
    monitoring_event_sender: MonitoringEventSender,
    notify_tx: NotifySender,
    pplns_window: Arc<RwLock<PplnsWindow>>,
    share_validator: Arc<dyn ShareValidator + Send + Sync>,
    metrics: MetricsHandle,
    /// Blocks deferred because their parent is not yet validated, keyed by the
    /// parent's expected height. Multiple blocks may share the same parent
    /// height during forks or rapid sync. Drained when the parent becomes
    /// BlockValid or confirmed.
    pending_blocks: BTreeMap<u32, Vec<ShareBlock>>,
}

/// Validation state of a block's parent, deciding how the block is handled.
///
/// Chain-context validation runs only when the parent is `Valid`; until then
/// the block is deferred. This keeps the `BlockValid` chain transitive from the
/// confirmed tip up, and guarantees that once we do validate, every dependency
/// is present in the store.
enum ParentState {
    /// Parent is `BlockValid` or on the confirmed chain. Carries its height.
    Valid(u32),
    /// Parent is only `HeaderValid`/`Pending`; defer the block. Carries the
    /// parent height used as the buffer key.
    Pending(u32),
    /// Parent is `Invalid`; the block is invalid by descent.
    Invalid,
    /// Parent metadata is missing or has no height. This is an anomaly (the
    /// block receiver admits a block only after its parent is `HeaderValid`),
    /// so the block is dropped and left for re-delivery.
    Unknown,
}

/// Outcome of processing one share block through organise.
enum ProcessOutcome {
    /// The block became `BlockValid` or was promoted. Carries the block's own
    /// height, from which dependent buffered blocks are drained.
    Advanced(u32),
    /// The block was deferred (parent not yet validated).
    Buffered,
    /// The block was dropped (invalid-by-descent or unknown parent).
    Dropped,
    /// The block failed chain-context validation and was marked Invalid, which
    /// reorged the candidate chain -- rebuilding it from the invalid block's
    /// parent onto the best surviving branch (a sibling if one remains, else the
    /// parent itself). Confirmation should try to advance onto the rebuilt chain.
    Invalidated,
    /// Validated with a valid parent but did not advance: an unexpected
    /// Recoverable error, or a failed BlockValid mark or promote.
    NotAdvanced,
}

impl OrganiseWorker {
    /// Creates a new organise worker.
    pub fn new(
        organise_rx: OrganiseReceiver,
        chain_store_handle: ChainStoreHandle,
        monitoring_event_sender: MonitoringEventSender,
        notify_tx: NotifySender,
        metrics: MetricsHandle,
        pplns_window: Arc<RwLock<PplnsWindow>>,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> Self {
        Self {
            organise_rx,
            chain_store_handle,
            monitoring_event_sender,
            notify_tx,
            pplns_window,
            share_validator,
            metrics,
            pending_blocks: BTreeMap::new(),
        }
    }

    /// Runs the organise worker until the channel closes or a fatal error occurs.
    ///
    /// Returns `Ok(())` on clean shutdown (channel closed).
    /// Returns `Err(OrganiseError)` on fatal failure (store writer dead).
    pub async fn run(mut self) -> Result<(), OrganiseError> {
        info!("Organise worker started");

        // Make sure pplns window is warmed up with current chain state in store
        self.update_pplns_window();

        while let Some(event) = self.organise_rx.recv().await {
            match event {
                OrganiseEvent::Block(share_block) => {
                    self.handle_organise_block_event(share_block).await?;
                }
                OrganiseEvent::InvalidBlock(blockhash) => {
                    self.handle_invalid_block_event(blockhash).await?;
                }
            }
        }
        info!("Organise worker stopped - channel closed");
        Ok(())
    }

    /// Handle a single share block: gate it on its parent, then follow up.
    ///
    /// A block that advances (becomes BlockValid or is promoted) drains its
    /// dependents. A buffered block opportunistically tries to advance the
    /// confirmed chain from the candidate chain (which may have reorged). Only
    /// `StoreError::ChannelClosed` (and, in Phase 2, a store error during
    /// validation) is propagated as a fatal `OrganiseError`.
    async fn handle_organise_block_event(
        &mut self,
        share_block: ShareBlock,
    ) -> Result<(), OrganiseError> {
        match self.process_share_block(share_block).await? {
            ProcessOutcome::Advanced(height) => {
                self.drain_pending_blocks(height).await?;
            }
            ProcessOutcome::Buffered | ProcessOutcome::Invalidated => {
                // The candidate and confirmed chains advance on different events:
                // Header events reorg the candidate chain (organise_header)
                // without touching confirmed. Buffered: a Header event may have
                // reorged the candidate onto an already-BlockValid fork since the
                // last organise_block. Invalidated: mark_invalid just rebuilt the
                // candidate chain from the invalid block's parent (best surviving
                // branch). Either way, catch the confirmed chain up.
                self.advance_confirmed_and_drain().await?;
            }
            ProcessOutcome::Dropped | ProcessOutcome::NotAdvanced => {}
        }
        Ok(())
    }

    /// Mark a block that failed pre-context validation Invalid, then catch the
    /// confirmed chain up.
    ///
    /// Without this the block keeps its `HeaderValid` status on the candidate
    /// chain, and `contiguous_candidates_with_block_data` stops there, so
    /// confirmation stalls at that height until some branch out-works it.
    /// Marking it Invalid rebuilds the candidate chain from its parent onto the
    /// best surviving branch, the same follow-up a chain-context Consensus
    /// failure needs.
    async fn handle_invalid_block_event(
        &mut self,
        blockhash: BlockHash,
    ) -> Result<(), OrganiseError> {
        if let Err(mark_error) = self.chain_store_handle.mark_invalid(blockhash).await {
            error!("Failed to mark {blockhash} Invalid: {mark_error}");
        }
        self.advance_confirmed_and_drain().await
    }

    /// Run organise_block to advance the confirmed chain, then drain the blocks
    /// buffered at each newly confirmed height.
    ///
    /// Reads the confirmed tip first so the drain covers every height the call
    /// confirms, not just the last one.
    async fn advance_confirmed_and_drain(&mut self) -> Result<(), OrganiseError> {
        let previous_tip = match self.chain_store_handle.get_tip_height() {
            Ok(tip) => tip,
            Err(error) => {
                error!("Error reading confirmed tip before drain: {error}");
                None
            }
        };
        match self.chain_store_handle.organise_block().await {
            Ok(Some(height)) => {
                self.update_pplns_window();
                let from = previous_tip.map_or(height, |tip| (tip + 1).min(height));
                for drain_height in from..=height {
                    self.drain_pending_blocks(drain_height).await?;
                }
                Ok(())
            }
            Ok(None) => {
                // Confirmation did not advance, so something is wedging the
                // promotion prefix. That block's parent is valid -- which is
                // why it reached validation at all -- so confirmation stopped
                // exactly at the parent, and the block sits buffered under the
                // confirmed tip's own height. Draining here re-attempts it, and
                // drain_pending_blocks cascades upward if it now advances.
                if let Some(tip) = previous_tip {
                    self.drain_pending_blocks(tip).await?;
                }
                Ok(())
            }
            Err(StoreError::ChannelClosed) => Err(OrganiseError {
                message: "Store writer channel closed".to_string(),
            }),
            Err(error) => {
                error!("Error advancing confirmed chain: {error}");
                Ok(())
            }
        }
    }

    /// Gate a block on its parent's state, then buffer, drop, or
    /// validate-and-promote it. Shared by fresh events and the drain path.
    async fn process_share_block(
        &mut self,
        share_block: ShareBlock,
    ) -> Result<ProcessOutcome, OrganiseError> {
        let blockhash = share_block.block_hash();
        match self.parent_state(&share_block.header.prev_share_blockhash) {
            ParentState::Invalid => {
                debug!("Dropping {blockhash}: parent is Invalid (invalid by descent)");
                Ok(ProcessOutcome::Dropped)
            }
            ParentState::Unknown => {
                debug!("Dropping {blockhash}: parent metadata unavailable");
                Ok(ProcessOutcome::Dropped)
            }
            ParentState::Pending(parent_height) => {
                self.buffer_block(parent_height, share_block);
                Ok(ProcessOutcome::Buffered)
            }
            ParentState::Valid(parent_height) => {
                self.validate_mark_promote(share_block, parent_height).await
            }
        }
    }

    /// Validate a block whose parent is already valid, mark it BlockValid, and
    /// promote it.
    ///
    /// In the PPLNS zone the block runs chain-context validation here; because
    /// the parent is validated every dependency is present, so a failure is a
    /// genuine consensus violation (the block is marked Invalid). Below the zone
    /// (the prune window) the block was already ASERT/PoW-validated by the
    /// validation worker (`validate_below_pplns_depth`), so it is marked
    /// BlockValid without re-validation.
    ///
    /// Both tiers are marked BlockValid before promotion, so the
    /// promotion gate -- which requires BlockValid down to the prune
    /// depth -- can confirm them. Returns `Advanced(height)` when the
    /// block becomes BlockValid or is promoted, so its dependents can
    /// be drained.
    async fn validate_mark_promote(
        &mut self,
        share_block: ShareBlock,
        parent_height: u32,
    ) -> Result<ProcessOutcome, OrganiseError> {
        let blockhash = share_block.block_hash();
        debug!("Organising block: {blockhash:?}");

        let in_pplns_zone = match check_pplns_zone(&blockhash, &self.chain_store_handle) {
            Ok(result) => result,
            Err(error_message) => {
                error!("Error checking for zone, will retry {blockhash}: {error_message}");
                self.buffer_block(parent_height, share_block);
                return Ok(ProcessOutcome::NotAdvanced);
            }
        };

        if in_pplns_zone
            && let Err(validation_error) = self.share_validator.validate_with_chain_context(
                &share_block,
                &self.chain_store_handle,
                Arc::clone(&self.pplns_window),
            )
        {
            match validation_error.kind() {
                FailureKind::Consensus => {
                    // The parent is validated, so all dependencies are present:
                    // this is a genuine consensus violation. Mark Invalid, which
                    // rebuilds the candidate chain from the invalid block's parent
                    // onto the best surviving branch, and return Invalidated so the
                    // caller advances confirmation onto it instead of waiting for
                    // the next event.
                    error!("Chain-context validation failed for {blockhash}: {validation_error}");
                    if let Err(mark_error) = self.chain_store_handle.mark_invalid(blockhash).await {
                        error!("Failed to mark {blockhash} Invalid: {mark_error}");
                    }
                    return Ok(ProcessOutcome::Invalidated);
                }
                FailureKind::StoreAccess => {
                    // The read against the store itself failed, or data whose
                    // absence can only mean corruption is gone. Verdicts a
                    // peer's block can provoke are classified Consensus or
                    // Recoverable, so reaching here is a local fault: fail fast
                    // rather than silently diverge.
                    error!(
                        "Fatal store error validating {blockhash} (parent is valid): {validation_error}"
                    );
                    return Err(OrganiseError {
                        message: format!(
                            "Store error validating {blockhash} with a valid parent: {validation_error}"
                        ),
                    });
                }
                FailureKind::Recoverable => {
                    // A chain-context check could not be decided because data
                    // it needs has not arrived yet (an ancestor header, a
                    // transient store read). The block may well be valid, so
                    // leave it for retry rather than marking it Invalid or
                    // crashing.
                    warn!(
                        "Recoverable validation error for {blockhash} at organise: {validation_error}"
                    );
                    self.buffer_block(parent_height, share_block);
                    return Ok(ProcessOutcome::NotAdvanced);
                }
                FailureKind::Unresolvable => {
                    // What the check needs is gone rather than late -- an
                    // anchor below the confirmed entries the PPLNS window
                    // retains -- and the window's oldest entry only moves
                    // forward, so no retry can decide it.
                    warn!("Dropping {blockhash}, cannot be resolved: {validation_error}");
                    return Ok(ProcessOutcome::Dropped);
                }
            }
        }

        // Mark BlockValid for both promotion tiers before promoting.
        if let Err(mark_error) = self.chain_store_handle.mark_block_valid(blockhash).await {
            // A rejected transition means the block is Pending or already
            // Invalid, which no retry can change; anything else is a store
            // failure that may not recur.
            if matches!(mark_error, StoreError::InvalidStatusTransition(_)) {
                error!("Cannot mark {blockhash} BlockValid: {mark_error}");
            } else {
                error!("Failed to mark {blockhash} BlockValid, will retry: {mark_error}");
                self.buffer_block(parent_height, share_block);
            }
            return Ok(ProcessOutcome::NotAdvanced);
        }

        match self
            .chain_store_handle
            .promote_block(share_block.header.clone())
            .await
        {
            Ok(Some(height)) => {
                self.post_promote(&share_block, height).await;
                // Drain dependents from this block's own height, not the
                // confirmed height, so a promotion cascade doesn't skip them.
                Ok(ProcessOutcome::Advanced(parent_height + 1))
            }
            Ok(None) => {
                // Marked BlockValid above even if it did not promote to confirmed
                // yet (e.g. its parent is not confirmed), so its dependents can be
                // drained from its height.
                Ok(ProcessOutcome::Advanced(parent_height + 1))
            }
            Err(StoreError::ChannelClosed) => {
                error!("Store writer channel closed during promote block");
                Err(OrganiseError {
                    message: "Store writer channel closed".to_string(),
                })
            }
            Err(error) => {
                error!("Error promoting block {blockhash}, will retry: {error}");
                self.buffer_block(parent_height, share_block);
                Ok(ProcessOutcome::NotAdvanced)
            }
        }
    }

    /// Classify a block's parent for the organise gate.
    ///
    /// `Valid` (BlockValid, or confirmed for below-zone blocks that are only
    /// HeaderValid) lets the block be validated and marked; `Pending` defers
    /// it; `Invalid` drops it by descent; `Unknown` (missing metadata/height)
    /// drops it for re-delivery.
    fn parent_state(&self, parent_hash: &BlockHash) -> ParentState {
        let metadata = match self.chain_store_handle.get_block_metadata(parent_hash) {
            Ok(metadata) => metadata,
            Err(error) => {
                debug!("Parent {parent_hash} metadata unavailable, deferring: {error}");
                return ParentState::Unknown;
            }
        };
        if metadata.status == Status::Invalid {
            return ParentState::Invalid;
        }
        let Some(height) = metadata.expected_height else {
            return ParentState::Unknown;
        };
        if metadata.status == Status::BlockValid || metadata.chain == ChainMembership::Confirmed {
            ParentState::Valid(height)
        } else {
            ParentState::Pending(height)
        }
    }

    /// Run post-promotion actions: update PPLNS, record confirmed work for
    /// the effort metric, optionally send new notify, and emit a monitoring
    /// event.
    async fn post_promote(&self, share_block: &ShareBlock, height: u32) {
        self.update_pplns_window();

        // Feed the block effort accumulator with this confirmed share's pool
        // difficulty. Uncles are excluded so the effort numerator tracks the
        // same confirmed-chain work as the hashrate (derived from chain work).
        //
        // Skip while syncing: during sync post_promote replays the whole
        // backlog, and work_since_last_block never resets (no real bitcoin
        // block is found during replay), so it would balloon to the entire
        // chain's work and report an absurd effort. Only real-time confirmed
        // shares count toward effort.
        if self.chain_store_handle.is_current() {
            let share_difficulty =
                bitcoin::Target::from_compact(share_block.header.bits).difficulty_float();
            let _ = self.metrics.record_confirmed_share(share_difficulty).await;

            // If this confirmed share is itself a bitcoin block, record the
            // find pool-wide (any node's miners) and reset the effort
            // accumulator toward the next block.
            if share_block.is_bitcoin_block() {
                let bitcoin_header = &share_block.header.bitcoin_header;
                let _ = self
                    .metrics
                    .record_block_found(
                        bitcoin_header.block_hash().to_string(),
                        share_block.header.bitcoin_height,
                    )
                    .await;
            }
        }

        match self.chain_store_handle.get_candidate_tip_height() {
            Ok(Some(candidate_tip_height)) if height >= candidate_tip_height => {
                self.send_new_notify(height, candidate_tip_height).await;
            }
            Ok(Some(_)) => {}
            _ => debug!("No candidate tip found"),
        }

        self.emit_share_monitoring_event(share_block, height);
    }

    /// Insert a block into the pending buffer, keyed by its parent height.
    ///
    /// Drops the block with an error log if the buffer is at capacity.
    /// The capacity check counts total blocks across all heights.
    fn buffer_block(&mut self, parent_height: u32, share_block: ShareBlock) {
        let total_blocks: usize = self.pending_blocks.values().map(|v| v.len()).sum();
        if total_blocks >= PENDING_BLOCKS_CAPACITY {
            error!(
                "Pending block buffer full ({PENDING_BLOCKS_CAPACITY}), dropping block {}",
                share_block.block_hash()
            );
            return;
        }
        debug!(
            "Buffering block {} at parent height {parent_height} (confirmed tip not yet reached)",
            share_block.block_hash()
        );
        self.pending_blocks
            .entry(parent_height)
            .or_insert_with(|| Vec::with_capacity(2))
            .push(share_block);
    }

    /// Re-attempt buffered blocks whose parent just became valid, from
    /// `from_height` upward.
    ///
    /// Blocks are keyed in the buffer by their parent's height, so the children
    /// of a block that just became valid at height `h` sit under key `h`. The
    /// scan walks heights contiguously from `from_height`, advancing to the
    /// next height only when the current one advanced something -- so it follows
    /// the newly-validated frontier and stops as soon as nothing more proceeds.
    /// This keeps a full sync linear rather than quadratic. A re-attempted block
    /// whose parent is still pending cheaply re-buffers (a metadata read, not a
    /// full validation).
    async fn drain_pending_blocks(&mut self, from_height: u32) -> Result<(), OrganiseError> {
        let mut height = Some(from_height);
        while let Some(current) = height
            && let Some(blocks) = self.pending_blocks.remove(&current)
        {
            debug!(
                "Draining {} buffered blocks waiting on height {current}",
                blocks.len()
            );
            let mut next_height = None;
            for share_block in blocks {
                if let ProcessOutcome::Advanced(advanced_height) =
                    self.process_share_block(share_block).await?
                {
                    next_height = Some(advanced_height);
                }
            }
            height = next_height;
        }
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
    use crate::accounting::payout::sharechain_pplns::pplns_window::MAX_PPLNS_WINDOW_SHARES;
    use crate::monitoring_events::create_monitoring_event_channel;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::shares::validation::ValidationError;
    use crate::store::block_tx_metadata::Status;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership};
    use crate::stratum::work::notify::{NotifyCmd, NotifyReceiver};
    use crate::test_utils::TestShareBlockBuilder;

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

    /// Spawn a throwaway metrics actor and return its handle for tests.
    fn create_test_metrics_handle() -> MetricsHandle {
        crate::accounting::stats::metrics::spawn_test_metrics_handle()
    }

    /// Build a stub share validator that approves every chain-context check.
    fn stub_share_validator_with_success() -> Arc<dyn ShareValidator + Send + Sync> {
        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _, _| Ok(()));
        Arc::new(mock_validator)
    }

    /// Build an OrganiseWorker whose chain store returns `metadata_result`
    /// for any get_block_metadata call. Used to unit-test has_valid_parent.
    fn worker_with_parent_metadata(
        metadata_result: Result<BlockMetadata, StoreError>,
    ) -> OrganiseWorker {
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(move |_| metadata_result.clone());

        let (_organise_tx, organise_rx) = create_organise_channel();
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        )
    }

    fn parent_metadata(status: Status, chain: ChainMembership) -> BlockMetadata {
        BlockMetadata {
            expected_height: Some(1),
            chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
            status,
            chain,
        }
    }

    #[tokio::test]
    async fn test_parent_state() {
        let parent = TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build()
            .block_hash();

        // A BlockValid parent (even off-chain) is Valid.
        let worker = worker_with_parent_metadata(Ok(parent_metadata(
            Status::BlockValid,
            ChainMembership::None,
        )));
        assert!(matches!(
            worker.parent_state(&parent),
            ParentState::Valid(1)
        ));

        // A confirmed parent that is only HeaderValid (genesis, or a block
        // confirmed below the PPLNS zone) is also Valid.
        let worker = worker_with_parent_metadata(Ok(parent_metadata(
            Status::HeaderValid,
            ChainMembership::Confirmed,
        )));
        assert!(matches!(
            worker.parent_state(&parent),
            ParentState::Valid(1)
        ));

        // A HeaderValid candidate parent is Pending (not yet validated).
        let worker = worker_with_parent_metadata(Ok(parent_metadata(
            Status::HeaderValid,
            ChainMembership::Candidate,
        )));
        assert!(matches!(
            worker.parent_state(&parent),
            ParentState::Pending(1)
        ));

        // An Invalid parent is Invalid (block is invalid by descent).
        let worker = worker_with_parent_metadata(Ok(parent_metadata(
            Status::Invalid,
            ChainMembership::None,
        )));
        assert!(matches!(worker.parent_state(&parent), ParentState::Invalid));

        // Missing parent metadata is Unknown.
        let worker = worker_with_parent_metadata(Err(StoreError::NotFound("missing".to_string())));
        assert!(matches!(worker.parent_state(&parent), ParentState::Unknown));
    }

    #[tokio::test]
    async fn test_organise_worker_stops_on_channel_close() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Drop sender so recv() returns None immediately
        drop(_organise_tx);

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
        // Successful chain-context validation must persist BlockValid.
        mock_chain_handle
            .expect_mark_block_valid()
            .times(1)
            .returning(|_| Ok(()));
        // Parent on the confirmed chain, so the transitivity gate lets the
        // block be marked BlockValid.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::HeaderValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    /// A prune-window block (below the PPLNS zone) must be marked BlockValid so
    /// the promotion gate -- which requires BlockValid down to the prune depth
    /// -- can confirm it. It was ASERT/PoW-validated by the validation worker,
    /// so chain-context validation must NOT run again here.
    #[tokio::test]
    async fn test_organise_worker_marks_prune_window_block_block_valid() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        // Parent is confirmed (parent_state == Valid) and the block sits at
        // height 5, far below the candidate tip, so check_pplns_zone is false.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::HeaderValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        // Candidate tip more than one PPLNS window above height 5, so
        // is_in_pplns_zone(5, tip) is false (prune window).
        let candidate_tip = MAX_PPLNS_WINDOW_SHARES as u32 + 100;
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(move || Ok(Some(candidate_tip)));
        // The prune-window block must be marked BlockValid even though it is
        // below the zone.
        mock_chain_handle
            .expect_mark_block_valid()
            .times(1)
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(None));

        // Below the zone, chain-context validation must NOT run.
        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator.expect_validate_with_chain_context().never();
        let share_validator: Arc<dyn ShareValidator + Send + Sync> = Arc::new(mock_validator);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            share_validator,
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    /// Transitivity gate: a block whose parent is only HeaderValid on the
    /// candidate chain (not BlockValid, not confirmed) must NOT be validated or
    /// marked BlockValid. It is buffered until the parent is validated.
    #[tokio::test]
    async fn test_block_not_marked_valid_when_parent_unvalidated() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        // Parent is HeaderValid on the candidate chain -- not yet validated.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::HeaderValid,
                    chain: ChainMembership::Candidate,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        // The block is buffered (parent not validated): never validated, never
        // marked, never promoted. The worker opportunistically tries
        // organise_block from the buffer branch.
        mock_chain_handle.expect_mark_block_valid().never();
        mock_chain_handle.expect_promote_block().never();
        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    /// A Consensus validation failure marks the block Invalid (rebuilding the
    /// candidate chain from the invalid block's parent onto the best surviving
    /// branch) and then advances the confirmed chain onto it via organise_block
    /// -- it must not wait for the next event. The invalid block itself is never
    /// promoted.
    #[tokio::test]
    async fn test_organise_worker_advances_confirmed_after_consensus_invalidation() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        // Validation failed -> the block must NOT be marked BlockValid.
        mock_chain_handle.expect_mark_block_valid().never();
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(10),
                    chain_work: bitcoin::Work::from_hex("0x00").unwrap(),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(10)));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(10)));
        // On chain-context validation failure the block must be marked Invalid
        // (so promotion never confirms it) and promote_block must NOT be called
        // for it. mark_invalid rebuilds the candidate chain from the invalid
        // block's parent onto the best surviving branch, and the worker then
        // calls organise_block to advance the confirmed chain onto it -- rather
        // than waiting for the next event.
        mock_chain_handle
            .expect_mark_invalid()
            .times(1)
            .returning(|_| Ok(()));
        mock_chain_handle.expect_promote_block().never();
        mock_chain_handle
            .expect_organise_block()
            .times(1)
            .returning(|| Ok(Some(6)));

        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _, _| Err(ValidationError::consensus("rejected for test")));
        let share_validator: Arc<dyn ShareValidator + Send + Sync> = Arc::new(mock_validator);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            share_validator,
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    /// An InvalidBlock event marks the named block Invalid, then runs
    /// organise_block so the confirmed chain can advance onto the surviving
    /// branch. The invalid block itself is never validated or promoted, and
    /// organise_block only promotes candidates that are already BlockValid, so
    /// nothing reaches the confirmed chain that skipped validation.
    ///
    /// The validation worker sends this when a pre-context check fails with all
    /// its dependencies present.
    #[tokio::test]
    async fn test_organise_worker_marks_invalid_block_event() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_invalid()
            .times(1)
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(10)));
        mock_chain_handle
            .expect_organise_block()
            .times(1)
            .returning(|| Ok(None));
        // The block failed validation, so it must never be marked valid or promoted.
        mock_chain_handle.expect_mark_block_valid().never();
        mock_chain_handle.expect_promote_block().never();

        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator.expect_validate_with_chain_context().never();
        let share_validator: Arc<dyn ShareValidator + Send + Sync> = Arc::new(mock_validator);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            share_validator,
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx
            .send(OrganiseEvent::InvalidBlock(share.block_hash()))
            .await
            .unwrap();
        drop(organise_tx);

        assert!(worker.run().await.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_fatal_on_channel_closed() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Err(StoreError::ChannelClosed));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
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
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Err(StoreError::Database("test error".to_string())));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
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
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(5)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle.expect_is_current().returning(|| true);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
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
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(1),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(1)));
        // Confirmed height 3 is below candidate tip 5
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(3)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle.expect_is_current().returning(|| true);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, mut notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // No NewNotify should have been sent
        assert!(notify_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_organise_worker_buffers_block_when_parent_above_confirmed_tip() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(10),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::HeaderValid,
                    chain: ChainMembership::Candidate,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle.expect_promote_block().never();
        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_organise_worker_does_not_buffer_when_parent_at_confirmed_tip() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(6)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle.expect_is_current().returning(|| true);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_post_promote_skips_effort_while_syncing() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(6)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        // Not current: the node is still syncing, so effort must not be recorded.
        mock_chain_handle.expect_is_current().returning(|| false);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        // Hold a metrics handle so we can inspect it after the worker runs.
        let metrics = create_test_metrics_handle();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            metrics.clone(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // The block was promoted, but because the chain was not current no
        // confirmed-share work was accumulated into the effort numerator.
        let pool_metrics = metrics.get_metrics().await;
        assert_eq!(pool_metrics.work_since_last_block, 0.0);
    }

    #[tokio::test]
    async fn test_post_promote_records_pool_block_find() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(6)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle.expect_is_current().returning(|| true);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let metrics = create_test_metrics_handle();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            metrics.clone(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Make the confirmed share a real bitcoin block: the regtest genesis
        // header meets its own target, so is_bitcoin_block() is true.
        let mut share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        share.header.bitcoin_header =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // The block find is recorded pool-wide from the share chain, and the
        // effort accumulator is reset by it.
        let pool_metrics = metrics.get_metrics().await;
        assert_eq!(pool_metrics.blocks_found_total, 1);
        assert_eq!(pool_metrics.blocks_found.len(), 1);
        assert_eq!(pool_metrics.work_since_last_block, 0.0);
    }

    #[tokio::test]
    async fn test_organise_worker_drains_buffered_block_after_promotion() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));

        // First call: block A has parent at height 100, tip is 5 -> buffer.
        // Second call: block B has parent at height 5, tip is 5 -> proceed.
        // Third call (during drain): block A re-checked, parent at 100 still.
        let metadata_call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let metadata_counter = metadata_call_count.clone();
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(move |_| {
                let count = metadata_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let height = if count == 0 { 100 } else { 5 };
                Ok(BlockMetadata {
                    expected_height: Some(height),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });

        // First call (should_buffer for block A): tip is 5 -> buffer.
        // Second call (should_buffer for block B): tip is 5 -> proceed.
        // Third call (drain after B promotes): tip is 100 -> drain A.
        // Fourth call (drain loop re-check): tip is 100 -> empty, stop.
        let tip_call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let tip_counter = tip_call_count.clone();
        mock_chain_handle
            .expect_get_tip_height()
            .returning(move || {
                let count = tip_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tip = if count < 2 { 5 } else { 100 };
                Ok(Some(tip))
            });

        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(None));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(Some(100)));
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(100)));
        mock_chain_handle.expect_is_current().returning(|| true);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Block A: parent height 100, will be buffered
        let share_a = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx
            .send(OrganiseEvent::Block(share_a))
            .await
            .unwrap();

        // Block B: parent height 5, will proceed and promote
        let share_b = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        organise_tx
            .send(OrganiseEvent::Block(share_b))
            .await
            .unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(result.is_ok());

        // promote_block was called at least twice: once for B, once for
        // drained A. The mock allows unlimited calls.
    }

    /// A transient failure after the parent gate must leave the block buffered
    /// for a later drain. Dropping it loses a block that is already stored, so
    /// nothing re-fetches it and its children wait on a parent that will never
    /// be marked BlockValid.
    /// End to end for the wedge: a block fails transiently, is re-buffered
    /// under its parent's height, and is retried when a later event finds
    /// confirmation stalled. Without the retry the confirmed tip cannot move
    /// -- this block is what blocks it -- so no confirm-driven drain ever
    /// reaches it and the node stays wedged until a peer happens to resend.
    #[tokio::test]
    async fn test_stalled_confirmation_retries_the_block_wedging_it() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        // Parent is confirmed at height 5, so the block reaches promotion and
        // is buffered under height 5 when that fails.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        // The confirmed tip stays at 5: this block is what stops it advancing.
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(None));
        mock_chain_handle.expect_is_current().returning(|| false);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        // Promotion fails once, then succeeds -- a transient store failure.
        let promote_attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempts = promote_attempts.clone();
        mock_chain_handle
            .expect_promote_block()
            .returning(move |_| {
                if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    Err(StoreError::Database("transient".to_string()))
                } else {
                    Ok(Some(6))
                }
            });

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let outcome = worker.process_share_block(share).await.unwrap();
        assert!(matches!(outcome, ProcessOutcome::NotAdvanced));
        assert_eq!(worker.pending_blocks.get(&5).map(Vec::len), Some(1));

        // A later event finds confirmation stalled and retries the wedging
        // block, which now promotes.
        worker.advance_confirmed_and_drain().await.unwrap();

        assert_eq!(
            promote_attempts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the wedging block must be re-attempted"
        );
        assert!(
            worker.pending_blocks.is_empty(),
            "a block that advances must leave the buffer"
        );
    }

    #[tokio::test]
    async fn test_transient_promote_failure_rebuffers_the_block() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        // Parent is confirmed at height 5, so the block passes the parent gate
        // and reaches promotion.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        // A store failure that says nothing about the block itself.
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Err(StoreError::Database("transient".to_string())));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let blockhash = share.block_hash();
        let outcome = worker.process_share_block(share).await.unwrap();

        assert!(matches!(outcome, ProcessOutcome::NotAdvanced));
        let buffered = worker
            .pending_blocks
            .get(&5)
            .expect("block must be buffered under its parent height for retry");
        assert_eq!(buffered.len(), 1);
        assert_eq!(buffered[0].block_hash(), blockhash);
    }

    /// An unresolvable chain-context failure drops the block instead of
    /// buffering it, and records no verdict.
    ///
    /// The buffer is keyed by parent height and drains only reach heights at or
    /// above the confirmed tip, so an entry whose parent is far below is never
    /// revisited: it would hold its slot until the buffer starts dropping live
    /// blocks. Marking it Invalid is not an option either -- a node retaining
    /// more of its window may judge the same block valid, and the verdict would
    /// bar its branch forever.
    #[tokio::test]
    async fn test_unresolvable_validation_error_drops_without_buffering() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        // Neither a verdict nor a promotion may follow a drop.
        mock_chain_handle.expect_mark_invalid().never();
        mock_chain_handle.expect_mark_block_valid().never();
        mock_chain_handle.expect_promote_block().never();

        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _, _| {
                Err(ValidationError::unresolvable(
                    "PPLNS window for anchor is truncated by eviction",
                ))
            });

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            Arc::new(mock_validator),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let outcome = worker.process_share_block(share).await.unwrap();

        assert!(matches!(outcome, ProcessOutcome::Dropped));
        assert!(
            worker.pending_blocks.is_empty(),
            "an unresolvable block must not occupy a buffer slot it can never leave"
        );
    }

    /// A rejected status transition means the block is Pending or already
    /// Invalid. No retry can change that, so it must not be re-buffered --
    /// otherwise it is re-attempted on every drain of its parent's height.
    #[tokio::test]
    async fn test_invalid_status_transition_does_not_rebuffer() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(6)));
        mock_chain_handle.expect_mark_block_valid().returning(|_| {
            Err(StoreError::InvalidStatusTransition(
                "block is Invalid".to_string(),
            ))
        });
        mock_chain_handle.expect_promote_block().never();

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let outcome = worker.process_share_block(share).await.unwrap();

        assert!(matches!(outcome, ProcessOutcome::NotAdvanced));
        assert!(
            worker.pending_blocks.is_empty(),
            "a permanently failing block must not be queued for retry"
        );
    }

    #[tokio::test]
    async fn test_drain_reattempts_all_blocks_sharing_a_parent_height() {
        // Two distinct blocks buffered under the same parent height must both be
        // re-attempted when that height is drained -- the buffer keeps a Vec per
        // height, not a single block.
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        // Parent is confirmed (Valid); the blocks sit below the PPLNS zone, so
        // no chain-context validation runs. They are still marked BlockValid
        // (prune-window blocks) and then promote directly.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(5),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(200_000)));
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));

        let promote_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let promote_counter = promote_count.clone();
        mock_chain_handle
            .expect_promote_block()
            .returning(move |_| {
                promote_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(Some(6))
            });
        mock_chain_handle.expect_is_current().returning(|| false);
        mock_chain_handle
            .expect_get_uncle_infos()
            .returning(|_| Vec::new());

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Two distinct blocks buffered under the same parent height (5).
        let share_a = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        let share_b = TestShareBlockBuilder::new().nonce(0xe9695792).build();
        worker.buffer_block(5, share_a);
        worker.buffer_block(5, share_b);

        worker.drain_pending_blocks(5).await.unwrap();

        // Both buffered blocks were re-attempted and promoted (neither was
        // overwritten by the other).
        assert_eq!(
            promote_count.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "both blocks sharing a parent height must be drained"
        );
    }

    /// Fail-first regression for the out-of-order stranding (#2). Validation
    /// runs one tokio task per block, so a child's OrganiseEvent can be handled
    /// before its parent's. The child must still become BlockValid once the
    /// parent does -- otherwise the contiguous promotion prefix wedges at the
    /// stranded child, and confirmation (which the child blocks) can never
    /// revisit it.
    ///
    /// Layout: GP is confirmed (height 2); P (height 3) and C (height 4) are a
    /// candidate fork at/below the confirmed tip. C is delivered before P. On
    /// the pre-fix code C is validated immediately, gate-blocked to HeaderValid,
    /// and never re-marked; here it is buffered and re-marked via the drain.
    #[tokio::test]
    async fn test_out_of_order_child_becomes_valid_after_parent() {
        use std::collections::HashSet;
        use std::sync::Mutex;

        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);

        let gp = TestShareBlockBuilder::new().nonce(0xe9695790).build();
        let gp_hash = gp.block_hash();
        let p = TestShareBlockBuilder::new()
            .prev_share_blockhash(gp_hash.to_string())
            .nonce(0xe9695791)
            .build();
        let p_hash = p.block_hash();
        let c = TestShareBlockBuilder::new()
            .prev_share_blockhash(p_hash.to_string())
            .nonce(0xe9695792)
            .build();
        let c_hash = c.block_hash();

        // Records which blocks have been marked BlockValid; the metadata mock
        // reflects the transition so a drained child sees a now-valid parent.
        let marked: Arc<Mutex<HashSet<BlockHash>>> = Arc::new(Mutex::new(HashSet::new()));

        let marked_meta = marked.clone();
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(move |hash| {
                let hash = *hash;
                let (height, status, chain) = if hash == gp_hash {
                    (2, Status::BlockValid, ChainMembership::Confirmed)
                } else if hash == p_hash {
                    let status = if marked_meta.lock().unwrap().contains(&p_hash) {
                        Status::BlockValid
                    } else {
                        Status::HeaderValid
                    };
                    (3, status, ChainMembership::Candidate)
                } else if hash == c_hash {
                    let status = if marked_meta.lock().unwrap().contains(&c_hash) {
                        Status::BlockValid
                    } else {
                        Status::HeaderValid
                    };
                    (4, status, ChainMembership::Candidate)
                } else {
                    (0, Status::BlockValid, ChainMembership::Confirmed)
                };
                Ok(BlockMetadata {
                    expected_height: Some(height),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status,
                    chain,
                })
            });
        let marked_mark = marked.clone();
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(move |hash| {
                marked_mark.lock().unwrap().insert(hash);
                Ok(())
            });
        // Small candidate tip so heights 3 and 4 are inside the PPLNS zone.
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(5)));
        // The fork is not promotable yet (candidate, off the confirmed chain).
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(None));
        // Buffering C triggers an opportunistic organise_block.
        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(None));
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(2)));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // Deliver the child before the parent (out of order).
        organise_tx.send(OrganiseEvent::Block(c)).await.unwrap();
        organise_tx.send(OrganiseEvent::Block(p)).await.unwrap();
        drop(organise_tx);

        worker.run().await.unwrap();

        let marked = marked.lock().unwrap();
        assert!(marked.contains(&p_hash), "parent P must be BlockValid");
        assert!(
            marked.contains(&c_hash),
            "child C must become BlockValid after its parent, not be stranded"
        );
    }

    /// When organise_block confirms a contiguous range of
    /// heights at once (common during sync), the Buffered/Invalidated follow-up
    /// must drain dependents buffered under the intermediate heights, not only
    /// the new top.
    ///
    /// C is buffered under intermediate height 7; organise_block advances the
    /// confirmed tip from 5 to 10. The drain must visit height 7 and process C.
    /// On the pre-fix code the drain started at the top (10) and walked only
    /// upward, skipping 6..9 and stranding C.
    #[tokio::test]
    async fn test_buffered_follow_up_drains_intermediate_confirmed_heights() {
        let (_organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();

        // Distinct parent hashes so the metadata mock can give T a Pending parent
        // (T buffers, triggering the follow-up) and C a Valid parent (C promotes).
        let t_parent = TestShareBlockBuilder::new()
            .nonce(0x0000aaaa)
            .build()
            .block_hash();
        let c_parent = TestShareBlockBuilder::new()
            .nonce(0x0000bbbb)
            .build()
            .block_hash();
        let share_t = TestShareBlockBuilder::new()
            .prev_share_blockhash(t_parent.to_string())
            .nonce(0x0000cccc)
            .build();
        let share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(c_parent.to_string())
            .nonce(0x0000dddd)
            .build();
        let c_hash = share_c.block_hash();

        mock_chain_handle
            .expect_get_block_metadata()
            .returning(move |hash| {
                let (height, status, chain) = if *hash == t_parent {
                    (5, Status::HeaderValid, ChainMembership::Candidate)
                } else if *hash == c_parent {
                    (7, Status::BlockValid, ChainMembership::Confirmed)
                } else if *hash == c_hash {
                    (7, Status::HeaderValid, ChainMembership::Candidate)
                } else {
                    (0, Status::BlockValid, ChainMembership::Confirmed)
                };
                Ok(BlockMetadata {
                    expected_height: Some(height),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status,
                    chain,
                })
            });
        // Previous confirmed tip 5; organise_block confirms up to 10 in one call.
        mock_chain_handle
            .expect_get_tip_height()
            .returning(|| Ok(Some(5)));
        mock_chain_handle
            .expect_organise_block()
            .returning(|| Ok(Some(10)));
        // Large candidate tip so C (height 7) is below the PPLNS zone and promotes
        // without chain-context validation.
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(200_000)));
        mock_chain_handle
            .expect_mark_block_valid()
            .returning(|_| Ok(()));
        mock_chain_handle
            .expect_promote_block()
            .returning(|_| Ok(None));

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let mut worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            stub_share_validator_with_success(),
        );

        // C buffered under intermediate height 7 (between old tip 5 and new tip 10).
        worker.buffer_block(7, share_c);
        // T buffers (Pending parent), triggering the organise_block + drain follow-up.
        worker.handle_organise_block_event(share_t).await.unwrap();

        assert!(
            !worker.pending_blocks.contains_key(&7),
            "dependent buffered under an intermediate confirmed height must be drained"
        );
    }

    /// A StoreAccess validation failure with a valid parent is fatal (data that
    /// must exist could not be read -- corruption or a bug). The block must NOT
    /// be marked Invalid, and the worker must stop with an error rather than
    /// silently diverge.
    #[tokio::test]
    async fn test_organise_worker_fatal_on_store_access_validation_error() {
        let (organise_tx, organise_rx) = create_organise_channel();
        let mut mock_chain_handle = MockChainStoreHandle::new();
        mock_chain_handle
            .expect_clone()
            .return_once(MockChainStoreHandle::new);
        // Parent is valid and the block is in the PPLNS zone, so validation runs.
        mock_chain_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(10),
                    chain_work: bitcoin::Work::from_be_bytes([0u8; 32]),
                    status: Status::BlockValid,
                    chain: ChainMembership::Confirmed,
                })
            });
        mock_chain_handle
            .expect_get_candidate_tip_height()
            .returning(|| Ok(Some(10)));
        // Must not mark Invalid/BlockValid, must not promote.
        mock_chain_handle.expect_mark_invalid().never();
        mock_chain_handle.expect_mark_block_valid().never();
        mock_chain_handle.expect_promote_block().never();

        let mut mock_validator = MockDefaultShareValidator::new();
        mock_validator
            .expect_validate_with_chain_context()
            .returning(|_, _, _| Err(ValidationError::store_access("store read failed")));
        let share_validator: Arc<dyn ShareValidator + Send + Sync> = Arc::new(mock_validator);

        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let (notify_tx, _notify_rx) = create_test_notify_channel();
        let worker = OrganiseWorker::new(
            organise_rx,
            mock_chain_handle,
            monitoring_tx,
            notify_tx,
            create_test_metrics_handle(),
            create_test_pplns_window(),
            share_validator,
        );

        let share = TestShareBlockBuilder::new().nonce(0xe9695791).build();
        organise_tx.send(OrganiseEvent::Block(share)).await.unwrap();
        drop(organise_tx);

        let result = worker.run().await;
        assert!(
            result.is_err(),
            "a store error with a valid parent must be fatal"
        );
    }
}
