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

//! Incremental PPLNS window cache for share chain payout computation.
//!
//! `PplnsWindow` caches confirmed share headers and their uncle data,
//! allowing incremental updates (loading only newly confirmed headers)
//! instead of re-reading the full window from RocksDB on every notify.

use super::address_keys::AddressKeys;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::chain::chain_store_handle::ConfirmedHeaderResult;
use crate::shares::share_block::ShareHeader;
use bitcoin::Address;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use tracing::debug;

/// Maximum number of confirmed shares in the PPLNS window.
/// At 6 shares per minute over 2 weeks: 6 * 60 * 24 * 14 = 120,960.
pub const MAX_PPLNS_WINDOW_SHARES: usize = 120960;

/// Divisor for the retained eviction buffer beyond the window: the cache
/// keeps the window plus `window / PPLNS_WINDOW_BUFFER_DIVISOR` extra shares
/// (1%, rounded up) so the distribution for an anchor slightly behind the
/// tip -- e.g. a sibling's parent after a competing sibling advanced the tip
/// -- is not truncated by eviction. Sized to cover realistic anchor offsets
/// (siblings, shallow forks) at negligible memory cost.
const PPLNS_WINDOW_BUFFER_DIVISOR: usize = 100;

/// Number of blocks from the chain tip that must be retained by each node.
/// Equals 2x the PPLNS window: one window for full tx validation and one
/// window for PoW-only validation that provides output availability.
pub const PRUNE_DEPTH: usize = 2 * MAX_PPLNS_WINDOW_SHARES;

/// Pruning runs every PRUNE_INTERVAL blocks (approximately 1 hour at
/// 10s/block: 60 * 6 = 360).
pub const PRUNE_INTERVAL: usize = 360;

/// Scale factor applied to all difficulty contributions.
/// Allows integer representation of 90%/10% uncle/nephew weighting.
pub(crate) const DIFFICULTY_SCALE: u128 = 10;

/// Scaled uncle weight: uncle contributes 9/10 of its difficulty.
pub(crate) const UNCLE_SCALED_WEIGHT: u128 = 9;

/// Scaled nephew bonus: nephew receives 1/10 of each uncle's difficulty.
pub(crate) const NEPHEW_SCALED_BONUS: u128 = 1;

/// Maximum depth to search for the fork point before falling back to
/// full invalidation. Limits the cost of `find_fork_height` to at most
/// this many RocksDB point lookups. A malicious miner forking from deep
/// in the window would otherwise force O(window_size) lookups.
const MAX_REORG_SCAN_DEPTH: usize = 100;

/// Initial capacity for the confirmed entries vector.
/// Based on typical PPLNS window of ~6 hours (6 shares/min * 60 * 6).
const INITIAL_ENTRIES_CAPACITY: usize = 2160;

/// A cached confirmed share entry with only the fields needed for payout.
struct ConfirmedEntry {
    blockhash: BlockHash,
    /// Confirmed chain height of this entry.
    height: u32,
    /// Internal key mapping the miner address in AddressKeys.
    internal_key: usize,
    /// Difficulty of the share
    difficulty: u128,
    /// Uncle entries, if any, referenced by the share
    uncle_entries: Vec<UncleEntry>,
    /// Total scaled weighted difficulty this entry contributes to the aggregate.
    /// Equals difficulty * DIFFICULTY_SCALE + nephew_bonus + uncle_weighted_sum.
    total_weighted_difficulty: u128,
}

/// Why accumulating the window stopped.
///
/// The first two are properties of the chain, so every node reaches them at
/// the same point. `OutOfEntries` is not: it means the cache ran out, and where
/// the cache ends depends on this node's own confirmed tip.
#[derive(Debug, PartialEq, Eq)]
enum WindowStopReason {
    /// The share difficulty threshold was reached.
    ThresholdMet,
    /// `max_window_shares` shares were counted, starting at the anchor.
    WindowFull,
    /// The walk consumed every entry available to it.
    OutOfEntries,
}

/// A cached uncle entry with only the fields needed for payout.
struct UncleEntry {
    /// Internal key mapping the miner address in AddressKeys.
    internal_key: usize,
    /// Base difficulty of the uncle share before weighting.
    difficulty: u128,
}

/// Candidate headers collected while walking backward from the anchor to a
/// confirmed ancestor (newest-to-oldest), paired with that ancestor's index
/// in `confirmed_entries`.
type CandidateWalk = (Vec<(BlockHash, ShareHeader)>, usize);

/// Incremental PPLNS window cache.
///
/// Caches confirmed share headers and uncle data from the share chain,
/// allowing incremental loading of only newly confirmed headers on each
/// update rather than re-reading the full window from RocksDB.
///
/// Caches MAX_PPLNS_WINDOW_SHARES number of confirmed entries and
/// their uncles, no matter how far back in time we need to go to get
/// to those many entries. This simplifies eviction and the cache
/// maintenance logic.
pub struct PplnsWindow {
    /// Confirmed share entries ordered newest-to-oldest, capped by both
    /// MAX_PPLNS_WINDOW_SHARES and the total_difficulty threshold.
    confirmed_entries: VecDeque<ConfirmedEntry>,
    /// The blockhash of the chain tip when this cache was last updated.
    cached_tip_blockhash: Option<BlockHash>,
    /// The height of the highest confirmed share in the cache.
    cached_top_height: Option<u32>,
    /// Sum of all confirmed entries' scaled weighted difficulties in the window.
    total_accumulated_difficulty: u128,
    /// Address internal key mapping
    address_keys: AddressKeys,
    /// Bitcoin network used for computing integer difficulty from Target.
    pub(crate) network: bitcoin::Network,
    /// Maximum confirmed entries retained before eviction. Defaults to
    /// `MAX_PPLNS_WINDOW_SHARES`; overridable in tests so eviction can be
    /// exercised without a full-capacity fixture.
    max_window_shares: usize,
}

impl PplnsWindow {
    /// Create an empty PplnsWindow with preallocated capacity.
    pub fn new(network: bitcoin::Network) -> Self {
        Self {
            confirmed_entries: VecDeque::with_capacity(INITIAL_ENTRIES_CAPACITY),
            cached_tip_blockhash: None,
            cached_top_height: None,
            total_accumulated_difficulty: 0,
            address_keys: AddressKeys::default(),
            network,
            max_window_shares: MAX_PPLNS_WINDOW_SHARES,
        }
    }

    /// Test-only constructor with an injectable eviction cap, so the
    /// eviction path can be driven without building a
    /// `MAX_PPLNS_WINDOW_SHARES`-sized fixture.
    #[cfg(test)]
    pub(super) fn new_with_max_window_shares(
        network: bitcoin::Network,
        max_window_shares: usize,
    ) -> Self {
        let mut window = Self::new(network);
        window.max_window_shares = max_window_shares;
        window
    }
}

impl PplnsWindow {
    /// Check whether the cache has any confirmed entries.
    pub fn is_empty(&self) -> bool {
        self.confirmed_entries.is_empty()
    }

    /// Return the bitcoin network this window was created for.
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// Read-only payout distribution starting from a given blockhash.
    ///
    /// Walks backward from start_hash through parent pointers until
    /// finding a confirmed entry in the window. Candidate entries
    /// along the walk contribute to the distribution first, then
    /// confirmed entries from that entry point onward.
    ///
    /// When start_hash is already in the confirmed entries, no store
    /// reads are needed and the walk produces zero candidate entries.
    ///
    /// The walk stops at the difficulty threshold or after `max_window_shares`
    /// shares. The count starts at the anchor -- `start_hash`, the share's
    /// declared parent -- and spans the unconfirmed shares back to the
    /// confirmed chain before continuing into confirmed entries: candidate
    /// shares contribute to the payout, so they consume the same window budget
    /// as confirmed ones. Both bounds are properties of the chain, so every
    /// node derives the same distribution for the same anchor whatever its own
    /// confirmed tip -- which is the point: the producer and a validator that
    /// has since advanced must reconstruct an identical coinbase.
    ///
    /// Errors when `start_hash` cannot be resolved to a confirmed ancestor
    /// (e.g. an anchor whose ancestry is not stored) or when a store read
    /// fails, so callers fail rather than silently treat an unresolved
    /// anchor or a transient read error as an empty distribution. The
    /// explicit empty/genesis case is handled by callers before this call
    /// (they check `is_empty`).
    ///
    /// Also errors when the walk exhausts the cache without reaching either
    /// bound and the cache no longer reaches the chain start. The result would
    /// then depend on where eviction has trimmed the back, which is a function
    /// of this node's tip rather than of the chain, so a truncated distribution
    /// is refused rather than returned.
    pub fn get_distribution_from_start_hash(
        &mut self,
        total_difficulty: u128,
        start_hash: BlockHash,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<HashMap<Address, u128>, Box<dyn Error + Send + Sync>> {
        let (candidate_entries, confirmed_start_index) =
            self.resolve_start_hash(start_hash, chain_store_handle)?;

        let scaled_threshold = total_difficulty.saturating_mul(DIFFICULTY_SCALE);
        let mut difficulty_by_key = vec![0u128; self.address_keys.len()];
        let mut accumulated_difficulty: u128 = 0;
        let mut shares_remaining = self.max_window_shares;

        let candidate_stop_reason = Self::accumulate_candidate_difficulty(
            &candidate_entries,
            &mut difficulty_by_key,
            &mut accumulated_difficulty,
            scaled_threshold,
            &mut shares_remaining,
        );

        let stop_reason = match candidate_stop_reason {
            Some(reason) => reason,
            // Budget left over from the candidate shares carries into the
            // confirmed entries, starting at the confirmed entry point.
            None => self.accumulate_confirmed_difficulty(
                &mut difficulty_by_key,
                &mut accumulated_difficulty,
                scaled_threshold,
                confirmed_start_index,
                shares_remaining,
            ),
        };

        if stop_reason == WindowStopReason::OutOfEntries && !self.reaches_chain_start() {
            return Err(format!(
                "PPLNS window for anchor {start_hash} is truncated by eviction: the walk ran \
                 out of cached entries at height {}, short of both the difficulty threshold \
                 and {} shares",
                self.confirmed_entries
                    .back()
                    .map_or(0, |entry| entry.height),
                self.max_window_shares,
            )
            .into());
        }

        Ok(self.collect_distribution(&difficulty_by_key))
    }

    /// Whether the oldest cached entry is the first block of the chain, so a
    /// walk that consumes every cached entry has covered the whole chain and
    /// is the same on every node.
    ///
    /// Once eviction has trimmed the back, the earliest cached height depends
    /// on this node's own confirmed tip, so a walk that reaches it would give
    /// a different answer on a node at a different tip.
    fn reaches_chain_start(&self) -> bool {
        self.confirmed_entries
            .back()
            .is_none_or(|entry| entry.height == 0)
    }

    /// Resolve the anchor to its candidate entries and confirmed entry point.
    ///
    /// If start_hash is in confirmed_entries, returns empty candidate
    /// entries and the confirmed index. Otherwise walks backward through
    /// parent pointers in the store, building candidate entries until a
    /// confirmed ancestor is found. Errors when no confirmed ancestor is
    /// reachable or a store read fails.
    fn resolve_start_hash(
        &mut self,
        start_hash: BlockHash,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(Vec<ConfirmedEntry>, usize), Box<dyn Error + Send + Sync>> {
        if let Some(confirmed_index) = self.find_start_index(start_hash) {
            return Ok((Vec::new(), confirmed_index));
        }

        let (candidate_headers, confirmed_index) =
            self.collect_candidate_headers(start_hash, chain_store_handle)?;
        let candidate_entries =
            self.build_entries_from_headers(&candidate_headers, chain_store_handle)?;
        Ok((candidate_entries, confirmed_index))
    }

    /// Walk backward from start_hash through parent pointers until
    /// finding a block whose parent is in the confirmed entries.
    /// Returns the collected headers (newest-to-oldest) and the
    /// index of the confirmed entry point the walk lands on.
    ///
    /// The returned headers begin with `start_hash` itself, so the anchor
    /// share is part of the window and consumes window budget like any other.
    ///
    /// The walk follows parent links regardless of validation `status`: the
    /// payout must be a pure function of the chain shape (headers), not of
    /// per-node, timing-dependent validation state, or the producer and a
    /// validator computing the window at different moments would derive
    /// different distributions.
    ///
    /// Errors when the walk runs off the end of the stored chain without
    /// reaching a confirmed ancestor (`get_share_header` returns
    /// `NotFound`: the anchor is unresolvable) or when any store read
    /// fails; both propagate so an unresolvable anchor or a transient read
    /// failure is never mistaken for an empty distribution.
    fn collect_candidate_headers(
        &self,
        start_hash: BlockHash,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<CandidateWalk, Box<dyn Error + Send + Sync>> {
        const INITIAL_CAPACITY: usize = 8;
        let mut candidate_headers = Vec::with_capacity(INITIAL_CAPACITY);
        let mut current_hash = start_hash;
        let mut confirmed_index = None;

        while confirmed_index.is_none() {
            let header = chain_store_handle.get_share_header(&current_hash)?;
            let parent_hash = header.prev_share_blockhash;
            candidate_headers.push((current_hash, header));
            current_hash = parent_hash;
            confirmed_index = self.find_start_index(current_hash);
        }

        match confirmed_index {
            Some(index) => Ok((candidate_headers, index)),
            None => Err("walk ended without reaching a confirmed ancestor".into()),
        }
    }

    /// Convert collected candidate headers into ConfirmedEntry values
    /// by resolving their difficulty and uncle data from the store.
    fn build_entries_from_headers(
        &mut self,
        candidate_headers: &[(BlockHash, ShareHeader)],
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<Vec<ConfirmedEntry>, Box<dyn Error + Send + Sync>> {
        let all_uncle_hashes: Vec<BlockHash> = candidate_headers
            .iter()
            .flat_map(|(_, header)| header.uncles.iter().copied())
            .collect();
        let uncle_lookup_table =
            self.build_uncle_entry_lookup_table(chain_store_handle, &all_uncle_hashes)?;

        let entries = candidate_headers
            .iter()
            .map(|(blockhash, header)| {
                let difficulty = header.get_difficulty(self.network);
                let uncle_entries = resolve_uncle_entries(&header.uncles, &uncle_lookup_table);
                self.build_confirmed_entry(
                    *blockhash,
                    0,
                    header.miner_bitcoin_address.clone(),
                    difficulty,
                    uncle_entries,
                )
            })
            .collect();

        Ok(entries)
    }

    /// Find the index of the entry matching the given blockhash.
    /// Returns `None` when the hash is not found in the window.
    fn find_start_index(&self, start_hash: BlockHash) -> Option<usize> {
        self.confirmed_entries
            .iter()
            .position(|entry| entry.blockhash == start_hash)
    }

    /// Walk candidate entries -- the anchor share and the unconfirmed shares
    /// below it -- accumulating difficulty per address.
    ///
    /// Consumes one share of `shares_remaining` per entry, so what is left for
    /// the confirmed entries is the window budget minus the candidate shares.
    /// Returns the reason the walk stopped, or `None` when the entries ran out
    /// with budget and threshold both still unspent, which means the caller
    /// should continue into the confirmed entries.
    fn accumulate_candidate_difficulty(
        candidate_entries: &[ConfirmedEntry],
        difficulty_by_key: &mut [u128],
        accumulated_difficulty: &mut u128,
        scaled_threshold: u128,
        shares_remaining: &mut usize,
    ) -> Option<WindowStopReason> {
        for entry in candidate_entries {
            if *shares_remaining == 0 {
                return Some(WindowStopReason::WindowFull);
            }
            *shares_remaining -= 1;
            let mut nephew_bonus: u128 = 0;
            for uncle_entry in &entry.uncle_entries {
                difficulty_by_key[uncle_entry.internal_key] = difficulty_by_key
                    [uncle_entry.internal_key]
                    .saturating_add(uncle_entry.difficulty.saturating_mul(UNCLE_SCALED_WEIGHT));
                nephew_bonus = nephew_bonus
                    .saturating_add(uncle_entry.difficulty.saturating_mul(NEPHEW_SCALED_BONUS));
            }

            difficulty_by_key[entry.internal_key] = difficulty_by_key[entry.internal_key]
                .saturating_add(
                    entry
                        .difficulty
                        .saturating_mul(DIFFICULTY_SCALE)
                        .saturating_add(nephew_bonus),
                );
            *accumulated_difficulty =
                accumulated_difficulty.saturating_add(entry.total_weighted_difficulty);

            if *accumulated_difficulty >= scaled_threshold {
                return Some(WindowStopReason::ThresholdMet);
            }
        }
        None
    }

    /// Walk confirmed entries from the confirmed entry point, accumulating
    /// difficulty per address until the threshold is met or `shares_remaining`
    /// -- the window budget left after the candidate shares -- runs out.
    ///
    /// Returns the reason the walk stopped. `OutOfEntries` means the cache
    /// itself ran out, which is the one stop reason that is not a property of
    /// the chain: the caller must check whether eviction has trimmed the back
    /// before trusting the result.
    fn accumulate_confirmed_difficulty(
        &self,
        difficulty_by_key: &mut [u128],
        accumulated_difficulty: &mut u128,
        scaled_threshold: u128,
        start_index: usize,
        shares_remaining: usize,
    ) -> WindowStopReason {
        let mut consumed = 0;
        for entry in self
            .confirmed_entries
            .iter()
            .skip(start_index)
            .take(shares_remaining)
        {
            consumed += 1;
            let mut nephew_bonus: u128 = 0;

            for uncle_entry in &entry.uncle_entries {
                difficulty_by_key[uncle_entry.internal_key] = difficulty_by_key
                    [uncle_entry.internal_key]
                    .saturating_add(uncle_entry.difficulty.saturating_mul(UNCLE_SCALED_WEIGHT));
                nephew_bonus = nephew_bonus
                    .saturating_add(uncle_entry.difficulty.saturating_mul(NEPHEW_SCALED_BONUS));
            }

            difficulty_by_key[entry.internal_key] = difficulty_by_key[entry.internal_key]
                .saturating_add(
                    entry
                        .difficulty
                        .saturating_mul(DIFFICULTY_SCALE)
                        .saturating_add(nephew_bonus),
                );
            *accumulated_difficulty =
                accumulated_difficulty.saturating_add(entry.total_weighted_difficulty);

            if *accumulated_difficulty >= scaled_threshold {
                return WindowStopReason::ThresholdMet;
            }
        }

        // Distinguish "counted a full window" from "the cache ran out": only
        // the latter depends on where eviction trimmed the back.
        if consumed == shares_remaining {
            WindowStopReason::WindowFull
        } else {
            WindowStopReason::OutOfEntries
        }
    }

    /// Free address-key slots no longer referenced by any cached entry.
    ///
    /// A miner address is retained while it appears as a share miner or an
    /// uncle miner in any `confirmed_entries` slot (including the overflow
    /// region past `total_difficulty`, since those entries stay cached).
    /// Once its last referencing entry leaves the cache -- via eviction or a
    /// reorg -- the slot is freed so the `AddressKeys` interner stays bounded
    /// and its linear `key_for` scan does not grow without bound. Runs after
    /// eviction in `update`; replaces the stale-key cleanup that the removed
    /// tip-anchored `get_distribution` performed inline.
    fn prune_unreferenced_keys(&mut self) {
        let mut referenced = vec![false; self.address_keys.len()];
        for entry in &self.confirmed_entries {
            referenced[entry.internal_key] = true;
            for uncle_entry in &entry.uncle_entries {
                referenced[uncle_entry.internal_key] = true;
            }
        }
        for (index, is_referenced) in referenced.iter().enumerate() {
            if !is_referenced {
                self.address_keys.remove(index);
            }
        }
    }

    /// Convert the Vec-based difficulty accumulation into a HashMap<Address, u128>.
    fn collect_distribution(&self, difficulty_by_key: &[u128]) -> HashMap<Address, u128> {
        let mut result = HashMap::with_capacity(difficulty_by_key.len());
        for (index, difficulty) in difficulty_by_key.iter().enumerate() {
            if *difficulty > 0
                && let Some(address) = self.address_keys.value_for(index)
            {
                result.insert(address.clone(), *difficulty);
            }
        }
        result
    }

    /// Update the cache from the chain store incrementally.
    ///
    /// Loads only newly confirmed headers since the last cached height,
    /// handles reorgs by removing only the divergent entries and loading
    /// the new fork, and evicts overflow entries that exceed either
    /// MAX_PPLNS_WINDOW_SHARES
    ///
    /// Returns Ok(true) if the cache was updated, Ok(false) if no changes.
    pub fn update(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let tip_blockhash = chain_store_handle.get_chain_tip()?;

        if self.cached_tip_blockhash == Some(tip_blockhash) {
            return Ok(false);
        }

        let tip_metadata = chain_store_handle.get_block_metadata(&tip_blockhash)?;
        let Some(tip_height) = tip_metadata.expected_height else {
            return Ok(false);
        };

        if let Some(cached_height) = self.cached_top_height {
            let is_simple_extension =
                self.is_simple_extension(cached_height, tip_height, chain_store_handle)?;

            if is_simple_extension {
                self.load_range(chain_store_handle, cached_height + 1, tip_height)?;
            } else {
                self.handle_reorg(chain_store_handle, tip_height)?;
            }
        } else {
            // no cached top height, first load
            let estimated_min_height = tip_height.saturating_sub(self.cache_capacity() as u32);
            self.load_range(chain_store_handle, estimated_min_height, tip_height)?;
        }

        self.evict_overflow();
        self.prune_unreferenced_keys();
        self.cached_tip_blockhash = Some(tip_blockhash);
        self.cached_top_height = Some(tip_height);

        Ok(true)
    }

    /// Check whether the new tip is a simple extension of the cached chain.
    ///
    /// Returns true when the tip is higher than the cached height and the
    /// confirmed blockhash at the cached height still matches the front
    /// entry in the cache.
    fn is_simple_extension(
        &self,
        cached_height: u32,
        tip_height: u32,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        if tip_height <= cached_height {
            return Ok(false);
        }

        let confirmed_at_cached = chain_store_handle.get_confirmed_at_height(cached_height)?;
        match self.confirmed_entries.front() {
            Some(entry) if entry.blockhash == confirmed_at_cached => Ok(true),
            _ => Ok(false),
        }
    }

    /// Handle a reorg by finding the fork point and doing targeted removal
    /// and reload. Falls back to full invalidation for deep reorgs.
    fn handle_reorg(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        tip_height: u32,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self.find_fork_height(chain_store_handle)? {
            Some(fork_height) => {
                debug!("Reorg detected in PPLNS window, rolling back to fork height {fork_height}");
                self.remove_entries_above_height(fork_height);
                self.cached_top_height = Some(fork_height);
                self.load_range(chain_store_handle, fork_height + 1, tip_height)?;
            }
            None => {
                debug!("Deep reorg detected in PPLNS window, full cache invalidation");
                self.invalidate();
                let estimated_min_height = tip_height.saturating_sub(self.cache_capacity() as u32);
                self.load_range(chain_store_handle, estimated_min_height, tip_height)?;
            }
        }
        Ok(())
    }

    /// Clear all cached state, forcing a full reload on next update.
    fn invalidate(&mut self) {
        self.confirmed_entries.clear();
        self.total_accumulated_difficulty = 0;
        self.cached_tip_blockhash = None;
        self.cached_top_height = None;
    }

    /// Find the fork height by walking cached entries from newest to oldest.
    ///
    /// Checks at most MAX_REORG_SCAN_DEPTH entries to bound the cost of
    /// deep reorgs. Returns the height of the first cached entry whose
    /// blockhash still matches the confirmed chain (the fork point), or
    /// None if no match is found within the scan limit.
    fn find_fork_height(
        &self,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<Option<u32>, Box<dyn Error + Send + Sync>> {
        let scan_limit = MAX_REORG_SCAN_DEPTH.min(self.confirmed_entries.len());

        for index in 0..scan_limit {
            let entry = &self.confirmed_entries[index];
            let confirmed_hash = chain_store_handle.get_confirmed_at_height(entry.height);

            match confirmed_hash {
                Ok(hash) if hash == entry.blockhash => return Ok(Some(entry.height)),
                _ => {}
            }
        }

        Ok(None)
    }

    /// Remove all cached entries with height strictly above the fork height.
    ///
    /// Pops entries from the front of the deque (newest first) and
    /// subtracts their contributions from the aggregate, until the
    /// front entry's height equals the fork height.
    fn remove_entries_above_height(&mut self, fork_height: u32) {
        while let Some(front) = self.confirmed_entries.front() {
            if front.height <= fork_height {
                return;
            }
            if let Some(entry) = self.confirmed_entries.pop_front() {
                self.remove_from_running_total(&entry);
            }
        }
    }

    /// Load confirmed headers for a height range and add them to the cache.
    ///
    /// Fetches headers from the chain store, resolves uncle data, builds
    /// confirmed entries, and adds each entry's contributions to the
    /// incremental aggregate. New entries are prepended (newest at front).
    fn load_range(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        from_height: u32,
        to_height: u32,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let confirmed_headers =
            chain_store_handle.get_confirmed_headers_in_range(from_height, to_height)?;

        if confirmed_headers.is_empty() {
            return Ok(());
        }

        let all_uncle_hashes = collect_unique_uncle_hashes(&confirmed_headers);
        let uncle_lookup_table =
            self.build_uncle_entry_lookup_table(chain_store_handle, &all_uncle_hashes)?;

        // Headers arrive newest-to-oldest. Reverse to oldest-first so
        // the newest entry ends up at position 0 in the deque after push_front.
        for ConfirmedHeaderResult {
            height,
            blockhash,
            header,
        } in confirmed_headers.into_iter().rev()
        {
            let difficulty = header.get_difficulty(self.network);
            let uncle_entries = resolve_uncle_entries(&header.uncles, &uncle_lookup_table);
            let entry = self.build_confirmed_entry(
                blockhash,
                height,
                header.miner_bitcoin_address,
                difficulty,
                uncle_entries,
            );
            self.add_to_running_total(&entry);
            self.confirmed_entries.push_front(entry);
        }

        Ok(())
    }

    /// Add a confirmed entry's weighted difficulty to the running total.
    fn add_to_running_total(&mut self, entry: &ConfirmedEntry) {
        self.total_accumulated_difficulty = self
            .total_accumulated_difficulty
            .saturating_add(entry.total_weighted_difficulty);
    }

    /// Remove a confirmed entry's weighted difficulty from the running total.
    fn remove_from_running_total(&mut self, entry: &ConfirmedEntry) {
        self.total_accumulated_difficulty = self
            .total_accumulated_difficulty
            .saturating_sub(entry.total_weighted_difficulty);
    }

    /// Total confirmed entries the cache loads and retains: the window cap
    /// plus a ~1% buffer (see `PPLNS_WINDOW_BUFFER_DIVISOR`) so an anchor
    /// slightly behind the tip still has its full window available.
    ///
    /// The buffer is therefore the supported anchor depth: an anchor at most
    /// `max_window_shares / PPLNS_WINDOW_BUFFER_DIVISOR` entries behind the tip
    /// still has `max_window_shares` entries cached below it, which is what
    /// `get_distribution_from_start_hash` needs to apply its count bound. A
    /// deeper anchor is reported as an error rather than silently truncated.
    fn cache_capacity(&self) -> usize {
        self.max_window_shares + self.max_window_shares.div_ceil(PPLNS_WINDOW_BUFFER_DIVISOR)
    }

    /// Trim the oldest confirmed entries down to `cache_capacity`.
    ///
    /// This bounds memory only. It must not be what bounds a window query:
    /// the back of the deque moves as this node's tip advances, so a walk that
    /// stopped there would give different answers on different nodes. Query
    /// bounds live in `get_distribution_from_start_hash`, which counts from the
    /// anchor and refuses a result that ran into an evicted back.
    fn evict_overflow(&mut self) {
        while self.confirmed_entries.len() > self.cache_capacity() {
            if let Some(entry) = self.confirmed_entries.pop_back() {
                self.remove_from_running_total(&entry);
            } else {
                return;
            }
        }
    }

    /// Build a ConfirmedEntry, resolving the miner address to an internal key.
    fn build_confirmed_entry(
        &mut self,
        blockhash: BlockHash,
        height: u32,
        miner_address: Address,
        difficulty: u128,
        uncle_entries: Vec<UncleEntry>,
    ) -> ConfirmedEntry {
        let internal_key = self.address_keys.key_for(miner_address);

        let mut nephew_bonus: u128 = 0;
        let mut uncle_weighted_sum: u128 = 0;
        for uncle_entry in &uncle_entries {
            uncle_weighted_sum = uncle_weighted_sum
                .saturating_add(uncle_entry.difficulty.saturating_mul(UNCLE_SCALED_WEIGHT));
            nephew_bonus = nephew_bonus
                .saturating_add(uncle_entry.difficulty.saturating_mul(NEPHEW_SCALED_BONUS));
        }
        let total_weighted_difficulty = difficulty
            .saturating_mul(DIFFICULTY_SCALE)
            .saturating_add(nephew_bonus)
            .saturating_add(uncle_weighted_sum);

        ConfirmedEntry {
            blockhash,
            height,
            difficulty,
            uncle_entries,
            total_weighted_difficulty,
            internal_key,
        }
    }

    /// Build an UncleEntry, resolving the miner address to an internal key.
    fn build_uncle_entry(&mut self, miner_address: Address, difficulty: u128) -> UncleEntry {
        let internal_key = self.address_keys.key_for(miner_address);
        UncleEntry {
            internal_key,
            difficulty,
        }
    }

    /// Build uncle entries and return a hashmap of uncle block hash
    /// -> uncle entry.
    /// The uncle headers are queried in a batch header query.
    fn build_uncle_entry_lookup_table(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        uncle_hashes: &[BlockHash],
    ) -> Result<HashMap<BlockHash, UncleEntry>, Box<dyn Error + Send + Sync>> {
        if uncle_hashes.is_empty() {
            return Ok(HashMap::new());
        }

        let uncle_headers = chain_store_handle.get_share_headers(uncle_hashes)?;
        let mut uncle_lookup = HashMap::with_capacity(uncle_headers.len());
        for (blockhash, header) in uncle_headers {
            let difficulty = header.get_difficulty(self.network);
            let uncle_entry = self.build_uncle_entry(header.miner_bitcoin_address, difficulty);
            uncle_lookup.insert(blockhash, uncle_entry);
        }
        Ok(uncle_lookup)
    }
}

/// Collect unique uncle blockhashes from confirmed headers for batch fetching.
fn collect_unique_uncle_hashes(confirmed_headers: &[ConfirmedHeaderResult]) -> Vec<BlockHash> {
    let mut seen_uncles: HashSet<BlockHash> = HashSet::new();
    let mut all_uncle_hashes = Vec::with_capacity(confirmed_headers.len());

    for result in confirmed_headers {
        let header = &result.header;
        for uncle_hash in &header.uncles {
            if seen_uncles.insert(*uncle_hash) {
                all_uncle_hashes.push(*uncle_hash);
            }
        }
    }

    all_uncle_hashes
}

/// Resolve uncle hashes into UncleEntry values using a pre-built lookup table.
fn resolve_uncle_entries(
    uncle_hashes: &[BlockHash],
    uncle_lookup: &HashMap<BlockHash, UncleEntry>,
) -> Vec<UncleEntry> {
    let mut entries = Vec::with_capacity(uncle_hashes.len());
    for uncle_hash in uncle_hashes {
        if let Some(uncle_entry) = uncle_lookup.get(uncle_hash) {
            entries.push(UncleEntry {
                difficulty: uncle_entry.difficulty,
                internal_key: uncle_entry.internal_key,
            });
        } else {
            tracing::warn!("Uncle header not found for {uncle_hash}, skipping");
        }
    }
    entries
}

#[cfg(any(test, feature = "test-utils"))]
impl PplnsWindow {
    /// Populate the window cache directly for benchmarking.
    ///
    /// Accepts confirmed shares and uncles as tuples of primitives,
    /// bypassing the chain store. Confirmed shares should be ordered
    /// newest-to-oldest. Uncle data is provided as (miner_address_string, difficulty).
    #[allow(clippy::type_complexity)] // benchmark-only shim: tuples mirror the store rows verbatim
    pub fn populate_for_benchmark(
        &mut self,
        confirmed_shares: Vec<(BlockHash, String, u128, Vec<(String, u128)>)>,
    ) {
        self.invalidate();
        self.confirmed_entries.reserve(confirmed_shares.len());

        let total_count = confirmed_shares.len() as u32;
        for (index, (blockhash, miner_address_string, difficulty, uncle_data)) in
            confirmed_shares.into_iter().enumerate()
        {
            let mut uncle_entries = Vec::with_capacity(uncle_data.len());
            for (uncle_miner_string, uncle_difficulty) in uncle_data {
                let uncle_miner = uncle_miner_string
                    .parse::<bitcoin::Address<_>>()
                    .unwrap()
                    .assume_checked();
                uncle_entries.push(self.build_uncle_entry(uncle_miner, uncle_difficulty));
            }

            let miner_address = miner_address_string
                .parse::<bitcoin::Address<_>>()
                .unwrap()
                .assume_checked();
            let height = total_count - 1 - index as u32;
            let entry = self.build_confirmed_entry(
                blockhash,
                height,
                miner_address,
                difficulty,
                uncle_entries,
            );
            self.add_to_running_total(&entry);
            self.confirmed_entries.push_back(entry);
        }

        if let Some(entry) = self.confirmed_entries.front() {
            self.cached_tip_blockhash = Some(entry.blockhash);
        }
        self.cached_top_height = Some(total_count.saturating_sub(1));
        eprintln!("  populated {} in window", self.confirmed_entries.len());
    }

    /// Expose the stale-key sweep for benchmarking. In production this runs
    /// only as an internal step of `update` after eviction.
    pub fn prune_unreferenced_keys_for_benchmark(&mut self) {
        self.prune_unreferenced_keys();
    }
}

#[cfg(test)]
mockall::mock! {
    pub PplnsWindow {
        pub fn new(network: bitcoin::Network) -> Self;
        pub fn network(&self) -> bitcoin::Network;
        pub fn update(
            &mut self,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;
        pub fn get_distribution_from_start_hash(
            &mut self,
            total_difficulty: u128,
            start_hash: BlockHash,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<HashMap<Address, u128>, Box<dyn std::error::Error + Send + Sync>>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::shares::share_block::ShareHeader;
    use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership, Status};
    use crate::test_utils::{
        PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_5G, PUBKEY_G, build_test_header,
        build_test_header_with_uncles,
    };
    use bitcoin::Work;
    use bitcoin::hashes::Hash;

    /// Network used for test difficulty calculations.
    const TEST_NETWORK: bitcoin::Network = bitcoin::Network::Signet;

    /// Create a ConfirmedEntry from a ShareHeader with no uncles.
    fn entry_from_header(
        window: &mut PplnsWindow,
        header: &ShareHeader,
        height: u32,
    ) -> ConfirmedEntry {
        window.build_confirmed_entry(
            header.block_hash(),
            height,
            header.miner_bitcoin_address.clone(),
            header.get_difficulty(TEST_NETWORK),
            Vec::new(),
        )
    }

    /// Create a ConfirmedEntry from a ShareHeader with resolved uncle entries.
    fn entry_from_header_with_uncles(
        window: &mut PplnsWindow,
        header: &ShareHeader,
        height: u32,
        uncle_entries: Vec<UncleEntry>,
    ) -> ConfirmedEntry {
        window.build_confirmed_entry(
            header.block_hash(),
            height,
            header.miner_bitcoin_address.clone(),
            header.get_difficulty(TEST_NETWORK),
            uncle_entries,
        )
    }

    /// Create an UncleEntry from a ShareHeader for test setup.
    fn uncle_entry_from_header(window: &mut PplnsWindow, header: &ShareHeader) -> UncleEntry {
        window.build_uncle_entry(
            header.miner_bitcoin_address.clone(),
            header.get_difficulty(TEST_NETWORK),
        )
    }

    /// Create a BlockMetadata with the given height and Confirmed status.
    fn metadata_at_height(height: u32) -> BlockMetadata {
        BlockMetadata {
            expected_height: Some(height),
            chain_work: Work::from_le_bytes([0u8; 32]),
            status: Status::BlockValid,
            chain: ChainMembership::Confirmed,
        }
    }

    /// Create a BlockMetadata with no height (empty chain).
    fn metadata_no_height() -> BlockMetadata {
        BlockMetadata {
            expected_height: None,
            chain_work: Work::from_le_bytes([0u8; 32]),
            status: Status::BlockValid,
            chain: ChainMembership::Confirmed,
        }
    }

    /// Build a chain of headers for testing.
    /// Returns (headers_vec, tip_hash) where headers_vec is newest-to-oldest
    /// with heights assigned starting from 0.
    fn build_test_chain(
        count: usize,
        miner_pubkeys: &[&str],
    ) -> (Vec<ConfirmedHeaderResult>, BlockHash) {
        let genesis_hash = BlockHash::all_zeros();
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = genesis_hash.to_string();

        for index in 0..count {
            let pubkey = miner_pubkeys[index % miner_pubkeys.len()];
            let header = build_test_header(&prev_hash, pubkey, 2);
            let blockhash = header.block_hash();
            prev_hash = blockhash.to_string();
            headers.push(ConfirmedHeaderResult {
                height: index as u32,
                blockhash,
                header,
            });
        }

        let tip_hash = headers.last().unwrap().blockhash;
        // Reverse to newest-to-oldest
        headers.reverse();
        (headers, tip_hash)
    }

    #[test]
    fn test_initial_full_load() {
        let (headers, tip_hash) = build_test_chain(5, &[PUBKEY_G, PUBKEY_2G]);

        let mut mock = MockChainStoreHandle::default();
        let headers_clone = headers.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let updated = window.update(&mock).unwrap();

        assert!(updated);
        assert!(!window.is_empty());
        assert_eq!(window.confirmed_entries.len(), 5);
        assert_eq!(window.cached_tip_blockhash, Some(tip_hash));
        assert_eq!(window.cached_top_height, Some(4));

        // All 5 entries have same difficulty (no uncles), total should be 5 * difficulty * DIFFICULTY_SCALE
        let difficulty = headers[0].header.get_difficulty(TEST_NETWORK);
        let expected_total = 5 * difficulty * DIFFICULTY_SCALE;
        assert_eq!(
            window.total_accumulated_difficulty, expected_total,
            "expected total_accumulated_difficulty {expected_total}, got {}",
            window.total_accumulated_difficulty
        );
    }

    #[test]
    fn test_incremental_load_new_shares() {
        let (all_headers, _) = build_test_chain(7, &[PUBKEY_G, PUBKEY_2G]);
        // Initial chain: headers at heights 0-4 (indices 2..7 in all_headers reversed)
        let initial_headers: Vec<ConfirmedHeaderResult> = all_headers[2..].to_vec();
        let initial_tip_hash = initial_headers[0].blockhash;

        // Set up initial load
        let mut mock = MockChainStoreHandle::default();
        let initial_headers_clone = initial_headers.clone();
        mock.expect_get_chain_tip()
            .returning(move || Ok(initial_tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(initial_headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();
        assert_eq!(window.confirmed_entries.len(), 5);

        // Now extend to height 6
        let new_tip_hash = all_headers[0].blockhash;
        let new_headers: Vec<ConfirmedHeaderResult> = all_headers[0..2].to_vec();
        let older_confirmed_tip_header = initial_headers[0].blockhash;

        let mut mock2 = MockChainStoreHandle::default();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(new_tip_hash));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(6)));
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(older_confirmed_tip_header));
        mock2
            .expect_get_confirmed_headers_in_range()
            .withf(|from, to| *from == 5 && *to == 6)
            .returning(move |_, _| Ok(new_headers.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2).unwrap();
        assert!(updated);
        assert_eq!(window.confirmed_entries.len(), 7);
        assert_eq!(window.cached_top_height, Some(6));
    }

    #[test]
    fn test_incremental_load_preserves_newest_first_ordering() {
        // Build a chain of 9 headers (heights 0..8), load in three batches
        // and verify the deque stays in newest-to-oldest order throughout.
        let (all_headers, _) = build_test_chain(9, &[PUBKEY_G, PUBKEY_2G, PUBKEY_3G]);

        // Batch 1: heights 0-2 (indices 6..9 in newest-to-oldest all_headers)
        let batch1: Vec<ConfirmedHeaderResult> = all_headers[6..].to_vec();
        let tip1 = batch1[0].blockhash;

        let mut mock1 = MockChainStoreHandle::default();
        let batch1_clone = batch1.clone();
        mock1.expect_get_chain_tip().returning(move || Ok(tip1));
        mock1
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));
        mock1
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(batch1_clone.clone()));
        mock1
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock1).unwrap();
        assert_eq!(window.confirmed_entries.len(), 3);
        // Deque should be [height2, height1, height0]
        assert_eq!(
            window.confirmed_entries[0].blockhash,
            all_headers[6].blockhash
        );
        assert_eq!(
            window.confirmed_entries[1].blockhash,
            all_headers[7].blockhash
        );
        assert_eq!(
            window.confirmed_entries[2].blockhash,
            all_headers[8].blockhash
        );

        // Batch 2: heights 3-5 (indices 3..6)
        let batch2: Vec<ConfirmedHeaderResult> = all_headers[3..6].to_vec();
        let tip2 = batch2[0].blockhash;
        let confirmed_at_2 = batch1[0].blockhash;

        let mut mock2 = MockChainStoreHandle::default();
        let batch2_clone = batch2.clone();
        mock2.expect_get_chain_tip().returning(move || Ok(tip2));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(5)));
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(confirmed_at_2));
        mock2
            .expect_get_confirmed_headers_in_range()
            .withf(|from, to| *from == 3 && *to == 5)
            .returning(move |_, _| Ok(batch2_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        window.update(&mock2).unwrap();
        assert_eq!(window.confirmed_entries.len(), 6);
        // Deque should be [height5, height4, height3, height2, height1, height0]
        assert_eq!(
            window.confirmed_entries[0].blockhash,
            all_headers[3].blockhash
        );
        assert_eq!(
            window.confirmed_entries[1].blockhash,
            all_headers[4].blockhash
        );
        assert_eq!(
            window.confirmed_entries[2].blockhash,
            all_headers[5].blockhash
        );
        assert_eq!(
            window.confirmed_entries[3].blockhash,
            all_headers[6].blockhash
        );
        assert_eq!(
            window.confirmed_entries[4].blockhash,
            all_headers[7].blockhash
        );
        assert_eq!(
            window.confirmed_entries[5].blockhash,
            all_headers[8].blockhash
        );

        // Batch 3: heights 6-8 (indices 0..3)
        let batch3: Vec<ConfirmedHeaderResult> = all_headers[0..3].to_vec();
        let tip3 = batch3[0].blockhash;
        let confirmed_at_5 = batch2[0].blockhash;

        let mut mock3 = MockChainStoreHandle::default();
        let batch3_clone = batch3.clone();
        mock3.expect_get_chain_tip().returning(move || Ok(tip3));
        mock3
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(8)));
        mock3
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(confirmed_at_5));
        mock3
            .expect_get_confirmed_headers_in_range()
            .withf(|from, to| *from == 6 && *to == 8)
            .returning(move |_, _| Ok(batch3_clone.clone()));
        mock3
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        window.update(&mock3).unwrap();
        assert_eq!(window.confirmed_entries.len(), 9);
        // Full deque: [height8, height7, ..., height0] -- strict newest-to-oldest
        for (index, entry) in window.confirmed_entries.iter().enumerate() {
            assert_eq!(
                entry.blockhash, all_headers[index].blockhash,
                "entry at position {index} has wrong blockhash"
            );
        }
    }

    #[test]
    fn test_no_update_when_tip_unchanged() {
        let (headers, tip_hash) = build_test_chain(3, &[PUBKEY_G]);

        let mut mock = MockChainStoreHandle::default();
        let headers_clone = headers.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();

        // Second update with same tip
        let mut mock2 = MockChainStoreHandle::default();
        mock2.expect_get_chain_tip().returning(move || Ok(tip_hash));

        let updated = window.update(&mock2).unwrap();
        assert!(!updated);
    }

    #[test]
    fn test_reorg_invalidates_and_reloads() {
        let (headers_a, tip_a) = build_test_chain(5, &[PUBKEY_G]);

        // Initial load of chain A
        let mut mock = MockChainStoreHandle::default();
        let headers_a_clone = headers_a.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_a));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_a_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();
        assert_eq!(window.confirmed_entries.len(), 5);

        // Reorg: different chain B at same heights
        let (headers_b, tip_b) = build_test_chain(5, &[PUBKEY_2G]);
        let different_hash_at_4 = headers_b[0].blockhash;

        let mut mock2 = MockChainStoreHandle::default();
        let headers_b_clone = headers_b.clone();
        mock2.expect_get_chain_tip().returning(move || Ok(tip_b));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(different_hash_at_4));
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_b_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2).unwrap();
        assert!(updated);
        assert_eq!(window.confirmed_entries.len(), 5);
        assert_eq!(window.cached_tip_blockhash, Some(tip_b));
    }

    #[test]
    fn test_count_based_eviction() {
        let genesis_hash = BlockHash::all_zeros();
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);
        let header_c = build_test_header(&header_b.block_hash().to_string(), PUBKEY_3G, 2);

        let difficulty = header_a.get_difficulty(TEST_NETWORK);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        // Newest at front: c, b, a
        let entry_c = entry_from_header(&mut window, &header_c, 2);
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        window.add_to_running_total(&entry_c);
        window.confirmed_entries.push_back(entry_c);
        window.add_to_running_total(&entry_b);
        window.confirmed_entries.push_back(entry_b);
        window.add_to_running_total(&entry_a);
        window.confirmed_entries.push_back(entry_a);

        // With 3 entries and MAX_PPLNS_WINDOW_SHARES >> 3, no eviction occurs
        window.evict_overflow();
        assert_eq!(window.confirmed_entries.len(), 3);

        let expected_total = 3 * difficulty * DIFFICULTY_SCALE;
        assert_eq!(
            window.total_accumulated_difficulty, expected_total,
            "expected total_accumulated_difficulty {expected_total}, got {}",
            window.total_accumulated_difficulty
        );
    }

    #[test]
    fn test_count_based_eviction_truncates_oldest() {
        let genesis_hash = BlockHash::all_zeros();
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let hash_a = header_a.block_hash();
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);
        let hash_b = header_b.block_hash();

        // Injected small window cap so eviction runs without a 120,960-entry
        // fixture. Eviction retains cache_capacity() = cap + ~1% buffer.
        const CAP: usize = 200;
        let mut window = PplnsWindow::new_with_max_window_shares(TEST_NETWORK, CAP);
        let capacity = window.cache_capacity();

        // Newest-to-oldest at the front: header_b, header_a, then padding.
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        window.confirmed_entries.push_back(entry_b);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        window.confirmed_entries.push_back(entry_a);

        // Pad so the total exceeds the retained capacity (window cap + buffer).
        let padding_address = header_a.miner_bitcoin_address.clone();
        for index in 0..capacity {
            let entry = window.build_confirmed_entry(
                BlockHash::all_zeros(),
                index as u32 + 2,
                padding_address.clone(),
                1u128,
                Vec::new(),
            );
            window.confirmed_entries.push_back(entry);
        }

        assert_eq!(window.confirmed_entries.len(), capacity + 2);

        window.evict_overflow();

        // Truncated to the retained capacity, dropping the 2 oldest from the back.
        assert_eq!(window.confirmed_entries.len(), capacity);
        // The newest entries (header_b, header_a) at front should still be present.
        assert_eq!(window.confirmed_entries[0].blockhash, hash_b);
        assert_eq!(window.confirmed_entries[1].blockhash, hash_a);
    }

    #[test]
    fn test_distribution_from_tip_includes_all_entries() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let difficulty1 = header1.get_difficulty(TEST_NETWORK);
        let difficulty2 = header2.get_difficulty(TEST_NETWORK);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let entry2 = entry_from_header(&mut window, &header2, 1);
        let entry1 = entry_from_header(&mut window, &header1, 0);
        window.add_to_running_total(&entry2);
        window.confirmed_entries.push_back(entry2);
        window.add_to_running_total(&entry1);
        window.confirmed_entries.push_back(entry1);

        // Anchoring on the tip (header2 at the front) walks the whole window.
        let result = window
            .get_distribution_from_start_hash(
                u128::MAX,
                header2.block_hash(),
                &MockChainStoreHandle::default(),
            )
            .expect("tip should be in window");

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[&header1.miner_bitcoin_address],
            difficulty1 * DIFFICULTY_SCALE
        );
        assert_eq!(
            result[&header2.miner_bitcoin_address],
            difficulty2 * DIFFICULTY_SCALE
        );

        // No uncles, so total_weighted == difficulty * DIFFICULTY_SCALE for each entry
        let expected_total = (difficulty1 + difficulty2) * DIFFICULTY_SCALE;
        assert_eq!(
            window.total_accumulated_difficulty, expected_total,
            "expected total_accumulated_difficulty {expected_total}, got {}",
            window.total_accumulated_difficulty
        );
    }

    #[test]
    fn test_get_distribution_with_start_hash() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let header3 = build_test_header(&header2.block_hash().to_string(), PUBKEY_3G, 2);
        let difficulty1 = header1.get_difficulty(TEST_NETWORK);
        let difficulty2 = header2.get_difficulty(TEST_NETWORK);

        // Entries are newest-to-oldest: header3 (index 0), header2 (index 1), header1 (index 2)
        let mut window = PplnsWindow::new(TEST_NETWORK);
        let entry3 = entry_from_header(&mut window, &header3, 2);
        let entry2 = entry_from_header(&mut window, &header2, 1);
        let entry1 = entry_from_header(&mut window, &header1, 0);
        window.add_to_running_total(&entry3);
        window.confirmed_entries.push_back(entry3);
        window.add_to_running_total(&entry2);
        window.confirmed_entries.push_back(entry2);
        window.add_to_running_total(&entry1);
        window.confirmed_entries.push_back(entry1);

        // Starting from header2 should skip header3, include header2 and header1
        let result = window
            .get_distribution_from_start_hash(
                u128::MAX,
                header2.block_hash(),
                &MockChainStoreHandle::default(),
            )
            .expect("header2 should be in window");
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[&header2.miner_bitcoin_address],
            difficulty2 * DIFFICULTY_SCALE
        );
        assert_eq!(
            result[&header1.miner_bitcoin_address],
            difficulty1 * DIFFICULTY_SCALE
        );
        assert!(!result.contains_key(&header3.miner_bitcoin_address));

        // Starting from the oldest entry should only include that entry
        let result = window
            .get_distribution_from_start_hash(
                u128::MAX,
                header1.block_hash(),
                &MockChainStoreHandle::default(),
            )
            .expect("header1 should be in window");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[&header1.miner_bitcoin_address],
            difficulty1 * DIFFICULTY_SCALE
        );
    }

    #[test]
    fn test_get_distribution_with_unknown_start_hash_returns_error() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let entry2 = entry_from_header(&mut window, &header2, 1);
        let entry1 = entry_from_header(&mut window, &header1, 0);
        window.add_to_running_total(&entry2);
        window.confirmed_entries.push_back(entry2);
        window.add_to_running_total(&entry1);
        window.confirmed_entries.push_back(entry1);

        // A hash not in the window and not in the store cannot be resolved
        // to a confirmed ancestor, so the walk errors rather than silently
        // producing an empty distribution.
        let unknown_hash = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 3).block_hash();
        let mut mock_store = MockChainStoreHandle::default();
        mock_store.expect_get_share_header().returning(|_| {
            Err(crate::store::writer::StoreError::NotFound(
                "not found".into(),
            ))
        });
        let result = window.get_distribution_from_start_hash(u128::MAX, unknown_hash, &mock_store);
        assert!(result.is_err());
    }

    #[test]
    fn test_uncle_weighting() {
        let genesis_hash = BlockHash::all_zeros();

        // Uncle header
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();
        let uncle_difficulty = uncle_header.get_difficulty(TEST_NETWORK);

        // Nephew that references the uncle
        let nephew_header =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);
        let nephew_difficulty = nephew_header.get_difficulty(TEST_NETWORK);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let uncle_entry = uncle_entry_from_header(&mut window, &uncle_header);
        let nephew_entry =
            entry_from_header_with_uncles(&mut window, &nephew_header, 0, vec![uncle_entry]);
        window.add_to_running_total(&nephew_entry);
        window.confirmed_entries.push_back(nephew_entry);

        let result = window
            .get_distribution_from_start_hash(
                u128::MAX,
                nephew_header.block_hash(),
                &MockChainStoreHandle::default(),
            )
            .expect("nephew should be in window");

        // Uncle gets UNCLE_SCALED_WEIGHT (9) times its difficulty
        let expected_uncle_weight = uncle_difficulty * UNCLE_SCALED_WEIGHT;
        assert_eq!(
            result[&uncle_header.miner_bitcoin_address],
            expected_uncle_weight
        );

        // Nephew gets base difficulty * DIFFICULTY_SCALE + uncle_difficulty * NEPHEW_SCALED_BONUS
        let expected_nephew_weight =
            nephew_difficulty * DIFFICULTY_SCALE + uncle_difficulty * NEPHEW_SCALED_BONUS;
        assert_eq!(
            result[&nephew_header.miner_bitcoin_address],
            expected_nephew_weight
        );

        // total_accumulated_difficulty includes nephew base scaled + uncle weighted + nephew bonus
        let expected_total = nephew_difficulty * DIFFICULTY_SCALE
            + uncle_difficulty * UNCLE_SCALED_WEIGHT
            + uncle_difficulty * NEPHEW_SCALED_BONUS;
        assert_eq!(
            window.total_accumulated_difficulty, expected_total,
            "expected total_accumulated_difficulty {expected_total}, got {}",
            window.total_accumulated_difficulty
        );
    }

    #[test]
    fn test_empty_chain() {
        let genesis_hash = BlockHash::all_zeros();

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip()
            .returning(move || Ok(genesis_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_no_height()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let updated = window.update(&mock).unwrap();

        assert!(!updated);
        assert!(window.is_empty());
    }

    #[test]
    fn test_reorg_to_shorter_chain() {
        let (headers, tip_hash) = build_test_chain(5, &[PUBKEY_G]);

        // Initial load at height 4
        let mut mock = MockChainStoreHandle::default();
        let headers_clone = headers.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();
        assert_eq!(window.cached_top_height, Some(4));

        // Reorg to shorter chain at height 2
        let (short_headers, short_tip) = build_test_chain(3, &[PUBKEY_2G]);

        let mut mock2 = MockChainStoreHandle::default();
        let short_headers_clone = short_headers.clone();
        let short_headers_for_lookup = short_headers.clone();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(short_tip));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));
        // find_fork_height queries confirmed_at_height for cached entries;
        // the short chain has different blockhashes, so return those (no match).
        // Heights above the short chain's tip return an error.
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |height| {
                let max_height = short_headers_for_lookup.len() as u32 - 1;
                if height > max_height {
                    return Err(crate::store::writer::StoreError::NotFound(
                        "height not found".into(),
                    ));
                }
                let index = (max_height - height) as usize;
                Ok(short_headers_for_lookup[index].blockhash)
            });
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(short_headers_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2).unwrap();
        assert!(updated);
        assert_eq!(window.confirmed_entries.len(), 3);
        assert_eq!(window.cached_top_height, Some(2));
        assert_eq!(
            window.cached_tip_blockhash,
            Some(short_headers[0].blockhash)
        );
    }

    #[test]
    fn test_uncle_data_is_evicted_when_entry_is_evicted() {
        let genesis_hash = BlockHash::all_zeros();

        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();

        let nephew1 =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);

        let nephew2 = build_test_header_with_uncles(
            &nephew1.block_hash().to_string(),
            PUBKEY_2G,
            2,
            vec![uncle_hash],
        );

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let uncle_entry_1 = uncle_entry_from_header(&mut window, &uncle_header);
        let entry_nephew1 =
            entry_from_header_with_uncles(&mut window, &nephew1, 1, vec![uncle_entry_1]);
        window.confirmed_entries.push_back(entry_nephew1);

        let uncle_entry_2 = uncle_entry_from_header(&mut window, &uncle_header);
        let entry_nephew2 =
            entry_from_header_with_uncles(&mut window, &nephew2, 0, vec![uncle_entry_2]);
        window.confirmed_entries.push_back(entry_nephew2);

        assert_eq!(window.confirmed_entries.len(), 2);
        assert_eq!(window.confirmed_entries[0].uncle_entries.len(), 1);
        assert_eq!(window.confirmed_entries[1].uncle_entries.len(), 1);

        // Truncate to keep only nephew1; nephew2's uncle data is dropped with it
        window.confirmed_entries.truncate(1);
        assert_eq!(window.confirmed_entries.len(), 1);
        assert_eq!(window.confirmed_entries[0].uncle_entries.len(), 1);

        // Clear everything
        window.confirmed_entries.clear();
        assert!(window.confirmed_entries.is_empty());
    }

    #[test]
    fn test_shallow_reorg_preserves_older_entries() {
        // Build a chain of 5 shares (heights 0-4), load into window.
        // Then reorg last 2 (heights 3-4) with different shares.
        // Heights 0-2 should be preserved, heights 3-4 replaced.
        let (headers_a, tip_a) = build_test_chain(5, &[PUBKEY_G]);

        // Initial load
        let mut mock = MockChainStoreHandle::default();
        let headers_a_clone = headers_a.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_a));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_a_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();
        assert_eq!(window.confirmed_entries.len(), 5);

        // Save the blockhashes for heights 0-2 (they should survive the reorg)
        // In the deque, front=newest: [height4, height3, height2, height1, height0]
        let preserved_hash_2 = window.confirmed_entries[2].blockhash;
        let preserved_hash_1 = window.confirmed_entries[3].blockhash;
        let preserved_hash_0 = window.confirmed_entries[4].blockhash;

        // Build a new fork: 2 new shares at heights 3-4 with different miner
        let fork_parent_hash = headers_a[2].blockhash;
        let fork_header_3 = build_test_header(&fork_parent_hash.to_string(), PUBKEY_2G, 2);
        let fork_hash_3 = fork_header_3.block_hash();
        let fork_header_4 = build_test_header(&fork_hash_3.to_string(), PUBKEY_2G, 2);
        let fork_hash_4 = fork_header_4.block_hash();

        // New headers for the fork (newest-to-oldest)
        let new_fork_headers = vec![
            ConfirmedHeaderResult {
                height: 4,
                blockhash: fork_hash_4,
                header: fork_header_4,
            },
            ConfirmedHeaderResult {
                height: 3,
                blockhash: fork_hash_3,
                header: fork_header_3,
            },
        ];

        let mut mock2 = MockChainStoreHandle::default();
        let new_fork_clone = new_fork_headers.clone();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(fork_hash_4));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));

        // is_simple_extension checks height 4 -- return the new (different) hash
        // find_fork_height walks entries: height 4 (no match), height 3 (no match),
        // height 2 (match!). Return the preserved hash at height 2.
        let preserved_2_copy = preserved_hash_2;
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |height| match height {
                4 => Ok(fork_hash_4),
                3 => Ok(fork_hash_3),
                2 => Ok(preserved_2_copy),
                _ => Err(crate::store::writer::StoreError::NotFound(
                    "not needed".into(),
                )),
            });

        // load_range(3, 4) fetches the fork headers
        mock2
            .expect_get_confirmed_headers_in_range()
            .withf(|from, to| *from == 3 && *to == 4)
            .returning(move |_, _| Ok(new_fork_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2).unwrap();
        assert!(updated);
        assert_eq!(window.confirmed_entries.len(), 5);

        // Verify heights 0-2 are preserved (at back of deque)
        assert_eq!(window.confirmed_entries[2].blockhash, preserved_hash_2);
        assert_eq!(window.confirmed_entries[3].blockhash, preserved_hash_1);
        assert_eq!(window.confirmed_entries[4].blockhash, preserved_hash_0);

        // Verify heights 3-4 are the new fork entries (at front of deque)
        assert_eq!(window.confirmed_entries[0].blockhash, fork_hash_4);
        assert_eq!(window.confirmed_entries[1].blockhash, fork_hash_3);
    }

    #[test]
    fn test_reorg_updates_aggregates_correctly() {
        // After a shallow reorg, address_difficulty_map should reflect
        // only the surviving + new entries.
        let (headers_a, tip_a) = build_test_chain(3, &[PUBKEY_G]);

        // Initial load: 3 shares all by PUBKEY_G
        let mut mock = MockChainStoreHandle::default();
        let headers_a_clone = headers_a.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_a));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_a_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();

        let difficulty = headers_a[0].header.get_difficulty(TEST_NETWORK);
        let miner_g = &headers_a[0].header.miner_bitcoin_address;

        // All 3 shares are by PUBKEY_G
        let dist = window
            .get_distribution_from_start_hash(u128::MAX, tip_a, &MockChainStoreHandle::default())
            .expect("tip should be in window");
        assert_eq!(dist.len(), 1);
        assert_eq!(dist[miner_g], 3 * difficulty * DIFFICULTY_SCALE);

        // Reorg: replace height 2 with a share by PUBKEY_2G
        let preserved_hash_at_1 = headers_a[1].blockhash; // height 1

        let fork_header = build_test_header(&preserved_hash_at_1.to_string(), PUBKEY_2G, 2);
        let fork_hash = fork_header.block_hash();
        let fork_headers = vec![ConfirmedHeaderResult {
            height: 2,
            blockhash: fork_hash,
            header: fork_header.clone(),
        }];

        let mut mock2 = MockChainStoreHandle::default();
        let fork_headers_clone = fork_headers.clone();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(fork_hash));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));

        let preserved_1 = preserved_hash_at_1;
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |height| match height {
                2 => Ok(fork_hash),
                1 => Ok(preserved_1),
                _ => Err(crate::store::writer::StoreError::NotFound(
                    "not needed".into(),
                )),
            });

        mock2
            .expect_get_confirmed_headers_in_range()
            .withf(|from, to| *from == 2 && *to == 2)
            .returning(move |_, _| Ok(fork_headers_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        window.update(&mock2).unwrap();

        let miner_2g = &fork_header.miner_bitcoin_address;

        // Now: 2 shares by PUBKEY_G (heights 0-1) + 1 share by PUBKEY_2G (height 2)
        let dist = window
            .get_distribution_from_start_hash(
                u128::MAX,
                fork_hash,
                &MockChainStoreHandle::default(),
            )
            .expect("fork tip should be in window");
        assert_eq!(dist.len(), 2);
        assert_eq!(
            dist[miner_g],
            2 * difficulty * DIFFICULTY_SCALE,
            "PUBKEY_G should have 2x difficulty scaled, got {}",
            dist[miner_g]
        );
        assert_eq!(
            dist[miner_2g],
            difficulty * DIFFICULTY_SCALE,
            "PUBKEY_2G should have 1x difficulty scaled, got {}",
            dist[miner_2g]
        );

        let expected_total = 3 * difficulty * DIFFICULTY_SCALE;
        assert_eq!(
            window.total_accumulated_difficulty, expected_total,
            "total should be {expected_total}, got {}",
            window.total_accumulated_difficulty
        );
    }

    #[test]
    fn test_confirmed_entry_has_correct_height() {
        let (headers, tip_hash) = build_test_chain(5, &[PUBKEY_G, PUBKEY_2G]);

        let mut mock = MockChainStoreHandle::default();
        let headers_clone = headers.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();

        // Deque is newest-to-oldest: [height4, height3, height2, height1, height0]
        assert_eq!(window.confirmed_entries[0].height, 4);
        assert_eq!(window.confirmed_entries[1].height, 3);
        assert_eq!(window.confirmed_entries[2].height, 2);
        assert_eq!(window.confirmed_entries[3].height, 1);
        assert_eq!(window.confirmed_entries[4].height, 0);
    }

    #[test]
    fn test_stale_address_key_removed_after_entry_evicted() {
        let genesis_hash = BlockHash::all_zeros();

        // Miner A at height 0, Miner B at height 1
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        // entry_b built first -> gets key 0, entry_a built second -> gets key 1
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        let miner_b_key = entry_b.internal_key;
        let miner_a_key = entry_a.internal_key;
        window.add_to_running_total(&entry_b);
        window.confirmed_entries.push_back(entry_b);
        window.add_to_running_total(&entry_a);
        window.confirmed_entries.push_back(entry_a);

        assert_eq!(window.address_keys.len(), 2);
        assert!(window.address_keys.value_for(miner_a_key).is_some());
        assert!(window.address_keys.value_for(miner_b_key).is_some());

        // Evict miner A's entry (oldest, at back)
        window.confirmed_entries.pop_back();

        // Pruning should free miner A's now-unreferenced key.
        window.prune_unreferenced_keys();

        assert!(
            window.address_keys.value_for(miner_a_key).is_none(),
            "stale key for evicted miner should be removed"
        );
        assert!(
            window.address_keys.value_for(miner_b_key).is_some(),
            "active miner key should be preserved"
        );
    }

    #[test]
    fn test_prune_preserves_keys_of_all_cached_entries() {
        let genesis_hash = BlockHash::all_zeros();

        // Three miners: A (oldest), B (middle), C (newest)
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);
        let header_c = build_test_header(&header_b.block_hash().to_string(), PUBKEY_3G, 2);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        let entry_c = entry_from_header(&mut window, &header_c, 2);
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        window.add_to_running_total(&entry_c);
        window.confirmed_entries.push_back(entry_c);
        window.add_to_running_total(&entry_b);
        window.confirmed_entries.push_back(entry_b);
        window.add_to_running_total(&entry_a);
        window.confirmed_entries.push_back(entry_a);

        assert_eq!(window.address_keys.len(), 3);

        // Nothing has left the cache, so pruning keeps every key -- retention
        // depends only on whether an entry references the key, not on where the
        // entry sits relative to any total_difficulty threshold.
        window.prune_unreferenced_keys();

        assert!(
            window.address_keys.value_for(0).is_some(),
            "cached miner key should be preserved"
        );
        assert!(
            window.address_keys.value_for(1).is_some(),
            "cached miner key should be preserved"
        );
        assert!(
            window.address_keys.value_for(2).is_some(),
            "cached miner key should be preserved"
        );
    }

    #[test]
    fn test_stale_key_slot_reused_by_new_address() {
        let genesis_hash = BlockHash::all_zeros();

        // Miner A at height 0, Miner B at height 1
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        // entry_b built first -> gets key 0, entry_a built second -> gets key 1
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        let miner_a_key = entry_a.internal_key;
        window.add_to_running_total(&entry_b);
        window.confirmed_entries.push_back(entry_b);
        window.add_to_running_total(&entry_a);
        window.confirmed_entries.push_back(entry_a);

        assert_eq!(window.address_keys.len(), 2);

        // Evict miner A, then trigger cleanup
        window.confirmed_entries.pop_back();
        window.prune_unreferenced_keys();

        assert!(
            window.address_keys.value_for(miner_a_key).is_none(),
            "stale key should be removed after cleanup"
        );

        // Add a new entry with miner C; it should reuse miner A's freed slot
        let header_c = build_test_header(&header_b.block_hash().to_string(), PUBKEY_3G, 2);
        let entry_c = entry_from_header(&mut window, &header_c, 2);
        let miner_c_key = entry_c.internal_key;
        window.add_to_running_total(&entry_c);
        window.confirmed_entries.push_front(entry_c);

        // Miner C should have taken the freed slot
        assert_eq!(
            miner_c_key, miner_a_key,
            "new miner should reuse the freed key slot"
        );
        assert_eq!(
            window.address_keys.value_for(miner_c_key),
            Some(&header_c.miner_bitcoin_address),
            "freed slot should now hold the new miner address"
        );
        // Total slots should still be 2, not grown to 3
        assert_eq!(
            window.address_keys.len(),
            2,
            "address keys should not grow when freed slots are available"
        );
    }

    #[test]
    fn test_prune_preserves_uncle_key_of_cached_entry() {
        let genesis_hash = BlockHash::all_zeros();

        // Uncle miner (PUBKEY_3G) appears only as an uncle, never as a share miner.
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();

        // Nephew at height 0 references the uncle.
        let nephew_header =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);

        // A second entry at height 1 by a different miner.
        let header_top = build_test_header(&nephew_header.block_hash().to_string(), PUBKEY_2G, 2);

        let mut window = PplnsWindow::new(TEST_NETWORK);
        // Uncle built first -> PUBKEY_3G gets key 0
        let uncle_entry = uncle_entry_from_header(&mut window, &uncle_header);
        let uncle_miner_key = uncle_entry.internal_key;
        let entry_top = entry_from_header(&mut window, &header_top, 1);
        let entry_nephew =
            entry_from_header_with_uncles(&mut window, &nephew_header, 0, vec![uncle_entry]);

        window.add_to_running_total(&entry_top);
        window.confirmed_entries.push_back(entry_top);
        window.add_to_running_total(&entry_nephew);
        window.confirmed_entries.push_back(entry_nephew);

        // The nephew is still cached, so pruning must keep its uncle's key even
        // though that miner never appears as a share miner.
        window.prune_unreferenced_keys();

        assert!(
            window.address_keys.value_for(uncle_miner_key).is_some(),
            "uncle miner key referenced by a cached nephew should be preserved"
        );
    }

    #[test]
    fn test_update_prunes_key_of_evicted_only_miner() {
        // Height 0 is mined by a unique miner (PUBKEY_5G); heights 1-4 by
        // PUBKEY_G. With a small window cap, the initial load pulls all five
        // then evicts the oldest, dropping height 0. update() must then prune
        // PUBKEY_5G's now-unreferenced key while keeping PUBKEY_G's.
        let (headers, tip_hash) =
            build_test_chain(5, &[PUBKEY_5G, PUBKEY_G, PUBKEY_G, PUBKEY_G, PUBKEY_G]);
        // headers are newest-to-oldest; height 0 (PUBKEY_5G) is at the back.
        let evicted_only_miner = headers[4].header.miner_bitcoin_address.clone();
        let active_miner = headers[0].header.miner_bitcoin_address.clone();

        let mut mock = MockChainStoreHandle::default();
        let headers_clone = headers.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        // cache_capacity for cap 2 is 2 + ceil(2/100) = 3, so heights 0 and 1
        // are evicted, leaving heights 2-4 (all PUBKEY_G).
        let mut window = PplnsWindow::new_with_max_window_shares(TEST_NETWORK, 2);
        window.update(&mock).unwrap();

        assert_eq!(window.confirmed_entries.len(), 3);

        let distribution = window
            .get_distribution_from_start_hash(u128::MAX, tip_hash, &MockChainStoreHandle::default())
            .expect("tip should be in window");
        assert!(
            !distribution.contains_key(&evicted_only_miner),
            "miner present only in evicted entries should not be paid"
        );
        assert!(
            distribution.contains_key(&active_miner),
            "retained miner should be paid"
        );

        // The interner slot for the evicted-only miner must be freed; the
        // active miner's slot must survive.
        let mut freed_evicted_miner = true;
        let mut kept_active_miner = false;
        for index in 0..window.address_keys.len() {
            match window.address_keys.value_for(index) {
                Some(address) if *address == evicted_only_miner => freed_evicted_miner = false,
                Some(address) if *address == active_miner => kept_active_miner = true,
                _ => {}
            }
        }
        assert!(
            freed_evicted_miner,
            "evicted-only miner key should be pruned from the interner"
        );
        assert!(
            kept_active_miner,
            "active miner key should be retained in the interner"
        );
    }

    #[test]
    fn test_deep_reorg_falls_back_to_full_invalidation() {
        // Build a chain longer than MAX_REORG_SCAN_DEPTH, reorg it fully.
        // find_fork_height should give up after MAX_REORG_SCAN_DEPTH lookups.
        let chain_len = MAX_REORG_SCAN_DEPTH + 10;
        let (headers_a, tip_a) = build_test_chain(chain_len, &[PUBKEY_G]);
        let top_height = (chain_len - 1) as u32;

        // Initial load
        let mut mock = MockChainStoreHandle::default();
        let headers_a_clone = headers_a.clone();
        mock.expect_get_chain_tip().returning(move || Ok(tip_a));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(top_height)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_a_clone.clone()));
        mock.expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let mut window = PplnsWindow::new(TEST_NETWORK);
        window.update(&mock).unwrap();
        assert_eq!(window.confirmed_entries.len(), chain_len);

        // Reorg with completely different chain at same heights
        let (headers_b, tip_b) = build_test_chain(chain_len, &[PUBKEY_2G]);
        let headers_b_clone = headers_b.clone();
        let headers_b_for_lookup = headers_b.clone();

        let mut mock2 = MockChainStoreHandle::default();
        mock2.expect_get_chain_tip().returning(move || Ok(tip_b));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(top_height)));
        // All heights return different hashes (different chain)
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |height| {
                let index = (top_height - height) as usize;
                if index < headers_b_for_lookup.len() {
                    Ok(headers_b_for_lookup[index].blockhash)
                } else {
                    Err(crate::store::writer::StoreError::NotFound(
                        "not found".into(),
                    ))
                }
            });
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers_b_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2).unwrap();
        assert!(updated);
        // Full invalidation + reload means all entries are from chain B
        assert_eq!(window.confirmed_entries.len(), chain_len);
        assert_eq!(window.cached_tip_blockhash, Some(tip_b));
        // Verify entries are from chain B (check first entry)
        assert_eq!(
            window.confirmed_entries[0].blockhash,
            headers_b[0].blockhash
        );
    }

    /// When the confirmed chain has share_a at height 3 but the
    /// candidate chain has a competing share_b at height 3 (same
    /// parent), a child of share_b should be able to look up its
    /// parent in the PPLNS window.
    ///
    /// share_b's children can validate as their parent is now in
    /// PPLNS window - thanks to candidate chain being followed to
    /// confirmed entries in pplns window.
    #[test]
    fn test_competing_block_not_in_pplns_window_confirmed_entries_but_is_building_on_candidate_chain()
     {
        let genesis_hash = BlockHash::all_zeros();

        // Build confirmed chain: genesis -> share1(h:0) -> share2(h:1) -> share_a(h:2)
        let share1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let share2 = build_test_header(&share1.block_hash().to_string(), PUBKEY_2G, 3);
        let share_a = build_test_header(&share2.block_hash().to_string(), PUBKEY_G, 4);

        // share_b is a competing block at same height as share_a
        // (same parent share2, different miner)
        let share_b = build_test_header(&share2.block_hash().to_string(), PUBKEY_3G, 5);

        // share_c is a child of share_b -- this is the block that
        // needs to validate during sync
        let share_c = build_test_header(&share_b.block_hash().to_string(), PUBKEY_2G, 6);

        // Populate PPLNS window with confirmed entries only (share_a branch)
        let mut window = PplnsWindow::new(TEST_NETWORK);
        let entry_a = entry_from_header(&mut window, &share_a, 2);
        let entry_2 = entry_from_header(&mut window, &share2, 1);
        let entry_1 = entry_from_header(&mut window, &share1, 0);
        window.add_to_running_total(&entry_a);
        window.confirmed_entries.push_back(entry_a);
        window.add_to_running_total(&entry_2);
        window.confirmed_entries.push_back(entry_2);
        window.add_to_running_total(&entry_1);
        window.confirmed_entries.push_back(entry_1);

        // share_a (confirmed) is findable in the window
        let result = window.get_distribution_from_start_hash(
            u128::MAX,
            share_a.block_hash(),
            &MockChainStoreHandle::default(),
        );
        assert!(
            result.is_ok(),
            "share_a should be in the PPLNS window (it is confirmed)"
        );

        // share_b is a competing block at the same height as share_a.
        // Both share the same parent (share2), so share_b's PPLNS
        // distribution should be computable from the confirmed
        // entries below it (share2, share1). A child of share_b
        // must be able to validate by looking up share_b in the
        // PPLNS window through the candiadtes chain.
        //
        // Set up a mock chain store so resolve_start_hash can walk
        // from share_c's prev (share_b) back to share2 (confirmed).
        let mut mock_store = MockChainStoreHandle::default();
        let share_b_clone = share_b.clone();
        let share_b_hash = share_b.block_hash();
        mock_store
            .expect_get_share_header()
            .withf(move |hash| *hash == share_b_hash)
            .returning(move |_| Ok(share_b_clone.clone()));
        // share_b is only HeaderValid and off any chain -- the walk follows
        // parent links regardless of validation status, so it is still
        // included (the old status/chain filter would have rejected it).
        mock_store.expect_get_block_metadata().returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(1),
                chain_work: Work::from_le_bytes([0u8; 32]),
                status: Status::HeaderValid,
                chain: ChainMembership::None,
            })
        });
        // No uncle headers needed for this test
        mock_store
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        assert_eq!(
            share_c.prev_share_blockhash,
            share_b.block_hash(),
            "share_c's parent is share_b"
        );
        let result = window.get_distribution_from_start_hash(
            u128::MAX,
            share_c.prev_share_blockhash,
            &mock_store,
        );
        assert!(
            result.is_ok(),
            "share_c must be able to find its parent share_b in the PPLNS window during sync"
        );
    }

    //* Regression for the testnet4 coinbase-mismatch wedge (hive.log
    //* 2026-08-06). Two siblings at height 197110 shared a parent
    //* (f1455ab0 @197109) and an identical coinbase. The first sibling
    //* confirmed, advancing the tip to 197110; post_promote updated the
    //* window and evict_overflow dropped the oldest share. Validating the
    //* second sibling then computed get_distribution_from_start_hash at the
    //* same parent against a window short by the evicted share, so its
    //* identical coinbase failed "Coinbase and template merkle root don't
    //* match merkle root", and the chain wedged.
    //*
    //* Invariant: the distribution at a fixed anchor must not change when a
    //* sibling promotion advances the tip and triggers eviction. Driven with
    //* an injected window cap of 3 and a bounded total_difficulty (3 shares)
    //* so eviction bites without a 120,960-entry fixture. The ~1% retained
    //* buffer (`cache_capacity`) keeps the anchor's oldest window share alive
    //* across the promotion; without it (evicting at the bare window cap) the
    //* second sibling's identical coinbase would fail validation, as
    //* it did in the testnet4 network with three nodes.
    #[test]
    fn test_distribution_at_anchor_invariant_to_sibling_promotion() {
        const MAX_SHARES: usize = 3;
        let genesis = BlockHash::all_zeros();

        // Confirmed chain a(0) -> b(1) -> c(2) -> parent(3), distinct miners.
        let a = build_test_header(&genesis.to_string(), PUBKEY_G, 2);
        let b = build_test_header(&a.block_hash().to_string(), PUBKEY_2G, 2);
        let c = build_test_header(&b.block_hash().to_string(), PUBKEY_3G, 2);
        let parent = build_test_header(&c.block_hash().to_string(), PUBKEY_4G, 2);
        // Sibling extends the parent; confirming it advances the tip past the
        // anchor and evicts the oldest window share.
        let sibling = build_test_header(&parent.block_hash().to_string(), PUBKEY_5G, 2);
        let parent_hash = parent.block_hash();

        // Window bounded to exactly MAX_SHARES (3) shares: parent, c, b. The
        // ~1% buffer keeps b alive when the sibling promotion evicts the
        // oldest cache entry.
        let window_difficulty = MAX_SHARES as u128 * a.get_difficulty(TEST_NETWORK);

        let mut window = PplnsWindow::new_with_max_window_shares(TEST_NETWORK, MAX_SHARES);

        // Update 1: tip = parent (height 3). Loads [parent, c, b, a]; the
        // buffer (cap 3 + 1) retains all four.
        let to_parent = vec![
            ConfirmedHeaderResult {
                height: 3,
                blockhash: parent.block_hash(),
                header: parent.clone(),
            },
            ConfirmedHeaderResult {
                height: 2,
                blockhash: c.block_hash(),
                header: c.clone(),
            },
            ConfirmedHeaderResult {
                height: 1,
                blockhash: b.block_hash(),
                header: b.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: a.block_hash(),
                header: a.clone(),
            },
        ];
        let parent_tip = parent.block_hash();
        let mut mock1 = MockChainStoreHandle::default();
        mock1
            .expect_get_chain_tip()
            .returning(move || Ok(parent_tip));
        mock1
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(3)));
        mock1
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(to_parent.clone()));
        window.update(&mock1).unwrap();

        let before = window
            .get_distribution_from_start_hash(
                window_difficulty,
                parent_hash,
                &MockChainStoreHandle::default(),
            )
            .expect("parent is in the window at the tip");

        // Update 2: tip = sibling (height 4). Simple extension -> loads
        // sibling, evicts the oldest (a) -> cache [sibling, parent, c, b].
        // The buffer keeps b, so parent's 3-share window is intact.
        let to_sibling = vec![ConfirmedHeaderResult {
            height: 4,
            blockhash: sibling.block_hash(),
            header: sibling.clone(),
        }];
        let sibling_tip = sibling.block_hash();
        let parent_at_cached = parent.block_hash();
        let mut mock2 = MockChainStoreHandle::default();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(sibling_tip));
        mock2
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(4)));
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(parent_at_cached));
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(to_sibling.clone()));
        window.update(&mock2).unwrap();

        let after = window
            .get_distribution_from_start_hash(
                window_difficulty,
                parent_hash,
                &MockChainStoreHandle::default(),
            )
            .expect("parent is still in the window after the sibling promotion");

        assert_eq!(
            before, after,
            "distribution at the parent anchor changed after a sibling promotion evicted a \
             window share -- an identical coinbase would fail validation"
        );
    }

    //* When the share difficulty in the window never reaches the threshold --
    //* the normal regime for a pool whose window does not cover
    //* bitcoin_difficulty * multiplier -- the walk used to run to the back of
    //* the deque, whose position depends on this node's own tip. Two nodes one
    //* block apart then derived different payouts for the same anchor. The
    //* count bound makes the walk stop at the same chain position on both.
    #[test]
    fn test_distribution_at_anchor_invariant_to_tip_when_threshold_unreachable() {
        const MAX_SHARES: usize = 3;
        let genesis = BlockHash::all_zeros();

        let a = build_test_header(&genesis.to_string(), PUBKEY_G, 2);
        let b = build_test_header(&a.block_hash().to_string(), PUBKEY_2G, 2);
        let c = build_test_header(&b.block_hash().to_string(), PUBKEY_3G, 2);
        let parent = build_test_header(&c.block_hash().to_string(), PUBKEY_4G, 2);
        let sibling = build_test_header(&parent.block_hash().to_string(), PUBKEY_5G, 2);
        let parent_hash = parent.block_hash();

        // A threshold the window can never meet, so only the count bound and
        // the end of the cache can stop the walk.
        let unreachable_difficulty = u128::MAX;

        let mut window = PplnsWindow::new_with_max_window_shares(TEST_NETWORK, MAX_SHARES);

        // Tip = parent (height 3). Cache holds [parent, c, b, a].
        let to_parent = vec![
            ConfirmedHeaderResult {
                height: 3,
                blockhash: parent.block_hash(),
                header: parent.clone(),
            },
            ConfirmedHeaderResult {
                height: 2,
                blockhash: c.block_hash(),
                header: c.clone(),
            },
            ConfirmedHeaderResult {
                height: 1,
                blockhash: b.block_hash(),
                header: b.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: a.block_hash(),
                header: a.clone(),
            },
        ];
        let parent_tip = parent.block_hash();
        let mut mock1 = MockChainStoreHandle::default();
        mock1
            .expect_get_chain_tip()
            .returning(move || Ok(parent_tip));
        mock1
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(3)));
        mock1
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(to_parent.clone()));
        window.update(&mock1).unwrap();

        let before = window
            .get_distribution_from_start_hash(
                unreachable_difficulty,
                parent_hash,
                &MockChainStoreHandle::default(),
            )
            .expect("the anchor has a full window of cached entries below it");

        // Tip = sibling (height 4). Cache becomes [sibling, parent, c, b]:
        // the anchor is now one entry behind the tip and `a` has been evicted.
        let to_sibling = vec![ConfirmedHeaderResult {
            height: 4,
            blockhash: sibling.block_hash(),
            header: sibling.clone(),
        }];
        let sibling_tip = sibling.block_hash();
        let parent_at_cached = parent.block_hash();
        let mut mock2 = MockChainStoreHandle::default();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(sibling_tip));
        mock2
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(4)));
        mock2
            .expect_get_confirmed_at_height()
            .returning(move |_| Ok(parent_at_cached));
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(to_sibling.clone()));
        window.update(&mock2).unwrap();

        let after = window
            .get_distribution_from_start_hash(
                unreachable_difficulty,
                parent_hash,
                &MockChainStoreHandle::default(),
            )
            .expect("the anchor still has a full window of cached entries below it");

        assert_eq!(
            before, after,
            "distribution at a fixed anchor changed as the local tip advanced"
        );
        // Exactly MAX_SHARES entries contributed: parent, c and b, one miner
        // each. `a` is excluded by the count bound, not by where eviction fell.
        assert_eq!(before.len(), MAX_SHARES);
    }

    //* An anchor deeper than the retained buffer has fewer than
    //* `max_window_shares` entries cached below it, so the walk runs out. The
    //* result would depend on where eviction trimmed the back, so it is
    //* refused rather than returned truncated.
    #[test]
    fn test_distribution_errors_when_eviction_truncates_the_window() {
        const MAX_SHARES: usize = 3;
        let genesis = BlockHash::all_zeros();

        let a = build_test_header(&genesis.to_string(), PUBKEY_G, 2);
        let b = build_test_header(&a.block_hash().to_string(), PUBKEY_2G, 2);
        let c = build_test_header(&b.block_hash().to_string(), PUBKEY_3G, 2);
        let parent = build_test_header(&c.block_hash().to_string(), PUBKEY_4G, 2);
        let sibling = build_test_header(&parent.block_hash().to_string(), PUBKEY_5G, 2);

        let mut window = PplnsWindow::new_with_max_window_shares(TEST_NETWORK, MAX_SHARES);

        let all_headers = vec![
            ConfirmedHeaderResult {
                height: 4,
                blockhash: sibling.block_hash(),
                header: sibling.clone(),
            },
            ConfirmedHeaderResult {
                height: 3,
                blockhash: parent.block_hash(),
                header: parent.clone(),
            },
            ConfirmedHeaderResult {
                height: 2,
                blockhash: c.block_hash(),
                header: c.clone(),
            },
            ConfirmedHeaderResult {
                height: 1,
                blockhash: b.block_hash(),
                header: b.clone(),
            },
            ConfirmedHeaderResult {
                height: 0,
                blockhash: a.block_hash(),
                header: a.clone(),
            },
        ];
        let sibling_tip = sibling.block_hash();
        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip()
            .returning(move || Ok(sibling_tip));
        mock.expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(4)));
        mock.expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(all_headers.clone()));
        window.update(&mock).unwrap();

        // Cache is capped at MAX_SHARES + 1, so it holds [sibling, parent, c, b]
        // and `a` is evicted: the back no longer reaches the chain start.
        let error = window
            .get_distribution_from_start_hash(
                u128::MAX,
                c.block_hash(),
                &MockChainStoreHandle::default(),
            )
            .expect_err("only two entries are cached below the anchor, short of the window");
        assert!(
            error.to_string().contains("truncated by eviction"),
            "unexpected error: {error}"
        );
    }
}
