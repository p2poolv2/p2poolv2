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
use bitcoin::Address;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use tracing::info;

/// Maximum number of confirmed shares in the PPLNS window.
/// At 6 shares per minute over 2 weeks: 6 * 60 * 24 * 14 = 120,960.
/// Provide a 10% buffer 120,960 * 1.1 = 133056
pub(crate) const MAX_PPLNS_WINDOW_SHARES: usize = 133056;

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

/// A cached uncle entry with only the fields needed for payout.
struct UncleEntry {
    /// Internal key mapping the miner address in AddressKeys.
    internal_key: usize,
    /// Base difficulty of the uncle share before weighting.
    difficulty: u128,
}

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
        }
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
    /// Iteration begins at the entry whose blockhash matches
    /// start_hash, skipping newer entries. Does not remove stale
    /// address keys, so it only requires `&self`. Suitable for
    /// callers that hold a read lock on a shared PplnsWindow, like
    /// the validation worker.
    pub fn get_distribution_from_start_hash(
        &self,
        total_difficulty: u128,
        start_hash: BlockHash,
    ) -> HashMap<Address, u128> {
        let start_index = self.find_start_index(start_hash);
        let (difficulty_by_key, _threshold_index) =
            self.walk_entries(total_difficulty, start_index);
        self.collect_distribution(&difficulty_by_key)
    }

    /// Get payout distribution from the tip and clean up stale
    /// address keys.
    ///
    /// Walk entries up to index where we meet
    /// total_difficulty. Continue from there to mark overflow
    /// entries.  Remove any address keys that are not in overflow and
    /// don't contribute any difficulty.
    ///
    /// Finally collect difficulties by addresses in a hashmap and
    /// return that.
    pub fn get_distribution(&mut self, total_difficulty: u128) -> HashMap<Address, u128> {
        let (difficulty_by_key, threshold_index) = self.walk_entries(total_difficulty, 0);

        let overflow_flags = self.mark_overflow_entries(threshold_index);
        self.remove_stale_keys(&difficulty_by_key, &overflow_flags);

        self.collect_distribution(&difficulty_by_key)
    }

    /// Accumulate difficulty by walking confirmed entries from
    /// start_index and return the per-key difficulty vector along
    /// with the threshold index.
    fn walk_entries(&self, total_difficulty: u128, start_index: usize) -> (Vec<u128>, usize) {
        let scaled_threshold = total_difficulty.saturating_mul(DIFFICULTY_SCALE);
        let mut difficulty_by_key = vec![0u128; self.address_keys.len()];
        let mut accumulated_difficulty: u128 = 0;

        let threshold_index = self.accumulate_difficulty(
            &mut difficulty_by_key,
            &mut accumulated_difficulty,
            scaled_threshold,
            start_index,
        );

        (difficulty_by_key, threshold_index)
    }

    /// Find the index of the entry matching the given blockhash.
    /// Returns 0 when the hash is not found.
    fn find_start_index(&self, start_hash: BlockHash) -> usize {
        self.confirmed_entries
            .iter()
            .position(|entry| entry.blockhash == start_hash)
            .unwrap_or(0)
    }

    /// Walk entries starting at start_index, accumulating difficulty
    /// per address until accumulated difficulty meets the threshold.
    /// Returns the index of the first entry past the threshold, or
    /// the total entry count if the threshold was never reached.
    fn accumulate_difficulty(
        &self,
        difficulty_by_key: &mut [u128],
        accumulated_difficulty: &mut u128,
        scaled_threshold: u128,
        start_index: usize,
    ) -> usize {
        for (offset, entry) in self.confirmed_entries.iter().skip(start_index).enumerate() {
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
                return start_index + offset + 1;
            }
        }
        self.confirmed_entries.len()
    }

    /// Mark address keys that appear in entries beyond the threshold
    /// so they are not removed as stale.
    fn mark_overflow_entries(&self, threshold_index: usize) -> Vec<bool> {
        let mut overflow_flags = vec![false; self.address_keys.len()];
        for entry in self.confirmed_entries.iter().skip(threshold_index) {
            overflow_flags[entry.internal_key] = true;
            for uncle_entry in &entry.uncle_entries {
                overflow_flags[uncle_entry.internal_key] = true;
            }
        }
        overflow_flags
    }

    /// Remove address keys that have zero difficulty and are not in
    /// the overflow region.
    fn remove_stale_keys(&mut self, difficulty_by_key: &[u128], overflow_flags: &[bool]) {
        for index in 0..difficulty_by_key.len() {
            if difficulty_by_key[index] == 0 && !overflow_flags[index] {
                self.address_keys.remove(index);
            }
        }
    }

    /// Convert the Vec-based difficulty accumulation into a HashMap<Address, u128>.
    fn collect_distribution(&self, difficulty_by_key: &[u128]) -> HashMap<Address, u128> {
        let mut result = HashMap::with_capacity(difficulty_by_key.len());
        for (index, difficulty) in difficulty_by_key.iter().enumerate() {
            if *difficulty > 0 {
                if let Some(address) = self.address_keys.value_for(index) {
                    result.insert(address.clone(), *difficulty);
                }
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
            let estimated_min_height = tip_height.saturating_sub(MAX_PPLNS_WINDOW_SHARES as u32);
            self.load_range(chain_store_handle, estimated_min_height, tip_height)?;
        }

        self.evict_overflow();
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
                info!("Reorg detected in PPLNS window, rolling back to fork height {fork_height}");
                self.remove_entries_above_height(fork_height);
                self.cached_top_height = Some(fork_height);
                self.load_range(chain_store_handle, fork_height + 1, tip_height)?;
            }
            None => {
                info!("Deep reorg detected in PPLNS window, full cache invalidation");
                self.invalidate();
                let estimated_min_height =
                    tip_height.saturating_sub(MAX_PPLNS_WINDOW_SHARES as u32);
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
        let uncle_lookup = self.fetch_uncle_lookup(chain_store_handle, &all_uncle_hashes)?;

        // Headers arrive newest-to-oldest. Reverse to oldest-first so
        // the newest entry ends up at position 0 in the deque after push_front.
        for ConfirmedHeaderResult {
            height,
            blockhash,
            header,
        } in confirmed_headers.into_iter().rev()
        {
            let difficulty = header.get_difficulty(self.network);
            let uncle_entries = resolve_uncle_entries(&header.uncles, &uncle_lookup);
            let entry = self.build_confirmed_entry(
                blockhash,
                height,
                header.miner_address,
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

    /// Remove confirmed entries to only maintain
    /// MAX_PPLNS_WINDOW_SHARES in confirmed entries. If difficulty is
    /// not reached in these many shares, we only ever maintain these many shares.
    fn evict_overflow(&mut self) {
        while self.confirmed_entries.len() > MAX_PPLNS_WINDOW_SHARES {
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

    /// Fetch uncle headers from the chain store and build a lookup table.
    fn fetch_uncle_lookup(
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
            let uncle_entry = self.build_uncle_entry(header.miner_address, difficulty);
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
use crate::shares::share_block::ShareHeader;

#[cfg(any(test, feature = "test-utils"))]
impl PplnsWindow {
    /// Populate the window cache directly for benchmarking.
    ///
    /// Accepts confirmed shares and uncles as tuples of primitives,
    /// bypassing the chain store. Confirmed shares should be ordered
    /// newest-to-oldest. Uncle data is provided as (miner_address_string, difficulty).
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
}

#[cfg(test)]
mockall::mock! {
    pub PplnsWindow {
        pub fn new(network: bitcoin::Network) -> Self;
        pub fn network(&self) -> bitcoin::Network;
        pub fn get_distribution_from_start_hash(
            &self,
            total_difficulty: u128,
            start_hash: BlockHash,
        ) -> HashMap<Address, u128>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
    use crate::shares::share_block::ShareHeader;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::{
        PUBKEY_2G, PUBKEY_3G, PUBKEY_G, build_test_header, build_test_header_with_uncles,
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
            header.miner_address.clone(),
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
            header.miner_address.clone(),
            header.get_difficulty(TEST_NETWORK),
            uncle_entries,
        )
    }

    /// Create an UncleEntry from a ShareHeader for test setup.
    fn uncle_entry_from_header(window: &mut PplnsWindow, header: &ShareHeader) -> UncleEntry {
        window.build_uncle_entry(
            header.miner_address.clone(),
            header.get_difficulty(TEST_NETWORK),
        )
    }

    /// Create a BlockMetadata with the given height and Confirmed status.
    fn metadata_at_height(height: u32) -> BlockMetadata {
        BlockMetadata {
            expected_height: Some(height),
            chain_work: Work::from_le_bytes([0u8; 32]),
            status: Status::Confirmed,
        }
    }

    /// Create a BlockMetadata with no height (empty chain).
    fn metadata_no_height() -> BlockMetadata {
        BlockMetadata {
            expected_height: None,
            chain_work: Work::from_le_bytes([0u8; 32]),
            status: Status::Confirmed,
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

        let mut window = PplnsWindow::new(TEST_NETWORK);
        // Fill beyond max: push max + 2 entries, first two are our named ones
        let entry_b = entry_from_header(&mut window, &header_b, 1);
        window.confirmed_entries.push_back(entry_b);
        let entry_a = entry_from_header(&mut window, &header_a, 0);
        window.confirmed_entries.push_back(entry_a);

        // Pad to exceed MAX_PPLNS_WINDOW_SHARES
        let max_shares = MAX_PPLNS_WINDOW_SHARES as usize;
        let padding_needed = max_shares; // total will be max + 2
        let padding_address = header_a.miner_address.clone();
        for index in 0..padding_needed {
            let entry = window.build_confirmed_entry(
                BlockHash::all_zeros(),
                index as u32 + 2,
                padding_address.clone(),
                1u128,
                Vec::new(),
            );
            window.confirmed_entries.push_back(entry);
        }

        assert_eq!(window.confirmed_entries.len(), max_shares + 2);

        window.evict_overflow();

        // Should be truncated to max_shares, dropping the 2 oldest from the back
        assert_eq!(window.confirmed_entries.len(), max_shares);
        // The newest entries (header_b, header_a) at front should still be present
        assert_eq!(window.confirmed_entries[0].blockhash, hash_b);
        assert_eq!(window.confirmed_entries[1].blockhash, hash_a);
    }

    #[test]
    fn test_get_distribution() {
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

        let result = window.get_distribution(u128::MAX);

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[&header1.miner_address],
            difficulty1 * DIFFICULTY_SCALE
        );
        assert_eq!(
            result[&header2.miner_address],
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
        let result = window.get_distribution_from_start_hash(u128::MAX, header2.block_hash());
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[&header2.miner_address],
            difficulty2 * DIFFICULTY_SCALE
        );
        assert_eq!(
            result[&header1.miner_address],
            difficulty1 * DIFFICULTY_SCALE
        );
        assert!(!result.contains_key(&header3.miner_address));

        // Starting from the oldest entry should only include that entry
        let result = window.get_distribution_from_start_hash(u128::MAX, header1.block_hash());
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[&header1.miner_address],
            difficulty1 * DIFFICULTY_SCALE
        );
    }

    #[test]
    fn test_get_distribution_with_unknown_start_hash_falls_back_to_top() {
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

        // A hash not in the window should fall back to starting from the top
        let unknown_hash = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 3).block_hash();
        let result = window.get_distribution_from_start_hash(u128::MAX, unknown_hash);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[&header1.miner_address],
            difficulty1 * DIFFICULTY_SCALE
        );
        assert_eq!(
            result[&header2.miner_address],
            difficulty2 * DIFFICULTY_SCALE
        );
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

        let result = window.get_distribution(u128::MAX);

        // Uncle gets UNCLE_SCALED_WEIGHT (9) times its difficulty
        let expected_uncle_weight = uncle_difficulty * UNCLE_SCALED_WEIGHT;
        assert_eq!(result[&uncle_header.miner_address], expected_uncle_weight);

        // Nephew gets base difficulty * DIFFICULTY_SCALE + uncle_difficulty * NEPHEW_SCALED_BONUS
        let expected_nephew_weight =
            nephew_difficulty * DIFFICULTY_SCALE + uncle_difficulty * NEPHEW_SCALED_BONUS;
        assert_eq!(result[&nephew_header.miner_address], expected_nephew_weight);

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
        let miner_g = &headers_a[0].header.miner_address;

        // All 3 shares are by PUBKEY_G
        let dist = window.get_distribution(u128::MAX);
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

        let miner_2g = &fork_header.miner_address;

        // Now: 2 shares by PUBKEY_G (heights 0-1) + 1 share by PUBKEY_2G (height 2)
        let dist = window.get_distribution(u128::MAX);
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

        // get_distribution should remove miner A's stale key
        let result = window.get_distribution(u128::MAX);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&header_b.miner_address));

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
    fn test_overflow_address_key_preserved() {
        let genesis_hash = BlockHash::all_zeros();

        // Three miners: A (oldest), B (middle), C (newest)
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);
        let header_c = build_test_header(&header_b.block_hash().to_string(), PUBKEY_3G, 2);
        let single_difficulty = header_a.get_difficulty(TEST_NETWORK);

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

        // Set threshold so only the newest entry (C) is included,
        // B and A overflow past the threshold
        let result = window.get_distribution(single_difficulty);

        // Only C should be in distribution
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&header_c.miner_address));

        // All three keys should still exist because B and A are in overflow
        assert!(
            window.address_keys.value_for(0).is_some(),
            "overflow miner key should be preserved"
        );
        assert!(
            window.address_keys.value_for(1).is_some(),
            "overflow miner key should be preserved"
        );
        assert!(
            window.address_keys.value_for(2).is_some(),
            "active miner key should be preserved"
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
        window.get_distribution(u128::MAX);

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
            Some(&header_c.miner_address),
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
    fn test_overflow_uncle_address_key_preserved() {
        let genesis_hash = BlockHash::all_zeros();

        // Uncle miner (PUBKEY_3G) only appears as uncle in the overflow region
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();

        // Nephew at height 0 references the uncle (this will be in overflow)
        let nephew_header =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);

        // A second entry at height 1 by a different miner (this hits the threshold)
        let header_top = build_test_header(&nephew_header.block_hash().to_string(), PUBKEY_2G, 2);
        let single_difficulty = header_top.get_difficulty(TEST_NETWORK);

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

        // Threshold = single difficulty, so only entry_top is included;
        // entry_nephew and its uncle are in overflow
        let result = window.get_distribution(single_difficulty);

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&header_top.miner_address));

        // Uncle miner's key should be preserved because it is in overflow
        assert!(
            window.address_keys.value_for(uncle_miner_key).is_some(),
            "uncle miner key in overflow should be preserved"
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
}
