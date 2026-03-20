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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareHeader;
use bitcoin::BlockHash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use tracing::info;

/// Maximum PPLNS window duration: two weeks in seconds.
pub(crate) const MAX_PPLNS_WINDOW_SECONDS: u32 = 2 * 7 * 24 * 60 * 60;

/// Maximum number of confirmed shares in the PPLNS window.
/// At 6 shares per minute over 2 weeks: 6 * 60 * 24 * 14 = 120,960.
pub(crate) const MAX_PPLNS_WINDOW_SHARES: u32 = 6 * 60 * 24 * 14;

/// Estimated maximum shares in the PPLNS window.
/// Conservative 2x multiplier to account for variable block times.
pub(crate) const ESTIMATED_MAX_SHARES_IN_WINDOW: u32 = MAX_PPLNS_WINDOW_SHARES * 2;

/// Uncle weight factor: uncles receive 90% of their difficulty.
pub const UNCLE_WEIGHT_FACTOR: f64 = 0.9;

/// Nephew bonus factor: nephews receive 10% of each uncle's difficulty as bonus.
pub(crate) const NEPHEW_BONUS_FACTOR: f64 = 0.1;

/// Initial capacity for the confirmed entries vector.
/// Based on typical PPLNS window of ~6 hours (6 shares/min * 60 * 6).
const INITIAL_ENTRIES_CAPACITY: usize = 2160;

/// Reasonable upper bound for distinct miners when sizing the difficulty map.
const ADDRESS_MAP_INIT_COUNT: usize = 256;

/// A cached confirmed share entry with only the fields needed for payout.
struct ConfirmedEntry {
    blockhash: BlockHash,
    miner_address: String,
    difficulty: f64,
    uncle_entries: Vec<UncleEntry>,
    /// Total weighted difficulty this entry contributes to the aggregate.
    /// Equals difficulty + nephew_bonus (from uncles) + sum of uncle weighted difficulties.
    total_weighted_difficulty: f64,
}

/// A cached uncle entry with only the fields needed for payout.
pub struct UncleEntry {
    /// Miner address string for the uncle share.
    pub miner_address: String,
    /// Base difficulty of the uncle share before weighting.
    pub difficulty: f64,
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
    /// Incrementally maintained aggregate of weighted difficulty per
    /// miner address. This gives us the payout distribution directly.
    address_difficulty_map: HashMap<String, f64>,
    /// Sum of all confirmed entries' difficulties  in the window.
    total_accumulated_difficulty: f64,
}

impl Default for PplnsWindow {
    /// Create an empty PplnsWindow with preallocated capacity.
    fn default() -> Self {
        Self {
            confirmed_entries: VecDeque::with_capacity(INITIAL_ENTRIES_CAPACITY),
            cached_tip_blockhash: None,
            cached_top_height: None,
            address_difficulty_map: HashMap::with_capacity(ADDRESS_MAP_INIT_COUNT),
            total_accumulated_difficulty: 0.0,
        }
    }
}

impl PplnsWindow {
    /// Check whether the cache has any confirmed entries.
    pub fn is_empty(&self) -> bool {
        self.confirmed_entries.is_empty()
    }

    /// Return the cached address difficulty map.
    ///
    /// This map is maintained incrementally by `update()` so no iteration
    /// over confirmed entries is needed.
    pub fn get_address_difficulty_map(&self) -> &HashMap<String, f64> {
        &self.address_difficulty_map
    }

    /// Update the cache from the chain store incrementally.
    ///
    /// Loads only newly confirmed headers since the last cached height,
    /// detects reorgs (invalidating the cache if needed), and evicts
    /// overflow entries that exceed either MAX_PPLNS_WINDOW_SHARES or
    /// total_difficulty.
    ///
    /// Returns Ok(true) if the cache was updated, Ok(false) if no changes.
    pub fn update(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
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
            if self.detect_reorg(cached_height, tip_height, chain_store_handle)? {
                info!("Reorg detected in PPLNS window, invalidating cache");
                self.invalidate();
            }
        }

        if let Some(cached_height) = self.cached_top_height {
            if tip_height > cached_height {
                self.load_range(chain_store_handle, cached_height + 1, tip_height)?;
                self.evict_overflow(total_difficulty);
            }
        } else {
            let estimated_min_height = tip_height.saturating_sub(ESTIMATED_MAX_SHARES_IN_WINDOW);
            self.load_range(chain_store_handle, estimated_min_height, tip_height)?;
            self.evict_overflow(total_difficulty);
        }

        self.cached_tip_blockhash = Some(tip_blockhash);
        self.cached_top_height = Some(tip_height);

        Ok(true)
    }

    /// Clear all cached state, forcing a full reload on next update.
    fn invalidate(&mut self) {
        self.confirmed_entries.clear();
        self.address_difficulty_map.clear();
        self.total_accumulated_difficulty = 0.0;
        self.cached_tip_blockhash = None;
        self.cached_top_height = None;
    }

    /// Detect whether the confirmed chain has diverged from our cached state.
    ///
    /// Checks if the confirmed blockhash at our cached top height still
    /// matches what we have cached. Also detects rollbacks where the new
    /// tip is shorter than our cached chain.
    fn detect_reorg(
        &self,
        cached_height: u32,
        new_tip_height: u32,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        if new_tip_height < cached_height {
            return Ok(true);
        }

        let confirmed_at_cached = chain_store_handle.get_confirmed_at_height(cached_height)?;

        match self.confirmed_entries.front() {
            Some(entry) if entry.blockhash != confirmed_at_cached => Ok(true),
            None => Ok(true),
            _ => Ok(false),
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
        let uncle_lookup = fetch_uncle_lookup(chain_store_handle, &all_uncle_hashes)?;

        // Headers arrive newest-to-oldest. Reverse and push_front so
        // the newest entry ends up at position 0 in the deque.
        for (blockhash, header) in confirmed_headers.into_iter().rev() {
            let difficulty = header.get_difficulty();
            let uncle_entries = resolve_uncle_entries(&header.uncles, &uncle_lookup);
            let entry = build_confirmed_entry(
                blockhash,
                header.miner_address.to_string(),
                difficulty,
                uncle_entries,
            );
            self.add_entry_to_aggregate(&entry);
            self.confirmed_entries.push_front(entry);
        }

        Ok(())
    }

    /// Add a confirmed entry's weighted difficulty contributions to the aggregate.
    fn add_entry_to_aggregate(&mut self, entry: &ConfirmedEntry) {
        let mut nephew_bonus: f64 = 0.0;

        for uncle_entry in &entry.uncle_entries {
            let uncle_weighted = uncle_entry.difficulty * UNCLE_WEIGHT_FACTOR;
            *self
                .address_difficulty_map
                .entry(uncle_entry.miner_address.clone())
                .or_insert(0.0) += uncle_weighted;

            nephew_bonus += uncle_entry.difficulty * NEPHEW_BONUS_FACTOR;
        }

        *self
            .address_difficulty_map
            .entry(entry.miner_address.clone())
            .or_insert(0.0) += entry.difficulty + nephew_bonus;

        self.total_accumulated_difficulty += entry.difficulty;
    }

    /// Remove a confirmed entry's weighted difficulty contributions from the aggregate.
    fn remove_entry_from_aggregate(&mut self, entry: &ConfirmedEntry) {
        let mut nephew_bonus: f64 = 0.0;

        for uncle_entry in &entry.uncle_entries {
            let uncle_weighted = uncle_entry.difficulty * UNCLE_WEIGHT_FACTOR;
            if let Some(value) = self
                .address_difficulty_map
                .get_mut(&uncle_entry.miner_address)
            {
                *value -= uncle_weighted;
            }

            nephew_bonus += uncle_entry.difficulty * NEPHEW_BONUS_FACTOR;
        }

        if let Some(value) = self.address_difficulty_map.get_mut(&entry.miner_address) {
            *value -= entry.difficulty + nephew_bonus;
        }

        self.total_accumulated_difficulty -= entry.difficulty;

        self.address_difficulty_map
            .retain(|_, difficulty| *difficulty > f64::EPSILON);
    }

    /// Evict the oldest confirmed entries until both the share count and
    /// total accumulated difficulty are within their limits.
    /// Check whether accumulated difficulty exceeds the threshold.
    ///
    /// Uses floor comparison to avoid floating point precision issues
    /// where repeated subtraction leaves a tiny residual above the limit.
    fn difficulty_exceeds_limit(&self, total_difficulty: f64) -> bool {
        self.total_accumulated_difficulty.floor() > total_difficulty.floor()
    }

    fn evict_overflow(&mut self, total_difficulty: f64) {
        let max_entries = MAX_PPLNS_WINDOW_SHARES as usize;

        while self.confirmed_entries.len() > max_entries
            || self.difficulty_exceeds_limit(total_difficulty)
        {
            if let Some(entry) = self.confirmed_entries.pop_back() {
                self.remove_entry_from_aggregate(&entry);
            } else {
                return;
            }
        }
    }
}

/// Build a ConfirmedEntry with pre-computed total weighted difficulty.
fn build_confirmed_entry(
    blockhash: BlockHash,
    miner_address: String,
    difficulty: f64,
    uncle_entries: Vec<UncleEntry>,
) -> ConfirmedEntry {
    let mut nephew_bonus: f64 = 0.0;
    let mut uncle_weighted_sum: f64 = 0.0;
    for uncle_entry in &uncle_entries {
        uncle_weighted_sum += uncle_entry.difficulty * UNCLE_WEIGHT_FACTOR;
        nephew_bonus += uncle_entry.difficulty * NEPHEW_BONUS_FACTOR;
    }
    let total_weighted_difficulty = difficulty + nephew_bonus + uncle_weighted_sum;

    ConfirmedEntry {
        blockhash,
        miner_address,
        difficulty,
        uncle_entries,
        total_weighted_difficulty,
    }
}

/// Collect unique uncle blockhashes from confirmed headers for batch fetching.
fn collect_unique_uncle_hashes(confirmed_headers: &[(BlockHash, ShareHeader)]) -> Vec<BlockHash> {
    let mut seen_uncles: HashSet<BlockHash> = HashSet::new();
    let mut all_uncle_hashes = Vec::with_capacity(confirmed_headers.len());

    for (_blockhash, header) in confirmed_headers {
        for uncle_hash in &header.uncles {
            if seen_uncles.insert(*uncle_hash) {
                all_uncle_hashes.push(*uncle_hash);
            }
        }
    }

    all_uncle_hashes
}

/// Fetch uncle headers from the chain store and build a lookup table.
fn fetch_uncle_lookup(
    chain_store_handle: &ChainStoreHandle,
    uncle_hashes: &[BlockHash],
) -> Result<HashMap<BlockHash, UncleEntry>, Box<dyn Error + Send + Sync>> {
    if uncle_hashes.is_empty() {
        return Ok(HashMap::new());
    }

    let uncle_headers = chain_store_handle.get_share_headers(uncle_hashes)?;
    let mut uncle_lookup = HashMap::with_capacity(uncle_headers.len());
    for (blockhash, header) in uncle_headers {
        let difficulty = header.get_difficulty();
        uncle_lookup.insert(
            blockhash,
            UncleEntry {
                miner_address: header.miner_address.to_string(),
                difficulty,
            },
        );
    }
    Ok(uncle_lookup)
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
                miner_address: uncle_entry.miner_address.clone(),
                difficulty: uncle_entry.difficulty,
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
    /// newest-to-oldest.
    pub fn populate_for_benchmark(
        &mut self,
        confirmed_shares: Vec<(BlockHash, String, f64, Vec<UncleEntry>)>,
    ) {
        self.invalidate();
        self.confirmed_entries.reserve(confirmed_shares.len());

        for (blockhash, miner_address, difficulty, uncle_entries) in confirmed_shares {
            let entry = build_confirmed_entry(blockhash, miner_address, difficulty, uncle_entries);
            self.add_entry_to_aggregate(&entry);
            self.confirmed_entries.push_back(entry);
        }

        if let Some(entry) = self.confirmed_entries.front() {
            self.cached_tip_blockhash = Some(entry.blockhash);
        }
        self.cached_top_height = Some(self.confirmed_entries.len() as u32);
    }

    /// Simulate the computational work of an incremental update for benchmarking.
    ///
    /// Performs the same processing as update -> load_range -> evict_overflow
    /// without requiring a ChainStoreHandle. Takes confirmed headers in
    /// newest-to-oldest order (as returned by the chain store) and uncle
    /// headers to process.
    pub fn load_entries_for_benchmark(
        &mut self,
        confirmed_headers: Vec<(BlockHash, ShareHeader)>,
        uncle_headers: Vec<(BlockHash, ShareHeader)>,
        total_difficulty: f64,
    ) {
        let mut uncle_lookup: HashMap<BlockHash, UncleEntry> =
            HashMap::with_capacity(uncle_headers.len());
        for (blockhash, header) in uncle_headers {
            let difficulty = header.get_difficulty();
            uncle_lookup.insert(
                blockhash,
                UncleEntry {
                    miner_address: header.miner_address.to_string(),
                    difficulty,
                },
            );
        }

        for (blockhash, header) in confirmed_headers.into_iter().rev() {
            let difficulty = header.get_difficulty();
            let uncle_entries = resolve_uncle_entries(&header.uncles, &uncle_lookup);
            let entry = build_confirmed_entry(
                blockhash,
                header.miner_address.to_string(),
                difficulty,
                uncle_entries,
            );
            self.add_entry_to_aggregate(&entry);
            self.confirmed_entries.push_front(entry);
        }

        if let Some(entry) = self.confirmed_entries.front() {
            self.cached_tip_blockhash = Some(entry.blockhash);
        }
        self.cached_top_height = Some(self.confirmed_entries.len() as u32);

        self.evict_overflow(total_difficulty);
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

    /// Create a ConfirmedEntry from a ShareHeader with no uncles.
    fn entry_from_header(header: &ShareHeader) -> ConfirmedEntry {
        build_confirmed_entry(
            header.block_hash(),
            header.miner_address.to_string(),
            header.get_difficulty(),
            Vec::new(),
        )
    }

    /// Create a ConfirmedEntry from a ShareHeader with resolved uncle entries.
    fn entry_from_header_with_uncles(
        header: &ShareHeader,
        uncle_entries: Vec<UncleEntry>,
    ) -> ConfirmedEntry {
        build_confirmed_entry(
            header.block_hash(),
            header.miner_address.to_string(),
            header.get_difficulty(),
            uncle_entries,
        )
    }

    /// Create a UncleEntry from a ShareHeader for test setup.
    fn uncle_entry_from_header(header: &ShareHeader) -> UncleEntry {
        UncleEntry {
            miner_address: header.miner_address.to_string(),
            difficulty: header.get_difficulty(),
        }
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
    /// Returns (headers_vec, tip_hash) where headers_vec is newest-to-oldest.
    fn build_test_chain(
        count: usize,
        miner_pubkeys: &[&str],
    ) -> (Vec<(BlockHash, ShareHeader)>, BlockHash) {
        let genesis_hash = BlockHash::all_zeros();
        let mut headers = Vec::with_capacity(count);
        let mut prev_hash = genesis_hash.to_string();

        for index in 0..count {
            let pubkey = miner_pubkeys[index % miner_pubkeys.len()];
            let header = build_test_header(&prev_hash, pubkey, 2);
            let blockhash = header.block_hash();
            prev_hash = blockhash.to_string();
            headers.push((blockhash, header));
        }

        let tip_hash = headers.last().unwrap().0;
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

        let mut window = PplnsWindow::default();
        let updated = window.update(&mock, f64::MAX).unwrap();

        assert!(updated);
        assert!(!window.is_empty());
        assert_eq!(window.confirmed_entries.len(), 5);
        assert_eq!(window.cached_tip_blockhash, Some(tip_hash));
        assert_eq!(window.cached_top_height, Some(4));
    }

    #[test]
    fn test_incremental_load_new_shares() {
        let (all_headers, _) = build_test_chain(7, &[PUBKEY_G, PUBKEY_2G]);
        // Initial chain: headers at heights 0-4 (indices 2..7 in all_headers reversed)
        let initial_headers: Vec<(BlockHash, ShareHeader)> = all_headers[2..].to_vec();
        let initial_tip_hash = initial_headers[0].0;

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

        let mut window = PplnsWindow::default();
        window.update(&mock, f64::MAX).unwrap();
        assert_eq!(window.confirmed_entries.len(), 5);

        // Now extend to height 6
        let new_tip_hash = all_headers[0].0;
        let new_headers: Vec<(BlockHash, ShareHeader)> = all_headers[0..2].to_vec();
        let older_confirmed_tip_header = initial_headers[0].0;

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

        let updated = window.update(&mock2, f64::MAX).unwrap();
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
        let batch1: Vec<(BlockHash, ShareHeader)> = all_headers[6..].to_vec();
        let tip1 = batch1[0].0;

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

        let mut window = PplnsWindow::default();
        window.update(&mock1, f64::MAX).unwrap();
        assert_eq!(window.confirmed_entries.len(), 3);
        // Deque should be [height2, height1, height0]
        assert_eq!(window.confirmed_entries[0].blockhash, all_headers[6].0);
        assert_eq!(window.confirmed_entries[1].blockhash, all_headers[7].0);
        assert_eq!(window.confirmed_entries[2].blockhash, all_headers[8].0);

        // Batch 2: heights 3-5 (indices 3..6)
        let batch2: Vec<(BlockHash, ShareHeader)> = all_headers[3..6].to_vec();
        let tip2 = batch2[0].0;
        let confirmed_at_2 = batch1[0].0;

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

        window.update(&mock2, f64::MAX).unwrap();
        assert_eq!(window.confirmed_entries.len(), 6);
        // Deque should be [height5, height4, height3, height2, height1, height0]
        assert_eq!(window.confirmed_entries[0].blockhash, all_headers[3].0);
        assert_eq!(window.confirmed_entries[1].blockhash, all_headers[4].0);
        assert_eq!(window.confirmed_entries[2].blockhash, all_headers[5].0);
        assert_eq!(window.confirmed_entries[3].blockhash, all_headers[6].0);
        assert_eq!(window.confirmed_entries[4].blockhash, all_headers[7].0);
        assert_eq!(window.confirmed_entries[5].blockhash, all_headers[8].0);

        // Batch 3: heights 6-8 (indices 0..3)
        let batch3: Vec<(BlockHash, ShareHeader)> = all_headers[0..3].to_vec();
        let tip3 = batch3[0].0;
        let confirmed_at_5 = batch2[0].0;

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

        window.update(&mock3, f64::MAX).unwrap();
        assert_eq!(window.confirmed_entries.len(), 9);
        // Full deque: [height8, height7, ..., height0] -- strict newest-to-oldest
        for index in 0..9 {
            assert_eq!(
                window.confirmed_entries[index].blockhash, all_headers[index].0,
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

        let mut window = PplnsWindow::default();
        window.update(&mock, f64::MAX).unwrap();

        // Second update with same tip
        let mut mock2 = MockChainStoreHandle::default();
        mock2.expect_get_chain_tip().returning(move || Ok(tip_hash));

        let updated = window.update(&mock2, f64::MAX).unwrap();
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

        let mut window = PplnsWindow::default();
        window.update(&mock, f64::MAX).unwrap();
        assert_eq!(window.confirmed_entries.len(), 5);

        // Reorg: different chain B at same heights
        let (headers_b, tip_b) = build_test_chain(5, &[PUBKEY_2G]);
        let different_hash_at_4 = headers_b[0].0;

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

        let updated = window.update(&mock2, f64::MAX).unwrap();
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

        let mut window = PplnsWindow::default();
        // Newest at front: c, b, a
        window
            .confirmed_entries
            .push_back(entry_from_header(&header_c));
        window
            .confirmed_entries
            .push_back(entry_from_header(&header_b));
        window
            .confirmed_entries
            .push_back(entry_from_header(&header_a));

        // With 3 entries and MAX_PPLNS_WINDOW_SHARES >> 3, no eviction occurs
        window.evict_overflow(f64::MAX);
        assert_eq!(window.confirmed_entries.len(), 3);
    }

    #[test]
    fn test_count_based_eviction_truncates_oldest() {
        let genesis_hash = BlockHash::all_zeros();
        let header_a = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let hash_a = header_a.block_hash();
        let header_b = build_test_header(&header_a.block_hash().to_string(), PUBKEY_2G, 2);
        let hash_b = header_b.block_hash();

        let mut window = PplnsWindow::default();
        // Fill beyond max: push max + 2 entries, first two are our named ones
        window
            .confirmed_entries
            .push_back(entry_from_header(&header_b));
        window
            .confirmed_entries
            .push_back(entry_from_header(&header_a));

        // Pad to exceed MAX_PPLNS_WINDOW_SHARES
        let max_shares = MAX_PPLNS_WINDOW_SHARES as usize;
        let padding_needed = max_shares; // total will be max + 2
        for index in 0..padding_needed {
            window.confirmed_entries.push_back(build_confirmed_entry(
                BlockHash::all_zeros(),
                format!("padding_{index}"),
                1.0,
                Vec::new(),
            ));
        }

        assert_eq!(window.confirmed_entries.len(), max_shares + 2);

        window.evict_overflow(f64::MAX);

        // Should be truncated to max_shares, dropping the 2 oldest from the back
        assert_eq!(window.confirmed_entries.len(), max_shares);
        // The newest entries (header_b, header_a) at front should still be present
        assert_eq!(window.confirmed_entries[0].blockhash, hash_b);
        assert_eq!(window.confirmed_entries[1].blockhash, hash_a);
    }

    #[test]
    fn test_address_difficulty_map() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let difficulty1 = header1.get_difficulty();
        let difficulty2 = header2.get_difficulty();

        let mut window = PplnsWindow::default();
        let entry2 = entry_from_header(&header2);
        let entry1 = entry_from_header(&header1);
        window.add_entry_to_aggregate(&entry2);
        window.confirmed_entries.push_back(entry2);
        window.add_entry_to_aggregate(&entry1);
        window.confirmed_entries.push_back(entry1);

        let result = window.get_address_difficulty_map();

        let miner1 = header1.miner_address.to_string();
        let miner2 = header2.miner_address.to_string();
        assert_eq!(result.len(), 2);
        assert!((result[&miner1] - difficulty1).abs() < 0.001);
        assert!((result[&miner2] - difficulty2).abs() < 0.001);
    }

    #[test]
    fn test_difficulty_cutoff_evicts_oldest() {
        let genesis_hash = BlockHash::all_zeros();
        let header1 = build_test_header(&genesis_hash.to_string(), PUBKEY_G, 2);
        let header2 = build_test_header(&header1.block_hash().to_string(), PUBKEY_2G, 2);
        let header3 = build_test_header(&header2.block_hash().to_string(), PUBKEY_3G, 2);
        let difficulty = header1.get_difficulty();

        let mut window = PplnsWindow::default();
        let entry3 = entry_from_header(&header3);
        let entry2 = entry_from_header(&header2);
        let entry1 = entry_from_header(&header1);
        window.add_entry_to_aggregate(&entry3);
        window.confirmed_entries.push_back(entry3);
        window.add_entry_to_aggregate(&entry2);
        window.confirmed_entries.push_back(entry2);
        window.add_entry_to_aggregate(&entry1);
        window.confirmed_entries.push_back(entry1);

        // All shares have the same difficulty, total is 3x. Evict with cutoff
        // that allows exactly one share's difficulty. After evicting the two
        // oldest entries the total drops to 1x which satisfies the limit.
        window.evict_overflow(difficulty);

        // Only the newest share (header3) should remain
        assert_eq!(window.confirmed_entries.len(), 1);
        assert_eq!(window.confirmed_entries[0].blockhash, header3.block_hash());
        let result = window.get_address_difficulty_map();
        let miner3 = header3.miner_address.to_string();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&miner3));
    }

    #[test]
    fn test_uncle_weighting() {
        let genesis_hash = BlockHash::all_zeros();

        // Uncle header
        let uncle_header = build_test_header(&genesis_hash.to_string(), PUBKEY_3G, 2);
        let uncle_hash = uncle_header.block_hash();
        let uncle_difficulty = uncle_header.get_difficulty();

        // Nephew that references the uncle
        let nephew_header =
            build_test_header_with_uncles(&genesis_hash.to_string(), PUBKEY_G, 2, vec![uncle_hash]);
        let nephew_difficulty = nephew_header.get_difficulty();

        let mut window = PplnsWindow::default();
        let nephew_entry = entry_from_header_with_uncles(
            &nephew_header,
            vec![uncle_entry_from_header(&uncle_header)],
        );
        window.add_entry_to_aggregate(&nephew_entry);
        window.confirmed_entries.push_back(nephew_entry);

        let result = window.get_address_difficulty_map();

        let nephew_miner = nephew_header.miner_address.to_string();
        let uncle_miner = uncle_header.miner_address.to_string();

        // Uncle gets 90% of its difficulty
        let expected_uncle_weight = uncle_difficulty * UNCLE_WEIGHT_FACTOR;
        assert!((result[&uncle_miner] - expected_uncle_weight).abs() < 0.001);

        // Nephew gets base difficulty + 10% of uncle's difficulty
        let expected_nephew_weight = nephew_difficulty + uncle_difficulty * NEPHEW_BONUS_FACTOR;
        assert!((result[&nephew_miner] - expected_nephew_weight).abs() < 0.001);
    }

    #[test]
    fn test_empty_chain() {
        let genesis_hash = BlockHash::all_zeros();

        let mut mock = MockChainStoreHandle::default();
        mock.expect_get_chain_tip()
            .returning(move || Ok(genesis_hash));
        mock.expect_get_block_metadata()
            .returning(move |_| Ok(metadata_no_height()));

        let mut window = PplnsWindow::default();
        let updated = window.update(&mock, f64::MAX).unwrap();

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

        let mut window = PplnsWindow::default();
        window.update(&mock, f64::MAX).unwrap();
        assert_eq!(window.cached_top_height, Some(4));

        // Reorg to shorter chain at height 2
        let (short_headers, short_tip) = build_test_chain(3, &[PUBKEY_2G]);

        let mut mock2 = MockChainStoreHandle::default();
        let short_headers_clone = short_headers.clone();
        mock2
            .expect_get_chain_tip()
            .returning(move || Ok(short_tip));
        mock2
            .expect_get_block_metadata()
            .returning(move |_| Ok(metadata_at_height(2)));
        mock2
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(short_headers_clone.clone()));
        mock2
            .expect_get_share_headers()
            .returning(|_| Ok(Vec::new()));

        let updated = window.update(&mock2, f64::MAX).unwrap();
        assert!(updated);
        assert_eq!(window.confirmed_entries.len(), 3);
        assert_eq!(window.cached_top_height, Some(2));
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

        let uncle_entry = uncle_entry_from_header(&uncle_header);

        let mut window = PplnsWindow::default();
        window
            .confirmed_entries
            .push_back(entry_from_header_with_uncles(
                &nephew1,
                vec![uncle_entry_from_header(&uncle_header)],
            ));
        window
            .confirmed_entries
            .push_back(entry_from_header_with_uncles(&nephew2, vec![uncle_entry]));

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
}
