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

use super::{ColumnFamily, Store, writer::StoreError};
use bitcoin::{BlockHash, Work, consensus::encode};

mod candidate;
mod confirmed;
pub mod organise_share;

/// Type to capture candidate and confirmed chains as vector of
/// height, blockhash pairs
type Chain = Vec<(u32, BlockHash)>;

/// Height type to avoid using u32
type Height = u32;

/// Top of a candidate or confirmed chain: blockhash, height, and cumulative work.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TopResult {
    pub hash: BlockHash,
    pub height: Height,
    pub work: Work,
}

/// Returns key for height with provided suffix
pub(super) fn height_to_key_with_suffix(height: Height, suffix: &str) -> Vec<u8> {
    [&height.to_be_bytes(), suffix.as_bytes()].concat()
}

impl Store {
    /// Fetch blockhashes from the BlockHeight CF for a given height range
    /// and key suffix. Filters iterator results to only include keys whose
    /// suffix matches, avoiding cross-contamination between candidate (":c")
    /// and confirmed (":f") entries that share the same height prefix.
    pub(super) fn get_chain_range(
        &self,
        from: Height,
        to: Height,
        suffix: &str,
    ) -> Result<Chain, StoreError> {
        if from > to {
            return Ok(Vec::new());
        }

        let block_height_cf = self.db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
        let suffix_bytes = suffix.as_bytes();

        let lower_key = height_to_key_with_suffix(from, suffix);
        // Upper bound is exclusive, so use to+1
        let upper_key = height_to_key_with_suffix(to + 1, suffix);

        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_lower_bound(lower_key.clone());
        read_opts.set_iterate_upper_bound(upper_key);

        let iter = self.db.iterator_cf_opt(
            &block_height_cf,
            read_opts,
            rocksdb::IteratorMode::From(&lower_key, rocksdb::Direction::Forward),
        );

        let capacity = (to - from + 1) as usize;
        let mut results = Vec::with_capacity(capacity);
        for item in iter.flatten() {
            let (key, value) = item;
            if key.ends_with(suffix_bytes) {
                results.push(encode::deserialize(&value)?);
            }
        }
        Ok((from..=to).zip(results).collect())
    }
}
