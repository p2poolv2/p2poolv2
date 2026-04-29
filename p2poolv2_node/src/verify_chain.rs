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

//! Debug tool that traverses the entire confirmed chain in a store.db
//! and verifies structural integrity of all blocks.
//!
//! Usage: verify_chain <path-to-store.db>

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use p2poolv2_lib::shares::validation::MAX_UNCLES;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::block_tx_metadata::Status;
use std::collections::{HashMap, HashSet};
use std::env;
use std::process;

/// Summary of verification results printed at the end.
struct VerificationSummary {
    total_confirmed: u32,
    total_uncles: u32,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl VerificationSummary {
    fn new() -> Self {
        Self {
            total_confirmed: 0,
            total_uncles: 0,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn error(&mut self, message: String) {
        eprintln!("  ERROR: {message}");
        self.errors.push(message);
    }

    fn warn(&mut self, message: String) {
        eprintln!("  WARN:  {message}");
        self.warnings.push(message);
    }
}

/// Check that an uncle's parent is an ancestor of the nephew on the
/// confirmed chain, making it an ancestor-type uncle rather than a
/// sibling.
fn is_uncle_ancestor_type(
    uncle_parent: &BlockHash,
    nephew_height: u32,
    confirmed_hashes: &HashMap<u32, BlockHash>,
) -> bool {
    for height in 0..nephew_height {
        if let Some(confirmed_hash) = confirmed_hashes.get(&height) {
            if *confirmed_hash == *uncle_parent {
                return true;
            }
        }
    }
    false
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: verify_chain <path-to-store.db>");
        process::exit(1);
    }
    let db_path = &args[1];

    println!("Opening store at: {db_path}");
    let store = match Store::new(db_path.clone(), true) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("Failed to open store: {error}");
            process::exit(1);
        }
    };

    let top_height = match store.get_top_confirmed_height() {
        Ok(height) => height,
        Err(error) => {
            eprintln!("Failed to read top confirmed height: {error}");
            process::exit(1);
        }
    };

    println!("Top confirmed height: {top_height}");

    let mut summary = VerificationSummary::new();

    // Track confirmed hashes by height for parent linkage checks
    let mut confirmed_hashes: HashMap<u32, BlockHash> =
        HashMap::with_capacity((top_height + 1) as usize);

    // Track which confirmed nephew references each uncle
    let mut uncle_to_nephew: HashMap<BlockHash, BlockHash> =
        HashMap::with_capacity((top_height + 1) as usize);

    // Set of all confirmed blockhashes for quick lookup
    let mut confirmed_set: HashSet<BlockHash> = HashSet::with_capacity((top_height + 1) as usize);

    // Previous block's chain_work for monotonicity check
    let mut previous_chain_work = None;

    let mut height = 0u32;
    while height <= top_height {
        summary.total_confirmed += 1;

        // 1. Get confirmed blockhash at this height
        let blockhash = match store.get_confirmed_at_height(height) {
            Ok(hash) => hash,
            Err(error) => {
                summary.error(format!("h:{height} - missing confirmed entry: {error}"));
                height += 1;
                continue;
            }
        };

        confirmed_hashes.insert(height, blockhash);
        confirmed_set.insert(blockhash);

        // 2. Verify header exists
        let header = match store.get_share_header(&blockhash) {
            Ok(Some(header)) => header,
            Ok(None) => {
                summary.error(format!(
                    "h:{height} {blockhash} - header missing from Header CF"
                ));
                height += 1;
                continue;
            }
            Err(error) => {
                summary.error(format!(
                    "h:{height} {blockhash} - error reading header: {error}"
                ));
                height += 1;
                continue;
            }
        };

        // 3. Verify full block data exists
        if !store.share_block_exists(&blockhash) {
            summary.error(format!(
                "h:{height} {blockhash} - block data missing (no txids in BlockTxids CF)"
            ));
        }

        // 4. Verify share can be fully reconstructed
        let share = store.get_share(&blockhash);
        match &share {
            Some(share_block) => {
                // 5. Verify transactions non-empty (at least coinbase)
                if share_block.transactions.is_empty() {
                    summary.error(format!(
                        "h:{height} {blockhash} - share has zero transactions (expected at least coinbase)"
                    ));
                }
            }
            None => {
                summary.error(format!(
                    "h:{height} {blockhash} - failed to reconstruct ShareBlock from store"
                ));
            }
        }

        // 6. Verify metadata exists and status is Confirmed
        match store.get_block_metadata(&blockhash) {
            Ok(metadata) => {
                if metadata.status != Status::Confirmed {
                    let status = metadata.status;
                    summary.error(format!(
                        "h:{height} {blockhash} - metadata status is {status:?}, expected Confirmed"
                    ));
                }

                // 7. Verify expected_height matches confirmed index height
                match metadata.expected_height {
                    Some(expected) if expected != height => {
                        summary.error(format!(
                            "h:{height} {blockhash} - metadata expected_height {expected} != confirmed index height {height}"
                        ));
                    }
                    None => {
                        summary.error(format!(
                            "h:{height} {blockhash} - metadata expected_height is None"
                        ));
                    }
                    _ => {}
                }

                // 8. Chain work monotonically increasing
                if let Some(prev_work) = previous_chain_work {
                    let chain_work = metadata.chain_work;
                    if chain_work <= prev_work {
                        summary.error(format!(
                            "h:{height} {blockhash} - chain_work {chain_work:?} not greater than previous {prev_work:?}"
                        ));
                    }
                }
                previous_chain_work = Some(metadata.chain_work);
            }
            Err(error) => {
                summary.error(format!(
                    "h:{height} {blockhash} - metadata missing: {error}"
                ));
            }
        }

        // 9. Parent linkage: prev_share_blockhash should match previous confirmed
        if height > 0 {
            if let Some(expected_parent) = confirmed_hashes.get(&(height - 1)) {
                let prev_height = height - 1;
                let prev_hash = header.prev_share_blockhash;
                if prev_hash != *expected_parent {
                    summary.error(format!(
                        "h:{height} {blockhash} - prev_share_blockhash {prev_hash} != confirmed at h:{prev_height} which is {expected_parent}"
                    ));
                }
            }
        } else {
            // Genesis: prev_share_blockhash should be all zeros
            let zero_hash = BlockHash::all_zeros();
            let prev_hash = header.prev_share_blockhash;
            if prev_hash != zero_hash {
                summary.warn(format!(
                    "h:0 {blockhash} - genesis prev_share_blockhash is {prev_hash} (expected all zeros)"
                ));
            }
        }

        // 10. Uncle checks
        let uncle_count = header.uncles.len();
        if uncle_count > MAX_UNCLES {
            summary.error(format!(
                "h:{height} {blockhash} - uncle count {uncle_count} exceeds MAX_UNCLES ({MAX_UNCLES})"
            ));
        }

        for uncle_hash in &header.uncles {
            summary.total_uncles += 1;

            // 10a. Uncle block exists in store
            let uncle_header = match store.get_share_header(uncle_hash) {
                Ok(Some(uncle_header)) => Some(uncle_header),
                Ok(None) => {
                    summary.error(format!(
                        "h:{height} {blockhash} - uncle {uncle_hash} header missing from store"
                    ));
                    None
                }
                Err(error) => {
                    summary.error(format!(
                        "h:{height} {blockhash} - error reading uncle {uncle_hash} header: {error}"
                    ));
                    None
                }
            };

            if !store.share_block_exists(uncle_hash) {
                summary.warn(format!(
                    "h:{height} {blockhash} - uncle {uncle_hash} block data missing (header-only)"
                ));
            }

            // 10b. Uncle not referenced by another confirmed nephew
            if let Some(previous_nephew) = uncle_to_nephew.get(uncle_hash) {
                summary.error(format!(
                    "h:{height} {blockhash} - uncle {uncle_hash} already referenced by confirmed nephew {previous_nephew}"
                ));
            } else {
                uncle_to_nephew.insert(*uncle_hash, blockhash);
            }

            // 10c. Uncle is not on the confirmed chain
            if confirmed_set.contains(uncle_hash) {
                summary.error(format!(
                    "h:{height} {blockhash} - uncle {uncle_hash} is on the confirmed chain"
                ));
            }

            // 10d. Uncle is ancestor-type (its parent is an ancestor of the nephew)
            if let Some(uncle_hdr) = &uncle_header {
                let uncle_parent = uncle_hdr.prev_share_blockhash;
                if !is_uncle_ancestor_type(
                    &uncle_parent,
                    height,
                    &confirmed_hashes,
                ) {
                    summary.error(format!(
                        "h:{height} {blockhash} - uncle {uncle_hash} parent {uncle_parent} is not an ancestor on confirmed chain (uncle should be an ancestor, not a sibling)"
                    ));
                }

                // 10e. Uncle should not have the same prev_share_blockhash as the nephew
                //       (that would make it a sibling, not an ancestor-type uncle)
                let nephew_parent = header.prev_share_blockhash;
                if uncle_parent == nephew_parent {
                    summary.warn(format!(
                        "h:{height} {blockhash} - uncle {uncle_hash} shares the same parent {uncle_parent} as the nephew (sibling uncle)"
                    ));
                }
            }
        }

        // Progress indicator every 1000 blocks
        if height % 1000 == 0 && height > 0 {
            println!("  verified {height} / {top_height} confirmed blocks...");
        }

        height += 1;
    }

    // Final summary
    println!("---");
    println!("Verification complete.");
    println!("  Confirmed blocks: {}", summary.total_confirmed);
    println!("  Total uncles referenced: {}", summary.total_uncles);
    println!("  Unique uncles: {}", uncle_to_nephew.len());
    println!("  Errors: {}", summary.errors.len());
    println!("  Warnings: {}", summary.warnings.len());

    if !summary.errors.is_empty() {
        println!("\nErrors found:");
        for (index, error) in summary.errors.iter().enumerate() {
            println!("  {}. {error}", index + 1);
        }
        process::exit(1);
    }

    if !summary.warnings.is_empty() {
        println!("\nWarnings:");
        for (index, warning) in summary.warnings.iter().enumerate() {
            println!("  {}. {warning}", index + 1);
        }
    }

    println!("\nChain verification passed.");
}
