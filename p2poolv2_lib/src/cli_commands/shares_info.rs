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

use bitcoin::{CompactTarget, Target};

use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::dag_store::{ShareInfo, UncleInfo};
use crate::utils::short_hex::short_id;
use crate::utils::time_provider::format_timestamp;
use std::error::Error;

/// Compute difficulty from a compact target using Bitcoin's true difficulty.
///
/// Uses `Target::difficulty_float()` which computes difficulty relative to
/// Bitcoin mainnet's difficulty-1 target, making it chain-neutral.
fn compact_target_to_difficulty(bits: CompactTarget) -> f64 {
    Target::from_compact(bits).difficulty_float()
}

/// Format collected shares as a human-readable text table.
///
/// Each share is displayed with its height, short blockhash, parent short hash,
/// short miner ID, difficulty, timestamp, and uncle information. Nephew rows
/// (shares that reference uncles) show up to three uncle short hashes in the
/// Uncles column. Uncle rows are marked with `*` in the Uncles column.
fn format_table(shares: &[ShareInfo], from_height: u32, to_height: u32) -> String {
    // Collect all uncle blockhashes so we can mark uncle rows with *
    let uncle_blockhash_count: usize = shares.iter().map(|share| share.uncles.len()).sum();
    let mut uncle_blockhashes = std::collections::HashSet::with_capacity(uncle_blockhash_count);
    for share in shares {
        for uncle in &share.uncles {
            uncle_blockhashes.insert(uncle.blockhash);
        }
    }

    // Pre-compute total row count for capacity: each share + its uncles
    let total_rows: usize = shares.iter().map(|share| 1 + share.uncles.len()).sum();
    let mut output = String::with_capacity(total_rows * 160);

    output.push_str(&format!(
        "Shares from height {} to {} ({} shares):\n",
        from_height,
        to_height,
        shares.len()
    ));
    output.push_str(&format!(
        "{:>6} | {:8} | {:8} | {:8} | {:>12} | {:19} | {}\n",
        "Height", "Hash", "Parent", "Miner", "Difficulty", "Time", "Uncles"
    ));
    output.push_str(&format!("{}\n", "-".repeat(101)));

    for share in shares {
        let blockhash_string = share.blockhash.to_string();
        let share_short_hash = short_id(&blockhash_string);
        let prev_blockhash_string = share.prev_blockhash.to_string();
        let parent_short_hash = short_id(&prev_blockhash_string);
        let miner_short_id = short_id(&share.miner_pubkey);
        let formatted_time = format_timestamp(share.timestamp as u64);
        let difficulty = compact_target_to_difficulty(share.bits);

        let is_uncle = uncle_blockhashes.contains(&share.blockhash);
        let uncle_column = build_uncle_column(is_uncle, &share.uncles);

        output.push_str(&format!(
            "{:>6} | {} | {} | {} | {:>12.4} | {} | {}\n",
            share.height,
            share_short_hash,
            parent_short_hash,
            miner_short_id,
            difficulty,
            formatted_time,
            uncle_column
        ));

        for uncle in &share.uncles {
            let uncle_blockhash_string = uncle.blockhash.to_string();
            let uncle_short_hash = short_id(&uncle_blockhash_string);
            let uncle_prev_string = uncle.prev_blockhash.to_string();
            let uncle_parent_short_hash = short_id(&uncle_prev_string);
            let uncle_miner_short_id = short_id(&uncle.miner_pubkey);
            let uncle_height_display = uncle
                .height
                .map(|height| format!("{height}"))
                .unwrap_or_else(|| "?".to_string());
            let uncle_formatted_time = format_timestamp(uncle.timestamp as u64);

            output.push_str(&format!(
                "{:>6} | {} | {} | {} | {:>12} | {} | *\n",
                uncle_height_display,
                uncle_short_hash,
                uncle_parent_short_hash,
                uncle_miner_short_id,
                "-",
                uncle_formatted_time
            ));
        }
    }

    output
}

/// Build the uncle column string for a share row.
///
/// If the share is itself an uncle, prepends `*`. If the share references
/// uncles (is a nephew), appends up to three uncle short hashes.
fn build_uncle_column(is_uncle: bool, uncles: &[UncleInfo]) -> String {
    let mut parts = Vec::with_capacity(4);

    if is_uncle {
        parts.push("*".to_string());
    }

    for uncle in uncles.iter().take(3) {
        let uncle_blockhash_string = uncle.blockhash.to_string();
        parts.push(short_id(&uncle_blockhash_string).to_string());
    }

    parts.join(" ")
}

/// Execute the shares-info command.
///
/// Resolves the height range from the provided arguments, collects confirmed
/// shares with their uncles, and prints a formatted text table to stdout.
pub fn execute(
    chain_store_handle: ChainStoreHandle,
    to: Option<u32>,
    num: u32,
) -> Result<(), Box<dyn Error>> {
    let tip_height = chain_store_handle
        .get_tip_height()?
        .ok_or("No confirmed chain tip found")?;

    let to_height = match to {
        Some(height) => {
            if height > tip_height {
                tip_height
            } else {
                height
            }
        }
        None => tip_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let store = chain_store_handle.store_handle().store();
    let shares = store.query_shares(from_height, to_height)?;

    let formatted_output = format_table(&shares, from_height, to_height);
    println!("{formatted_output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::share_block::ShareBlock;
    use crate::test_utils::setup_test_chain_store_handle;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_short_id_normal() {
        let long_hex = "0000000086704a35f17580d06f76d4c0";
        assert_eq!(short_id(long_hex), "00000000");
    }

    #[test]
    fn test_short_id_short_input() {
        let short_hex = "abcd";
        assert_eq!(short_id(short_hex), "abcd");
    }

    #[test]
    fn test_short_id_exact_eight() {
        let exact = "12345678";
        assert_eq!(short_id(exact), "12345678");
    }

    #[tokio::test]
    async fn test_execute_empty_chain() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let result = execute(chain_store_handle, None, 10);
        assert!(
            result.is_err(),
            "Execute should error with no confirmed chain"
        );
    }

    #[tokio::test]
    async fn test_execute_with_genesis_only() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, None, 10);
        assert!(
            result.is_ok(),
            "Execute should succeed with genesis: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_execute_num_larger_than_chain() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        // Requesting 100 shares but chain only has genesis at height 0
        let result = execute(chain_store_handle, None, 100);
        assert!(
            result.is_ok(),
            "Execute should clamp to available shares: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_format_table_empty() {
        let shares: Vec<ShareInfo> = Vec::new();
        let output = format_table(&shares, 0, 0);
        assert!(output.contains("0 shares"));
    }

    #[test]
    fn test_format_table_with_uncles() {
        let uncle_hash = BlockHash::from_byte_array([0xaa; 32]);
        let uncle_parent = BlockHash::from_byte_array([0xbb; 32]);
        let nephew_hash = BlockHash::from_byte_array([0xcc; 32]);
        let nephew_parent = BlockHash::from_byte_array([0xdd; 32]);

        let uncle_info = UncleInfo {
            blockhash: uncle_hash,
            prev_blockhash: uncle_parent,
            miner_pubkey: "030303030303030303030303030303030303030303030303030303030303030303"
                .to_string(),
            timestamp: 1_700_000_010,
            height: Some(5),
        };

        let nephew = ShareInfo {
            blockhash: nephew_hash,
            prev_blockhash: nephew_parent,
            height: 6,
            miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                .to_string(),
            timestamp: 1_700_000_020,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![uncle_info],
        };

        let output = format_table(&[nephew], 5, 6);

        // Table header should include Uncles column
        assert!(
            output.contains("Uncles"),
            "header should have Uncles column"
        );

        // Nephew row should show uncle short hash in its Uncles column
        let uncle_hash_string = uncle_hash.to_string();
        let uncle_short = short_id(&uncle_hash_string);
        assert!(
            output.contains(uncle_short),
            "nephew row should show uncle short hash"
        );

        // Uncle sub-row should be marked with *
        assert!(output.contains("| *"), "uncle row should be marked with *");

        // Uncle sub-row should show its parent hash
        let uncle_parent_string = uncle_parent.to_string();
        let uncle_parent_short = short_id(&uncle_parent_string);
        // The uncle parent short hash should appear in the uncle sub-row
        let lines: Vec<&str> = output.lines().collect();
        let uncle_row = lines
            .iter()
            .find(|line| line.contains("| *"))
            .expect("should have an uncle row");
        assert!(
            uncle_row.contains(uncle_parent_short),
            "uncle row should show its parent hash"
        );
        assert!(uncle_row.contains("5"), "uncle row should show its height");
    }
}
