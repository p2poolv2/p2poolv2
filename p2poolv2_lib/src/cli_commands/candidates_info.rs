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

use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::store::dag_store::ShareInfo;
use crate::utils::short_hex::short_id;
use crate::utils::time_provider::format_timestamp;
use std::error::Error;

/// Format collected candidate shares as a human-readable text table.
///
/// Each share is displayed with its height, short blockhash, short miner ID,
/// and formatted timestamp. Uncles are shown indented below their parent share.
fn format_table(shares: &[ShareInfo], from_height: u32, to_height: u32) -> String {
    let mut output = String::with_capacity(shares.len() * 120);

    output.push_str(&format!(
        "Candidates from height {} to {} ({} shares):\n",
        from_height,
        to_height,
        shares.len()
    ));
    output.push_str(&format!("{}\n", "=".repeat(72)));

    for share in shares {
        let blockhash_string = share.blockhash.to_string();
        let share_short_hash = short_id(&blockhash_string);
        let miner_short_id = short_id(&share.miner_pubkey);
        let formatted_time = format_timestamp(share.timestamp as u64);

        output.push_str(&format!(
            "Height {:>6} | {} | miner: {} | {}\n",
            share.height, share_short_hash, miner_short_id, formatted_time
        ));

        for uncle in &share.uncles {
            let uncle_blockhash_string = uncle.blockhash.to_string();
            let uncle_short_hash = short_id(&uncle_blockhash_string);
            let uncle_miner_short_id = short_id(&uncle.miner_pubkey);
            let uncle_height_display = uncle
                .height
                .map(|height| format!("{height}"))
                .unwrap_or_else(|| "?".to_string());

            output.push_str(&format!(
                "  uncle h={uncle_height_display:<6} | {uncle_short_hash} | miner: {uncle_miner_short_id}\n"
            ));
        }
    }

    output
}

/// Execute the candidates-info command.
///
/// Resolves the height range from the candidate chain tip, collects candidate
/// shares with their uncles, and prints a formatted text table to stdout.
pub fn execute(
    chain_store_handle: ChainStoreHandle,
    to: Option<u32>,
    num: u32,
) -> Result<(), Box<dyn Error>> {
    let candidate_height = chain_store_handle
        .get_candidate_tip_height()?
        .ok_or("No candidate chain tip found")?;

    let to_height = match to {
        Some(height) => {
            if height > candidate_height {
                candidate_height
            } else {
                height
            }
        }
        None => candidate_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let store = chain_store_handle.store_handle().store();
    let shares = store.query_candidates(from_height, to_height)?;

    let formatted_output = format_table(&shares, from_height, to_height);
    println!("{formatted_output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::share_block::ShareBlock;
    use crate::test_utils::setup_test_chain_store_handle;

    #[tokio::test]
    async fn test_execute_no_candidates() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, None, 10);
        assert!(
            result.is_err(),
            "Execute should error when no candidates exist"
        );
    }

    #[test]
    fn test_format_table_empty() {
        let shares: Vec<ShareInfo> = Vec::new();
        let output = format_table(&shares, 1, 1);
        assert!(output.contains("0 shares"));
    }
}
