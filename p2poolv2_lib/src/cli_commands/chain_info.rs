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

use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{BlockHash, hashes::Hash};
use serde::Serialize;
use std::error::Error;

/// Structure to hold chain information
#[derive(Serialize)]
struct ChainInfo {
    genesis_blockhash: Option<String>,
    chain_tip_height: Option<u32>,
    total_work: String,
    chain_tip_blockhash: String,
    total_shares: u64,
}

/// Implementation of the info command
pub fn execute(chain_store_handle: ChainStoreHandle) -> Result<(), Box<dyn Error>> {
    // Get genesis block hash
    let genesis_blockhash = chain_store_handle.get_genesis_blockhash();

    // Get chain tip height
    let chain_tip_height = chain_store_handle
        .get_tip_height()
        .unwrap_or_default()
        .unwrap_or_default();

    // Get chain tip blockhash
    let chain_tip_blockhash = format!("{:?}", chain_store_handle.get_chain_tip());

    // Get total work (difficulty)
    let total_work = format!("{:?}", chain_store_handle.get_total_work());

    // Count total number of shares in the chain
    let mut total_shares = 0;
    for h in 0..=chain_tip_height {
        let blockhashes = chain_store_handle.get_blockhashes_for_height(h);
        total_shares += blockhashes.len() as u64;
    }

    // Create info object
    let info = ChainInfo {
        genesis_blockhash: Some(
            genesis_blockhash
                .unwrap_or(BlockHash::all_zeros())
                .to_string(),
        ),
        chain_tip_height: Some(chain_tip_height),
        total_work,
        chain_tip_blockhash,
        total_shares,
    };

    // Serialize to JSON and print
    println!("{}", serde_json::to_string_pretty(&info)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::execute;
    use crate::shares::share_block::ShareBlock;
    use crate::test_utils::setup_test_chain_store_handle;

    #[test_log::test(tokio::test)]
    async fn test_execute_empty_chain() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        // Execute the info command
        let result = execute(chain_store_handle);

        // Verify the command executed successfully
        assert!(result.is_ok(), "Execute should not return an error");
    }

    #[tokio::test]
    async fn test_execute_with_genesis() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        // Initialize genesis block
        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        // Execute the info command
        let result = execute(chain_store_handle);

        // Verify the command executed successfully
        assert!(result.is_ok(), "Execute should not return an error");
    }
}
