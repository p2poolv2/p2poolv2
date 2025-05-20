// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use crate::shares::chain::chain::Chain;
use serde::Serialize;
use std::error::Error;

/// Structure to hold chain information
#[derive(Serialize)]
struct ChainInfo {
    genesis_block_hash: Option<String>,
    chain_tip_height: Option<u32>,
    total_work: String,
    chain_tip_blockhash: Option<String>,
    total_shares: u64,
}

/// Implementation of the info command
pub fn execute(chain: Chain) -> Result<(), Box<dyn Error>> {
    // Get genesis block hash
    let genesis_block_hash = chain.genesis_block_hash.map(|hash| format!("{:?}", hash));

    // Get chain tip height
    let chain_tip_height = chain.get_tip_height();

    // Get chain tip blockhash
    let chain_tip_blockhash = chain.chain_tip.map(|hash| format!("{:?}", hash));

    // Get total work (difficulty)
    let total_work = format!("{:?}", chain.total_difficulty);

    // Count total number of shares in the chain
    let mut total_shares = 0;
    if let Some(height) = chain_tip_height {
        for h in 0..=height {
            let blockhashes = chain.store.get_blockhashes_for_height(h);
            total_shares += blockhashes.len() as u64;
        }
    }

    // Create info object
    let info = ChainInfo {
        genesis_block_hash,
        chain_tip_height,
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
    use crate::shares::chain::chain::Chain;
    use crate::shares::store::Store;
    use crate::shares::ShareBlock;
    use tempfile::tempdir;

    #[test]
    fn test_execute_empty_chain() {
        // Create a temporary directory for the store
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        let chain = Chain::new(
            store,
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        );

        // Execute the info command with an empty store
        let result = execute(chain);

        // Verify the command executed successfully
        assert!(result.is_ok(), "Execute should not return an error");
    }
}
