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

use crate::shares::chain::chain_store::ChainStore;
use crate::utils::time_provider::format_timestamp;
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;

/// Structure to hold PPLNS share information for JSON output
#[derive(Serialize)]
struct PplnsShareInfo {
    difficulty: u64,
    btcaddress: String,
    workername: String,
    timestamp: u64,
    formatted_time: String,
}

/// Implementation of the pplns-shares command
pub fn execute(
    chain_store: Arc<ChainStore>,
    limit: usize,
    start_time: Option<u64>,
    end_time: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    // Get PPLNS shares with filtering
    let shares = chain_store.get_pplns_shares_filtered(Some(limit), start_time, end_time);

    // Convert to display format
    let share_infos: Vec<PplnsShareInfo> = shares
        .into_iter()
        .map(|share| PplnsShareInfo {
            difficulty: share.difficulty,
            btcaddress: share.btcaddress.unwrap_or_default(),
            workername: share.workername.unwrap_or_default(),
            timestamp: share.n_time,
            formatted_time: format_timestamp(share.n_time),
        })
        .collect();

    // Serialize to JSON and print
    println!("{}", serde_json::to_string_pretty(&share_infos)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::execute;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::shares::ShareBlock;
    use crate::shares::chain::chain_store::ChainStore;
    use crate::store::Store;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_execute_empty_store() {
        // Create a temporary directory for the store
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let chain = Arc::new(ChainStore::new(
            store,
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        // Execute the pplns-shares command with an empty store
        let result = execute(chain, 10, None, None);

        // Verify the command executed successfully
        assert!(result.is_ok(), "Execute should not return an error");
    }

    #[test]
    fn test_execute_with_shares() {
        // Create a temporary directory for the store
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());

        // Add test shares
        let shares = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1000,
                "job1".to_string(),
                "extra1".to_string(),
                "nonce1".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                2000,
                "job1".to_string(),
                "extra1".to_string(),
                "nonce1".to_string(),
            ),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        let chain = Arc::new(ChainStore::new(
            store,
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        // Execute the pplns-shares command
        let result = execute(chain, 10, None, None);

        // Verify the command executed successfully
        assert!(result.is_ok(), "Execute should not return an error");
    }
}
