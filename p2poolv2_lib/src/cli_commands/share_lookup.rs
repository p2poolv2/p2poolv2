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
use crate::store::block_tx_metadata::Status;
use crate::utils::time_provider::format_timestamp;
use bitcoin::BlockHash;
use serde::Serialize;
use std::error::Error;
use std::str::FromStr;

/// Specifies how to look up shares.
pub enum LookupQuery<'a> {
    /// Look up by full blockhash.
    Hash(&'a str),
    /// Look up all shares at a given height.
    Height(u32),
}

/// JSON output structure for share lookup.
#[derive(Serialize)]
struct ShareLookupOutput {
    blockhash: String,
    height: Option<u32>,
    status: String,
    parent: String,
    uncles: Vec<String>,
    miner_pubkey: String,
    merkle_root: String,
    bits: String,
    time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    transactions: Option<Vec<String>>,
}

/// Format a Status enum value as a human-readable string.
fn format_status(status: &Status) -> &'static str {
    match status {
        Status::Pending => "Pending",
        Status::HeaderValid => "HeaderValid",
        Status::Invalid => "Invalid",
        Status::Candidate => "Candidate",
        Status::BlockValid => "BlockValid",
        Status::Confirmed => "Confirmed",
    }
}

/// Build the JSON output for a single share identified by its blockhash.
fn build_share_output(
    chain_store_handle: &ChainStoreHandle,
    blockhash: &BlockHash,
    full: bool,
) -> Result<ShareLookupOutput, Box<dyn Error>> {
    let store = chain_store_handle.store_handle().store();

    let share_header = store
        .get_share_header(blockhash)?
        .ok_or_else(|| format!("Share not found for blockhash {blockhash}"))?;

    let metadata = store.get_block_metadata(blockhash).ok();

    let height = metadata
        .as_ref()
        .and_then(|metadata| metadata.expected_height);
    let status = metadata
        .as_ref()
        .map(|metadata| format_status(&metadata.status))
        .unwrap_or("Unknown");

    let transaction_ids = if full {
        let share_block = chain_store_handle
            .get_share(blockhash)
            .ok_or_else(|| format!("Full share not found for blockhash {blockhash}"))?;

        let txids: Vec<String> = share_block
            .transactions
            .iter()
            .map(|transaction| transaction.compute_txid().to_string())
            .collect();

        Some(txids)
    } else {
        None
    };

    Ok(ShareLookupOutput {
        blockhash: blockhash.to_string(),
        height,
        status: status.to_string(),
        parent: share_header.prev_share_blockhash.to_string(),
        uncles: share_header
            .uncles
            .iter()
            .map(|uncle| uncle.to_string())
            .collect(),
        miner_pubkey: share_header.miner_pubkey.to_string(),
        merkle_root: share_header.merkle_root.to_string(),
        bits: format!("{:#x}", share_header.bits.to_consensus()),
        time: format_timestamp(share_header.time as u64),
        transactions: transaction_ids,
    })
}

/// Execute the share-lookup command.
///
/// Dispatches to the appropriate lookup method based on the query type.
/// Hash lookup prints a single JSON object. Height lookup prints a JSON
/// array of all shares at that height.
pub fn execute(
    chain_store_handle: ChainStoreHandle,
    query: LookupQuery,
    full: bool,
) -> Result<(), Box<dyn Error>> {
    match query {
        LookupQuery::Hash(hash_string) => execute_by_hash(&chain_store_handle, hash_string, full),
        LookupQuery::Height(height) => execute_by_height(&chain_store_handle, height, full),
    }
}

/// Look up a single share by its full blockhash and print it as JSON.
fn execute_by_hash(
    chain_store_handle: &ChainStoreHandle,
    hash_string: &str,
    full: bool,
) -> Result<(), Box<dyn Error>> {
    let blockhash = BlockHash::from_str(hash_string)
        .map_err(|error| format!("Invalid blockhash '{hash_string}': {error}"))?;

    let output = build_share_output(chain_store_handle, &blockhash, full)?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Look up all shares at a given height and print them as a JSON array.
fn execute_by_height(
    chain_store_handle: &ChainStoreHandle,
    height: u32,
    full: bool,
) -> Result<(), Box<dyn Error>> {
    let blockhashes = chain_store_handle.get_blockhashes_for_height(height);
    if blockhashes.is_empty() {
        return Err(format!("No shares found at height {height}").into());
    }

    let mut outputs = Vec::with_capacity(blockhashes.len());
    for blockhash in &blockhashes {
        outputs.push(build_share_output(chain_store_handle, blockhash, full)?);
    }
    println!("{}", serde_json::to_string_pretty(&outputs)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::share_block::ShareBlock;
    use crate::test_utils::setup_test_chain_store_handle;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_format_status_all_variants() {
        assert_eq!(format_status(&Status::Pending), "Pending");
        assert_eq!(format_status(&Status::HeaderValid), "HeaderValid");
        assert_eq!(format_status(&Status::BlockValid), "BlockValid");
        assert_eq!(format_status(&Status::Invalid), "Invalid");
        assert_eq!(format_status(&Status::Candidate), "Candidate");
        assert_eq!(format_status(&Status::Confirmed), "Confirmed");
    }

    #[tokio::test]
    async fn test_execute_hash_not_found() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let random_hash = BlockHash::all_zeros().to_string();
        let result = execute(chain_store_handle, LookupQuery::Hash(&random_hash), false);
        assert!(result.is_err(), "Should error for unknown blockhash");
    }

    #[tokio::test]
    async fn test_execute_hash_genesis_header() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        let genesis_hash = genesis.header.block_hash().to_string();
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, LookupQuery::Hash(&genesis_hash), false);
        assert!(
            result.is_ok(),
            "Should succeed for genesis: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_execute_hash_genesis_full() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        let genesis_hash = genesis.header.block_hash().to_string();
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, LookupQuery::Hash(&genesis_hash), true);
        assert!(
            result.is_ok(),
            "Should succeed with --full for genesis: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_execute_invalid_hash() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let result = execute(
            chain_store_handle,
            LookupQuery::Hash("not_a_valid_hash"),
            false,
        );
        assert!(result.is_err(), "Should error for invalid hash string");
    }

    #[tokio::test]
    async fn test_execute_height_genesis() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, LookupQuery::Height(0), false);
        assert!(
            result.is_ok(),
            "Should find genesis at height 0: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_execute_height_not_found() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let genesis = ShareBlock::build_genesis_for_network(bitcoin::Network::Signet);
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .expect("Failed to initialize genesis");

        let result = execute(chain_store_handle, LookupQuery::Height(999), false);
        assert!(result.is_err(), "Should error for height with no shares");
    }
}
