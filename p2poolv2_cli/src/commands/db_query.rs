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

//! Direct database query functions for offline CLI usage.
//!
//! These functions open a RocksDB store in read-only mode and query it
//! directly, without requiring a running node or API server.

use bitcoin::BlockHash;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::block_tx_metadata::Status;
use p2poolv2_lib::store::dag_store::MAX_UNCLES_DEPTH;
use p2poolv2_lib::store::writer::StoreError;
use p2poolv2_lib::utils::time_provider::format_timestamp;
use serde::Serialize;
use std::error::Error;
use std::str::FromStr;

/// Open a RocksDB store in read-only mode.
pub fn open_store(db_path: &str) -> Result<Store, Box<dyn Error>> {
    Store::new(db_path.to_string(), true)
        .map_err(|error| format!("Failed to open database at {db_path}: {error}").into())
}

/// Query chain info directly from the store.
pub fn info(store: &Store) -> Result<(), Box<dyn Error>> {
    let genesis_blockhash = store.get_genesis_blockhash().map(|h| h.to_string());

    let chain_tip_height = match store.get_top_confirmed_height() {
        Ok(height) => Some(height),
        Err(StoreError::NotFound(_)) => None,
        Err(error) => return Err(format!("Failed to get tip height: {error}").into()),
    };

    let chain_tip_blockhash = match store.get_chain_tip() {
        Ok(hash) => Some(hash.to_string()),
        Err(StoreError::NotFound(_)) => None,
        Err(error) => return Err(format!("Failed to get chain tip: {error}").into()),
    };

    let total_work = match store.get_total_work() {
        Ok(work) => format!("{work:#x}"),
        Err(error) => return Err(format!("Failed to get total work: {error}").into()),
    };

    let top_candidate_height = match store.get_top_candidate_height() {
        Ok(height) => Some(height),
        Err(StoreError::NotFound(_)) => None,
        Err(error) => return Err(format!("Failed to get candidate tip height: {error}").into()),
    };

    let top_candidate_blockhash = top_candidate_height.and_then(|height| {
        store
            .get_candidate_at_height(height)
            .ok()
            .map(|h| h.to_string())
    });

    let response = serde_json::json!({
        "genesis_blockhash": genesis_blockhash,
        "chain_tip_height": chain_tip_height,
        "total_work": total_work,
        "chain_tip_blockhash": chain_tip_blockhash,
        "top_candidate_height": top_candidate_height,
        "top_candidate_blockhash": top_candidate_blockhash,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Query confirmed shares directly from the store.
pub fn shares(store: &Store, to: Option<u32>, num: u32) -> Result<(), Box<dyn Error>> {
    let tip_height = store
        .get_top_confirmed_height()
        .map_err(|error| format!("Failed to get tip height: {error}"))?;

    let to_height = match to {
        Some(height) if height > tip_height => tip_height,
        Some(height) => height,
        None => tip_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let shares = store
        .query_shares(from_height, to_height)
        .map_err(|error| format!("Failed to query shares: {error}"))?;

    let response = serde_json::json!({
        "from_height": from_height,
        "to_height": to_height,
        "shares": shares,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Query share headers directly from the store (matches /share_headers endpoint).
pub fn share_headers(
    store: &Store,
    to: Option<u32>,
    num: u32,
    include_txs: bool,
    include_merkle_branches: bool,
) -> Result<(), Box<dyn Error>> {
    let tip_height = store
        .get_top_confirmed_height()
        .map_err(|error| format!("Failed to get tip height: {error}"))?;

    let to_height = match to {
        Some(height) if height > tip_height => tip_height,
        Some(height) => height,
        None => tip_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let need_full_blocks = include_txs || include_merkle_branches;

    let headers: Vec<serde_json::Value> = if need_full_blocks {
        let share_blocks = store
            .query_share_blocks(from_height, to_height)
            .map_err(|error| format!("Failed to query share blocks: {error}"))?;

        share_blocks
            .into_iter()
            .map(|sb| {
                let mut entry = serde_json::to_value(&sb.header).unwrap_or_default();
                if include_txs {
                    entry["transactions"] =
                        serde_json::to_value(&sb.transactions).unwrap_or_default();
                }
                if include_merkle_branches {
                    entry["template_merkle_branches"] =
                        serde_json::to_value(&sb.template_merkle_branches).unwrap_or_default();
                }
                entry
            })
            .collect()
    } else {
        let raw_headers = store
            .query_share_headers(from_height, to_height)
            .map_err(|error| format!("Failed to query share headers: {error}"))?;

        raw_headers
            .into_iter()
            .map(|h| serde_json::to_value(&h).unwrap_or_default())
            .collect()
    };

    let response = serde_json::json!({
        "from_height": from_height,
        "to_height": to_height,
        "headers": headers,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Query candidate shares directly from the store.
pub fn candidates(store: &Store, to: Option<u32>, num: u32) -> Result<(), Box<dyn Error>> {
    let candidate_height = store
        .get_top_candidate_height()
        .map_err(|error| format!("Failed to get candidate tip height: {error}"))?;

    let to_height = match to {
        Some(height) if height > candidate_height => candidate_height,
        Some(height) => height,
        None => candidate_height,
    };

    let from_height = to_height.saturating_sub(num.saturating_sub(1));

    let candidates = store
        .query_candidates(from_height, to_height)
        .map_err(|error| format!("Failed to query candidates: {error}"))?;

    let response = serde_json::json!({
        "from_height": from_height,
        "to_height": to_height,
        "shares": candidates,
    });
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Look up a single share by hash or height directly from the store.
pub fn share_lookup(
    store: &Store,
    hash: Option<String>,
    height: Option<u32>,
    full: bool,
) -> Result<(), Box<dyn Error>> {
    match (hash, height) {
        (Some(hash_string), None) => {
            let blockhash = BlockHash::from_str(&hash_string)
                .map_err(|error| format!("Invalid blockhash '{hash_string}': {error}"))?;
            let output = build_share_output(store, &blockhash, full)?;
            let response = serde_json::to_string_pretty(&vec![output])?;
            println!("{response}");
        }
        (None, Some(height)) => {
            let outputs = lookup_by_height(store, height, full)?;
            let response = serde_json::to_string_pretty(&outputs)?;
            println!("{response}");
        }
        _ => return Err("Exactly one of hash or height must be provided".into()),
    }
    Ok(())
}

/// Query PPLNS shares directly from the store.
pub fn pplns_shares(
    store: &Store,
    limit: usize,
    start_time: Option<u64>,
    end_time: Option<u64>,
) -> Result<(), Box<dyn Error>> {
    let shares = store.get_pplns_shares_filtered(Some(limit), start_time, end_time);
    let response = serde_json::to_string_pretty(&shares)?;
    println!("{response}");
    Ok(())
}

// --- Helper types and functions for share lookup ---

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

#[derive(Serialize)]
struct BitcoinHeaderOutput {
    block_hash: String,
    version: i32,
    prev_blockhash: String,
    merkle_root: String,
    time: String,
    bits: String,
    nonce: u32,
}

#[derive(Serialize)]
struct ShareLookupOutput {
    blockhash: String,
    height: Option<u32>,
    status: String,
    parent: String,
    uncles: Vec<String>,
    miner_address: String,
    merkle_root: String,
    bits: String,
    time: String,
    bitcoin_header: BitcoinHeaderOutput,
    template_merkle_branches_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    transactions: Option<Vec<String>>,
}

fn build_share_output(
    store: &Store,
    blockhash: &BlockHash,
    full: bool,
) -> Result<ShareLookupOutput, Box<dyn Error>> {
    let share_header = store
        .get_share_header(blockhash)?
        .ok_or_else(|| format!("Share not found for blockhash {blockhash}"))?;

    let metadata = match store.get_block_metadata(blockhash) {
        Ok(metadata) => Some(metadata),
        Err(StoreError::NotFound(_)) => None,
        Err(error) => return Err(format!("Failed to get metadata for {blockhash}: {error}").into()),
    };

    let height = metadata
        .as_ref()
        .and_then(|metadata| metadata.expected_height);
    let status = metadata
        .as_ref()
        .map(|metadata| format_status(&metadata.status))
        .unwrap_or("Unknown");

    let bitcoin_header = &share_header.bitcoin_header;
    let bitcoin_header_output = BitcoinHeaderOutput {
        block_hash: bitcoin_header.block_hash().to_string(),
        version: bitcoin_header.version.to_consensus(),
        prev_blockhash: bitcoin_header.prev_blockhash.to_string(),
        merkle_root: bitcoin_header.merkle_root.to_string(),
        time: format_timestamp(bitcoin_header.time as u64),
        bits: format!("{:#x}", bitcoin_header.bits.to_consensus()),
        nonce: bitcoin_header.nonce,
    };

    let template_merkle_branches_count = store
        .get_template_merkle_branches(blockhash)
        .unwrap_or_default()
        .len();

    let transaction_ids = if full {
        let share_block = store
            .get_share(blockhash)
            .ok_or_else(|| format!("Full share not found for blockhash {blockhash}"))?;

        Some(
            share_block
                .transactions
                .iter()
                .map(|tx| tx.compute_txid().to_string())
                .collect(),
        )
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
        miner_address: share_header.miner_bitcoin_address.to_string(),
        merkle_root: share_header.merkle_root.to_string(),
        bits: format!("{:#x}", share_header.bits.to_consensus()),
        time: format_timestamp(share_header.time as u64),
        bitcoin_header: bitcoin_header_output,
        template_merkle_branches_count,
        transactions: transaction_ids,
    })
}

fn lookup_by_height(
    store: &Store,
    height: u32,
    full: bool,
) -> Result<Vec<ShareLookupOutput>, Box<dyn Error>> {
    let mut blockhashes = Vec::with_capacity(4);

    if let Ok(confirmed_hash) = store.get_confirmed_at_height(height) {
        blockhashes.push(confirmed_hash);
    }

    let upper_height = height.saturating_add(MAX_UNCLES_DEPTH as u32);
    if let Some(start_height) = height.checked_add(1) {
        for scan_height in start_height..=upper_height {
            let Ok(scan_hash) = store.get_confirmed_at_height(scan_height) else {
                continue;
            };
            let Ok(Some(header)) = store.get_share_header(&scan_hash) else {
                continue;
            };
            for uncle_hash in &header.uncles {
                if blockhashes.contains(uncle_hash) {
                    continue;
                }
                let uncle_height = match store.get_block_metadata(uncle_hash) {
                    Ok(metadata) => metadata.expected_height,
                    Err(StoreError::NotFound(_)) => None,
                    Err(error) => {
                        return Err(format!(
                            "Failed to get metadata for uncle {uncle_hash}: {error}"
                        )
                        .into());
                    }
                };
                if uncle_height == Some(height) {
                    blockhashes.push(*uncle_hash);
                }
            }
        }
    }

    if blockhashes.is_empty() {
        return Err(format!("No shares found at height {height}").into());
    }

    let mut outputs = Vec::with_capacity(blockhashes.len());
    for blockhash in &blockhashes {
        outputs.push(build_share_output(store, blockhash, full)?);
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::test_utils::{genesis_for_tests, setup_test_chain_store_handle};

    /// Helper: set up a store with genesis and return the Store reference and temp dir.
    /// The ChainStoreHandle populates the store; we then query it directly via Store.
    async fn setup_store_with_genesis() -> (std::sync::Arc<Store>, tempfile::TempDir) {
        let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();
        chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();
        let store = chain_store_handle.store_handle().store().clone();
        (store, temp_dir)
    }

    // --- open_store tests ---

    #[test]
    fn test_open_store_invalid_path() {
        let result = open_store("/nonexistent/path/to/db");
        assert!(result.is_err());
    }

    // --- info tests ---

    #[tokio::test]
    async fn test_info_calls_store_on_empty_db() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = chain_store_handle.store_handle().store();
        // Empty store has no total_work, so info returns an error
        let result = info(store);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_info_calls_store_with_genesis() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = info(&store);
        assert!(result.is_ok());
    }

    // --- shares tests ---

    #[tokio::test]
    async fn test_shares_errors_on_empty_store() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = chain_store_handle.store_handle().store();
        let result = shares(store, None, 10);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shares_calls_store_with_genesis() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = shares(&store, Some(0), 1);
        assert!(result.is_ok());
    }

    // --- share_headers tests ---

    #[tokio::test]
    async fn test_share_headers_errors_on_empty_store() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = chain_store_handle.store_handle().store();
        let result = share_headers(store, None, 10, false, false);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_headers_calls_store_with_genesis() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_headers(&store, Some(0), 1, false, false);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_share_headers_with_transactions() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_headers(&store, Some(0), 1, true, false);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_share_headers_with_merkle_branches() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_headers(&store, Some(0), 1, false, true);
        assert!(result.is_ok());
    }

    // --- candidates tests ---

    #[tokio::test]
    async fn test_candidates_errors_on_empty_store() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = chain_store_handle.store_handle().store();
        let result = candidates(store, None, 10);
        assert!(result.is_err());
    }

    // --- share_lookup tests ---

    #[tokio::test]
    async fn test_share_lookup_invalid_hash() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_lookup(&store, Some("not-a-hash".to_string()), None, false);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_lookup_not_found_by_hash() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_lookup(
            &store,
            Some("0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_lookup_genesis_by_height() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_lookup(&store, None, Some(0), false);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_share_lookup_genesis_by_hash() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let genesis = genesis_for_tests();
        let genesis_hash = genesis.block_hash().to_string();
        let result = share_lookup(&store, Some(genesis_hash), None, false);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_share_lookup_genesis_full() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let genesis = genesis_for_tests();
        let genesis_hash = genesis.block_hash().to_string();
        let result = share_lookup(&store, Some(genesis_hash), None, true);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_share_lookup_not_found_by_height() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_lookup(&store, None, Some(999), false);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_share_lookup_requires_hash_or_height() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = share_lookup(&store, None, None, false);
        assert!(result.is_err());
    }

    // --- pplns_shares tests ---

    #[tokio::test]
    async fn test_pplns_shares_calls_store() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        // Should succeed (returns empty list on store with no pplns data)
        let result = pplns_shares(&store, 100, None, None);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pplns_shares_with_time_filter() {
        let (store, _temp_dir) = setup_store_with_genesis().await;
        let result = pplns_shares(&store, 10, Some(1_700_000_000), Some(1_700_100_000));
        assert!(result.is_ok());
    }

    // --- format_status tests ---

    #[test]
    fn test_format_status_all_variants() {
        assert_eq!(format_status(&Status::Pending), "Pending");
        assert_eq!(format_status(&Status::HeaderValid), "HeaderValid");
        assert_eq!(format_status(&Status::Invalid), "Invalid");
        assert_eq!(format_status(&Status::Candidate), "Candidate");
        assert_eq!(format_status(&Status::BlockValid), "BlockValid");
        assert_eq!(format_status(&Status::Confirmed), "Confirmed");
    }
}
