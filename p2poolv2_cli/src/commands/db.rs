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

//! Database maintenance commands that operate directly on the RocksDB store.
//!
//! These commands require `--db-path` and open the store in read-write mode.
//! The node must be stopped before running these commands.

use super::DbCommands;
use bitcoin::BlockHash;
use p2poolv2_lib::store::Store;
use p2poolv2_lib::store::block_tx_metadata::{ChainMembership, Status};
use p2poolv2_lib::store::dag_store::MAX_BLOCKS_PER_HEIGHT;
use p2poolv2_lib::store::writer::StoreError;
use std::error::Error;

/// Open a RocksDB store in read-write mode for maintenance operations.
fn open_store_readwrite(db_path: &str) -> Result<Store, Box<dyn Error>> {
    Store::new(db_path.to_string(), false)
        .map_err(|error| format!("Failed to open database at {db_path}: {error}").into())
}

/// Dispatch a db subcommand.
pub fn execute(command: &DbCommands, db_path: &str) -> Result<(), Box<dyn Error>> {
    let store = open_store_readwrite(db_path)?;
    match command {
        DbCommands::CleanupDenseHeights => cleanup_dense_heights(&store),
    }
}

/// Clean up dense heights by marking excess HeaderValid blocks as Invalid.
///
/// Walks the height index and for each height with more than
/// MAX_BLOCKS_PER_HEIGHT blocks, keeps every block on the candidate or
/// confirmed chain, every BlockValid block, and HeaderValid blocks that are
/// referenced as uncles. Marks the remaining off-chain, unreferenced
/// HeaderValid blocks as Invalid.
fn cleanup_dense_heights(store: &Store) -> Result<(), Box<dyn Error>> {
    let top_height = match store.get_top_confirmed_height() {
        Ok(height) => height,
        Err(StoreError::NotFound(_)) => {
            println!("No confirmed chain found, nothing to clean up");
            return Ok(());
        }
        Err(error) => return Err(format!("Failed to get top height: {error}").into()),
    };

    let mut total_invalidated = 0usize;
    let mut dense_heights = 0usize;

    let height_entries = store.get_blockhashes_for_height_range(0, top_height);

    for (height, blockhashes) in height_entries {
        if blockhashes.len() <= MAX_BLOCKS_PER_HEIGHT {
            continue;
        }

        let metadata_results = store.get_block_metadata_batch(&blockhashes)?;

        // Only off-chain HeaderValid blocks are eligible for invalidation.
        // Blocks on the candidate or confirmed chain, and BlockValid blocks,
        // are always kept regardless of how dense the height is.
        let off_chain_header_valid: Vec<BlockHash> = metadata_results
            .iter()
            .filter(|(_, metadata)| {
                metadata.status == Status::HeaderValid && metadata.chain == ChainMembership::None
            })
            .map(|(hash, _)| *hash)
            .collect();

        if off_chain_header_valid.is_empty() {
            continue;
        }

        dense_heights += 1;
        let kept_count = blockhashes.len() - off_chain_header_valid.len();
        println!(
            "Height {height}: {total} blocks ({kept} on-chain/valid, {hv} off-chain HeaderValid)",
            total = blockhashes.len(),
            kept = kept_count,
            hv = off_chain_header_valid.len(),
        );

        let mut batch = Store::get_write_batch();
        let mut height_invalidated = 0usize;

        for blockhash in &off_chain_header_valid {
            let is_uncle = store.get_nephews(blockhash).is_some();
            if is_uncle {
                continue;
            }
            let mut metadata = store.get_block_metadata(blockhash)?;
            metadata.status = Status::Invalid;
            store.update_block_metadata(blockhash, &metadata, &mut batch)?;
            height_invalidated += 1;
        }

        if height_invalidated > 0 {
            store.commit_batch(batch)?;
            println!("  Invalidated {height_invalidated} unreferenced HeaderValid blocks");
            total_invalidated += height_invalidated;
        }
    }

    println!(
        "Cleanup complete: {dense_heights} dense heights found, {total_invalidated} blocks invalidated"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::test_utils::{
        TestShareBlockBuilder, genesis_for_tests, setup_test_chain_store_handle,
    };

    #[tokio::test]
    async fn test_cleanup_dense_heights_invalidates_unreferenced_header_valid() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();
        chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Confirmed block at height 1
        let confirmed = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(1)
            .work(2)
            .build();
        chain_store_handle
            .add_share_block(confirmed.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(confirmed.header.clone())
            .await
            .unwrap();
        chain_store_handle
            .mark_block_valid(confirmed.block_hash())
            .await
            .unwrap();
        chain_store_handle.organise_block().await.unwrap();

        // Uncle at height 1 (organise header stores as HeaderValid)
        let uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(100)
            .build();
        chain_store_handle
            .add_share_block(uncle.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(uncle.header.clone())
            .await
            .unwrap();

        // Confirmed block at height 2 referencing uncle
        let confirmed_with_uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(confirmed.block_hash().to_string())
            .uncles(vec![uncle.block_hash()])
            .nonce(2)
            .work(2)
            .build();
        chain_store_handle
            .add_share_block(confirmed_with_uncle.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(confirmed_with_uncle.header.clone())
            .await
            .unwrap();
        chain_store_handle
            .mark_block_valid(confirmed_with_uncle.block_hash())
            .await
            .unwrap();
        chain_store_handle.organise_block().await.unwrap();

        // 25 unreferenced HeaderValid blocks at height 1
        for nonce in 200..225 {
            let spam = TestShareBlockBuilder::new()
                .prev_share_blockhash(genesis.block_hash().to_string())
                .nonce(nonce)
                .build();
            chain_store_handle
                .add_share_block(spam.clone())
                .await
                .unwrap();
            chain_store_handle
                .organise_header(spam.header.clone())
                .await
                .unwrap();
        }

        let store = chain_store_handle.store_handle().store();
        let blocks_before = store.get_blockhashes_for_height(1);
        assert_eq!(blocks_before.len(), 27);

        cleanup_dense_heights(store).unwrap();

        // Uncle and confirmed should survive, 25 spam blocks invalidated
        let metadata_results = store.get_block_metadata_batch(&blocks_before).unwrap();
        let valid_count = metadata_results
            .iter()
            .filter(|(_, metadata)| metadata.status != Status::Invalid)
            .count();
        // 1 confirmed + 1 uncle-referenced HeaderValid = 2 valid
        assert_eq!(valid_count, 2);
    }
}
