// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Whether any block that references `blockhash` as an uncle is still one the
/// sync sender would serve (status not `Invalid`, not `Pending`).
///
/// A genuine uncle -- one declared by a served block -- must be kept: the sender
/// filters `Invalid`/`Pending` blocks, so invalidating a served block's uncle
/// would leave the receiver unable to satisfy `verify_all_uncles_available`.
/// A flood sibling referenced only by other dead (Invalid) siblings has no live
/// nephew and is safe to invalidate. Because uncles are strictly lower-height
/// ancestors of their nephews, processing heights top-down means every nephew
/// has already been finalised when its uncle is examined, so this single check
/// yields the full transitive closure of uncles reachable from served blocks.
fn has_live_nephew(store: &Store, blockhash: &BlockHash) -> Result<bool, Box<dyn Error>> {
    let Some(nephews) = store.get_nephews(blockhash) else {
        return Ok(false);
    };
    for nephew in nephews {
        let metadata = store.get_block_metadata(&nephew)?;
        if metadata.status != Status::Invalid && metadata.status != Status::Pending {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Clean up dense heights by marking excess off-chain blocks as Invalid.
///
/// Walks the height index top-down and for each height with more than
/// MAX_BLOCKS_PER_HEIGHT blocks, keeps every block on the candidate or
/// confirmed chain and every block still referenced as an uncle by a served
/// block. Marks the remaining off-chain blocks -- whether `HeaderValid`
/// (received via header sync) or `BlockValid` (mined locally onto a losing
/// fork, the dense-height flood) -- as Invalid, so the sync sender's
/// Pending/Invalid filter stops serving them and the height collapses to its
/// real chain block(s).
///
/// Heights are processed top-down so that flood siblings which only reference
/// each other as uncles collapse: the highest are invalidated first, which
/// then leaves the ones below them with no live nephew.
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

    // Top-down: a block's nephews are strictly higher, so they are finalised
    // before the block is examined.
    for (height, blockhashes) in height_entries.into_iter().rev() {
        if blockhashes.len() <= MAX_BLOCKS_PER_HEIGHT {
            continue;
        }

        let metadata_results = store.get_block_metadata_batch(&blockhashes)?;

        // Off-chain blocks the sender would serve (HeaderValid or BlockValid,
        // and not on the candidate or confirmed chain) are eligible for
        // invalidation. Blocks on the candidate or confirmed chain are always
        // kept; blocks still referenced as an uncle by a served block are kept
        // below. A BlockValid off-chain block is a share this node mined onto
        // a losing fork.
        let off_chain_removable: Vec<BlockHash> = metadata_results
            .iter()
            .filter(|(_, metadata)| {
                metadata.chain == ChainMembership::None
                    && matches!(metadata.status, Status::HeaderValid | Status::BlockValid)
            })
            .map(|(hash, _)| *hash)
            .collect();

        if off_chain_removable.is_empty() {
            continue;
        }

        dense_heights += 1;
        let kept_count = blockhashes.len() - off_chain_removable.len();
        println!(
            "Height {height}: {total} blocks ({kept} on-chain, {removable} off-chain removable)",
            total = blockhashes.len(),
            kept = kept_count,
            removable = off_chain_removable.len(),
        );

        let mut batch = Store::get_write_batch();
        let mut height_invalidated = 0usize;

        for blockhash in &off_chain_removable {
            if has_live_nephew(store, blockhash)? {
                continue;
            }
            let mut metadata = store.get_block_metadata(blockhash)?;
            metadata.status = Status::Invalid;
            store.update_block_metadata(blockhash, &metadata, &mut batch)?;
            height_invalidated += 1;
        }

        if height_invalidated > 0 {
            store.commit_batch(batch)?;
            println!("  Invalidated {height_invalidated} off-chain blocks with no live nephew");
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

    #[tokio::test]
    async fn test_cleanup_dense_heights_invalidates_offchain_block_valid() {
        // Reproduces the case where dense height is full of
        // BlockValid siblings this node mined onto a losing fork. They must be
        // invalidated; the confirmed block and a BlockValid uncle survive.
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

        // Off-chain BlockValid uncle at height 1, referenced by a confirmed
        // block at height 2. A BlockValid uncle must be kept.
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
        chain_store_handle
            .mark_block_valid(uncle.block_hash())
            .await
            .unwrap();

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

        // 25 off-chain BlockValid siblings at height 1 (the mined-fork flood)
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
            chain_store_handle
                .mark_block_valid(spam.block_hash())
                .await
                .unwrap();
        }

        let store = chain_store_handle.store_handle().store();
        let blocks_before = store.get_blockhashes_for_height(1);
        assert_eq!(blocks_before.len(), 27);

        cleanup_dense_heights(store).unwrap();

        // Confirmed + BlockValid uncle survive; 25 BlockValid spam invalidated.
        let metadata_results = store.get_block_metadata_batch(&blocks_before).unwrap();
        let valid_count = metadata_results
            .iter()
            .filter(|(_, metadata)| metadata.status != Status::Invalid)
            .count();
        assert_eq!(valid_count, 2);
    }

    #[tokio::test]
    async fn test_cleanup_dense_heights_invalidates_uncle_of_dead_sibling() {
        // flood siblings reference each other as
        // uncles across consecutive dense heights, so none is "unreferenced".
        // Processing top-down, the higher flood is invalidated first, which
        // leaves the lower flood with no live nephew, so it too is removed.
        // A naive "kept if any nephew exists" check would leave the lower
        // height dense and still walling sync.
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();
        chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        // Confirmed chain: genesis -> C1 (h1) -> C2 (h2)
        let c1 = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .nonce(1)
            .work(2)
            .build();
        chain_store_handle
            .add_share_block(c1.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(c1.header.clone())
            .await
            .unwrap();
        chain_store_handle
            .mark_block_valid(c1.block_hash())
            .await
            .unwrap();
        chain_store_handle.organise_block().await.unwrap();

        let c2 = TestShareBlockBuilder::new()
            .prev_share_blockhash(c1.block_hash().to_string())
            .nonce(2)
            .work(2)
            .build();
        chain_store_handle
            .add_share_block(c2.clone())
            .await
            .unwrap();
        chain_store_handle
            .organise_header(c2.header.clone())
            .await
            .unwrap();
        chain_store_handle
            .mark_block_valid(c2.block_hash())
            .await
            .unwrap();
        chain_store_handle.organise_block().await.unwrap();

        // 25 off-chain flood siblings at h1
        let mut lower_flood = Vec::with_capacity(25);
        for nonce in 200..225 {
            let f1 = TestShareBlockBuilder::new()
                .prev_share_blockhash(genesis.block_hash().to_string())
                .nonce(nonce)
                .build();
            chain_store_handle
                .add_share_block(f1.clone())
                .await
                .unwrap();
            chain_store_handle
                .organise_header(f1.header.clone())
                .await
                .unwrap();
            chain_store_handle
                .mark_block_valid(f1.block_hash())
                .await
                .unwrap();
            lower_flood.push(f1.block_hash());
        }

        // 25 off-chain flood siblings at h2, each declaring a distinct h1
        // flood block as an uncle -- so every h1 flood block has a nephew,
        // but only a dead (off-chain) one.
        for (index, uncle) in lower_flood.iter().enumerate() {
            let f2 = TestShareBlockBuilder::new()
                .prev_share_blockhash(c1.block_hash().to_string())
                .uncles(vec![*uncle])
                .nonce(300 + index as u32)
                .build();
            chain_store_handle
                .add_share_block(f2.clone())
                .await
                .unwrap();
            chain_store_handle
                .organise_header(f2.header.clone())
                .await
                .unwrap();
            chain_store_handle
                .mark_block_valid(f2.block_hash())
                .await
                .unwrap();
        }

        let store = chain_store_handle.store_handle().store();
        assert_eq!(store.get_blockhashes_for_height(1).len(), 26); // C1 + 25 flood
        assert_eq!(store.get_blockhashes_for_height(2).len(), 26); // C2 + 25 flood

        cleanup_dense_heights(store).unwrap();

        // Both heights collapse to their single confirmed block: the h1 flood
        // is invalidated even though every one had a nephew, because those
        // nephews (the h2 flood) were invalidated first.
        let after_h1 = store.get_block_metadata_batch(&lower_flood).unwrap();
        let live_h1 = after_h1
            .iter()
            .filter(|(_, metadata)| metadata.status != Status::Invalid)
            .count();
        assert_eq!(live_h1, 0, "all h1 flood siblings should be invalidated");
    }
}
