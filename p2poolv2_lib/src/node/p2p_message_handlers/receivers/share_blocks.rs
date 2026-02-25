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

use crate::node::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::organise_worker::{OrganiseEvent, OrganiseSender};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation;
use std::error::Error;
use tracing::{debug, error, info};

/// Handle a ShareBlock received from a peer in response to a getblocks request.
///
/// The peer_id identifies the peer that sent the block, allowing
/// follow-up requests to be directed back to the same peer.
///
/// Validates the ShareBlock, stores it in the chain, notifies the block
/// fetcher that this block was received, and sends it to the organise
/// worker for candidate-to-confirmed promotion.
pub async fn handle_share_block(
    _peer_id: libp2p::PeerId,
    share_block: ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: BlockFetcherHandle,
    organise_tx: OrganiseSender,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received share block: {:?}", share_block);
    if let Err(validation_error) =
        validation::validate_share_block(&share_block, chain_store_handle)
    {
        error!("Share block validation failed: {}", validation_error);
        return Err(validation_error.into());
    }

    let block_hash = share_block.block_hash();

    // TODO: Check if this will be an uncle, for now add to main chain
    if let Err(store_error) = chain_store_handle
        .add_share_block(share_block.clone(), true)
        .await
    {
        error!("Failed to add share: {}", store_error);
        return Err("Error adding share to chain".into());
    }

    // Notify block fetcher that this block was received (removes from in-flight)
    if let Err(send_error) = block_fetcher_handle
        .send(BlockFetcherEvent::BlockReceived(block_hash))
        .await
    {
        error!(
            "Failed to send BlockReceived to block fetcher: {}",
            send_error
        );
    }

    // Send to organise worker for candidate-to-confirmed promotion
    info!("Sending block to organise worker for promotion");
    if let Err(send_error) = organise_tx.send(OrganiseEvent::Block(share_block)).await {
        error!("Failed to send block to organise worker: {}", send_error);
    }

    debug!("Successfully added share block to chain");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::block_fetcher;
    use crate::node::organise_worker;
    use crate::store::writer::StoreError;
    use crate::test_utils::{
        TestShareBlockBuilder, build_block_from_work_components, genesis_for_tests,
    };
    use bitcoin::hashes::Hash as _;
    use mockall::predicate::*;

    /// Create test block fetcher and organise handles.
    fn test_handles() -> (BlockFetcherHandle, OrganiseSender) {
        let (block_fetcher_tx, _) = block_fetcher::create_block_fetcher_channel();
        let (organise_tx, _) = organise_worker::create_organise_channel();
        (block_fetcher_tx, organise_tx)
    }

    #[tokio::test]
    async fn test_handle_share_block_success() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let share_block =
            build_block_from_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        // Set up mock expectations
        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Ok(()));
        chain_store_handle
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        let (block_fetcher_handle, organise_tx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            organise_tx,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_share_block_validation_error() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a share with an uncle that does not exist in the store
        let uncle_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse::<bitcoin::BlockHash>()
            .unwrap();
        let share_block = TestShareBlockBuilder::new()
            .uncles(vec![uncle_hash])
            .build();

        chain_store_handle
            .expect_get_share()
            .with(eq(uncle_hash))
            .returning(|_| None);

        let (block_fetcher_handle, organise_tx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            organise_tx,
        )
        .await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("not found in store"),
            "Expected uncle not found error, got: {error_message}"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_add_share_error() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        let share_block =
            build_block_from_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        // Set up mock expectations
        chain_store_handle
            .expect_add_share_block()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Err(StoreError::Database("Failed to add share".to_string())));
        chain_store_handle
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        let (block_fetcher_handle, organise_tx) = test_handles();
        let result = handle_share_block(
            peer_id,
            share_block,
            &chain_store_handle,
            block_fetcher_handle,
            organise_tx,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
}
