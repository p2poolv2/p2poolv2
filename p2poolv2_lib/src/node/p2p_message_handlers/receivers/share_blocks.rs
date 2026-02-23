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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::shares::validation;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tracing::{debug, error};

/// Handle a ShareBlock received from a peer in response to a getblocks request.
///
/// Validate the ShareBlock and store it in the chain.
/// We do not send any inventory message as we do not want to gossip the share block.
/// Share blocks are gossiped using the libp2p gossipsub protocol.
pub async fn handle_share_block<T: TimeProvider + Send + Sync>(
    share_block: ShareBlock,
    chain_store_handle: &ChainStoreHandle,
    time_provider: &T,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received share block: {:?}", share_block);
    if let Err(validation_error) =
        validation::validate_share_block(&share_block, chain_store_handle, time_provider)
    {
        error!("Share block validation failed: {}", validation_error);
        return Err(validation_error.into());
    }

    // TODO: Check if this will be an uncle, for now add to main chain
    if let Err(e) = chain_store_handle.add_share(share_block, true).await {
        error!("Failed to add share: {}", e);
        return Err("Error adding share to chain".into());
    }

    debug!("Successfully added share blocks to chain");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::writer::StoreError;
    use crate::test_utils::{
        TestShareBlockBuilder, build_block_from_work_components, genesis_for_tests,
    };
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::hashes::Hash as _;
    use mockall::predicate::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_handle_share_block_success() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let share_block =
            build_block_from_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        // Set up mock expectations
        chain_store_handle
            .expect_add_share()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Ok(()));
        chain_store_handle
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(
            bitcoin::absolute::Time::from_consensus(share_block.header.bitcoin_header.time)
                .unwrap(),
        );

        let result = handle_share_block(share_block, &chain_store_handle, &time_provider).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_share_block_validation_error() {
        let chain_store_handle = ChainStoreHandle::default();
        let share_block = TestShareBlockBuilder::new().build();

        let time_provider = TestTimeProvider::new(SystemTime::now());

        let result = handle_share_block(share_block, &chain_store_handle, &time_provider).await;
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains("seconds from current time"),
            "Expected timestamp validation error, got: {error_message}"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_add_share_error() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let share_block =
            build_block_from_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        // Set up mock expectations
        chain_store_handle
            .expect_add_share()
            .with(eq(share_block.clone()), eq(true))
            .returning(|_, _| Err(StoreError::Database("Failed to add share".to_string())));
        chain_store_handle
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(
            bitcoin::absolute::Time::from_consensus(share_block.header.bitcoin_header.time)
                .unwrap(),
        );

        let result = handle_share_block(share_block, &chain_store_handle, &time_provider).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
}
