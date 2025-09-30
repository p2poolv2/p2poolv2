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

use crate::shares::ShareBlock;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::validation;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use std::sync::Arc;
use tracing::{error, info};

/// Handle a ShareBlock received from a peer in response to a getblocks request.
///
/// Validate the ShareBlock and store it in the chain
/// We do not send any inventory message as we do not want to gossip the share block.
/// Share blocks are gossiped using the libp2p gossipsub protocol.
pub async fn handle_share_block<T: TimeProvider + Send + Sync>(
    share_block: ShareBlock,
    store: Arc<ChainStore>,
    time_provider: &T,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Received share block: {:?}", share_block);
    if let Err(e) = validation::validate(&share_block, store.clone(), time_provider).await {
        error!("Share block validation failed: {}", e);
        return Err("Share block validation failed".into());
    }
    if let Err(e) = store.add_share(share_block.clone()) {
        error!("Failed to add share: {}", e);
        return Err("Error adding share to chain".into());
    }
    info!("Successfully added share blocks to chain");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestBlockBuilder, load_valid_workbases_userworkbases_and_shares};
    use crate::utils::time_provider::TestTimeProvider;
    use mockall::predicate::*;
    use std::sync::Arc;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_handle_share_block_success() {
        let mut store = ChainStore::default();
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<bitcoin::PublicKey>()
            .unwrap();
        let share_header = crate::shares::miner_message::builders::build_share_header(
            &workbases[0],
            &shares[0],
            &userworkbases[0],
            pubkey,
        )
        .unwrap();

        let share_block = crate::shares::miner_message::builders::build_share_block(
            &workbases[0],
            &userworkbases[0],
            &shares[0],
            share_header,
        )
        .unwrap();

        // Set up mock expectations
        store
            .expect_add_share()
            .with(eq(share_block.clone()))
            .returning(|_| Ok(()));

        store
            .expect_get_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(workbases[0].clone()));

        store
            .expect_get_user_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(userworkbases[0].clone()));

        let mut time_provider = TestTimeProvider(SystemTime::now());
        time_provider.set_time(shares[0].ntime);

        let result = handle_share_block(share_block, Arc::new(store), &time_provider).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_share_block_validation_error() {
        let mut store = ChainStore::default();
        let share_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .workinfoid(7473434392883363843)
            .build();

        // Set up mock to return None for workbase to trigger validation error
        store
            .expect_get_workbase()
            .with(eq(7473434392883363843))
            .returning(|_| None);

        let time_provider = TestTimeProvider(SystemTime::now());

        let result = handle_share_block(share_block, Arc::new(store), &time_provider).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Share block validation failed"
        );
    }

    #[tokio::test]
    async fn test_handle_share_block_add_share_error() {
        let mut store = ChainStore::default();
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<bitcoin::PublicKey>()
            .unwrap();
        let share_header = crate::shares::miner_message::builders::build_share_header(
            &workbases[0],
            &shares[0],
            &userworkbases[0],
            pubkey,
        )
        .unwrap();

        let share_block = crate::shares::miner_message::builders::build_share_block(
            &workbases[0],
            &userworkbases[0],
            &shares[0],
            share_header,
        )
        .unwrap();

        // Set up mock expectations
        store
            .expect_add_share()
            .with(eq(share_block.clone()))
            .returning(|_| Err("Failed to add share".into()));

        store
            .expect_get_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(workbases[0].clone()));

        store
            .expect_get_user_workbase()
            .with(eq(7473434392883363843))
            .returning(move |_| Some(userworkbases[0].clone()));

        let mut time_provider = TestTimeProvider(SystemTime::now());
        time_provider.set_time(shares[0].ntime);

        let result = handle_share_block(share_block, Arc::new(store), &time_provider).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Error adding share to chain"
        );
    }
}
