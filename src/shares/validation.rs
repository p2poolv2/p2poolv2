// Copyright (C) 2024 [Kulpreet Singh]
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

#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::transactions::compute_merkle_root;
use crate::shares::ShareBlock;
use crate::utils::time_provider::TimeProviderTrait;
use mockall::predicate::eq;
use std::error::Error;

pub const MAX_UNCLES: usize = 3;
pub const MAX_TIME_DIFF: u64 = 60;

/// Validate the share block, returning Error in case of failure to validate
/// TODO: validate nonce and blockhash meets difficulty
/// DONE: validate prev_share_blockhash is in store
/// DONE: validate uncles are in store and no more than MAX_UNCLES
/// DONE: validate timestamp is within the last 10 minutes
/// TODO: validate merkle root
/// TODO: validate coinbase transaction
pub async fn validate(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
    time_provider: &dyn TimeProviderTrait,
) -> Result<(), Box<dyn Error>> {
    if let Err(e) = validate_timestamp(share, time_provider).await {
        return Err(format!("Share timestamp validation failed: {}", e).into());
    }
    if let Err(e) = validate_prev_share_blockhash(share, chain_handle).await {
        return Err(format!("Share prev_share_blockhash validation failed: {}", e).into());
    }
    if let Err(e) = validate_uncles(share, chain_handle).await {
        return Err(format!("Share uncles validation failed: {}", e).into());
    }
    if let Err(e) = share.miner_share.validate() {
        return Err(format!("Share validation failed: {}", e).into());
    }
    if let Err(e) = validate_merkle_root(share).await {
        return Err(format!("Share merkle root validation failed: {}", e).into());
    }

    Ok(())
}

/// Validate the merkle root of transactions in the share block matches the one in the header
pub async fn validate_merkle_root(share: &ShareBlock) -> Result<(), Box<dyn Error>> {
    let calculated_merkle_root = compute_merkle_root(&share.transactions);
    let calculated_merkle_root = calculated_merkle_root.ok_or_else(|| {
        Box::<dyn Error>::from("Cannot compute merkle root for empty transaction list")
    })?;
    if calculated_merkle_root != share.header.merkle_root {
        return Err(format!(
            "Invalid merkle root. Expected {}, got {}",
            share.header.merkle_root, calculated_merkle_root
        )
        .into());
    }
    Ok(())
}

/// Validate prev_share_blockhash is in store
pub async fn validate_prev_share_blockhash(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
) -> Result<(), Box<dyn Error>> {
    match share.header.prev_share_blockhash {
        Some(prev_share_blockhash) => {
            if chain_handle.get_share(prev_share_blockhash).await.is_none() {
                return Err(format!(
                    "Prev share blockhash {} not found in store",
                    prev_share_blockhash
                )
                .into());
            }
            Ok(())
        }
        None => Ok(()),
    }
}

/// Validate the share uncles are in store and no more than MAX_UNCLES
pub async fn validate_uncles(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
) -> Result<(), Box<dyn Error>> {
    if share.header.uncles.len() > MAX_UNCLES {
        return Err("Too many uncles".into());
    }
    for uncle in &share.header.uncles {
        if chain_handle.get_share(*uncle).await.is_none() {
            return Err(format!("Uncle {} not found in store", uncle.to_string()).into());
        }
    }
    Ok(())
}

/// Validate the share timestamp is within the last 60 seconds
pub async fn validate_timestamp(
    share: &ShareBlock,
    time_provider: &dyn TimeProviderTrait,
) -> Result<(), Box<dyn Error>> {
    let current_time = time_provider.current_time();

    let miner_share_time = share.miner_share.ntime.to_consensus_u32() as u64;
    let time_diff = if current_time > miner_share_time {
        current_time - miner_share_time
    } else {
        miner_share_time - current_time
    };

    tracing::info!("Time diff: {}", time_diff);

    if time_diff > MAX_TIME_DIFF {
        return Err(format!(
            "Share timestamp {} is more than {} seconds from current time {}",
            share.miner_share.ntime.to_consensus_u32(),
            MAX_TIME_DIFF,
            current_time
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::{BlockHash, PublicKey};
    use crate::test_utils::simple_miner_share;
    use crate::test_utils::test_share_block;
    use crate::utils::time_provider::TestTimeProvider;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_old_timestamp() {
        // Set timestamp to 2 minutes in the future from the share ntime
        let timestamp = u32::from_str_radix("678a17fe", 16).unwrap();
        let mut time_provider = TestTimeProvider::new();
        time_provider.set_time(timestamp as u64 + 120);

        let miner_share = simple_miner_share(None, None, None, None);
        let miner_pubkey: PublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let share = ShareBlock::new(
            miner_share,
            miner_pubkey,
            bitcoin::Network::Regtest,
            &mut vec![],
        );

        assert!(validate_timestamp(&share, &time_provider).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_future_timestamp() {
        let mut miner_share = simple_miner_share(None, None, None, None);

        // Set timestamp to 2 minutes in the past from the share ntime
        let timestamp = u32::from_str_radix("678a17fe", 16).unwrap();
        let mut time_provider = TestTimeProvider::new();
        time_provider.set_time(timestamp as u64 - 120);

        let miner_pubkey: PublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let share = ShareBlock::new(
            miner_share,
            miner_pubkey,
            bitcoin::Network::Regtest,
            &mut vec![],
        );

        assert!(validate_timestamp(&share, &time_provider).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_succeed_for_valid_timestamp() {
        let mut miner_share = simple_miner_share(None, None, None, None);

        // Set timestamp to ntime in the share
        let timestamp = u32::from_str_radix("678a17fe", 16).unwrap();
        let mut time_provider = TestTimeProvider::new();
        time_provider.set_time(timestamp as u64);

        let miner_pubkey: PublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let share = ShareBlock::new(
            miner_share,
            miner_pubkey,
            bitcoin::Network::Regtest,
            &mut vec![],
        );

        assert!(validate_timestamp(&share, &time_provider).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_prev_blockhash_exists() {
        let mut chain_handle = ChainHandle::default();

        // Set up initial share that will be referenced as prev_share_blockhash
        let initial_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        chain_handle
            .expect_get_share()
            .with(eq(initial_share.header.blockhash))
            .returning(move |_| Some(initial_share.clone()));

        // Create new share pointing to existing share - should validate
        let valid_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"),
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );
        assert!(validate_prev_share_blockhash(&valid_share, &chain_handle)
            .await
            .is_ok());

        // Create share pointing to non-existent previous hash - should fail validation
        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7";
        let invalid_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"),
            Some(non_existent_hash),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        chain_handle
            .expect_get_share()
            .with(eq(non_existent_hash.parse::<BlockHash>().unwrap()))
            .returning(move |_| None);

        assert!(validate_prev_share_blockhash(&invalid_share, &chain_handle)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_uncles() {
        let mut chain_handle = ChainHandle::default();

        // Create initial shares to use as uncles
        let uncle1 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let uncle2 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let uncle3 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let uncle4 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let uncle1_clone = uncle1.clone();
        let uncle2_clone = uncle2.clone();
        let uncle3_clone = uncle3.clone();
        let uncle4_clone = uncle4.clone();
        chain_handle
            .expect_get_share()
            .with(eq(uncle1_clone.header.blockhash))
            .returning(move |_| Some(uncle1_clone.clone()));
        chain_handle
            .expect_get_share()
            .with(eq(uncle2_clone.header.blockhash))
            .returning(move |_| Some(uncle2_clone.clone()));
        chain_handle
            .expect_get_share()
            .with(eq(uncle3_clone.header.blockhash))
            .returning(move |_| Some(uncle3_clone.clone()));
        chain_handle
            .expect_get_share()
            .with(eq(uncle4_clone.header.blockhash))
            .returning(move |_| Some(uncle4_clone.clone()));

        // Test share with valid number of uncles (MAX_UNCLES = 3)
        let valid_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![
                uncle1.header.blockhash,
                uncle2.header.blockhash,
                uncle3.header.blockhash,
            ],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        assert!(validate_uncles(&valid_share, &chain_handle).await.is_ok());

        // Test share with too many uncles (> MAX_UNCLES)
        let invalid_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"),
            None,
            vec![
                uncle1.header.blockhash,
                uncle2.header.blockhash,
                uncle3.header.blockhash,
                uncle4.header.blockhash,
            ],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );
        assert!(validate_uncles(&invalid_share, &chain_handle)
            .await
            .is_err());

        // Test share with non-existent uncle
        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse()
            .unwrap();
        chain_handle
            .expect_get_share()
            .with(eq(non_existent_hash))
            .returning(move |_| None);

        let invalid_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8"),
            None,
            vec![uncle1.header.blockhash, non_existent_hash],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );
        assert!(validate_uncles(&invalid_share, &chain_handle)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_merkle_root_for_only_coinbase_transaction_in_share() {
        let share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        assert!(validate_merkle_root(&share).await.is_ok());
    }
}
