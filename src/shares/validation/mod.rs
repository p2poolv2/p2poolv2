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

mod bitcoin_block_validation;

#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::ShareBlock;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;

pub const MAX_UNCLES: usize = 3;
pub const MAX_TIME_DIFF: u64 = 60;

/// Validate the share block, returning Error in case of failure to validate
/// validate nonce and blockhash meets difficulty
/// validate prev_share_blockhash is in store
/// validate uncles are in store and no more than MAX_UNCLES
/// validate timestamp is within the last 10 minutes
/// validate merkle root
/// validate coinbase transaction
pub async fn validate(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
    time_provider: &impl TimeProvider,
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
    let workbase = chain_handle
        .get_workbase(share.header.miner_share.workinfoid)
        .await;
    if workbase.is_none() {
        return Err(format!(
            "Missing workbase for share - workinfoid: {}",
            share.header.miner_share.workinfoid
        )
        .into());
    }
    let userworkbase = chain_handle
        .get_user_workbase(share.header.miner_share.workinfoid)
        .await;
    if userworkbase.is_none() {
        return Err(format!(
            "Missing user workbase for share - workinfoid: {}",
            share.header.miner_share.workinfoid
        )
        .into());
    }
    if let Err(e) = share
        .header
        .miner_share
        .validate(&workbase.unwrap(), &userworkbase.unwrap())
    {
        return Err(format!("Share validation failed: {}", e).into());
    }

    Ok(())
}

/// Validate prev_share_blockhash is in store or block is genesis
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
    time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    let current_time = time_provider.seconds_since_epoch();

    let miner_share_time = share.header.miner_share.ntime.to_consensus_u32() as u64;
    let time_diff = if current_time > miner_share_time {
        current_time - miner_share_time
    } else {
        miner_share_time - current_time
    };

    if time_diff > MAX_TIME_DIFF {
        return Err(format!(
            "Share timestamp {} is more than {} seconds from current time {}",
            share.header.miner_share.ntime.to_consensus_u32(),
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
    use crate::shares::{PublicKey, ShareBlockHash};
    use crate::test_utils::load_valid_workbases_userworkbases_and_shares;
    use crate::test_utils::simple_miner_share;
    use crate::test_utils::TestBlockBuilder;
    use crate::utils::time_provider::TestTimeProvider;
    use std::time::SystemTime;
    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_old_timestamp() {
        let miner_share = simple_miner_share(None, None, None, None, None);
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
        let mut time_provider = TestTimeProvider(SystemTime::now());
        let share_timestamp = share.header.miner_share.ntime.to_consensus_u32() as u64 - 120;

        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(share_timestamp as u32).unwrap());

        let result = validate_timestamp(&share, &time_provider).await;
        assert_eq!(
            result.err().unwrap().to_string(),
            "Share timestamp 1735224490 is more than 60 seconds from current time 1735224370"
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_future_timestamp() {
        let miner_share = simple_miner_share(None, None, None, None, None);
        let mut time_provider = TestTimeProvider(SystemTime::now());
        let future_time = miner_share.ntime.to_consensus_u32() as u64 + 120;
        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(future_time as u32).unwrap());

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
        let miner_share = simple_miner_share(None, None, None, None, None);
        let mut time_provider = TestTimeProvider(SystemTime::now());
        time_provider.set_time(miner_share.ntime);

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
        // Create and add initial share to chain
        let initial_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Create new share pointing to existing share - should validate
        let valid_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(initial_share.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut chain_handle = ChainHandle::default();
        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(
                initial_share.cached_blockhash.unwrap(),
            ))
            .returning(move |_| Some(initial_share.clone()));

        assert!(validate_prev_share_blockhash(&valid_share, &chain_handle)
            .await
            .is_ok());

        // Create share pointing to non-existent previous hash - should fail validation
        let non_existent_hash: ShareBlockHash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7".into();
        let invalid_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .prev_share_blockhash(non_existent_hash)
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(non_existent_hash))
            .returning(move |_| None);

        assert!(validate_prev_share_blockhash(&invalid_share, &chain_handle)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_uncles() {
        let mut chain_handle = ChainHandle::default();

        // Create initial shares to use as uncles
        let uncle1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle1_clone = uncle1.clone();
        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(uncle1.cached_blockhash.unwrap()))
            .returning(move |_| Some(uncle1_clone.clone()));

        let uncle2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle2_clone = uncle2.clone();

        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(uncle2.cached_blockhash.unwrap()))
            .returning(move |_| Some(uncle2_clone.clone()));

        let uncle3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle3_clone = uncle3.clone();

        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(uncle3.cached_blockhash.unwrap()))
            .returning(move |_| Some(uncle3_clone.clone()));

        let uncle4 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle4_clone = uncle4.clone();

        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(uncle4.cached_blockhash.unwrap()))
            .returning(move |_| Some(uncle4_clone.clone()));

        // Test share with valid number of uncles (MAX_UNCLES = 3)
        let valid_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .uncles(vec![
                uncle1.cached_blockhash.unwrap(),
                uncle2.cached_blockhash.unwrap(),
                uncle3.cached_blockhash.unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_uncles(&valid_share, &chain_handle).await.is_ok());

        // Test share with too many uncles (> MAX_UNCLES)
        let invalid_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .uncles(vec![
                uncle1.cached_blockhash.unwrap(),
                uncle2.cached_blockhash.unwrap(),
                uncle3.cached_blockhash.unwrap(),
                uncle4.cached_blockhash.unwrap(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_uncles(&invalid_share, &chain_handle)
            .await
            .is_err());

        // Test share with non-existent uncle
        let non_existent_hash: ShareBlockHash =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7".into();

        chain_handle
            .expect_get_share()
            .with(mockall::predicate::eq(non_existent_hash))
            .returning(|_| None);

        let invalid_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8")
            .uncles(vec![uncle1.cached_blockhash.unwrap(), non_existent_hash])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_uncles(&invalid_share, &chain_handle)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_share() {
        let mut chain_handle = ChainHandle::default();

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
        chain_handle
            .expect_add_share()
            .with(mockall::predicate::eq(share_block.clone()))
            .returning(|_| Ok(()));

        chain_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| share_block);
        chain_handle
            .expect_get_workbase()
            .with(mockall::predicate::eq(7473434392883363843))
            .returning(move |_| Some(workbases[0].clone()));
        chain_handle
            .expect_get_user_workbase()
            .with(mockall::predicate::eq(7473434392883363843))
            .returning(move |_| Some(userworkbases[0].clone()));

        let mut time_provider = TestTimeProvider(SystemTime::now());
        time_provider.set_time(shares[0].ntime);

        // Test handle_request directly without request_id
        let result = validate(&share_block, &chain_handle, &time_provider).await;

        assert!(result.is_ok());
    }
}
