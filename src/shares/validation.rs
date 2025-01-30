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

use crate::shares::chain::ChainHandle;
use crate::shares::ShareBlock;
use std::char::MAX;
use std::error::Error;

pub const MAX_UNCLES: usize = 3;
pub const MAX_TIME_DIFF: u64 = 60;

/// Validate the share block, returning Error in case of failure to validate
/// TODO: validate nonce and blockhash meets difficulty
/// DONE: validate prev_share_blockhash is in store
/// DONE: validate uncles are in store and no more than MAX_UNCLES
/// DONE: validate timestamp is within the last 10 minutes
pub async fn validate(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
) -> Result<(), Box<dyn Error>> {
    if let Err(e) = validate_timestamp(share).await {
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

    Ok(())
}

/// Validate prev_share_blockhash is in store
pub async fn validate_prev_share_blockhash(
    share: &ShareBlock,
    chain_handle: &ChainHandle,
) -> Result<(), Box<dyn Error>> {
    match share.prev_share_blockhash {
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
    if share.uncles.len() > MAX_UNCLES {
        return Err("Too many uncles".into());
    }
    for uncle in &share.uncles {
        if chain_handle.get_share(*uncle).await.is_none() {
            return Err(format!("Uncle {} not found in store", uncle.to_string()).into());
        }
    }
    Ok(())
}

/// Validate the share timestamp is within the last 60 seconds
pub async fn validate_timestamp(share: &ShareBlock) -> Result<(), Box<dyn Error>> {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time_diff = if current_time > share.timestamp {
        current_time - share.timestamp
    } else {
        share.timestamp - current_time
    };

    tracing::info!("Time diff: {}", time_diff);

    if time_diff > MAX_TIME_DIFF {
        return Err(format!(
            "Share timestamp {} is more than {} seconds from current time {}",
            share.timestamp, MAX_TIME_DIFF, current_time
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::simple_miner_share;

    #[tokio::test]
    async fn test_validate_timestamp() {
        let share = simple_miner_share(None, None, None, None);
        // assert!(validate_timestamp(&share).await.is_ok());
    }
}
