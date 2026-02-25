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

mod bitcoin_block_validation;

use super::share_block::ShareHeader;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::utils::time_provider::TimeProvider;
use bitcoin::{BlockHash, Target};
use std::fmt;

/// Validation errors for share headers and share blocks.
#[derive(Debug)]
pub enum ValidationError {
    /// The number of uncles exceeds MAX_UNCLES
    TooManyUncles { count: usize, maximum: usize },
    /// The block hash does not meet the share target
    InsufficientWork {
        block_hash: BlockHash,
        target: Target,
    },
    /// The share timestamp is too far from the current time
    TimestampOutOfRange {
        share_timestamp: u64,
        current_time: u64,
        max_difference: u64,
    },
    /// An uncle referenced in the share was not found in the chain store
    UncleNotFound { uncle_hash: BlockHash },
    /// Bitcoin block validation failed via RPC
    BitcoinBlockValidation(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyUncles { count, maximum } => {
                write!(
                    formatter,
                    "Too many uncles: {count} exceeds maximum of {maximum}"
                )
            }
            Self::InsufficientWork { block_hash, target } => {
                write!(
                    formatter,
                    "Share block hash {block_hash} does not meet share target {target}"
                )
            }
            Self::TimestampOutOfRange {
                share_timestamp,
                current_time,
                max_difference,
            } => {
                write!(
                    formatter,
                    "Share timestamp {share_timestamp} is more than {max_difference} seconds from current time {current_time}"
                )
            }
            Self::UncleNotFound { uncle_hash } => {
                write!(formatter, "Uncle {uncle_hash} not found in store")
            }
            Self::BitcoinBlockValidation(message) => {
                write!(formatter, "Bitcoin block validation failed: {message}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Maximum uncles in a share block header
pub const MAX_UNCLES: usize = 3;
/// Maximum time difference allowed between current tip and received shares
pub const MAX_TIME_DIFF: u64 = 60;

/// Validate the share header by checking proof of work and uncle count.
///
/// Verifies that the share's block hash meets its compact target (bits)
/// and that the number of uncles does not exceed MAX_UNCLES.
pub fn validate_share_header(
    share: &ShareHeader,
    _chain_store_handle: &ChainStoreHandle,
) -> Result<(), ValidationError> {
    if share.uncles.len() > MAX_UNCLES {
        return Err(ValidationError::TooManyUncles {
            count: share.uncles.len(),
            maximum: MAX_UNCLES,
        });
    }

    let target = Target::from_compact(share.bits);
    let block_hash = share.block_hash();
    if !target.is_met_by(block_hash) {
        return Err(ValidationError::InsufficientWork { block_hash, target });
    }

    Ok(())
}

/// Validate the share block, returning ValidationError in case of failure.
/// TODO: validate nonce and blockhash meets pool difficulty
/// validate prev_share_blockhash is in store
/// validate uncles are in store and no more than MAX_UNCLES
/// TODO: validate merkle root
/// TODO: validate coinbase transaction
pub fn validate_share_block(
    share: &ShareBlock,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(), ValidationError> {
    validate_uncles(share, chain_store_handle)?;
    // TODO: Populate bitcoin block from ShortIDs in share and use bitcoin_block_validation to validate difficulty
    // OR - Fetch difficulty from bitcoind rpc and validate share blockhash meets difficulty
    Ok(())
}

/// Validate the share uncles are in store and no more than MAX_UNCLES.
pub fn validate_uncles(
    share: &ShareBlock,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(), ValidationError> {
    if share.header.uncles.len() > MAX_UNCLES {
        return Err(ValidationError::TooManyUncles {
            count: share.header.uncles.len(),
            maximum: MAX_UNCLES,
        });
    }
    for uncle in &share.header.uncles {
        if chain_store_handle.get_share(uncle).is_none() {
            return Err(ValidationError::UncleNotFound { uncle_hash: *uncle });
        }
    }
    Ok(())
}

/// Validate the share timestamp is within the last 60 seconds.
pub fn validate_timestamp(
    share: &ShareBlock,
    time_provider: &impl TimeProvider,
) -> Result<(), ValidationError> {
    let current_time = time_provider.seconds_since_epoch();

    let block_timestamp = share.header.bitcoin_header.time as u64;
    let time_diff = current_time.abs_diff(block_timestamp);

    if time_diff > MAX_TIME_DIFF {
        return Err(ValidationError::TimestampOutOfRange {
            share_timestamp: block_timestamp,
            current_time,
            max_difference: MAX_TIME_DIFF,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestShareBlockBuilder, genesis_for_tests};
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::{BlockHash, hashes::Hash};
    use mockall::predicate::*;
    use std::time::SystemTime;

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_old_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        let share_timestamp = share.header.bitcoin_header.time as u64 - 120;

        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(share_timestamp as u32).unwrap());

        let result = validate_timestamp(&share, &time_provider);
        let error = result.unwrap_err();
        assert!(
            matches!(error, ValidationError::TimestampOutOfRange { .. }),
            "Expected TimestampOutOfRange, got: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "Share timestamp {} is more than {MAX_TIME_DIFF} seconds from current time {}",
                share.header.bitcoin_header.time as u64,
                time_provider.seconds_since_epoch()
            )
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_future_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        let future_time = share.header.bitcoin_header.time as u64 + 120;
        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(future_time as u32).unwrap());

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let error = validate_timestamp(&share, &time_provider).unwrap_err();
        assert!(matches!(error, ValidationError::TimestampOutOfRange { .. }));
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_succeed_for_valid_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(
            bitcoin::absolute::Time::from_consensus(share.header.bitcoin_header.time).unwrap(),
        );

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_timestamp(&share, &time_provider).is_ok());
    }

    #[tokio::test]
    async fn test_validate_uncles() {
        let mut seq = mockall::Sequence::new();
        let mut chain_store_handle = ChainStoreHandle::default();

        // Create initial shares to use as uncles
        let uncle1 = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle1_clone = uncle1.clone();
        chain_store_handle
            .expect_get_share()
            .times(1)
            .in_sequence(&mut seq)
            .with(mockall::predicate::eq(uncle1.block_hash()))
            .returning(move |_| Some(uncle1_clone.clone()));

        let uncle2 = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle2_clone = uncle2.clone();

        chain_store_handle
            .expect_get_share()
            .times(1)
            .in_sequence(&mut seq)
            .with(mockall::predicate::eq(uncle2.block_hash()))
            .returning(move |_| Some(uncle2_clone.clone()));

        let uncle3 = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let uncle3_clone = uncle3.clone();

        chain_store_handle
            .expect_get_share()
            .times(1)
            .in_sequence(&mut seq)
            .with(mockall::predicate::eq(uncle3.block_hash()))
            .returning(move |_| Some(uncle3_clone.clone()));

        let uncle4 = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let _uncle4_clone = uncle4.clone();

        // Test share with non-existent uncle
        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse::<BlockHash>()
            .unwrap();

        let _invalid_share_b = TestShareBlockBuilder::new()
            .uncles(vec![uncle1.block_hash(), non_existent_hash])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Test share with valid number of uncles (MAX_UNCLES = 3)
        let valid_share = TestShareBlockBuilder::new()
            .uncles(vec![
                uncle1.block_hash(),
                uncle2.block_hash(),
                uncle3.block_hash(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_uncles(&valid_share, &chain_store_handle).is_ok());

        // Test share with too many uncles (> MAX_UNCLES)
        let invalid_share = TestShareBlockBuilder::new()
            .uncles(vec![
                uncle1.block_hash(),
                uncle2.block_hash(),
                uncle3.block_hash(),
                uncle4.block_hash(),
            ])
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(validate_uncles(&invalid_share, &chain_store_handle).is_err());

        assert!(validate_uncles(&invalid_share, &chain_store_handle).is_err());
    }

    #[tokio::test]
    async fn test_validate_share() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let share_block = crate::test_utils::build_block_from_work_components(
            "../p2poolv2_tests/test_data/validation/stratum/b/",
        );

        // Set up mock expectations
        chain_store_handle
            .expect_add_share_block()
            .with(
                mockall::predicate::eq(share_block.clone()),
                mockall::predicate::eq(true),
            )
            .returning(|_, _| Ok(()));
        chain_store_handle
            .expect_get_share()
            .with(eq(bitcoin::BlockHash::all_zeros()))
            .returning(|_| Some(genesis_for_tests()));

        chain_store_handle
            .expect_setup_share_for_chain()
            .returning(|share_block| Ok(share_block));

        let result = validate_share_block(&share_block, &chain_store_handle);

        assert!(result.is_ok());
    }

    /// Load share headers test data from JSON fixture file
    fn load_share_headers_test_data() -> serde_json::Value {
        let json_string =
            std::fs::read_to_string("../p2poolv2_tests/test_data/validation/share_headers.json")
                .expect("Failed to read share_headers.json");
        serde_json::from_str(&json_string).unwrap()
    }

    #[test]
    fn test_validate_share_header_valid() {
        let chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();

        let result = validate_share_header(&header, &chain_store_handle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_share_header_fails_for_hash_not_meeting_target() {
        let chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["tight_target_header"].clone()).unwrap();

        let error = validate_share_header(&header, &chain_store_handle).unwrap_err();
        assert!(
            matches!(error, ValidationError::InsufficientWork { .. }),
            "Expected InsufficientWork, got: {error:?}"
        );
        assert!(error.to_string().contains("does not meet share target"));
    }

    #[test]
    fn test_validate_share_header_fails_for_too_many_uncles() {
        let chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["too_many_uncles_header"].clone()).unwrap();

        let error = validate_share_header(&header, &chain_store_handle).unwrap_err();
        assert!(
            matches!(error, ValidationError::TooManyUncles { .. }),
            "Expected TooManyUncles, got: {error:?}"
        );
        assert!(error.to_string().contains("Too many uncles"));
    }

    #[test]
    fn test_validate_share_header_succeeds_with_max_uncles() {
        let chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["max_uncles_header"].clone()).unwrap();

        let result = validate_share_header(&header, &chain_store_handle);
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result.err());
    }
}
