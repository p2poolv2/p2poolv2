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

mod bitcoin_block_validation;

use super::share_block::ShareHeader;
#[cfg(test)]
#[mockall_double::double]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(not(test))]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::ShareBlock;
use crate::utils::time_provider::TimeProvider;
use bitcoin::{Amount, Target, TxMerkleNode};
use std::collections::HashSet;
use std::fmt;

/// Validation error wrapping a descriptive message string.
#[derive(Debug)]
pub struct ValidationError(String);

impl ValidationError {
    /// Create a new ValidationError with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for ValidationError {}

/// Maximum uncles in a share block header
pub const MAX_UNCLES: usize = 3;
/// Maximum time difference allowed between current tip and received shares
pub const MAX_TIME_DIFF: u64 = 60;
/// Maximum block size not counting bitcoin blocks limited to 200kB
pub const BLOCK_TXS_SIZE_LIMIT: u32 = 200 * 1024;
/// Maximum number of transactions allowed in a share block
pub const TXS_COUNT_LIMIT: u32 = 100;

/// Trait for share validation operations.
///
/// Provides methods to validate share headers, share blocks, uncles,
/// pool difficulty, and timestamps. Use `DefaultShareValidator` for
/// the production implementation.
pub trait ShareValidator {
    /// Validate the share header by checking proof of work and uncle count.
    ///
    /// Verifies that the number of uncles does not exceed MAX_UNCLES,
    /// then delegates to validate_with_pool_difficulty using the stored
    /// pool difficulty instance.
    fn validate_share_header(
        &self,
        share_header: &ShareHeader,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError>;

    /// Validate that the bitcoin header in the share header meets the pool difficulty.
    ///
    /// Also validates that the advertised bits in the share header match
    /// the pool difficulty as computed by our node.
    ///
    /// Looks up the parent share in the chain store to obtain the parent timestamp
    /// and height, then uses the stored pool difficulty to calculate the expected
    /// target for this share. Returns an error if the bitcoin block hash does not
    /// meet the calculated target.
    fn validate_with_pool_difficulty(
        &self,
        share_header: &ShareHeader,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError>;

    /// Validate the share block, returning ValidationError in case of failure.
    ///
    /// Returns Ok immediately if the block's metadata status is already
    /// BlockValid, allowing re-scheduled blocks (e.g. children of a
    /// newly validated parent) to skip redundant validation while still
    /// proceeding through organise_block.
    fn validate_share_block(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError>;

    /// Validate the share uncles are in store and no more than MAX_UNCLES.
    fn validate_uncles(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError>;

    /// Validate the share timestamp is within the last 60 seconds.
    fn validate_timestamp(
        &self,
        share: &ShareBlock,
        time_provider: &dyn TimeProvider,
    ) -> Result<(), ValidationError>;
}

/// Production implementation of ShareValidator.
///
/// Stores a `PoolDifficulty` instance initialized at construction time,
/// avoiding repeated builds on each validation call.
pub struct DefaultShareValidator {
    pool_difficulty: PoolDifficulty,
}

impl DefaultShareValidator {
    /// Create a new DefaultShareValidator with the given pool difficulty.
    ///
    /// Callers should build the `PoolDifficulty` from the chain store
    /// (via `PoolDifficulty::build`) and pass it here.
    pub fn new(pool_difficulty: PoolDifficulty) -> Self {
        Self { pool_difficulty }
    }

    /// Validate that the total size of share transactions does not exceed BLOCK_TXS_SIZE_LIMIT.
    fn validate_block_size(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let total_size: usize = share.transactions.iter().map(|tx| tx.total_size()).sum();
        if total_size > BLOCK_TXS_SIZE_LIMIT as usize {
            return Err(ValidationError::new(format!(
                "Block transactions size {total_size} exceeds limit of {BLOCK_TXS_SIZE_LIMIT}"
            )));
        }
        Ok(())
    }

    /// Validate the first share transaction in the share block is a coinbase transaction.
    fn validate_coinbase(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let first_tx = share
            .transactions
            .first()
            .ok_or_else(|| ValidationError::new("Share block has no transactions"))?;
        if first_tx.is_coinbase() {
            Ok(())
        } else {
            Err(ValidationError::new(
                "First transaction in share block is not a coinbase transaction",
            ))
        }
    }

    /// Validate the merkle root in the header matches the computed merkle root from transactions.
    fn validate_merkle_root(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let computed_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            share.transactions.iter().map(|tx| tx.compute_txid()),
        )
        .ok_or_else(|| ValidationError::new("Cannot compute merkle root from empty transactions"))?
        .into();

        if share.header.merkle_root != computed_root {
            return Err(ValidationError::new(format!(
                "Merkle root mismatch: header has {} but transactions compute to {}",
                share.header.merkle_root, computed_root
            )));
        }
        Ok(())
    }

    /// Validate that the total number of transactions does not exceed TXS_COUNT_LIMIT.
    fn validate_transaction_count(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let count = share.transactions.len() as u32;
        if count > TXS_COUNT_LIMIT {
            return Err(ValidationError::new(format!(
                "Transaction count {count} exceeds limit of {TXS_COUNT_LIMIT}"
            )));
        }
        Ok(())
    }

    /// Validate scripts and signatures for all non-coinbase transactions.
    ///
    /// For each input of each non-coinbase transaction, looks up the spent
    /// output from the chain store and verifies the script using
    /// libbitcoinconsensus. Coinbase transactions are skipped since they
    /// have no inputs to validate.
    fn validate_scripts(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        for transaction in &share.transactions {
            if transaction.is_coinbase() {
                continue;
            }

            let txid = transaction.compute_txid();
            let serialized_tx = bitcoin::consensus::serialize(&transaction.0);

            for (input_index, input) in transaction.input.iter().enumerate() {
                let spent_output = chain_store_handle
                    .get_output(
                        &input.previous_output.txid,
                        input.previous_output.vout,
                    )
                    .map_err(|error| {
                        ValidationError::new(format!(
                            "Failed to look up spent output {} for transaction {txid} input {input_index}: {error}",
                            input.previous_output
                        ))
                    })?;

                // Not checking for taproot yet.
                bitcoinconsensus::verify(
                    spent_output.script_pubkey.as_bytes(),
                    spent_output.value.to_sat(),
                    &serialized_tx,
                    None,
                    input_index,
                )
                .map_err(|error| {
                    ValidationError::new(format!(
                        "Script verification failed for transaction {txid} input {input_index}: {error:?}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Validate each transaction in the share block (context-free checks).
    ///
    /// Checks performed on the block:
    /// - No duplicate transactions
    ///
    /// Checks performed per transaction:
    /// - Has at least one output
    /// - Non-coinbase transactions have at least one input
    /// - No duplicate inputs (non-coinbase only)
    /// - Each output value does not exceed MAX_MONEY
    /// - Total output value does not overflow or exceed MAX_MONEY
    ///
    /// Script validation and signature verification are not performed here
    /// as rust-bitcoin does not provide a script execution engine.
    fn validate_transactions(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let mut seen_txids = HashSet::with_capacity(share.transactions.len());
        for transaction in &share.transactions {
            let txid = transaction.compute_txid();
            if !seen_txids.insert(txid) {
                return Err(ValidationError::new(format!(
                    "Duplicate transaction {txid} in block"
                )));
            }
            if transaction.output.is_empty() {
                return Err(ValidationError::new(format!(
                    "Transaction {txid} has no outputs",
                )));
            }

            if !transaction.is_coinbase() && transaction.input.is_empty() {
                return Err(ValidationError::new(format!(
                    "Non-coinbase transaction {txid} has no inputs",
                )));
            }

            if !transaction.is_coinbase() {
                let capacity = transaction.input.len();
                let mut seen_outpoints = HashSet::with_capacity(capacity);
                for input in &transaction.input {
                    if !seen_outpoints.insert(input.previous_output) {
                        return Err(ValidationError::new(format!(
                            "Transaction {txid} has duplicate input {}",
                            input.previous_output
                        )));
                    }
                }
            }

            let mut total_output = Amount::ZERO;
            for output in &transaction.output {
                if output.value > Amount::MAX_MONEY {
                    return Err(ValidationError::new(format!(
                        "Transaction {txid} output value {} exceeds maximum",
                        output.value
                    )));
                }
                total_output = total_output.checked_add(output.value).ok_or_else(|| {
                    ValidationError::new(format!("Transaction {txid} total output value overflow",))
                })?;
            }
            if total_output > Amount::MAX_MONEY {
                return Err(ValidationError::new(format!(
                    "Transaction {txid} total output value {total_output} exceeds maximum",
                )));
            }
        }
        Ok(())
    }
}

impl ShareValidator for DefaultShareValidator {
    fn validate_share_header(
        &self,
        share_header: &ShareHeader,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        if share_header.uncles.len() > MAX_UNCLES {
            return Err(ValidationError::new(format!(
                "Too many uncles: {} exceeds maximum of {}",
                share_header.uncles.len(),
                MAX_UNCLES
            )));
        }

        self.validate_with_pool_difficulty(share_header, chain_store_handle)
    }

    fn validate_with_pool_difficulty(
        &self,
        share_header: &ShareHeader,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        let parent_hash = share_header.prev_share_blockhash;
        let parent_header = chain_store_handle
            .get_share_header(&parent_hash)
            .map_err(|_| {
                ValidationError::new(format!("Parent share {parent_hash} not found in store"))
            })?;

        let parent_metadata = chain_store_handle
            .get_block_metadata(&parent_hash)
            .map_err(|_| {
                ValidationError::new(format!("Parent share {parent_hash} not found in store"))
            })?;

        let parent_height = parent_metadata.expected_height.ok_or_else(|| {
            ValidationError::new(format!("Parent share {parent_hash} not found in store"))
        })?;

        let parent_time = parent_header.time;

        let calculated_target = self
            .pool_difficulty
            .calculate_target(parent_time, parent_height);
        let target = Target::from_compact(calculated_target);
        let bitcoin_block_hash = share_header.bitcoin_header.block_hash();

        // Ensure the advertised header bits match the calculated pool target.
        if share_header.bits != calculated_target {
            return Err(ValidationError::new(format!(
                "Share header bits {:#010x} does not match calculated pool target {:#010x}",
                share_header.bits.to_consensus(),
                calculated_target.to_consensus()
            )));
        }

        if !target.is_met_by(bitcoin_block_hash) {
            return Err(ValidationError::new(format!(
                "Bitcoin block hash {bitcoin_block_hash} does not meet share target {target}"
            )));
        }

        Ok(())
    }

    fn validate_share_block(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        // When a hole in the chain is filled, schedule_dependents
        // re-schedules children that were already validated but could
        // not be promoted because their parent was not yet confirmed.
        // Return Ok immediately so organise_block gets another chance
        // to promote them without re-running validation.
        // Note: validate_and_emit also checks this before calling us,
        // but that check avoids duplicate organise/inv events, while
        // this one avoids redundant validation work if a caller bypasses
        // validate_and_emit.
        if chain_store_handle.has_status(
            &share.block_hash(),
            crate::store::block_tx_metadata::Status::BlockValid,
        ) {
            return Ok(());
        }
        self.validate_uncles(share, chain_store_handle)?;
        self.validate_block_size(share)?;
        // self.validate_coinbase(share)?;
        // self.validate_commitment(share);
        self.validate_merkle_root(share)?;
        self.validate_transaction_count(share)?;
        self.validate_transactions(share)?;
        self.validate_scripts(share, chain_store_handle)?;
        Ok(())
    }

    fn validate_uncles(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        if share.header.uncles.len() > MAX_UNCLES {
            return Err(ValidationError::new(format!(
                "Too many uncles: {} exceeds maximum of {}",
                share.header.uncles.len(),
                MAX_UNCLES
            )));
        }
        for uncle in &share.header.uncles {
            if chain_store_handle.get_share(uncle).is_none() {
                return Err(ValidationError::new(format!(
                    "Uncle {uncle} not found in store"
                )));
            }
        }
        Ok(())
    }

    fn validate_timestamp(
        &self,
        share: &ShareBlock,
        time_provider: &dyn TimeProvider,
    ) -> Result<(), ValidationError> {
        let current_time = time_provider.seconds_since_epoch();

        let share_timestamp = share.header.time as u64;
        let time_diff = current_time.abs_diff(share_timestamp);

        if time_diff > MAX_TIME_DIFF {
            return Err(ValidationError::new(format!(
                "Share timestamp {share_timestamp} is more than {MAX_TIME_DIFF} seconds from current time {current_time}"
            )));
        }
        Ok(())
    }
}

// Mock for DefaultShareValidator using mockall.
// Use with #[mockall_double::double] to swap real type for mock in tests.
#[cfg(test)]
mockall::mock! {
    pub DefaultShareValidator {
    }

    impl ShareValidator for DefaultShareValidator {
        fn validate_share_header(
            &self,
            share_header: &ShareHeader,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<(), ValidationError>;

        fn validate_with_pool_difficulty(
            &self,
            share_header: &ShareHeader,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<(), ValidationError>;

        fn validate_share_block(
            &self,
            share: &ShareBlock,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<(), ValidationError>;

        fn validate_uncles(
            &self,
            share: &ShareBlock,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<(), ValidationError>;

        fn validate_timestamp(
            &self,
            share: &ShareBlock,
            time_provider: &dyn TimeProvider,
        ) -> Result<(), ValidationError>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::share_block::ShareTransaction;
    use crate::test_utils::{
        TestShareBlockBuilder, genesis_for_tests, load_share_headers_test_data,
        setup_pool_difficulty_mocks,
    };
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::{BlockHash, ScriptBuf, TxOut, hashes::Hash};
    use mockall::predicate::*;
    use std::time::SystemTime;

    fn validator() -> DefaultShareValidator {
        DefaultShareValidator::new(PoolDifficulty::default())
    }

    fn validator_with(pool_difficulty: PoolDifficulty) -> DefaultShareValidator {
        DefaultShareValidator::new(pool_difficulty)
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_old_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        let share_timestamp = share.header.time as u64 - 120;

        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(share_timestamp as u32).unwrap());

        let result = validator().validate_timestamp(&share, &time_provider);
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Share timestamp {} is more than {MAX_TIME_DIFF} seconds from current time {}",
                share.header.time as u64,
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
        let future_time = share.header.time as u64 + 120;
        time_provider
            .set_time(bitcoin::absolute::Time::from_consensus(future_time as u32).unwrap());

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let error = validator()
            .validate_timestamp(&share, &time_provider)
            .unwrap_err();
        assert!(error.to_string().contains("seconds from current time"));
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_succeed_for_valid_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        assert!(
            validator()
                .validate_timestamp(&share, &time_provider)
                .is_ok()
        );
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

        assert!(
            validator()
                .validate_uncles(&valid_share, &chain_store_handle)
                .is_ok()
        );

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

        assert!(
            validator()
                .validate_uncles(&invalid_share, &chain_store_handle)
                .is_err()
        );

        assert!(
            validator()
                .validate_uncles(&invalid_share, &chain_store_handle)
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_validate_share() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let share_block = crate::test_utils::build_block_from_work_components(
            "../p2poolv2_tests/test_data/validation/stratum/b/",
        );

        // Set up mock expectations
        chain_store_handle
            .expect_has_status()
            .returning(|_, _| false);
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
            .returning(Ok);

        let result = validator().validate_share_block(&share_block, &chain_store_handle);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_share_block_returns_ok_for_block_valid_status() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        chain_store_handle
            .expect_has_status()
            .returning(|_, _| true);

        let result = validator().validate_share_block(&share_block, &chain_store_handle);
        assert!(
            result.is_ok(),
            "Expected Ok for BlockValid status, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_share_header_valid() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let mut pool_difficulty = PoolDifficulty::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["valid_header"].clone()).unwrap();

        setup_pool_difficulty_mocks(
            &mut chain_store_handle,
            &mut pool_difficulty,
            BlockHash::all_zeros(),
            0x207FFFFF,
        );

        let result = validator_with(pool_difficulty)
            .validate_with_pool_difficulty(&header, &chain_store_handle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_share_header_fails_for_bits_mismatch() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let mut pool_difficulty = PoolDifficulty::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["tight_target_header"].clone()).unwrap();

        setup_pool_difficulty_mocks(
            &mut chain_store_handle,
            &mut pool_difficulty,
            BlockHash::all_zeros(),
            0x02020000,
        );

        let error = validator_with(pool_difficulty)
            .validate_with_pool_difficulty(&header, &chain_store_handle)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match calculated pool target")
        );
    }

    #[test]
    fn test_validate_share_header_fails_for_insufficient_work() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let mut pool_difficulty = PoolDifficulty::default();
        let test_data = load_share_headers_test_data();
        let mut header: ShareHeader =
            serde_json::from_value(test_data["tight_target_header"].clone()).unwrap();

        // Use a tight target that matches the header bits so the bits check
        // passes, but the block hash will not meet this tight target.
        let tight_target_bits = 0x01010000u32;
        header.bits = bitcoin::CompactTarget::from_consensus(tight_target_bits);

        setup_pool_difficulty_mocks(
            &mut chain_store_handle,
            &mut pool_difficulty,
            BlockHash::all_zeros(),
            tight_target_bits,
        );

        let error = validator_with(pool_difficulty)
            .validate_with_pool_difficulty(&header, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("does not meet share target"));
    }

    #[test]
    fn test_validate_share_header_fails_for_too_many_uncles() {
        let chain_store_handle = ChainStoreHandle::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["too_many_uncles_header"].clone()).unwrap();

        let error = validator()
            .validate_share_header(&header, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("Too many uncles"));
    }

    #[test]
    fn test_validate_share_header_succeeds_with_max_uncles() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let mut pool_difficulty = PoolDifficulty::default();
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["max_uncles_header"].clone()).unwrap();

        setup_pool_difficulty_mocks(
            &mut chain_store_handle,
            &mut pool_difficulty,
            BlockHash::all_zeros(),
            0x207FFFFF,
        );

        let result = validator_with(pool_difficulty)
            .validate_with_pool_difficulty(&header, &chain_store_handle);
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result.err());
    }

    /// Build a transaction with a large script to produce a specific serialized size.
    fn build_large_transaction(target_size: usize) -> bitcoin::Transaction {
        let script = ScriptBuf::from_bytes(vec![0u8; target_size]);
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: script,
            }],
        }
    }

    #[test]
    fn test_validate_block_size_succeeds_for_small_block() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = validator().validate_block_size(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_block_size_fails_when_exceeding_limit() {
        let large_tx = build_large_transaction(BLOCK_TXS_SIZE_LIMIT as usize);
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(large_tx)
            .build();

        let result = validator().validate_block_size(&share);
        let error = result.unwrap_err();
        assert!(error.to_string().contains("exceeds limit of"));
    }

    #[test]
    fn test_validate_block_size_succeeds_at_exactly_limit() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let coinbase_size: usize = share.transactions.iter().map(|tx| tx.total_size()).sum();
        let remaining = BLOCK_TXS_SIZE_LIMIT as usize - coinbase_size;

        // Use a two-pass approach: build a candidate transaction, measure its
        // total size, then adjust the script size to hit the exact target.
        let candidate_tx = build_large_transaction(remaining);
        let overshoot = candidate_tx.total_size() - remaining;
        let fill_size = remaining - overshoot;

        let fill_tx = build_large_transaction(fill_size);
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(fill_tx)
            .build();

        let total_size: usize = share.transactions.iter().map(|tx| tx.total_size()).sum();
        assert_eq!(total_size, BLOCK_TXS_SIZE_LIMIT as usize);

        let result = validator().validate_block_size(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_merkle_root_succeeds_for_valid_share() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = validator().validate_merkle_root(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_merkle_root_fails_for_tampered_header() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        share.header.merkle_root = TxMerkleNode::all_zeros();

        let error = validator().validate_merkle_root(&share).unwrap_err();
        assert!(error.to_string().contains("Merkle root mismatch"));
    }

    #[test]
    fn test_validate_merkle_root_fails_when_transaction_removed() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(build_large_transaction(100))
            .build();

        // Remove the last transaction so the computed merkle root diverges from header
        share.transactions.pop();

        let error = validator().validate_merkle_root(&share).unwrap_err();
        assert!(error.to_string().contains("Merkle root mismatch"));
    }

    #[test]
    fn test_validate_transaction_count_succeeds_for_small_block() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = validator().validate_transaction_count(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transaction_count_succeeds_at_exactly_limit() {
        let mut builder = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202");

        // Builder already includes 1 coinbase tx, so add TXS_COUNT_LIMIT - 1 more
        for _ in 0..(TXS_COUNT_LIMIT - 1) {
            builder = builder.add_transaction(build_large_transaction(10));
        }
        let share = builder.build();

        assert_eq!(share.transactions.len() as u32, TXS_COUNT_LIMIT);
        let result = validator().validate_transaction_count(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transaction_count_fails_when_exceeding_limit() {
        let mut builder = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202");

        // Builder already includes 1 coinbase tx, so add TXS_COUNT_LIMIT more to exceed
        for _ in 0..TXS_COUNT_LIMIT {
            builder = builder.add_transaction(build_large_transaction(10));
        }
        let share = builder.build();

        assert!(share.transactions.len() as u32 > TXS_COUNT_LIMIT);
        let error = validator().validate_transaction_count(&share).unwrap_err();
        assert!(error.to_string().contains("exceeds limit of"));
    }

    #[test]
    fn test_validate_transactions_succeeds_for_valid_block() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = validator().validate_transactions(&share);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transactions_fails_for_empty_outputs() {
        let empty_output_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: Vec::new(),
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share.transactions.push(ShareTransaction(empty_output_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(error.to_string().contains("has no outputs"));
    }

    #[test]
    fn test_validate_transactions_fails_for_empty_inputs_non_coinbase() {
        let no_input_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share.transactions.push(ShareTransaction(no_input_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(error.to_string().contains("has no inputs"));
    }

    #[test]
    fn test_validate_transactions_fails_for_duplicate_inputs() {
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };
        let duplicate_input_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: outpoint,
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: outpoint,
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share
            .transactions
            .push(ShareTransaction(duplicate_input_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(error.to_string().contains("has duplicate input"));
    }

    #[test]
    fn test_validate_transactions_fails_for_output_exceeding_max_money() {
        let over_max_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: bitcoin::Amount::MAX_MONEY + bitcoin::Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share.transactions.push(ShareTransaction(over_max_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(error.to_string().contains("output value"));
        assert!(error.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_transactions_fails_for_total_output_overflow() {
        let near_max = bitcoin::Amount::MAX_MONEY;
        let overflow_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![
                TxOut {
                    value: near_max,
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: bitcoin::Amount::from_sat(1),
                    script_pubkey: ScriptBuf::new(),
                },
            ],
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share.transactions.push(ShareTransaction(overflow_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(
            error.to_string().contains("exceeds maximum") || error.to_string().contains("overflow")
        );
    }

    #[test]
    fn test_validate_transactions_fails_for_duplicate_transactions() {
        let duplicate_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share
            .transactions
            .push(ShareTransaction(duplicate_tx.clone()));
        share.transactions.push(ShareTransaction(duplicate_tx));

        let error = validator().validate_transactions(&share).unwrap_err();
        assert!(error.to_string().contains("Duplicate transaction"));
    }

    #[test]
    fn test_validate_scripts_succeeds_for_coinbase_only() {
        let chain_store_handle = ChainStoreHandle::default();

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = validator().validate_scripts(&share, &chain_store_handle);
        assert!(
            result.is_ok(),
            "Coinbase-only block should pass script validation"
        );
    }

    /// Build a spending transaction that uses OP_TRUE as redeem script via P2SH.
    ///
    /// The scriptPubKey is P2SH `hash160 OP_TRUE equal`, and the scriptSig pushes
    /// the OP_TRUE redeem script. This creates a valid spend without needing
    /// real signatures.
    fn build_p2sh_op_true_spent_output_and_spending_tx() -> (bitcoin::TxOut, bitcoin::Transaction) {
        // Redeem script: OP_TRUE (0x51)
        let redeem_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();

        // P2SH scriptPubKey: OP_HASH160 <hash(redeem_script)> OP_EQUAL
        let script_pubkey = redeem_script.to_p2sh();

        let spent_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey,
        };

        // scriptSig pushes the redeem script.
        // Build the push manually: <length> <redeem_script_bytes>
        let mut script_sig_bytes = Vec::with_capacity(1 + redeem_script.len());
        script_sig_bytes.push(redeem_script.len() as u8);
        script_sig_bytes.extend_from_slice(redeem_script.as_bytes());
        let script_sig = ScriptBuf::from(script_sig_bytes);

        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig,
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        (spent_output, spending_tx)
    }

    #[test]
    fn test_validate_scripts_succeeds_for_valid_p2sh_script() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let (spent_output, spending_tx) = build_p2sh_op_true_spent_output_and_spending_tx();

        let spent_output_clone = spent_output.clone();
        chain_store_handle
            .expect_get_output()
            .returning(move |_txid, _vout| Ok(spent_output_clone.clone()));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let result = validator().validate_scripts(&share, &chain_store_handle);
        assert!(
            result.is_ok(),
            "Valid P2SH OP_TRUE spend should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_scripts_fails_for_invalid_script() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a spent output with P2SH wrapping OP_TRUE
        let redeem_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let script_pubkey = redeem_script.to_p2sh();

        let spent_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey,
        };

        // Spending tx with EMPTY scriptSig -- does not push the redeem script
        let invalid_spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spent_output_clone = spent_output.clone();
        chain_store_handle
            .expect_get_output()
            .returning(move |_txid, _vout| Ok(spent_output_clone.clone()));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(invalid_spending_tx)
            .build();

        let error = validator()
            .validate_scripts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("Script verification failed"),
            "Expected script verification failure, got: {error}"
        );
    }

    #[test]
    fn test_validate_scripts_fails_for_missing_utxo() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        chain_store_handle
            .expect_get_output()
            .returning(|_txid, _vout| {
                Err(crate::store::writer::StoreError::NotFound(
                    "Output not found".to_string(),
                ))
            });

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_scripts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("Failed to look up spent output"),
            "Expected UTXO lookup failure, got: {error}"
        );
    }
}
