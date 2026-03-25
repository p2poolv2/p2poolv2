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
use crate::accounting::OutputPair;
use crate::accounting::payout::payout_distribution::{
    append_proportional_distribution, include_address_and_cut,
};
#[cfg(test)]
#[mockall_double::double]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
#[cfg(not(test))]
use crate::accounting::payout::sharechain_pplns::PplnsWindow;
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
use crate::shares::share_block::{ShareBlock, ShareTransaction};
use crate::shares::share_commitment::ShareCommitment;
use crate::store::block_tx_metadata::Status;
use crate::stratum::work::coinbase;
use crate::utils::time_provider::TimeProvider;
use bitcoin::{Address, Amount, BlockHash, Target, Transaction, TxMerkleNode};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

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

/// Initial block subsidy in satoshis (50 BTC).
const INITIAL_SUBSIDY_SATS: u64 = 5_000_000_000;
/// Number of blocks between each halving.
const HALVING_INTERVAL: i64 = 210_000;
/// Maximum number of halvings before subsidy reaches zero.
const MAX_HALVINGS: i64 = 64;

/// Compute the block subsidy for a given block height.
///
/// Uses Bitcoin's halving schedule: 50 BTC initially, halving every
/// 210,000 blocks, reaching zero after 64 halvings.
fn compute_block_subsidy(height: i64) -> Amount {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= MAX_HALVINGS {
        return Amount::ZERO;
    }
    Amount::from_sat(INITIAL_SUBSIDY_SATS >> halvings)
}

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
        pplns_window: Arc<RwLock<PplnsWindow>>,
    ) -> Result<(), ValidationError>;

    /// Validate uncles: count within MAX_UNCLES, no duplicates, each exists
    /// in store, and none are on the confirmed chain.
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
    /// Multiplier applied to bitcoin difficulty when walking the PPLNS window.
    difficulty_multiplier: u128,
}

impl DefaultShareValidator {
    /// Create a new DefaultShareValidator with the given pool difficulty
    /// and difficulty multiplier for PPLNS window walks.
    pub fn new(pool_difficulty: PoolDifficulty, difficulty_multiplier: u128) -> Self {
        Self {
            pool_difficulty,
            difficulty_multiplier,
        }
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
    /// Iterates over each non-coinbase transaction, collects spent outputs
    /// from the chain store, and verifies each input script using
    /// libbitcoinconsensus. Coinbase transactions are skipped since they
    /// have no inputs to validate.
    fn validate_scripts(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        for (index, transaction) in share.transactions.iter().enumerate() {
            if index == 0 {
                continue;
            }
            let txid = transaction.compute_txid();
            let spent_outputs =
                Self::collect_spent_outputs(transaction, chain_store_handle, &txid)?;
            Self::validate_scripts_for_tx(transaction, &spent_outputs, &txid)?;
        }
        Ok(())
    }

    /// Collect all spent outputs for a transaction from the chain store.
    ///
    /// Uses a batch query to fetch all previous outputs in a single
    /// store call. Taproot verification requires the full set of spent
    /// outputs for signature hashing, so all outputs are collected
    /// upfront. Returns (input_index, TxOut) pairs in input order.
    fn collect_spent_outputs(
        transaction: &ShareTransaction,
        chain_store_handle: &ChainStoreHandle,
        txid: &bitcoin::Txid,
    ) -> Result<Vec<(usize, bitcoin::TxOut)>, ValidationError> {
        chain_store_handle
            .get_all_prevouts(&transaction.0)
            .map_err(|error| {
                ValidationError::new(format!(
                    "Failed to look up spent outputs for transaction {txid}: {error}"
                ))
            })
    }

    /// Verify all input scripts for a single transaction.
    ///
    /// Builds the bitcoinconsensus Utxo slice from the spent outputs and
    /// calls the consensus script verifier for each input. The Utxo
    /// struct holds raw pointers into the TxOut data, so spent_outputs
    /// must remain alive for the duration of verification.
    fn validate_scripts_for_tx(
        transaction: &ShareTransaction,
        spent_outputs: &[(usize, bitcoin::TxOut)],
        txid: &bitcoin::Txid,
    ) -> Result<(), ValidationError> {
        let serialized_tx = bitcoin::consensus::serialize(&transaction.0);

        let utxos: Vec<bitcoinconsensus::Utxo> = spent_outputs
            .iter()
            .map(|(_index, txout)| bitcoinconsensus::Utxo {
                script_pubkey: txout.script_pubkey.as_bytes().as_ptr(),
                script_pubkey_len: txout.script_pubkey.len() as u32,
                value: txout.value.to_sat() as i64,
            })
            .collect();

        for (input_index, spent_output) in spent_outputs {
            bitcoinconsensus::verify(
                spent_output.script_pubkey.as_bytes(),
                spent_output.value.to_sat(),
                &serialized_tx,
                Some(&utxos),
                *input_index,
            )
            .map_err(|error| {
                ValidationError::new(format!(
                    "Script verification failed for transaction {txid} input {input_index}: {error:?}"
                ))
            })?;
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

    /// Validate the share coinbase pays 1 BTC to the miner address in the header.
    fn validate_share_coinbase(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let coinbase = share
            .transactions
            .first()
            .ok_or_else(|| ValidationError::new("Share block has no transactions"))?;

        if !coinbase.is_coinbase() {
            return Err(ValidationError::new(
                "First transaction in share block is not a coinbase transaction",
            ));
        }

        if coinbase.output.len() != 1 {
            return Err(ValidationError::new(format!(
                "Share coinbase has {} outputs, expected 1",
                coinbase.output.len()
            )));
        }

        let output = &coinbase.output[0];
        if output.value != Amount::ONE_BTC {
            return Err(ValidationError::new(format!(
                "Share coinbase pays {} but expected {}",
                output.value,
                Amount::ONE_BTC
            )));
        }

        let expected_script = share.header.miner_address.script_pubkey();
        if output.script_pubkey != expected_script {
            return Err(ValidationError::new(
                "Share coinbase output does not pay to the miner address in header",
            ));
        }

        Ok(())
    }

    /// Validate the commitment hash in the bitcoin coinbase scriptSig matches
    /// the expected commitment reconstructed from the share header.
    fn validate_commitment_hash(
        &self,
        share: &ShareBlock,
        bitcoin_coinbase: &Transaction,
    ) -> Result<(), ValidationError> {
        let extracted_hash = coinbase::extract_commitment_hash_from_coinbase(bitcoin_coinbase)
            .map_err(|error| {
                ValidationError::new(format!("Failed to extract commitment hash: {error}"))
            })?;

        let bitcoin_template_transactions = if share.bitcoin_transactions.len() > 1 {
            &share.bitcoin_transactions[1..]
        } else {
            &[]
        };
        let expected_commitment =
            ShareCommitment::from_share_header(&share.header, bitcoin_template_transactions);
        let expected_hash = expected_commitment.hash();

        if extracted_hash != expected_hash {
            return Err(ValidationError::new(format!(
                "Commitment hash mismatch: coinbase has {extracted_hash} but share computes to {expected_hash}"
            )));
        }

        Ok(())
    }

    /// Validate the coinbase payouts match expected and the share commitment
    /// in the bitcoin coinbase matches the share block.
    fn validate_bitcoin_coinbase(
        &self,
        share: &ShareBlock,
        pplns_window: Arc<RwLock<PplnsWindow>>,
    ) -> Result<(), ValidationError> {
        let bitcoin_coinbase = share
            .bitcoin_transactions
            .first()
            .ok_or_else(|| ValidationError::new("Share block has no bitcoin transactions"))?;

        if !bitcoin_coinbase.is_coinbase() {
            return Err(ValidationError::new(
                "First transaction of bitcoin block is not a coinbase",
            ));
        }

        self.validate_commitment_hash(share, bitcoin_coinbase)?;
        self.validate_bitcoin_payout(share, bitcoin_coinbase, pplns_window)?;
        Ok(())
    }

    /// Validate bitcoin coinbase payout meets our PplnsWindow.
    ///
    /// Computes the expected distribution from the PPLNS window using
    /// bitcoin header difficulty * difficulty_multiplier, then verifies
    /// that the coinbase outputs match the expected donation, fee, and
    /// proportional PPLNS outputs.
    fn validate_bitcoin_payout(
        &self,
        share: &ShareBlock,
        coinbase_transaction: &Transaction,
        pplns_window: Arc<RwLock<PplnsWindow>>,
    ) -> Result<(), ValidationError> {
        let window = pplns_window
            .read()
            .expect("PPLNS window lock poisoned on read");

        let bitcoin_difficulty = share.header.bitcoin_header.difficulty(window.network());
        let total_difficulty = bitcoin_difficulty.saturating_mul(self.difficulty_multiplier);

        let address_difficulty_map = window
            .get_distribution_from_start_hash(total_difficulty, share.header.prev_share_blockhash)
            .ok_or_else(|| {
                ValidationError::new("prev_share_blockhash not found in PPLNS window")
            })?;

        let total_amount = Self::compute_total_payout_amount(coinbase_transaction)?;
        Self::validate_total_against_subsidy(coinbase_transaction, total_amount)?;

        let expected_outputs =
            Self::build_expected_outputs(&share.header, &address_difficulty_map, total_amount)?;
        match expected_outputs {
            Some(outputs) => Self::compare_outputs(&outputs, coinbase_transaction),
            None => Ok(()),
        }
    }

    /// Sum non-OP_RETURN coinbase outputs to get the total payout amount.
    fn compute_total_payout_amount(
        coinbase_transaction: &Transaction,
    ) -> Result<Amount, ValidationError> {
        let total = coinbase_transaction
            .output
            .iter()
            .filter(|output| !output.script_pubkey.is_op_return())
            .try_fold(Amount::ZERO, |accumulated, output| {
                accumulated.checked_add(output.value)
            })
            .ok_or_else(|| ValidationError::new("Coinbase payout total overflows"))?;
        if total == Amount::ZERO {
            return Err(ValidationError::new("Coinbase has no payout outputs"));
        }
        Ok(total)
    }

    /// Validate that coinbase total is at least the block subsidy for the encoded height.
    fn validate_total_against_subsidy(
        coinbase_transaction: &Transaction,
        total_amount: Amount,
    ) -> Result<(), ValidationError> {
        let height =
            coinbase::extract_height_from_coinbase(coinbase_transaction).map_err(|error| {
                ValidationError::new(format!("Failed to extract block height: {error}"))
            })?;
        let subsidy = compute_block_subsidy(height);
        if total_amount < subsidy {
            return Err(ValidationError::new(format!(
                "Coinbase total {total_amount} is less than block subsidy {subsidy} at height {height}"
            )));
        }
        Ok(())
    }

    /// Build the expected payout outputs from share header donation/fee and PPLNS distribution.
    ///
    /// When the PPLNS window is empty (bootstrap phase), returns None
    /// since the miner uses a bootstrap address we cannot verify.
    fn build_expected_outputs(
        share_header: &ShareHeader,
        address_difficulty_map: &HashMap<Address, u128>,
        total_amount: Amount,
    ) -> Result<Option<Vec<OutputPair>>, ValidationError> {
        if address_difficulty_map.is_empty() {
            return Ok(None);
        }

        let mut distribution = Vec::with_capacity(address_difficulty_map.len() + 2);

        let remaining_after_donation = include_address_and_cut(
            &mut distribution,
            total_amount,
            &share_header.donation_address,
            share_header.donation,
        );
        let remaining_after_fees = include_address_and_cut(
            &mut distribution,
            remaining_after_donation,
            &share_header.fee_address,
            share_header.fee,
        );

        append_proportional_distribution(
            address_difficulty_map,
            remaining_after_fees,
            &mut distribution,
        )
        .map_err(|error| {
            ValidationError::new(format!("Failed to compute payout distribution: {error}"))
        })?;

        Ok(Some(distribution))
    }

    /// Compare expected output pairs against actual coinbase outputs.
    ///
    /// Filters out OP_RETURN outputs (witness commitments) from the coinbase,
    /// then checks that the count and each (script_pubkey, value) pair match.
    fn compare_outputs(
        expected_outputs: &[OutputPair],
        coinbase_transaction: &Transaction,
    ) -> Result<(), ValidationError> {
        let actual_payout_outputs: Vec<_> = coinbase_transaction
            .output
            .iter()
            .filter(|output| !output.script_pubkey.is_op_return())
            .collect();

        if expected_outputs.len() != actual_payout_outputs.len() {
            return Err(ValidationError::new(format!(
                "Expected {} payout outputs but coinbase has {}",
                expected_outputs.len(),
                actual_payout_outputs.len()
            )));
        }

        for (index, (expected, actual)) in expected_outputs
            .iter()
            .zip(actual_payout_outputs.iter())
            .enumerate()
        {
            let expected_script = expected.address.script_pubkey();
            if actual.script_pubkey != expected_script {
                return Err(ValidationError::new(format!(
                    "Payout output {index}: script mismatch"
                )));
            }
            if actual.value != expected.amount {
                return Err(ValidationError::new(format!(
                    "Payout output {index}: expected {} but got {}",
                    expected.amount, actual.value
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
        pplns_window: Arc<RwLock<PplnsWindow>>,
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
        if chain_store_handle.has_status(&share.block_hash(), Status::BlockValid) {
            return Ok(());
        }
        self.validate_uncles(share, chain_store_handle)?;
        self.validate_block_size(share)?;
        self.validate_share_coinbase(share)?;
        self.validate_bitcoin_coinbase(share, pplns_window)?;
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
        let unique_uncles: HashSet<&BlockHash> = share.header.uncles.iter().collect();
        if share.header.uncles.len() != unique_uncles.len() {
            return Err(ValidationError::new("Share has duplicate uncles"));
        }
        for uncle in &share.header.uncles {
            if !chain_store_handle.share_block_exists(uncle) {
                return Err(ValidationError::new(format!(
                    "Uncle {uncle} not found in store"
                )));
            };
            if chain_store_handle.has_status(uncle, Status::Confirmed) {
                return Err(ValidationError::new(format!(
                    "Uncle {uncle} is on confirmed chain"
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
            pplns_window: Arc<RwLock<PplnsWindow>>,
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
        TestShareBlockBuilder, build_block_from_work_components, genesis_for_tests,
        load_share_headers_test_data, setup_pool_difficulty_mocks,
    };
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{BlockHash, ScriptBuf, TxOut, hashes::Hash};
    use mockall::predicate::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::SystemTime;

    fn validator() -> DefaultShareValidator {
        DefaultShareValidator::new(PoolDifficulty::default(), 1)
    }

    fn validator_with(pool_difficulty: PoolDifficulty) -> DefaultShareValidator {
        DefaultShareValidator::new(pool_difficulty, 1)
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

    use crate::test_utils::{PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_G};

    #[tokio::test]
    async fn test_validate_uncles_valid() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let uncle1 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_G).build();
        let uncle2 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_2G).build();
        let uncle3 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_3G).build();

        // All uncles exist and are not confirmed
        chain_store_handle
            .expect_share_block_exists()
            .returning(|_| true);
        chain_store_handle
            .expect_has_status()
            .returning(|_, _| false);

        let valid_share = TestShareBlockBuilder::new()
            .uncles(vec![
                uncle1.block_hash(),
                uncle2.block_hash(),
                uncle3.block_hash(),
            ])
            .miner_pubkey(PUBKEY_G)
            .build();

        assert!(
            validator()
                .validate_uncles(&valid_share, &chain_store_handle)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_uncles_too_many() {
        let chain_store_handle = ChainStoreHandle::default();

        let uncle1 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_G).build();
        let uncle2 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_2G).build();
        let uncle3 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_3G).build();
        let uncle4 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_4G).build();

        let invalid_share = TestShareBlockBuilder::new()
            .uncles(vec![
                uncle1.block_hash(),
                uncle2.block_hash(),
                uncle3.block_hash(),
                uncle4.block_hash(),
            ])
            .miner_pubkey(PUBKEY_G)
            .build();

        let result = validator().validate_uncles(&invalid_share, &chain_store_handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many uncles"));
    }

    #[tokio::test]
    async fn test_validate_uncles_duplicate() {
        let chain_store_handle = ChainStoreHandle::default();

        let uncle1 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_G).build();

        let invalid_share = TestShareBlockBuilder::new()
            .uncles(vec![uncle1.block_hash(), uncle1.block_hash()])
            .miner_pubkey(PUBKEY_G)
            .build();

        let result = validator().validate_uncles(&invalid_share, &chain_store_handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate uncles"));
    }

    #[tokio::test]
    async fn test_validate_uncles_not_in_store() {
        let mut chain_store_handle = ChainStoreHandle::default();

        chain_store_handle
            .expect_share_block_exists()
            .returning(|_| false);

        let non_existent_hash = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse::<BlockHash>()
            .unwrap();

        let invalid_share = TestShareBlockBuilder::new()
            .uncles(vec![non_existent_hash])
            .miner_pubkey(PUBKEY_G)
            .build();

        let result = validator().validate_uncles(&invalid_share, &chain_store_handle);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in store")
        );
    }

    #[tokio::test]
    async fn test_validate_uncles_on_confirmed_chain() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let uncle1 = TestShareBlockBuilder::new().miner_pubkey(PUBKEY_G).build();

        // Uncle exists but is on the confirmed chain
        chain_store_handle
            .expect_share_block_exists()
            .returning(|_| true);
        chain_store_handle
            .expect_has_status()
            .returning(|_, _| true);

        let invalid_share = TestShareBlockBuilder::new()
            .uncles(vec![uncle1.block_hash()])
            .miner_pubkey(PUBKEY_G)
            .build();

        let result = validator().validate_uncles(&invalid_share, &chain_store_handle);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("on confirmed chain")
        );
    }

    #[tokio::test]
    async fn test_validate_share() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let share_block =
            build_block_from_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

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

        let pplns_window = {
            let mut mock_window = PplnsWindow::default();
            mock_window
                .expect_network()
                .return_const(bitcoin::Network::Regtest);
            mock_window
                .expect_get_distribution_from_start_hash()
                .returning(|_, _| Some(HashMap::new()));
            Arc::new(RwLock::new(mock_window))
        };
        let result =
            validator().validate_share_block(&share_block, &chain_store_handle, pplns_window);

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

        let pplns_window = {
            let mut mock_window = PplnsWindow::default();
            mock_window
                .expect_network()
                .return_const(bitcoin::Network::Regtest);
            mock_window
                .expect_get_distribution_from_start_hash()
                .returning(|_, _| Some(HashMap::new()));
            Arc::new(RwLock::new(mock_window))
        };
        let result =
            validator().validate_share_block(&share_block, &chain_store_handle, pplns_window);
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
            .expect_get_all_prevouts()
            .returning(move |_tx| Ok(vec![(0, spent_output_clone.clone())]));

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
            .expect_get_all_prevouts()
            .returning(move |_tx| Ok(vec![(0, spent_output_clone.clone())]));

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
            .expect_get_all_prevouts()
            .returning(|_tx| {
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
            error
                .to_string()
                .contains("Failed to look up spent outputs"),
            "Expected UTXO lookup failure, got: {error}"
        );
    }

    #[test]
    fn test_compute_total_payout_amount() {
        let address = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address,
                amount: Amount::from_sat(5_000_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();
        let total = DefaultShareValidator::compute_total_payout_amount(&coinbase_tx).unwrap();
        assert_eq!(total, Amount::from_sat(5_000_000_000));
    }

    #[test]
    fn test_validate_total_against_subsidy_passes() {
        let address = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address,
                amount: Amount::from_sat(5_000_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();
        let result = DefaultShareValidator::validate_total_against_subsidy(
            &coinbase_tx,
            Amount::from_sat(5_000_000_000),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_total_against_subsidy_fails_below_subsidy() {
        let address = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address,
                amount: Amount::from_sat(100_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();
        let error = DefaultShareValidator::validate_total_against_subsidy(
            &coinbase_tx,
            Amount::from_sat(100_000_000),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("less than block subsidy"),
            "Expected subsidy error, got: {error}"
        );
    }

    #[test]
    fn test_build_expected_outputs_empty_distribution_returns_none() {
        let header = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build()
            .header;
        let empty_map = HashMap::new();
        let result = DefaultShareValidator::build_expected_outputs(
            &header,
            &empty_map,
            Amount::from_sat(5_000_000_000),
        )
        .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_build_expected_outputs_proportional_no_donation_or_fee() {
        let header = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build()
            .header;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );

        let mut difficulty_map = HashMap::with_capacity(2);
        difficulty_map.insert(address_a.clone(), 600u128);
        difficulty_map.insert(address_b.clone(), 400u128);

        let total_amount = Amount::from_sat(1_000_000_000);
        let outputs =
            DefaultShareValidator::build_expected_outputs(&header, &difficulty_map, total_amount)
                .unwrap()
                .expect("Should return Some for non-empty distribution");

        assert_eq!(outputs.len(), 2);
        let total_distributed: Amount = outputs.iter().map(|output| output.amount).sum();
        assert_eq!(total_distributed, total_amount);

        assert!(outputs.contains(&OutputPair {
            address: address_a,
            amount: Amount::from_sat(600_000_000)
        }));
        assert!(outputs.contains(&OutputPair {
            address: address_b,
            amount: Amount::from_sat(400_000_000)
        }));
    }

    #[test]
    fn test_build_expected_outputs_with_donation_and_fee() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let donation_address = crate::test_utils::parse_address_from_string(
            "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c",
        );
        let fee_address = crate::test_utils::parse_address_from_string(
            "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
        );

        let mut header = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build()
            .header;

        header.donation_address = Some(donation_address.clone());
        header.donation = Some(500); // 5%
        header.fee_address = Some(fee_address.clone());
        header.fee = Some(200); // 2%

        let mut difficulty_map = HashMap::new();
        difficulty_map.insert(address_a.clone(), 1000u128);

        let total = Amount::from_sat(10_000_000_000);
        let outputs =
            DefaultShareValidator::build_expected_outputs(&header, &difficulty_map, total)
                .unwrap()
                .expect("Should return Some for non-empty distribution");

        // 3 outputs: donation, fee, miner
        assert_eq!(outputs.len(), 3);

        // Donation: 5% of 10 BTC = 0.5 BTC
        assert_eq!(outputs[0].address, donation_address);
        assert_eq!(outputs[0].amount, Amount::from_sat(500_000_000));

        // Fee: 2% of (10 - 0.5) = 2% of 9.5 BTC = 0.19 BTC
        assert_eq!(outputs[1].address, fee_address);
        assert_eq!(outputs[1].amount, Amount::from_sat(190_000_000));

        // Miner gets remainder: 10 - 0.5 - 0.19 = 9.31 BTC
        assert_eq!(outputs[2].address, address_a);
        assert_eq!(outputs[2].amount, Amount::from_sat(9_310_000_000));

        let total_distributed: Amount = outputs.iter().map(|output| output.amount).sum();
        assert_eq!(total_distributed, total);
    }

    #[test]
    fn test_compare_outputs_matching() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );
        let expected = vec![
            OutputPair {
                address: address_a.clone(),
                amount: Amount::from_sat(600_000_000),
            },
            OutputPair {
                address: address_b.clone(),
                amount: Amount::from_sat(400_000_000),
            },
        ];

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[
                OutputPair {
                    address: address_a,
                    amount: Amount::from_sat(600_000_000),
                },
                OutputPair {
                    address: address_b,
                    amount: Amount::from_sat(400_000_000),
                },
            ],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let result = DefaultShareValidator::compare_outputs(&expected, &coinbase_tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compare_outputs_count_mismatch() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );
        let expected = vec![
            OutputPair {
                address: address_a.clone(),
                amount: Amount::from_sat(600_000_000),
            },
            OutputPair {
                address: address_b,
                amount: Amount::from_sat(400_000_000),
            },
        ];

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(1_000_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let error = DefaultShareValidator::compare_outputs(&expected, &coinbase_tx).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Expected 2 payout outputs but coinbase has 1"),
            "Got: {error}"
        );
    }

    #[test]
    fn test_compare_outputs_value_mismatch() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let expected = vec![OutputPair {
            address: address_a.clone(),
            amount: Amount::from_sat(600_000_000),
        }];

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(500_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let error = DefaultShareValidator::compare_outputs(&expected, &coinbase_tx).unwrap_err();
        assert!(error.to_string().contains("expected"), "Got: {error}");
    }

    #[test]
    fn test_compare_outputs_script_mismatch() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );
        let expected = vec![OutputPair {
            address: address_a,
            amount: Amount::from_sat(1_000_000_000),
        }];

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_b,
                amount: Amount::from_sat(1_000_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let error = DefaultShareValidator::compare_outputs(&expected, &coinbase_tx).unwrap_err();
        assert!(
            error.to_string().contains("script mismatch"),
            "Got: {error}"
        );
    }

    #[test]
    fn test_compare_outputs_skips_witness_commitment() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let witness_commitment =
            "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9";
        let expected = vec![OutputPair {
            address: address_a.clone(),
            amount: Amount::from_sat(3_125_000_000),
        }];

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(3_125_000_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            Some(witness_commitment.to_string()),
            &[],
            None,
        )
        .unwrap();

        // Coinbase has 2 outputs (payout + OP_RETURN), but compare should skip OP_RETURN
        assert_eq!(coinbase_tx.output.len(), 2);
        let result = DefaultShareValidator::compare_outputs(&expected, &coinbase_tx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_block_subsidy_genesis() {
        let subsidy = compute_block_subsidy(0);
        assert_eq!(subsidy, Amount::from_sat(5_000_000_000));
    }

    #[test]
    fn test_compute_block_subsidy_first_halving() {
        let subsidy = compute_block_subsidy(210_000);
        assert_eq!(subsidy, Amount::from_sat(2_500_000_000));
    }

    #[test]
    fn test_compute_block_subsidy_fourth_halving() {
        let subsidy = compute_block_subsidy(840_000);
        assert_eq!(subsidy, Amount::from_sat(312_500_000));
    }

    #[test]
    fn test_compute_block_subsidy_before_final_halving() {
        // Halving 32 is the last one that produces a non-zero subsidy
        // 5_000_000_000 >> 32 = 1 (rounded down from integer division)
        let subsidy = compute_block_subsidy(32 * 210_000);
        assert_eq!(subsidy, Amount::from_sat(1));
    }

    #[test]
    fn test_compute_block_subsidy_after_all_halvings() {
        let subsidy = compute_block_subsidy(64 * 210_000);
        assert_eq!(subsidy, Amount::ZERO);
    }

    #[test]
    fn test_validate_bitcoin_payout_with_matching_distribution() {
        use bitcoin::script::PushBytesBuf;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );

        // Build coinbase with 60%/40% split of 3.125 BTC at height 840000
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[
                OutputPair {
                    address: address_a.clone(),
                    amount: Amount::from_sat(187_500_000),
                },
                OutputPair {
                    address: address_b.clone(),
                    amount: Amount::from_sat(125_000_000),
                },
            ],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        // Build share block using TestShareBlockBuilder to get valid structure,
        // then replace bitcoin_transactions with our custom coinbase
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.bitcoin_transactions = vec![coinbase_tx];

        // Mock PplnsWindow returning matching 60/40 distribution
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        let addr_b_clone = address_b.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _| {
                let mut distribution = HashMap::with_capacity(2);
                distribution.insert(addr_a_clone.clone(), 600u128);
                distribution.insert(addr_b_clone.clone(), 400u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let result = validator().validate_bitcoin_payout(
            &share_block,
            &share_block.bitcoin_transactions[0],
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Expected valid payout, got: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_with_wrong_amounts() {
        use bitcoin::script::PushBytesBuf;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );

        // Build coinbase with 50/50 split (wrong for 60/40 distribution)
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[
                OutputPair {
                    address: address_a.clone(),
                    amount: Amount::from_sat(156_250_000),
                },
                OutputPair {
                    address: address_b.clone(),
                    amount: Amount::from_sat(156_250_000),
                },
            ],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.bitcoin_transactions = vec![coinbase_tx];

        // Mock PplnsWindow returning 60/40 distribution
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        let addr_b_clone = address_b.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _| {
                let mut distribution = HashMap::with_capacity(2);
                distribution.insert(addr_a_clone.clone(), 600u128);
                distribution.insert(addr_b_clone.clone(), 400u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let error = validator()
            .validate_bitcoin_payout(
                &share_block,
                &share_block.bitcoin_transactions[0],
                pplns_window,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("expected"),
            "Expected value mismatch error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_empty_window_skips_distribution_check() {
        use bitcoin::script::PushBytesBuf;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(312_500_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.bitcoin_transactions = vec![coinbase_tx];

        // Mock PplnsWindow returning empty distribution (bootstrap phase)
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(|_, _| Some(HashMap::new()));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let result = validator().validate_bitcoin_payout(
            &share_block,
            &share_block.bitcoin_transactions[0],
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Empty window should skip payout check, got: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_fails_when_prev_share_blockhash_not_in_window() {
        use bitcoin::script::PushBytesBuf;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );

        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(312_500_000),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.bitcoin_transactions = vec![coinbase_tx];

        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(|_, _| None);
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let error = validator()
            .validate_bitcoin_payout(
                &share_block,
                &share_block.bitcoin_transactions[0],
                pplns_window,
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("prev_share_blockhash not found in PPLNS window"),
            "Expected PPLNS window miss error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_below_subsidy_fails() {
        use bitcoin::script::PushBytesBuf;

        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );

        // Coinbase with 1 sat at height 840000 (subsidy is 3.125 BTC)
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[OutputPair {
                address: address_a,
                amount: Amount::from_sat(1),
            }],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.bitcoin_transactions = vec![coinbase_tx];

        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(|_, _| Some(HashMap::new()));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let error = validator()
            .validate_bitcoin_payout(
                &share_block,
                &share_block.bitcoin_transactions[0],
                pplns_window,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("less than block subsidy"),
            "Expected subsidy error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_with_transactions_donation_and_fees() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::sha256d;
        use bitcoin::script::PushBytesBuf;
        use bitcoin::transaction::{Sequence, TxIn};

        let miner_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let miner_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );
        let miner_c = crate::test_utils::parse_address_from_string(
            "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c",
        );
        let donation_address = crate::test_utils::parse_address_from_string(
            "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
        );
        let fee_address = crate::test_utils::parse_address_from_string(
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        );

        // At height 840000 the subsidy is 3.125 BTC = 312_500_000 sats.
        // Two regular transactions contribute 100_000 sats total in fees.
        // Total coinbase value = 312_500_000 + 100_000 = 312_600_000
        let total_coinbase_sats: u64 = 312_600_000;

        // Donation: 5% (500 bp)
        let donation_bp: u16 = 500;
        let donation_amount = total_coinbase_sats * donation_bp as u64 / 10_000;
        // Fee: 2% (200 bp) of remainder after donation
        let fee_bp: u16 = 200;
        let after_donation = total_coinbase_sats - donation_amount;
        let fee_amount = after_donation * fee_bp as u64 / 10_000;
        let remaining = after_donation - fee_amount;

        // Three miners with difficulties 500, 300, 200 (total 1000).
        // append_proportional_distribution sorts by address string:
        //   miner_c (bc1q34..): diff 200 -> 58_206_120
        //   miner_a (bc1qar..): diff 500 -> 145_515_300
        //   miner_b (bc1qw5..): diff 300 -> remainder = 87_309_180
        let miner_c_amount = remaining * 200 / 1000;
        let miner_a_amount = remaining * 500 / 1000;
        let miner_b_amount = remaining - miner_c_amount - miner_a_amount;

        // Build coinbase: donation, fee, then 3 miners in sorted address order
        let coinbase_tx = coinbase::build_coinbase_transaction(
            Version(2),
            &[
                OutputPair {
                    address: donation_address.clone(),
                    amount: Amount::from_sat(donation_amount),
                },
                OutputPair {
                    address: fee_address.clone(),
                    amount: Amount::from_sat(fee_amount),
                },
                OutputPair {
                    address: miner_c.clone(),
                    amount: Amount::from_sat(miner_c_amount),
                },
                OutputPair {
                    address: miner_a.clone(),
                    amount: Amount::from_sat(miner_a_amount),
                },
                OutputPair {
                    address: miner_b.clone(),
                    amount: Amount::from_sat(miner_b_amount),
                },
            ],
            840_000,
            PushBytesBuf::from(&[0u8]),
            None,
            &[],
            None,
        )
        .unwrap();

        // Build two regular bitcoin transactions (spending dummy inputs)
        let regular_tx_1 = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: sha256d::Hash::all_zeros().into(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(950_000),
                script_pubkey: miner_a.script_pubkey(),
            }],
        };

        let regular_tx_2 = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: sha256d::Hash::all_zeros().into(),
                    vout: 1,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(450_000),
                script_pubkey: miner_b.script_pubkey(),
            }],
        };

        // Share block with coinbase + 2 regular transactions
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.donation_address = Some(donation_address.clone());
        share_block.header.donation = Some(donation_bp);
        share_block.header.fee_address = Some(fee_address.clone());
        share_block.header.fee = Some(fee_bp);
        share_block.bitcoin_transactions = vec![coinbase_tx, regular_tx_1, regular_tx_2];

        // Mock PplnsWindow returning 3 miners with difficulties 500, 300, 200
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let miner_a_clone = miner_a.clone();
        let miner_b_clone = miner_b.clone();
        let miner_c_clone = miner_c.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _| {
                let mut distribution = HashMap::with_capacity(3);
                distribution.insert(miner_a_clone.clone(), 500u128);
                distribution.insert(miner_b_clone.clone(), 300u128);
                distribution.insert(miner_c_clone.clone(), 200u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let result = validator().validate_bitcoin_payout(
            &share_block,
            &share_block.bitcoin_transactions[0],
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Expected valid payout with 3 miners, donation, fee and 3 txs, got: {}",
            result.unwrap_err()
        );

        // Verify the amounts sum correctly, for our sanity
        assert_eq!(donation_amount, 15_630_000);
        assert_eq!(fee_amount, 5_939_400);
        assert_eq!(miner_c_amount, 58_206_120);
        assert_eq!(miner_a_amount, 145_515_300);
        assert_eq!(miner_b_amount, 87_309_180);
        assert_eq!(
            donation_amount + fee_amount + miner_c_amount + miner_a_amount + miner_b_amount,
            total_coinbase_sats
        );
    }
}
