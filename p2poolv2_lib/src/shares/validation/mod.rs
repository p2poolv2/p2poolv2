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

use super::share_block::{MAX_POOL_TARGET, ShareHeader};
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
use crate::shares::transactions::coinbase::{compute_commitment_hash, compute_witness_root};
use crate::shares::witness_commitment::WITNESS_COMMITMENT_LENGTH;
use crate::store::block_tx_metadata::Status;
use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoin::hashes::Hash as HashTrait;
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    Address, Amount, BlockHash, CompactTarget, Target, TxMerkleNode, transaction::Version,
};
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
/// Maximum number of seconds a share timestamp may be ahead of the local clock.
pub const MAX_FUTURE_TIME_SECS: u64 = 120;
/// Number of ancestor share headers used to compute median time past.
pub const MTP_WINDOW: usize = 11;
/// Maximum block size not counting bitcoin blocks limited to 200kB
pub const BLOCK_TXS_SIZE_LIMIT: u32 = 200 * 1024;
/// Maximum number of transactions allowed in a share block
pub const TXS_COUNT_LIMIT: u32 = 100;
/// Coinbase outputs cannot be spent until the containing block is this
/// many blocks deep. 70% of blocks-per-day at 10s block time (0.70 * 86400 / 10).
pub const COINBASE_MATURITY: usize = 6048;
/// Maximum total sigop cost allowed in a share block (matches Bitcoin consensus).
pub const MAX_BLOCK_SIGOPS_COST: usize = 80_000;

/// Trait for share validation operations.
///
/// Provides methods to validate share headers, share blocks, uncles,
/// pool difficulty, and timestamps. Use `DefaultShareValidator` for
/// the production implementation.
pub trait ShareValidator {
    /// Validate the share header with minimum difficulty checks only.
    ///
    /// Verifies uncle count and that the declared target meets the pool
    /// minimum difficulty floor. Does not require parent lookup.
    /// Full pool difficulty validation happens in validate_share_block.
    fn validate_share_header(&self, share_header: &ShareHeader) -> Result<(), ValidationError>;

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

    /// Validate the share timestamp.
    ///
    /// Enforces two rules:
    /// 1. Share `header.time` must be strictly greater than the median time
    ///    of the previous 11 share-chain ancestors (median time past).
    /// 2. Share `header.time` must not be more than `MAX_FUTURE_TIME_SECS`
    ///    seconds ahead of the local clock.
    fn validate_timestamp(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
        time_provider: &dyn TimeProvider,
    ) -> Result<(), ValidationError>;

    /// Run validations that depend on the confirmed-chain context.
    ///
    /// Called by the organise worker just before promoting a block, when the
    /// parent is guaranteed to be confirmed and `get_confirmed_headers_in_range`
    /// returns a stable ancestor window.
    fn validate_with_chain_context(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError>;

    /// Validate a share header meets minimum pool difficulty without requiring parent.
    ///
    /// Checks uncle count, that header's meets the header's own
    /// declared bits target, and that the declared target is no easier than
    /// MAX_POOL_TARGET. This is the anti-spam gate for header sync and broadcast
    /// validation -- cheap and requires no store lookups.
    fn validate_header_minimum_difficulty(
        &self,
        share_header: &ShareHeader,
    ) -> Result<(), ValidationError>;

    /// Return a reference to the pool difficulty anchored at the chain genesis.
    ///
    /// Used by header-sync validation to run ASERT checks without rebuilding a
    /// fresh PoolDifficulty on every batch.
    fn pool_difficulty(&self) -> &PoolDifficulty;
}

/// Production implementation of ShareValidator.
///
/// Stores a `PoolDifficulty` instance initialised at construction time,
/// avoiding repeated builds on each validation call.
pub struct DefaultShareValidator {
    pool_difficulty: PoolDifficulty,
    /// Multiplier applied to bitcoin difficulty when walking the PPLNS window.
    difficulty_multiplier: u128,
    /// Pool signature included in the coinbase transaction.
    pool_signature: Vec<u8>,
    /// Time provider used to enforce the future-time bound on share timestamps.
    time_provider: Arc<dyn TimeProvider + Send + Sync>,
}

impl DefaultShareValidator {
    /// Create a new DefaultShareValidator with the given pool difficulty,
    /// difficulty multiplier for PPLNS window walks, and pool signature
    /// for coinbase reconstruction. Uses `SystemTimeProvider` for timestamp
    /// validation.
    pub fn new(
        pool_difficulty: PoolDifficulty,
        difficulty_multiplier: u128,
        pool_signature: Vec<u8>,
    ) -> Self {
        Self::with_time_provider(
            pool_difficulty,
            difficulty_multiplier,
            pool_signature,
            Arc::new(SystemTimeProvider),
        )
    }

    /// Create a new DefaultShareValidator with an explicit time provider.
    pub fn with_time_provider(
        pool_difficulty: PoolDifficulty,
        difficulty_multiplier: u128,
        pool_signature: Vec<u8>,
        time_provider: Arc<dyn TimeProvider + Send + Sync>,
    ) -> Self {
        Self {
            pool_difficulty,
            difficulty_multiplier,
            pool_signature,
            time_provider,
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
    /// Validate scripts, input/output values, and sigop cost for all
    /// transactions in the share block.
    ///
    /// Collects spent outputs once per non-coinbase transaction and runs
    /// script verification, input-vs-output value checks, and sigop cost
    /// accumulation in a single pass. The coinbase contributes sigop cost
    /// but is exempt from script and value validation.
    fn validate_scripts_values_and_sigops(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        let mut total_sigop_cost: usize = 0;

        for (index, transaction) in share.transactions.iter().enumerate() {
            if index == 0 {
                let coinbase_sigop_cost = transaction.0.total_sigop_cost(|_outpoint| None);
                total_sigop_cost = total_sigop_cost.saturating_add(coinbase_sigop_cost);
            } else {
                let txid = transaction.compute_txid();
                let spent_outputs =
                    Self::collect_spent_outputs(transaction, chain_store_handle, &txid)?;
                Self::validate_scripts_for_tx(transaction, &spent_outputs, &txid)?;
                Self::validate_input_output_values(transaction, &spent_outputs, &txid)?;
                let tx_sigop_cost =
                    Self::compute_transaction_sigop_cost(transaction, &spent_outputs);
                total_sigop_cost = total_sigop_cost.saturating_add(tx_sigop_cost);
            }
        }

        if total_sigop_cost > MAX_BLOCK_SIGOPS_COST {
            return Err(ValidationError::new(format!(
                "Block sigop cost {total_sigop_cost} exceeds maximum {MAX_BLOCK_SIGOPS_COST}"
            )));
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

    /// Check that total input value is at least total output value for a
    /// single non-coinbase transaction.
    fn validate_input_output_values(
        transaction: &ShareTransaction,
        spent_outputs: &[(usize, bitcoin::TxOut)],
        txid: &bitcoin::Txid,
    ) -> Result<(), ValidationError> {
        let mut total_input = Amount::ZERO;
        for (_index, txout) in spent_outputs {
            total_input = total_input.checked_add(txout.value).ok_or_else(|| {
                ValidationError::new(format!("Transaction {txid} total input value overflow"))
            })?;
        }
        if total_input > Amount::MAX_MONEY {
            return Err(ValidationError::new(format!(
                "Transaction {txid} total input value {total_input} exceeds maximum"
            )));
        }

        let mut total_output = Amount::ZERO;
        for output in &transaction.output {
            total_output = total_output.checked_add(output.value).ok_or_else(|| {
                ValidationError::new(format!("Transaction {txid} total output value overflow"))
            })?;
        }

        if total_input < total_output {
            return Err(ValidationError::new(format!(
                "Transaction {txid} outputs {total_output} exceed inputs {total_input}"
            )));
        }
        Ok(())
    }

    /// Compute the BIP141 sigop cost for a single transaction given its
    /// spent outputs. Uses `Transaction::total_sigop_cost` which applies
    /// the correct weighting (legacy sigops * 4, witness sigops * 1).
    fn compute_transaction_sigop_cost(
        transaction: &ShareTransaction,
        spent_outputs: &[(usize, bitcoin::TxOut)],
    ) -> usize {
        let mut lookup: HashMap<bitcoin::OutPoint, &bitcoin::TxOut> =
            HashMap::with_capacity(spent_outputs.len());
        for (position, (_input_index, txout)) in spent_outputs.iter().enumerate() {
            let outpoint = transaction.input[position].previous_output;
            lookup.insert(outpoint, txout);
        }
        transaction
            .0
            .total_sigop_cost(|outpoint| lookup.get(outpoint).map(|txout| (*txout).clone()))
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

    /// Validate the share coinbase creates an output with 1 share
    /// unit to the miner address in the header and second a witness commitment output
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

        // Two coinbase outputs: first to the miner and second a witness commitment output
        if coinbase.output.len() != 2 {
            return Err(ValidationError::new(format!(
                "Share coinbase has {} outputs, expected 2",
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

        let expected_script = share.header.miner_bitcoin_address.script_pubkey();
        if output.script_pubkey != expected_script {
            return Err(ValidationError::new(
                "Share coinbase output does not pay to the miner address in header",
            ));
        }

        Ok(())
    }

    /// Validate the BIP141 witness commitment in the share coinbase.
    ///
    /// The share coinbase must carry a 32-byte witness reserved value on
    /// its input witness stack and a witness commitment output whose
    /// 32-byte hash matches `SHA256d(witness_root || reserved_value)`,
    /// where `witness_root` is the merkle root of share transaction
    /// wtxids with the coinbase slot replaced by all-zeros (BIP141).
    fn validate_share_witness_commitment(&self, share: &ShareBlock) -> Result<(), ValidationError> {
        let coinbase = share
            .transactions
            .first()
            .ok_or_else(|| ValidationError::new("Share block has no transactions"))?;

        let witness_stack: Vec<&[u8]> = coinbase.input[0].witness.iter().collect();
        if witness_stack.len() != 1 || witness_stack[0].len() != 32 {
            return Err(ValidationError::new(
                "Share coinbase input witness must be a single 32-byte reserved value",
            ));
        }
        let witness_reserved_value = witness_stack[0];

        // share coinbase has two outputs - a single miner output and
        // then a witnesscommitment output
        let commitment_output = &coinbase.output[1];
        if commitment_output.value != Amount::ZERO {
            return Err(ValidationError::new(format!(
                "Share coinbase witness commitment output must have zero value, got {}",
                commitment_output.value
            )));
        }
        let commitment_script = commitment_output.script_pubkey.as_bytes();
        if commitment_script.len() != WITNESS_COMMITMENT_LENGTH
            || commitment_script[..6] != [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
        {
            return Err(ValidationError::new(
                "Share coinbase witness commitment output has invalid BIP141 header",
            ));
        }

        let other_share_transactions = &share.transactions[1..];
        let witness_root = compute_witness_root(other_share_transactions);
        let expected_commitment = compute_commitment_hash(&witness_root, witness_reserved_value);

        if commitment_script[6..] != expected_commitment.as_byte_array()[..] {
            return Err(ValidationError::new(
                "Share coinbase witness commitment does not match recomputed witness root",
            ));
        }

        Ok(())
    }

    /// Validate the bitcoin coinbase by reconstructing it from the share header
    /// fields and verifying the merkle root matches the bitcoin header.
    fn validate_bitcoin_coinbase(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
        pplns_window: Arc<RwLock<PplnsWindow>>,
    ) -> Result<(), ValidationError> {
        self.validate_bitcoin_payout(share, chain_store_handle, pplns_window)?;
        Ok(())
    }

    /// Validate the bitcoin coinbase against the PPLNS window distribution.
    ///
    /// Computes the expected distribution from the PPLNS window using
    /// bitcoin header difficulty * difficulty_multiplier, reconstructs
    /// the expected coinbase transaction, and verifies that the merkle
    /// root computed from the reconstructed coinbase and the template
    /// merkle branches matches the bitcoin header's merkle root.
    ///
    /// When prev_share_blockhash is not on the confirmed chain (e.g.
    /// during a candidate chain reorg), walks backward through the
    /// store to find the confirmed ancestor and includes the
    /// intermediate candidate entries in the distribution.
    fn validate_bitcoin_payout(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
        pplns_window: Arc<RwLock<PplnsWindow>>,
    ) -> Result<(), ValidationError> {
        let mut window = pplns_window
            .write()
            .expect("PPLNS window lock poisoned on write");

        let bitcoin_difficulty = share.header.bitcoin_header.difficulty(window.network());
        let total_difficulty = bitcoin_difficulty.saturating_mul(self.difficulty_multiplier);

        let address_difficulty_map = window
            .get_distribution_from_start_hash(
                total_difficulty,
                share.header.prev_share_blockhash,
                chain_store_handle,
            )
            .ok_or_else(|| {
                ValidationError::new("prev_share_blockhash not found in PPLNS window")
            })?;

        let coinbase_value = share.header.coinbase_value;

        let expected_outputs =
            Self::build_expected_outputs(&share.header, &address_difficulty_map, coinbase_value)?;
        let expected_commitment_hash = ShareCommitment::from_share_header(&share.header).hash();

        let flags = match &share.header.coinbaseaux_flags {
            Some(aux_flags) => aux_flags.to_push_bytes_buf(),
            None => PushBytesBuf::from(&[0u8]),
        };
        let pool_signature = &self.pool_signature;
        let reconstructed_coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &expected_outputs,
            share.header.bitcoin_height as i64,
            flags,
            share.header.witness_commitment.as_ref(),
            pool_signature,
            Some(expected_commitment_hash),
            share.header.coinbase_nsecs,
            Some(share.header.extranonce.as_bytes()),
        )
        .map_err(|error| ValidationError(format!("Error building coinbase {error}")))?;

        let reconstructed_coinbase_txid = reconstructed_coinbase.compute_txid();
        let recomputed_root = compute_merkle_root_from_branches(
            reconstructed_coinbase_txid,
            &share.template_merkle_branches,
        );

        if recomputed_root != share.header.bitcoin_header.merkle_root {
            Err(ValidationError(
                "Coinbase and template merkle root don't match merkle root".into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Build the expected payout outputs from share header donation/fee and PPLNS distribution.
    ///
    /// When the PPLNS window is empty (bootstrap phase), returns an error.
    fn build_expected_outputs(
        share_header: &ShareHeader,
        address_difficulty_map: &HashMap<Address, u128>,
        coinbase_value: u64,
    ) -> Result<Vec<OutputPair>, ValidationError> {
        if address_difficulty_map.is_empty() {
            return Err(ValidationError("Can't build output from empty distribution. There should be at least one payout address".into()));
        }

        let mut distribution = Vec::with_capacity(address_difficulty_map.len() + 2);

        let remaining_after_donation = include_address_and_cut(
            &mut distribution,
            Amount::from_sat(coinbase_value),
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

        Ok(distribution)
    }
}

impl ShareValidator for DefaultShareValidator {
    fn validate_share_header(&self, share_header: &ShareHeader) -> Result<(), ValidationError> {
        self.validate_header_minimum_difficulty(share_header)
    }

    fn pool_difficulty(&self) -> &PoolDifficulty {
        &self.pool_difficulty
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
            .calculate_target_clamped(parent_time, parent_height);
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

    fn validate_header_minimum_difficulty(
        &self,
        share_header: &ShareHeader,
    ) -> Result<(), ValidationError> {
        if share_header.uncles.len() > MAX_UNCLES {
            return Err(ValidationError::new(format!(
                "Too many uncles: {} exceeds maximum of {}",
                share_header.uncles.len(),
                MAX_UNCLES
            )));
        }

        let declared_target = Target::from_compact(share_header.bits);
        let max_pool_target = Target::from_compact(CompactTarget::from_consensus(MAX_POOL_TARGET));
        if declared_target > max_pool_target {
            return Err(ValidationError::new(format!(
                "Share target {declared_target} is easier than maximum pool target {max_pool_target}"
            )));
        }

        let bitcoin_block_hash = share_header.bitcoin_header.block_hash();
        if !declared_target.is_met_by(bitcoin_block_hash) {
            return Err(ValidationError::new(format!(
                "Bitcoin block hash {bitcoin_block_hash} does not meet declared target {declared_target}"
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
        self.validate_with_pool_difficulty(&share.header, chain_store_handle)?;
        self.validate_uncles(share, chain_store_handle)?;
        self.validate_block_size(share)?;
        self.validate_share_coinbase(share)?;
        self.validate_bitcoin_coinbase(share, chain_store_handle, pplns_window)?;
        self.validate_merkle_root(share)?;
        self.validate_share_witness_commitment(share)?;
        self.validate_transaction_count(share)?;
        self.validate_transactions(share)?;
        self.validate_scripts_values_and_sigops(share, chain_store_handle)?;
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
        chain_store_handle: &ChainStoreHandle,
        time_provider: &dyn TimeProvider,
    ) -> Result<(), ValidationError> {
        let current_time = time_provider.seconds_since_epoch();
        let share_timestamp = share.header.time as u64;

        if share_timestamp > current_time + MAX_FUTURE_TIME_SECS {
            return Err(ValidationError::new(format!(
                "Share timestamp {share_timestamp} is more than {MAX_FUTURE_TIME_SECS} seconds ahead of local time {current_time}"
            )));
        }

        let parent_hash = share.header.prev_share_blockhash;
        let parent_metadata = chain_store_handle
            .get_block_metadata(&parent_hash)
            .map_err(|_| {
                ValidationError::new(format!(
                    "Parent share {parent_hash} metadata not found for MTP check"
                ))
            })?;
        let parent_height = parent_metadata.expected_height.ok_or_else(|| {
            ValidationError::new(format!(
                "Parent share {parent_hash} has no expected height for MTP check"
            ))
        })?;
        let from_height = parent_height.saturating_sub(MTP_WINDOW as u32 - 1);
        let confirmed_headers = chain_store_handle
            .get_confirmed_headers_in_range(from_height, parent_height)
            .map_err(|err| {
                ValidationError::new(format!(
                    "Failed to fetch ancestor headers for MTP check: {err}"
                ))
            })?;
        if confirmed_headers.is_empty() {
            return Err(ValidationError::new(format!(
                "No confirmed ancestor headers found for MTP check at height {parent_height}"
            )));
        }
        let mut sorted_times: Vec<u32> = confirmed_headers
            .iter()
            .map(|entry| entry.header.time)
            .collect();
        sorted_times.sort_unstable();
        let median = sorted_times[sorted_times.len() / 2];
        if share.header.time <= median {
            return Err(ValidationError::new(format!(
                "Share timestamp {share_timestamp} is not greater than median time past {median}"
            )));
        }
        Ok(())
    }

    fn validate_with_chain_context(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        self.validate_timestamp(share, chain_store_handle, self.time_provider.as_ref())?;
        self.validate_prevouts(share, chain_store_handle)
    }
}

impl DefaultShareValidator {
    /// Validate that every input of every non-coinbase transaction in the
    /// share block spends an output that:
    ///
    /// 1. Exists in the `Outputs` column family.
    /// 2. Belongs to a transaction on the confirmed sharechain *or* to
    ///    an earlier transaction in this same share block. (Inputs that
    ///    reference uncle / unconfirmed external inclusions are
    ///    rejected.)
    /// 3. Has not already been spent by another transaction on the
    ///    confirmed sharechain.
    /// 4. Is not spent by more than one input in this share block.
    ///
    /// In-block prevouts (inputs whose source txid is an earlier
    /// transaction in the same block) are exempt from the
    /// confirmed-chain check. The producing tx is being introduced
    /// atomically with its spender, but they are *still* checked for
    /// existence against the `Outputs` CF, so a spender that references
    /// a non-existent vout of an in-block producer is rejected.
    fn validate_prevouts(
        &self,
        share: &ShareBlock,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<(), ValidationError> {
        let total_inputs: usize = share
            .transactions
            .iter()
            .filter(|share_transaction| !share_transaction.0.is_coinbase())
            .map(|share_transaction| share_transaction.0.input.len())
            .sum();
        let mut all_outpoints: Vec<bitcoin::OutPoint> = Vec::with_capacity(total_inputs);
        let mut external_source_txids: HashSet<bitcoin::Txid> =
            HashSet::with_capacity(total_inputs);
        let mut seen_prevouts: HashSet<bitcoin::OutPoint> = HashSet::with_capacity(total_inputs);
        let mut in_block_txids: HashSet<bitcoin::Txid> =
            HashSet::with_capacity(share.transactions.len());
        for share_transaction in &share.transactions {
            let transaction = &share_transaction.0;
            if !transaction.is_coinbase() {
                for input in &transaction.input {
                    let outpoint = input.previous_output;
                    if !seen_prevouts.insert(outpoint) {
                        return Err(ValidationError::new(format!(
                            "Duplicate prevout {}:{} spent by two inputs in the same share block",
                            outpoint.txid, outpoint.vout
                        )));
                    }
                    all_outpoints.push(outpoint);
                    if !in_block_txids.contains(&outpoint.txid) {
                        external_source_txids.insert(outpoint.txid);
                    }
                }
            }
            in_block_txids.insert(transaction.compute_txid());
        }

        let external_source_txids: Vec<bitcoin::Txid> = external_source_txids.into_iter().collect();
        if !chain_store_handle
            .are_all_txids_confirmed(&external_source_txids)
            .map_err(|error| {
                ValidationError::new(format!("Failed to query confirmed status: {error}"))
            })?
        {
            return Err(ValidationError::new("prevout not on confirmed chain"));
        }
        let coinbase_outpoints = chain_store_handle
            .check_prevouts_and_find_coinbase(&all_outpoints)
            .map_err(|error| {
                ValidationError::new(format!(
                    "One or more prevouts do not exist in the Outputs store: {error}"
                ))
            })?;
        if chain_store_handle
            .is_any_prevout_spent(&all_outpoints)
            .map_err(|error| {
                ValidationError::new(format!("Failed to query SpendsIndex: {error}"))
            })?
        {
            return Err(ValidationError::new(
                "One or more prevouts are already spent",
            ));
        }
        if !coinbase_outpoints.is_empty() {
            if let Some(immature) = chain_store_handle
                .find_immature_coinbase_prevout(&coinbase_outpoints, COINBASE_MATURITY)
                .map_err(|error| {
                    ValidationError::new(format!("Failed to check coinbase maturity: {error}"))
                })?
            {
                return Err(ValidationError::new(format!(
                    "Coinbase output {}:{} is not yet mature (requires at least {} blocks of depth)",
                    immature.txid, immature.vout, COINBASE_MATURITY
                )));
            }
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
            chain_store_handle: &ChainStoreHandle,
            time_provider: &dyn TimeProvider,
        ) -> Result<(), ValidationError>;

        fn validate_with_chain_context(
            &self,
            share: &ShareBlock,
            chain_store_handle: &ChainStoreHandle,
        ) -> Result<(), ValidationError>;

        fn validate_header_minimum_difficulty(
            &self,
            share_header: &ShareHeader,
        ) -> Result<(), ValidationError>;

        fn pool_difficulty(&self) -> &PoolDifficulty;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store_handle::ConfirmedHeaderResult;
    use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
    use crate::shares::extranonce::Extranonce;
    use crate::shares::share_block::ShareTransaction;
    use crate::shares::share_commitment::ShareCommitment;
    use crate::shares::witness_commitment::WitnessCommitment;
    use crate::store::block_tx_metadata::BlockMetadata;
    use crate::store::writer::StoreError;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::stratum::work::gbt::build_merkle_branches_for_template;
    use crate::test_utils::{
        TEST_COINBASE_NSECS, TestShareBlockBuilder, build_block_from_work_components,
        genesis_for_tests, load_share_headers_test_data, make_test_address,
        setup_pool_difficulty_mocks,
    };
    use crate::utils::time_provider::TestTimeProvider;
    use bitcoin::pow::Work;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{BlockHash, ScriptBuf, TxOut, hashes::Hash};
    use mockall::predicate::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::SystemTime;

    fn validator() -> DefaultShareValidator {
        DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec())
    }

    fn validator_with(pool_difficulty: PoolDifficulty) -> DefaultShareValidator {
        DefaultShareValidator::new(pool_difficulty, 1, b"P2Poolv2".to_vec())
    }

    fn confirmed_header_with_time(time: u32, height: u32) -> ConfirmedHeaderResult {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share.header.time = time;
        ConfirmedHeaderResult {
            height,
            blockhash: share.block_hash(),
            header: share.header,
        }
    }

    fn metadata_at_height(height: u32) -> BlockMetadata {
        BlockMetadata {
            expected_height: Some(height),
            chain_work: Work::from_le_bytes([0u8; 32]),
            status: Status::Confirmed,
        }
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_when_not_greater_than_mtp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        // 11 ancestor headers with strictly increasing times centred on
        // share.header.time so the median equals share.header.time.
        let share_time = share.header.time;
        let mut headers: Vec<ConfirmedHeaderResult> = Vec::with_capacity(MTP_WINDOW);
        for offset in 0..MTP_WINDOW as i32 {
            let time = (share_time as i32 + offset - (MTP_WINDOW as i32 / 2)) as u32;
            headers.push(confirmed_header_with_time(time, offset as u32));
        }
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(20)));
        chain_store_handle
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers.clone()));

        let median = share_time;
        let result = validator().validate_timestamp(&share, &chain_store_handle, &time_provider);
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "Share timestamp {} is not greater than median time past {median}",
                share.header.time as u64
            )
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_fail_for_future_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        let local_time = share.header.time as u64 - (MAX_FUTURE_TIME_SECS + 1);
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(local_time as u32).unwrap());

        let chain_store_handle = ChainStoreHandle::default();
        let error = validator()
            .validate_timestamp(&share, &chain_store_handle, &time_provider)
            .unwrap_err();
        assert!(
            error.to_string().contains("seconds ahead of local time"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_should_succeed_for_valid_timestamp() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        // 11 ancestors all strictly older than share.header.time so median < share.header.time.
        let share_time = share.header.time;
        let mut headers: Vec<ConfirmedHeaderResult> = Vec::with_capacity(MTP_WINDOW);
        for offset in 1..=MTP_WINDOW as u32 {
            headers.push(confirmed_header_with_time(share_time - offset, offset));
        }
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(20)));
        chain_store_handle
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers.clone()));

        assert!(
            validator()
                .validate_timestamp(&share, &chain_store_handle, &time_provider)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_fails_when_parent_metadata_missing() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("genesis".into())));

        let error = validator()
            .validate_timestamp(&share, &chain_store_handle, &time_provider)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("metadata not found for MTP check"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_fails_when_parent_height_missing() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: None,
                    chain_work: Work::from_le_bytes([0u8; 32]),
                    status: Status::Confirmed,
                })
            });

        let error = validator()
            .validate_timestamp(&share, &chain_store_handle, &time_provider)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no expected height for MTP check"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn test_validate_timestamp_succeeds_with_fewer_than_window_ancestors() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let mut time_provider = TestTimeProvider::new(SystemTime::now());
        time_provider.set_time(bitcoin::absolute::Time::from_consensus(share.header.time).unwrap());

        let share_time = share.header.time;
        let mut headers: Vec<ConfirmedHeaderResult> = Vec::with_capacity(3);
        for offset in 1..=3u32 {
            headers.push(confirmed_header_with_time(share_time - offset, offset));
        }
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| Ok(metadata_at_height(2)));
        chain_store_handle
            .expect_get_confirmed_headers_in_range()
            .returning(move |_, _| Ok(headers.clone()));

        assert!(
            validator()
                .validate_timestamp(&share, &chain_store_handle, &time_provider)
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

    #[test_log::test(tokio::test)]
    async fn test_validate_share() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let share_block = build_block_from_work_components(
            "../p2poolv2_tests/test_data/validation/stratum/b/",
            TEST_COINBASE_NSECS,
        );

        // Mark as BlockValid so validate_with_pool_difficulty is skipped.
        // The test fixture's bitcoin header doesn't have valid PoW against
        // pool difficulty. Pool difficulty is tested in dedicated tests.
        chain_store_handle
            .expect_has_status()
            .returning(|_, _| true);
        chain_store_handle
            .expect_add_share_block()
            .with(mockall::predicate::eq(share_block.clone()))
            .returning(|_| Ok(()));
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
                .returning(|_, _, _| Some(HashMap::from([(make_test_address(1), 100)])));
            Arc::new(RwLock::new(mock_window))
        };
        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let result =
            validator.validate_share_block(&share_block, &chain_store_handle, pplns_window);

        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
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
                .returning(|_, _, _| Some(HashMap::new()));
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
        let test_data = load_share_headers_test_data();
        let header: ShareHeader =
            serde_json::from_value(test_data["too_many_uncles_header"].clone()).unwrap();

        let error = validator().validate_share_header(&header).unwrap_err();
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

        let result = validator().validate_scripts_values_and_sigops(&share, &chain_store_handle);
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

        let result = validator().validate_scripts_values_and_sigops(&share, &chain_store_handle);
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
            .validate_scripts_values_and_sigops(&share, &chain_store_handle)
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
            .validate_scripts_values_and_sigops(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to look up spent outputs"),
            "Expected UTXO lookup failure, got: {error}"
        );
    }

    #[test]
    fn test_validate_prevouts_exist_succeeds_for_coinbase_only() {
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(|_outpoints| Ok(Vec::new()));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .returning(|_outpoints| Ok(false));
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let result = validator().validate_prevouts(&share, &chain_store_handle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_prevouts_exist_succeeds_when_confirmed_present_and_unspent() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (_spent_output, spending_tx) = build_p2sh_op_true_spent_output_and_spending_tx();

        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(|_outpoints| Ok(Vec::new()));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .returning(|_outpoints| Ok(false));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let result = validator().validate_prevouts(&share, &chain_store_handle);
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
    }

    #[test]
    fn test_validate_prevouts_exist_fails_when_source_tx_not_confirmed() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (_spent_output, spending_tx) = build_p2sh_op_true_spent_output_and_spending_tx();

        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(false));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("prevout not on confirmed chain"),
            "got: {error}"
        );
    }

    #[test]
    fn test_validate_prevouts_exist_fails_when_prevout_missing() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (_spent_output, spending_tx) = build_p2sh_op_true_spent_output_and_spending_tx();

        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(|_outpoints| Err(StoreError::NotFound("Output not found".to_string())));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("do not exist"), "got: {error}");
    }

    #[test]
    fn test_validate_prevouts_exist_fails_when_prevout_already_spent() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (_spent_output, spending_tx) = build_p2sh_op_true_spent_output_and_spending_tx();

        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(|_outpoints| Ok(Vec::new()));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .returning(|_outpoints| Ok(true));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("already spent"), "got: {error}");
    }

    #[test]
    fn test_validate_prevouts_exist_skips_in_block_source_tx() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let producing_tx = bitcoin::Transaction {
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
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let producing_txid = producing_tx.compute_txid();

        let in_block_spender = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: producing_txid,
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

        // The confirmation check sees only the producing tx's external
        // prevout (Txid::all_zeros) — the in-block source txid is
        // exempt. The existence and spent checks see *both* outpoints
        // because in-block prevouts must still be checked against the
        // Outputs CF (and harmlessly probed in SpendsIndex).
        let producing_txid_for_check = producing_txid;
        chain_store_handle
            .expect_are_all_txids_confirmed()
            .withf(|txids| txids.len() == 1 && txids[0] == bitcoin::Txid::all_zeros())
            .returning(|_txids| Ok(true));
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .withf(move |outpoints| {
                outpoints.len() == 2
                    && outpoints
                        .iter()
                        .any(|outpoint| outpoint.txid == bitcoin::Txid::all_zeros())
                    && outpoints
                        .iter()
                        .any(|outpoint| outpoint.txid == producing_txid_for_check)
            })
            .returning(|_outpoints| Ok(Vec::new()));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .withf(move |outpoints| outpoints.len() == 2)
            .returning(|_outpoints| Ok(false));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(producing_tx)
            .add_transaction(in_block_spender)
            .build();

        let result = validator().validate_prevouts(&share, &chain_store_handle);
        assert!(result.is_ok(), "expected Ok, got {:?}", result.err());
    }

    #[test]
    fn test_validate_prevouts_fails_when_in_block_spend_references_missing_vout() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let producing_tx = bitcoin::Transaction {
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
            // producer has only one output (vout 0).
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let producing_txid = producing_tx.compute_txid();

        // spender references vout 5 — does not exist.
        let in_block_spender = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: producing_txid,
                    vout: 5,
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

        // Confirmation check passes for the external prevout.
        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));
        // Existence check fails because the in-block spender references
        // a non-existent vout.
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(|_outpoints| Err(StoreError::NotFound("Output not found".to_string())));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(producing_tx)
            .add_transaction(in_block_spender)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("do not exist"), "got: {error}");
    }

    #[test]
    fn test_validate_prevouts_fails_when_two_inputs_spend_same_prevout() {
        let chain_store_handle = ChainStoreHandle::default();

        let shared_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0,
        };

        let spender_a = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: shared_prevout,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let spender_b = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: shared_prevout,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(20_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // No store mocks set: the duplicate-prevout check rejects the
        // share before any chain_store_handle method is called.
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spender_a)
            .add_transaction(spender_b)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("Duplicate prevout"),
            "got: {error}"
        );
    }

    #[test]
    fn test_validate_prevouts_rejects_immature_coinbase_spend() {
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));

        let coinbase_outpoint = bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0);
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(move |_outpoints| Ok(vec![coinbase_outpoint]));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .returning(|_outpoints| Ok(false));
        chain_store_handle
            .expect_find_immature_coinbase_prevout()
            .returning(move |_outpoints, _min_depth| Ok(Some(coinbase_outpoint)));

        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_prevouts(&share, &chain_store_handle)
            .unwrap_err();
        assert!(error.to_string().contains("not yet mature"), "got: {error}");
    }

    #[test]
    fn test_validate_prevouts_accepts_mature_coinbase_spend() {
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_are_all_txids_confirmed()
            .returning(|_txids| Ok(true));

        let coinbase_outpoint = bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0);
        chain_store_handle
            .expect_check_prevouts_and_find_coinbase()
            .returning(move |_outpoints| Ok(vec![coinbase_outpoint]));
        chain_store_handle
            .expect_is_any_prevout_spent()
            .returning(|_outpoints| Ok(false));
        chain_store_handle
            .expect_find_immature_coinbase_prevout()
            .returning(|_outpoints, _min_depth| Ok(None));

        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let result = validator().validate_prevouts(&share, &chain_store_handle);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_expected_outputs_empty_distribution_returns_error() {
        let header = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build()
            .header;
        let empty_map = HashMap::new();
        let result =
            DefaultShareValidator::build_expected_outputs(&header, &empty_map, 5_000_000_000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("empty distribution"),
        );
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

        let total_amount = 1_000_000_000;
        let outputs =
            DefaultShareValidator::build_expected_outputs(&header, &difficulty_map, total_amount)
                .unwrap();

        assert_eq!(outputs.len(), 2);
        let total_distributed: Amount = outputs.iter().map(|output| output.amount).sum();
        assert_eq!(total_distributed, Amount::from_sat(total_amount));

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

        let total = 10_000_000_000;
        let outputs =
            DefaultShareValidator::build_expected_outputs(&header, &difficulty_map, total).unwrap();

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
        assert_eq!(total_distributed, Amount::from_sat(total));
    }

    #[test]
    fn test_validate_bitcoin_payout_with_matching_distribution() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );

        // Build share block first to get header fields for commitment
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.coinbase_value = 312_500_000;
        share_block.header.bitcoin_height = 840_000;

        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();

        // Build coinbase matching how the validator reconstructs it
        let coinbase_tx = build_bitcoin_coinbase_transaction(
            Version::TWO,
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
            share_block.header.bitcoin_height as i64,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(commitment_hash),
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        share_block.header.bitcoin_header.merkle_root = coinbase_tx.compute_txid().into();

        // Mock PplnsWindow returning matching 60/40 distribution
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        let addr_b_clone = address_b.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _, _| {
                let mut distribution = HashMap::with_capacity(2);
                distribution.insert(addr_a_clone.clone(), 600u128);
                distribution.insert(addr_b_clone.clone(), 400u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let result = validator.validate_bitcoin_payout(
            &share_block,
            &ChainStoreHandle::default(),
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
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );
        let address_b = crate::test_utils::parse_address_from_string(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );

        // Build share block first to get header fields for commitment
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.coinbase_value = 312_500_000;
        share_block.header.bitcoin_height = 840_000;

        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();

        // Build coinbase with 50/50 split (wrong for 60/40 distribution)
        let coinbase_tx = build_bitcoin_coinbase_transaction(
            Version::TWO,
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
            share_block.header.bitcoin_height as i64,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(commitment_hash),
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        share_block.header.bitcoin_header.merkle_root = coinbase_tx.compute_txid().into();

        // Mock PplnsWindow returning 60/40 distribution
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        let addr_b_clone = address_b.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _, _| {
                let mut distribution = HashMap::with_capacity(2);
                distribution.insert(addr_a_clone.clone(), 600u128);
                distribution.insert(addr_b_clone.clone(), 400u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        // The reconstructed coinbase will have different outputs (60/40),
        // producing a different merkle root than the 50/50 coinbase
        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let error = validator
            .validate_bitcoin_payout(&share_block, &ChainStoreHandle::default(), pplns_window)
            .unwrap_err();
        assert!(
            error.to_string().contains("merkle root"),
            "Expected merkle root mismatch error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_empty_window_returns_error() {
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.coinbase_value = 312_500_000;
        share_block.header.bitcoin_height = 840_000;

        // Mock PplnsWindow returning empty distribution
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(|_, _, _| Some(HashMap::new()));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let error = validator()
            .validate_bitcoin_payout(&share_block, &ChainStoreHandle::default(), pplns_window)
            .unwrap_err();
        assert!(
            error.to_string().contains("empty distribution"),
            "Expected empty distribution error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_fails_when_prev_share_blockhash_not_in_window() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );

        let coinbase_tx = build_bitcoin_coinbase_transaction(
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
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(|_, _, _| None);
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let error = validator()
            .validate_bitcoin_payout(&share_block, &ChainStoreHandle::default(), pplns_window)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("prev_share_blockhash not found in PPLNS window"),
            "Expected PPLNS window miss error, got: {error}"
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_with_wrong_coinbase_value_fails() {
        let address_a = crate::test_utils::parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        );

        // Build share block with coinbase_value=1 sat
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.coinbase_value = 1;
        share_block.header.bitcoin_height = 840_000;

        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();

        // Build coinbase with 1 sat matching the header
        let coinbase_tx = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: address_a.clone(),
                amount: Amount::from_sat(1),
            }],
            share_block.header.bitcoin_height as i64,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(commitment_hash),
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        share_block.header.bitcoin_header.merkle_root = coinbase_tx.compute_txid().into();

        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _, _| Some(HashMap::from([(addr_a_clone.clone(), 100u128)])));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        // The reconstructed coinbase will also have 1 sat to address_a,
        // so merkle roots should match and validation should pass
        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let result = validator.validate_bitcoin_payout(
            &share_block,
            &ChainStoreHandle::default(),
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Expected valid payout, got: {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_validate_bitcoin_payout_with_transactions_donation_and_fees() {
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

        // Build share block header with donation/fee fields
        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.donation_address = Some(donation_address.clone());
        share_block.header.donation = Some(donation_bp);
        share_block.header.fee_address = Some(fee_address.clone());
        share_block.header.fee = Some(fee_bp);
        share_block.header.coinbase_value = total_coinbase_sats;
        share_block.header.bitcoin_height = 840_000;

        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();

        // Build coinbase: donation, fee, then 3 miners in sorted address order
        let coinbase_tx = build_bitcoin_coinbase_transaction(
            Version::TWO,
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
            share_block.header.bitcoin_height as i64,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(commitment_hash),
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        share_block.header.bitcoin_header.merkle_root = coinbase_tx.compute_txid().into();

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
            .returning(move |_, _, _| {
                let mut distribution = HashMap::with_capacity(3);
                distribution.insert(miner_a_clone.clone(), 500u128);
                distribution.insert(miner_b_clone.clone(), 300u128);
                distribution.insert(miner_c_clone.clone(), 200u128);
                Some(distribution)
            });
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let result = validator.validate_bitcoin_payout(
            &share_block,
            &ChainStoreHandle::default(),
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Expected valid payout with 3 miners, donation, fee, got: {}",
            result.unwrap_err()
        );

        // Verify the amounts sum correctly
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

    #[test]
    fn test_validate_bitcoin_payout_with_template_transactions() {
        let template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/validation/stratum/gbt_with_transactions.json"
        ))
        .expect("Failed to parse template JSON");

        let address_a = make_test_address(1);

        let mut share_block = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        share_block.header.coinbase_value = template.coinbasevalue;
        share_block.header.bitcoin_height = template.height as u64;
        share_block.header.coinbaseaux_flags = template
            .coinbaseaux
            .get("flags")
            .and_then(|flags| hex::decode(flags).ok())
            .map(|bytes| CoinbaseAuxFlags::new(&bytes));
        share_block.header.witness_commitment = template
            .default_witness_commitment
            .as_deref()
            .and_then(|hex_str| WitnessCommitment::from_hex(hex_str).ok());

        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();

        let coinbase_tx = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: address_a.clone(),
                amount: Amount::from_sat(template.coinbasevalue),
            }],
            template.height as i64,
            share_block
                .header
                .coinbaseaux_flags
                .as_ref()
                .map(|flags| flags.to_push_bytes_buf())
                .unwrap_or_else(|| PushBytesBuf::from(&[0u8])),
            share_block.header.witness_commitment.as_ref(),
            b"P2Poolv2",
            Some(commitment_hash),
            TEST_COINBASE_NSECS,
            Some(Extranonce::default().as_bytes()),
        )
        .unwrap();

        // Build full bitcoin transaction list: coinbase + template transactions
        let template_transactions: Vec<bitcoin::Transaction> = template
            .transactions
            .iter()
            .map(bitcoin::Transaction::from)
            .collect();
        let mut all_bitcoin_txids = vec![coinbase_tx.compute_txid()];
        all_bitcoin_txids.extend(template_transactions.iter().map(|tx| tx.compute_txid()));

        // Compute the full merkle root from all txids
        let full_merkle_root: TxMerkleNode =
            bitcoin::merkle_tree::calculate_root(all_bitcoin_txids.into_iter())
                .unwrap()
                .into();
        share_block.header.bitcoin_header.merkle_root = full_merkle_root;

        // Set merkle branches from template transactions
        share_block.template_merkle_branches = build_merkle_branches_for_template(&template)
            .into_iter()
            .map(TxMerkleNode::from_raw_hash)
            .collect();

        // Mock PplnsWindow returning 100% to address_a
        let mut mock_window = PplnsWindow::default();
        mock_window
            .expect_network()
            .return_const(bitcoin::Network::Signet);
        let addr_a_clone = address_a.clone();
        mock_window
            .expect_get_distribution_from_start_hash()
            .returning(move |_, _, _| Some(HashMap::from([(addr_a_clone.clone(), 1000u128)])));
        let pplns_window = Arc::new(RwLock::new(mock_window));

        let validator =
            DefaultShareValidator::new(PoolDifficulty::default(), 1, b"P2Poolv2".to_vec());
        let result = validator.validate_bitcoin_payout(
            &share_block,
            &ChainStoreHandle::default(),
            pplns_window,
        );
        assert!(
            result.is_ok(),
            "Expected valid payout with 4 template transactions, got: {}",
            result.unwrap_err()
        );

        // Verify we actually tested with non-empty merkle branches
        assert_eq!(
            share_block.template_merkle_branches.len(),
            3,
            "Expected 3 merkle branches for 4 template transactions"
        );
    }

    #[test]
    fn test_validate_header_minimum_difficulty_rejects_easy_target() {
        let share = TestShareBlockBuilder::new().build();
        // Default test shares use 0x1b4188f5 (genesis max target) which is
        // easier than MAX_POOL_TARGET (0x1b384bd7)
        let result = validator().validate_header_minimum_difficulty(&share.header);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("easier than maximum pool target"),
        );
    }

    #[test]
    fn test_validate_header_minimum_difficulty_rejects_invalid_pow() {
        let mut header = TestShareBlockBuilder::new().build().header;
        // Set bits to MAX_POOL_TARGET -- the bitcoin block hash from the
        // default test builder does not meet this target.
        header.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let result = validator().validate_header_minimum_difficulty(&header);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not meet declared target"),
        );
    }

    #[test]
    fn test_validate_header_minimum_difficulty_rejects_too_many_uncles() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        header.uncles = vec![BlockHash::all_zeros(); MAX_UNCLES + 1];
        let result = validator().validate_header_minimum_difficulty(&header);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many uncles"),);
    }

    #[test]
    fn test_validate_input_output_values_fails_when_outputs_exceed_inputs() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let redeem_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let mut script_sig_bytes = Vec::with_capacity(1 + redeem_script.len());
        script_sig_bytes.push(redeem_script.len() as u8);
        script_sig_bytes.extend_from_slice(redeem_script.as_bytes());
        let script_sig = ScriptBuf::from(script_sig_bytes);

        let spent_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: redeem_script.to_p2sh(),
        };

        // Output (100_000) exceeds the input (50_000)
        let overspending_tx = bitcoin::Transaction {
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
                value: bitcoin::Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spent_output_clone = spent_output.clone();
        chain_store_handle
            .expect_get_all_prevouts()
            .returning(move |_tx| Ok(vec![(0, spent_output_clone.clone())]));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(overspending_tx)
            .build();

        let error = validator()
            .validate_scripts_values_and_sigops(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("outputs") && error.to_string().contains("exceed inputs"),
            "Expected output-exceeds-input error, got: {error}"
        );
    }

    #[test]
    fn test_validate_input_output_values_fails_when_total_input_exceeds_max_money() {
        let mut chain_store_handle = ChainStoreHandle::default();

        let redeem_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let mut script_sig_bytes = Vec::with_capacity(1 + redeem_script.len());
        script_sig_bytes.push(redeem_script.len() as u8);
        script_sig_bytes.extend_from_slice(redeem_script.as_bytes());
        let script_sig = ScriptBuf::from(script_sig_bytes);

        // Two inputs each worth MAX_MONEY, so total input exceeds MAX_MONEY
        let prevout_value = Amount::MAX_MONEY;
        let spent_output_a = bitcoin::TxOut {
            value: prevout_value,
            script_pubkey: redeem_script.to_p2sh(),
        };
        let spent_output_b = bitcoin::TxOut {
            value: Amount::from_sat(1),
            script_pubkey: redeem_script.to_p2sh(),
        };

        let spending_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::all_zeros(),
                        vout: 0,
                    },
                    script_sig: script_sig.clone(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: bitcoin::Txid::all_zeros(),
                        vout: 1,
                    },
                    script_sig,
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spent_output_a_clone = spent_output_a.clone();
        let spent_output_b_clone = spent_output_b.clone();
        chain_store_handle
            .expect_get_all_prevouts()
            .returning(move |_tx| {
                Ok(vec![
                    (0, spent_output_a_clone.clone()),
                    (1, spent_output_b_clone.clone()),
                ])
            });

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(spending_tx)
            .build();

        let error = validator()
            .validate_scripts_values_and_sigops(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("total input value")
                && error.to_string().contains("exceeds maximum"),
            "Expected MAX_MONEY input error, got: {error}"
        );
    }

    #[test]
    fn test_validate_sigop_cost_fails_when_exceeding_limit() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Build a non-coinbase transaction whose outputs contain enough
        // OP_CHECKSIG opcodes to exceed MAX_BLOCK_SIGOPS_COST.
        // Each OP_CHECKSIG in an output scriptPubKey costs 4 sigop units
        // (legacy weight). MAX_BLOCK_SIGOPS_COST = 80_000, so
        // 20_001 OP_CHECKSIGs = 80_004 cost.
        let sigop_count = (MAX_BLOCK_SIGOPS_COST / 4) + 1;
        let mut script_bytes = Vec::with_capacity(sigop_count);
        for _ in 0..sigop_count {
            script_bytes.push(bitcoin::opcodes::all::OP_CHECKSIG.to_u8());
        }
        let heavy_script = ScriptBuf::from(script_bytes);

        // Use P2SH OP_TRUE so script validation passes; the heavy sigops
        // are in the output scriptPubKey, not the spending script.
        let redeem_script = bitcoin::Script::builder()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .into_script();
        let mut script_sig_bytes = Vec::with_capacity(1 + redeem_script.len());
        script_sig_bytes.push(redeem_script.len() as u8);
        script_sig_bytes.extend_from_slice(redeem_script.as_bytes());
        let script_sig = ScriptBuf::from(script_sig_bytes);

        let spent_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(5_000_000_000),
            script_pubkey: redeem_script.to_p2sh(),
        };

        let heavy_tx = bitcoin::Transaction {
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
                value: bitcoin::Amount::from_sat(4_999_000_000),
                script_pubkey: heavy_script,
            }],
        };

        let spent_output_clone = spent_output.clone();
        chain_store_handle
            .expect_get_all_prevouts()
            .returning(move |_tx| Ok(vec![(0, spent_output_clone.clone())]));

        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .add_transaction(heavy_tx)
            .build();

        let error = validator()
            .validate_scripts_values_and_sigops(&share, &chain_store_handle)
            .unwrap_err();
        assert!(
            error.to_string().contains("sigop cost")
                && error.to_string().contains("exceeds maximum"),
            "Expected sigop cost exceeded error, got: {error}"
        );
    }

    #[test]
    fn test_validate_share_witness_commitment_succeeds_for_valid_block() {
        let share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();
        let result = validator().validate_share_witness_commitment(&share);
        assert!(
            result.is_ok(),
            "Expected valid witness commitment, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_share_witness_commitment_fails_for_tampered_commitment() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Flip a byte inside the 32-byte commitment hash (after the 6-byte header).
        let mut script_bytes = share.transactions[0].output[1]
            .script_pubkey
            .as_bytes()
            .to_vec();
        script_bytes[10] ^= 0xFF;
        share.transactions[0].0.output[1].script_pubkey = ScriptBuf::from(script_bytes);

        let error = validator()
            .validate_share_witness_commitment(&share)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match recomputed witness root"),
            "Expected commitment mismatch error, got: {error}"
        );
    }

    #[test]
    fn test_validate_share_witness_commitment_fails_for_bad_bip141_header() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Corrupt the BIP141 magic bytes in the commitment output.
        let mut script_bytes = share.transactions[0].output[1]
            .script_pubkey
            .as_bytes()
            .to_vec();
        script_bytes[2] = 0x00;
        share.transactions[0].0.output[1].script_pubkey = ScriptBuf::from(script_bytes);

        let error = validator()
            .validate_share_witness_commitment(&share)
            .unwrap_err();
        assert!(
            error.to_string().contains("invalid BIP141 header"),
            "Expected BIP141 header error, got: {error}"
        );
    }

    #[test]
    fn test_validate_share_witness_commitment_fails_for_bad_reserved_value() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Replace the 32-byte reserved value with a 16-byte value.
        let mut witness = bitcoin::Witness::new();
        witness.push([0u8; 16]);
        share.transactions[0].0.input[0].witness = witness;

        let error = validator()
            .validate_share_witness_commitment(&share)
            .unwrap_err();
        assert!(
            error.to_string().contains("single 32-byte reserved value"),
            "Expected reserved value error, got: {error}"
        );
    }

    #[test]
    fn test_validate_share_witness_commitment_fails_for_non_zero_commitment_value() {
        let mut share = TestShareBlockBuilder::new()
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Set a non-zero value on the commitment output (BIP141 requires
        // zero value so miners cannot burn funds into an unspendable output).
        share.transactions[0].0.output[1].value = bitcoin::Amount::from_sat(1);

        let error = validator()
            .validate_share_witness_commitment(&share)
            .unwrap_err();
        assert!(
            error.to_string().contains("must have zero value"),
            "Expected zero-value error, got: {error}"
        );
    }
}
