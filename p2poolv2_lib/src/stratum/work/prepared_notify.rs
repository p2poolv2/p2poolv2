// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::block_template::{BlockTemplate, parse_flags};
use super::coinbase::{
    LOCKTIME_LENGTH, build_bitcoin_coinbase_transaction, get_timestamp_bytes, split_coinbase,
};
use super::error::WorkError;
use super::gbt::build_merkle_branches_for_template;
use super::tracker::JobTracker;
use crate::accounting::OutputPair;
use crate::address::Address as P2PoolAddress;
use crate::shares::share_commitment::{
    ShareCommitment, build_commitment_prefix, build_commitment_suffix, commitment_digest,
};
use crate::shares::transactions::coinbase::compute_witness_root;
use crate::shares::witness_commitment::WitnessCommitment;
use crate::stratum::util::{reverse_four_byte_chunks, to_be_hex};
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoin::WitnessProgram;
use bitcoin::hashes::{self, Hash};
use bitcoin::transaction::Version;
use bitcoin::{Address, BlockHash, CompactTarget};
use std::sync::Arc;

/// Hex characters per byte.
const HEX_PER_BYTE: usize = 2;

/// Hex of the opcode starting coinbase2: the nsecs push, OP_PUSHBYTES_8.
const NSECS_PUSH_OPCODE_HEX: &str = "08";

/// Hex length of the nsecs push at the front of coinbase2: the
/// OP_PUSHBYTES_8 opcode (1 byte) and the 8-byte little-endian nsecs.
const NSECS_PUSH_HEX_LENGTH: usize = HEX_PER_BYTE * (1 + 8);

/// Hex of the commitment output's script opcodes preceding the hash:
/// OP_RETURN (0x6a) and OP_PUSHBYTES_32 (0x20).
const COMMITMENT_SCRIPT_OPCODES_HEX: &str = "6a20";

/// Hex length of the 32-byte commitment hash in the commitment output.
const COMMITMENT_HASH_HEX_LENGTH: usize = HEX_PER_BYTE * 32;

/// Hex length of the 4-byte locktime ending coinbase2, which follows the
/// commitment hash.
const LOCKTIME_HEX_LENGTH: usize = HEX_PER_BYTE * LOCKTIME_LENGTH;

/// Split coinbase2 around its per-miner parts -- the nsecs push at the front
/// and the commitment hash before the locktime -- into the static middle and
/// the locktime.
///
/// Checks the layout before slicing: the nsecs push opens coinbase2, and the
/// commitment output's opcodes and `dummy_commitment_hex` sit right before the
/// locktime. A coinbase built any other way would place each miner's
/// commitment in the wrong bytes, and every share would then fail validation
/// with nothing pointing back here.
fn split_coinbase2(
    coinbase2: &str,
    dummy_commitment_hex: &str,
) -> Result<(String, String), WorkError> {
    let minimum_length = NSECS_PUSH_HEX_LENGTH
        + COMMITMENT_SCRIPT_OPCODES_HEX.len()
        + COMMITMENT_HASH_HEX_LENGTH
        + LOCKTIME_HEX_LENGTH;
    if coinbase2.len() < minimum_length {
        return Err(WorkError {
            message: format!("coinbase2 of {} hex chars is too short", coinbase2.len()),
        });
    }
    let locktime_start = coinbase2.len() - LOCKTIME_HEX_LENGTH;
    let commitment_start = locktime_start - COMMITMENT_HASH_HEX_LENGTH;
    let opcodes_start = commitment_start - COMMITMENT_SCRIPT_OPCODES_HEX.len();

    let has_expected_layout = coinbase2.starts_with(NSECS_PUSH_OPCODE_HEX)
        && &coinbase2[opcodes_start..commitment_start] == COMMITMENT_SCRIPT_OPCODES_HEX
        && &coinbase2[commitment_start..locktime_start] == dummy_commitment_hex;
    if !has_expected_layout {
        return Err(WorkError {
            message: "coinbase2 does not start with the nsecs push and end with the commitment output and locktime".to_string(),
        });
    }

    Ok((
        coinbase2[NSECS_PUSH_HEX_LENGTH..commitment_start].to_string(),
        coinbase2[locktime_start..].to_string(),
    ))
}

/// Pre-serialized notify message with placeholders for per-miner fields.
///
/// coinbase1 is static (same for all miners): [height][aux_flags][EXTRANONCE_SEPARATOR]
/// coinbase2 is built per-miner:
/// [nsecs][pool_sig][sequence][outputs..][padding output][commitment output][locktime]
/// where the commitment output is `OP_RETURN OP_PUSHBYTES_32 <commitment_hash>`.
/// Only the nsecs push and the 32 commitment bytes differ between miners, and
/// both are fixed size, so the padding that block-aligns the prefix is the same
/// for every miner on a template.
///
/// The JSON template has fixed-size placeholders for job_id and the full coinbase2.
/// The commitment encoding is split into a prefix (fields before time) and a
/// suffix (fields after time), so that per-share hashing inserts a fresh 4-byte
/// timestamp between them without rebuilding the whole commitment.
pub struct PreparedNotifyParams {
    /// Pre-serialized JSON notify string with placeholder job_id and coinbase2
    json_template: String,
    /// Byte offset of the 16-char job_id placeholder in json_template
    job_id_offset: usize,
    /// Byte offset of the coinbase2 placeholder in json_template
    coinbase2_offset: usize,
    /// Length of the coinbase2 placeholder in json_template
    coinbase2_placeholder_len: usize,
    /// Pre-serialized commitment fields before time:
    /// prev_share_blockhash + uncles + bits
    commitment_prefix: Vec<u8>,
    /// Pre-serialized commitment fields after time (before miner address):
    /// donation_address + donation + fee_address + fee
    commitment_suffix: Vec<u8>,
    /// Previous share block hash (for building ShareCommitment struct)
    prev_share_blockhash: BlockHash,
    /// Uncle block hashes (for building ShareCommitment struct)
    uncles: Vec<BlockHash>,
    /// Share chain difficulty target (for building ShareCommitment struct)
    bits: CompactTarget,
    /// Donation address for developers
    donation_address: Option<Address>,
    /// Donation in basis points
    donation: Option<u16>,
    /// Fee address for the pool operator
    fee_address: Option<Address>,
    /// Fee in basis points
    fee: Option<u16>,
    /// Shared block template
    template: Arc<BlockTemplate>,
    /// Static coinbase1 hex (identical for all miners)
    coinbase1: String,
    /// Coinbase2 hex between the nsecs push and the commitment hash bytes:
    /// [pool_sig][sequence][outputs..][padding output][commitment output header]
    coinbase2_middle: String,
    /// Coinbase2 hex after the commitment hash bytes: the locktime.
    coinbase2_locktime: String,
    /// Merkle branches for the template transactions (excluding coinbase).
    /// Passed through to JobDetails so validators can verify the bitcoin merkle root.
    merkle_branches: Vec<bitcoin::TxMerkleNode>,
}

impl PreparedNotifyParams {
    /// The ASERT-computed pool target for shares built on these params.
    pub fn bits(&self) -> bitcoin::CompactTarget {
        self.bits
    }
}

/// Serialize the merkle branches array as a JSON array string.
fn serialize_merkle_branches_json(branches: &[String]) -> String {
    let mut result = String::with_capacity(branches.len() * 68);
    result.push('[');
    for (index, branch) in branches.iter().enumerate() {
        if index > 0 {
            result.push(',');
        }
        result.push('"');
        result.push_str(branch);
        result.push('"');
    }
    result.push(']');
    result
}

/// Build the pre-serialized JSON notify string by concatenation.
///
/// coinbase1 is static. coinbase2 gets a placeholder that is replaced per-miner.
/// Returns the JSON string, the byte offset of the job_id placeholder,
/// the byte offset of the coinbase2 placeholder, and the placeholder length.
#[allow(clippy::too_many_arguments)] // wiring constructor: each parameter is a distinct collaborator, a params struct would only move the list
fn build_json_template(
    coinbase1: &str,
    coinbase2_placeholder: &str,
    prevhash_byte_swapped: &str,
    merkle_branches: &[String],
    version_hex: &str,
    nbits: &str,
    ntime_hex: &str,
    clean_jobs: bool,
) -> (String, usize, usize, usize) {
    let estimated_capacity =
        256 + coinbase1.len() + coinbase2_placeholder.len() + merkle_branches.len() * 68;
    let mut json = String::with_capacity(estimated_capacity);

    json.push_str(r#"{"method":"mining.notify","params":[""#);
    let job_id_offset = json.len();
    json.push_str("0000000000000000"); // 16-char placeholder for job_id
    json.push_str(r#"",""#);
    json.push_str(prevhash_byte_swapped);
    json.push_str(r#"",""#);
    json.push_str(coinbase1);
    json.push_str(r#"",""#);
    let coinbase2_offset = json.len();
    let coinbase2_placeholder_len = coinbase2_placeholder.len();
    json.push_str(coinbase2_placeholder);
    json.push_str(r#"","#);
    json.push_str(&serialize_merkle_branches_json(merkle_branches));
    json.push_str(r#",""#);
    json.push_str(version_hex);
    json.push_str(r#"",""#);
    json.push_str(nbits);
    json.push_str(r#"",""#);
    json.push_str(ntime_hex);
    json.push_str(r#"","#);
    if clean_jobs {
        json.push_str("true");
    } else {
        json.push_str("false");
    }
    json.push_str("]}");

    (
        json,
        job_id_offset,
        coinbase2_offset,
        coinbase2_placeholder_len,
    )
}

/// Builder for constructing PreparedNotifyParams with pre-computed shared fields.
///
/// By serializing notify params once, we avoid needing to serialize
/// for each stratum client. Instead, we pick up the prepared notify
/// params and use the miner address to build share commitment, thus
/// the coinbase1 for each individual client.
pub(crate) struct PreparedNotifyParamsBuilder {
    template: Arc<BlockTemplate>,
    output_distribution: Vec<OutputPair>,
    pool_signature: Vec<u8>,
    clean_jobs: bool,
    prev_share_blockhash: BlockHash,
    uncles: Vec<BlockHash>,
    bits: CompactTarget,
    donation_address: Option<Address>,
    donation: Option<u16>,
    fee_address: Option<Address>,
    fee: Option<u16>,
}

impl PreparedNotifyParamsBuilder {
    /// Create a new builder with required parameters.
    pub fn new(
        template: Arc<BlockTemplate>,
        output_distribution: Vec<OutputPair>,
        pool_signature: &[u8],
        clean_jobs: bool,
    ) -> Self {
        Self {
            template,
            output_distribution,
            pool_signature: pool_signature.to_vec(),
            clean_jobs,
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: Vec::new(),
            bits: CompactTarget::from_consensus(0),
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
        }
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: BlockHash) -> Self {
        self.prev_share_blockhash = prev_share_blockhash;
        self
    }

    pub fn uncles(mut self, uncles: Vec<BlockHash>) -> Self {
        self.uncles = uncles;
        self
    }

    pub fn bits(mut self, bits: CompactTarget) -> Self {
        self.bits = bits;
        self
    }

    pub fn donation_address(mut self, donation_address: Option<Address>) -> Self {
        self.donation_address = donation_address;
        self
    }

    pub fn donation(mut self, donation: Option<u16>) -> Self {
        self.donation = donation;
        self
    }

    pub fn fee_address(mut self, fee_address: Option<Address>) -> Self {
        self.fee_address = fee_address;
        self
    }

    pub fn fee(mut self, fee: Option<u16>) -> Self {
        self.fee = fee;
        self
    }

    /// Build the PreparedNotifyParams by constructing the coinbase transaction
    /// with a dummy commitment hash, splitting it, and constructing the
    /// pre-serialized JSON template.
    ///
    /// coinbase1 is static (same for all miners). coinbase2 is split around its
    /// two per-miner parts -- the nsecs push at the front and the commitment
    /// hash bytes before the locktime -- into a static middle and locktime.
    pub fn build(self) -> Result<PreparedNotifyParams, WorkError> {
        let coinbaseaux = parse_flags(self.template.coinbaseaux.get("flags").cloned())?;
        let witness_commitment = self
            .template
            .default_witness_commitment
            .as_deref()
            .map(WitnessCommitment::from_hex)
            .transpose()
            .map_err(|error| WorkError {
                message: format!("Invalid witness commitment: {error}"),
            })?;

        // Build coinbase with dummy commitment hash and dummy nsecs.
        // After split_coinbase, coinbase1 is fully static, coinbase2 starts
        // with [nsecs_push][pool_sig_push]... and ends with
        // [commitment_hash][locktime].
        let dummy_commitment_hash = hashes::sha256::Hash::from_byte_array([0xab_u8; 32]);

        let coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            self.output_distribution.as_slice(),
            self.template.height as i64,
            coinbaseaux,
            witness_commitment.as_ref(),
            &self.pool_signature,
            Some(dummy_commitment_hash),
            0u64,
            None,
        )?;

        let (coinbase1, coinbase2_full) = split_coinbase(&coinbase)?;

        let (coinbase2_middle, coinbase2_locktime) = split_coinbase2(
            &coinbase2_full,
            &hex::encode(dummy_commitment_hash.as_byte_array()),
        )?;

        // Pre-compute merkle branches
        let merkle_branches_raw = build_merkle_branches_for_template(&self.template);
        let merkle_branches_hex: Vec<String> = merkle_branches_raw
            .iter()
            .map(|branch| to_be_hex(&branch.to_string()))
            .collect();

        let prevhash_byte_swapped = reverse_four_byte_chunks(&self.template.previousblockhash)
            .map_err(|error| WorkError {
                message: format!("Failed to reverse previous block hash: {error}"),
            })?;

        let version_hex = hex::encode(self.template.version.to_be_bytes());
        let ntime_hex = hex::encode(self.template.curtime.to_be_bytes());

        // Use a zero-filled placeholder for coinbase2 in the JSON template.
        // It will be replaced per-miner with the actual coinbase2.
        let coinbase2_placeholder = "0".repeat(coinbase2_full.len());

        let (json_template, job_id_offset, coinbase2_offset, coinbase2_placeholder_len) =
            build_json_template(
                &coinbase1,
                &coinbase2_placeholder,
                &prevhash_byte_swapped,
                &merkle_branches_hex,
                &version_hex,
                &self.template.bits,
                &ntime_hex,
                self.clean_jobs,
            );

        let commitment_prefix =
            build_commitment_prefix(self.prev_share_blockhash, &self.uncles, self.bits);
        let commitment_suffix = build_commitment_suffix(
            &self.donation_address,
            self.donation,
            &self.fee_address,
            self.fee,
            compute_witness_root(&[]),
            self.template.coinbasevalue,
        );

        Ok(PreparedNotifyParams {
            json_template,
            job_id_offset,
            coinbase2_offset,
            coinbase2_placeholder_len,
            commitment_prefix,
            commitment_suffix,
            prev_share_blockhash: self.prev_share_blockhash,
            uncles: self.uncles,
            bits: self.bits,
            donation_address: self.donation_address,
            donation: self.donation,
            fee_address: self.fee_address,
            fee: self.fee,
            template: self.template,
            coinbase1,
            coinbase2_middle,
            coinbase2_locktime,
            merkle_branches: merkle_branches_raw
                .into_iter()
                .map(bitcoin::TxMerkleNode::from_raw_hash)
                .collect(),
        })
    }
}

/// Hex of the commitment digest for one miner.
///
/// Uses the prefix and suffix pre-built once per template, so the per-miner
/// cost is a memcpy plus the tail append -- not a re-encode of the shared
/// fields. With thousands of workers these calls are serial, so the last miner
/// to be notified pays the sum of all of them; re-encoding the donation and fee
/// bech32 strings per miner is exactly what this avoids.
fn get_commitment_hex(
    commitment_prefix: &[u8],
    time: u32,
    commitment_suffix: &[u8],
    miner_bitcoin_address: Option<&Address>,
    miner_address: Option<WitnessProgram>,
) -> String {
    let digest = commitment_digest(
        commitment_prefix,
        time,
        commitment_suffix,
        miner_bitcoin_address,
        miner_address,
    );
    hex::encode(digest.as_byte_array())
}

/// Build a per-miner coinbase2 hex from the commitment hash, a fresh
/// timestamp, and the static middle and locktime.
fn build_per_miner_coinbase2(
    commitment_hash_hex: &str,
    nsecs: u64,
    coinbase2_middle: &str,
    coinbase2_locktime: &str,
) -> String {
    // nsecs push: 0x08 opcode + 8 bytes LE
    let nsecs_bytes = nsecs.to_le_bytes();
    let mut coinbase2 = String::with_capacity(
        NSECS_PUSH_HEX_LENGTH
            + coinbase2_middle.len()
            + COMMITMENT_HASH_HEX_LENGTH
            + coinbase2_locktime.len(),
    );
    coinbase2.push_str("08");
    coinbase2.push_str(&hex::encode(nsecs_bytes));
    coinbase2.push_str(coinbase2_middle);
    coinbase2.push_str(commitment_hash_hex);
    coinbase2.push_str(coinbase2_locktime);
    coinbase2
}

/// Build a per-miner notify message from the prepared template.
///
/// Computes the miner-specific commitment hash, assembles per-miner coinbase2,
/// overwrites placeholders in the pre-built JSON, and inserts the job into the tracker.
/// When either address is None (solo or Hydrapool mode), a commitment hash is
/// still computed from whatever is available, but no `ShareCommitment` is built:
/// a share needs both a bitcoin payout identity and a share chain owner.
pub(crate) fn build_notify_from_prepared(
    prepared: &PreparedNotifyParams,
    miner_bitcoin_address: Option<&Address>,
    miner_address: Option<&P2PoolAddress>,
    tracker_handle: &JobTracker,
) -> Result<String, WorkError> {
    let fresh_time = SystemTimeProvider.seconds_since_epoch() as u32;

    let nsecs = get_timestamp_bytes(&SystemTimeProvider);

    // Build ShareCommitment only when both addresses are available: the share
    // chain coinbase needs an owner and the bitcoin coinbase needs a payee.
    let share_commitment = match (miner_bitcoin_address, miner_address) {
        (Some(bitcoin_address), Some(share_address)) => Some(ShareCommitment {
            prev_share_blockhash: prepared.prev_share_blockhash,
            uncles: prepared.uncles.clone(),
            miner_bitcoin_address: bitcoin_address.clone(),
            miner_address: share_address.witness_program(),
            share_witness_root: compute_witness_root(&[]),
            bits: prepared.bits,
            time: fresh_time,
            donation_address: prepared.donation_address.clone(),
            donation: prepared.donation,
            fee_address: prepared.fee_address.clone(),
            fee: prepared.fee,
            coinbase_value: prepared.template.coinbasevalue,
        }),
        _ => None,
    };

    // The hash the miner embeds in its bitcoin coinbase must be the hash of the
    // commitment we store, so derive one from the other rather than building
    // the same digest twice.
    let commitment_hash_hex = get_commitment_hex(
        &prepared.commitment_prefix,
        fresh_time,
        &prepared.commitment_suffix,
        miner_bitcoin_address,
        miner_address.map(|address| address.witness_program()),
    );

    // Build per-miner coinbase2
    let coinbase2 = build_per_miner_coinbase2(
        &commitment_hash_hex,
        nsecs,
        &prepared.coinbase2_middle,
        &prepared.coinbase2_locktime,
    );

    // Get next job_id
    let job_id = tracker_handle.get_next_job_id();
    let job_id_hex = format!("{job_id:016x}");

    // Clone the JSON template and overwrite the fixed-size placeholders.
    let mut notify_json = prepared.json_template.clone();
    notify_json.replace_range(
        prepared.job_id_offset..prepared.job_id_offset + 16,
        &job_id_hex,
    );
    notify_json.replace_range(
        prepared.coinbase2_offset..prepared.coinbase2_offset + prepared.coinbase2_placeholder_len,
        &coinbase2,
    );

    // Insert job into tracker
    tracker_handle.insert_job(
        Arc::clone(&prepared.template),
        prepared.coinbase1.clone(),
        coinbase2,
        share_commitment,
        nsecs,
        prepared.merkle_branches.clone(),
        job_id,
    );

    Ok(notify_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::stratum::work::tracker::{JobId, start_tracker_actor};
    use crate::test_utils::make_test_share_address;
    use crate::test_utils::make_test_share_program;
    use bitcoin::{CompressedPublicKey, Network};

    fn test_template() -> BlockTemplate {
        let data = include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        );
        serde_json::from_str(data).expect("Failed to parse BlockTemplate")
    }

    fn test_address() -> Address {
        let miner_pubkey: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        Address::p2wpkh(&miner_pubkey, Network::Signet)
    }

    fn test_output_distribution(template: &BlockTemplate) -> Vec<OutputPair> {
        vec![OutputPair {
            address: test_address(),
            amount: bitcoin::Amount::from_sat(template.coinbasevalue),
        }]
    }

    fn test_notify_params_builder(
        template: Arc<BlockTemplate>,
        clean_jobs: bool,
    ) -> PreparedNotifyParamsBuilder {
        let output_distribution = test_output_distribution(&template);
        PreparedNotifyParamsBuilder::new(template, output_distribution, b"test_pool", clean_jobs)
            .bits(CompactTarget::from_consensus(0x1d00ffff))
    }

    #[test]
    fn test_prepare_notify_params_produces_valid_json() {
        let template = Arc::new(test_template());
        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        // Verify the JSON is parseable
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared.json_template).expect("JSON should be valid");
        assert_eq!(parsed["method"], "mining.notify");
        let params = parsed["params"].as_array().expect("params should be array");
        assert_eq!(params.len(), 9);

        // Verify offsets are within bounds
        assert!(prepared.job_id_offset + 16 <= prepared.json_template.len());
        assert!(
            prepared.coinbase2_offset + prepared.coinbase2_placeholder_len
                <= prepared.json_template.len()
        );
    }

    #[tokio::test]
    async fn test_build_notify_from_prepared_produces_valid_notify() {
        let template = Arc::new(test_template());
        let address = test_address();
        let tracker_handle = start_tracker_actor();

        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let notify_json = build_notify_from_prepared(
            &prepared,
            Some(&address),
            Some(&make_test_share_address(1, bitcoin::Network::Signet)),
            &tracker_handle,
        )
        .expect("build_notify_from_prepared should succeed");

        // Verify the result is valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&notify_json).expect("notify JSON should be valid");
        assert_eq!(parsed["method"], "mining.notify");

        // Verify job_id was filled in (not zeros)
        let params = parsed["params"].as_array().unwrap();
        let job_id_str = params[0].as_str().unwrap();
        assert_ne!(job_id_str, "0000000000000000");

        // Verify job was inserted in tracker by parsing the job_id from JSON
        let job_id = JobId(u64::from_str_radix(job_id_str, 16).unwrap());
        let job_details = tracker_handle.get_job(job_id);
        assert!(job_details.is_some());

        // Verify commitment was stored with correct miner address
        let details = job_details.unwrap();
        let commitment = details.share_commitment.as_ref().unwrap();
        assert_eq!(commitment.miner_bitcoin_address, address);
        assert_eq!(commitment.prev_share_blockhash, BlockHash::all_zeros());

        // Verify merkle branches were stored in job details (1 branch for 1-txn template)
        assert_eq!(
            details.template_merkle_branches.len(),
            1,
            "Expected 1 merkle branch for 1-txn template"
        );
    }

    #[tokio::test]
    async fn test_commitment_hash_matches_struct_hash() {
        let template = Arc::new(test_template());
        let address = test_address();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let tracker_handle = start_tracker_actor();
        let coinbase_value = template.coinbasevalue;

        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let notify_json = build_notify_from_prepared(
            &prepared,
            Some(&address),
            Some(&make_test_share_address(1, bitcoin::Network::Signet)),
            &tracker_handle,
        )
        .expect("build_notify_from_prepared should succeed");

        // Parse job_id from JSON to look up the tracker entry
        let parsed: serde_json::Value = serde_json::from_str(&notify_json).unwrap();
        let job_id_str = parsed["params"][0].as_str().unwrap();
        let job_id = JobId(u64::from_str_radix(job_id_str, 16).unwrap());
        let details = tracker_handle.get_job(job_id).unwrap();
        let commitment = details.share_commitment.as_ref().unwrap();

        // Build the same commitment directly using the fresh time that
        // build_notify_from_prepared stored in the tracker.
        let direct_commitment = ShareCommitment {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: Vec::new(),
            miner_bitcoin_address: address,
            miner_address: make_test_share_program(1),
            share_witness_root: compute_witness_root(&[]),
            bits,
            time: commitment.time,
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            coinbase_value,
        };

        assert_eq!(commitment.hash(), direct_commitment.hash());
    }

    #[test]
    fn test_different_addresses_produce_different_hashes() {
        let template = Arc::new(test_template());
        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let address1 = test_address();
        let other_pubkey: CompressedPublicKey =
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
                .parse()
                .unwrap();
        let address2 = Address::p2wpkh(&other_pubkey, Network::Signet);
        let share_address = make_test_share_program(1);

        let time = 1_700_000_000;
        let hash1 = get_commitment_hex(
            &prepared.commitment_prefix,
            time,
            &prepared.commitment_suffix,
            Some(&address1),
            Some(share_address),
        );
        let hash2 = get_commitment_hex(
            &prepared.commitment_prefix,
            time,
            &prepared.commitment_suffix,
            Some(&address2),
            Some(share_address),
        );

        assert_ne!(
            hash1, hash2,
            "the bitcoin address must reach the commitment hash"
        );
    }

    /// Mirror of `test_different_addresses_produce_different_hashes`: hold the
    /// bitcoin address fixed and vary the share address instead.
    ///
    /// Both assert on the commitment hash rather than the notify JSON, because
    /// the JSON carries a fresh job id and timestamp per call and so always
    /// differs -- which would make either test pass even if the address were
    /// ignored entirely.
    /// The two callers of `commitment_digest` must agree: the notify path uses
    /// a prefix and suffix pre-built per template, while `ShareCommitment::hash`
    /// serializes its own fields per share. A miner mines the first and every
    /// validator reconstructs the second, so a divergence means no share is
    /// ever accepted.
    #[test]
    fn notify_hash_matches_share_commitment_hash() {
        let template = Arc::new(test_template());
        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let bitcoin_address = test_address();
        let share_address = make_test_share_program(1);
        let share_witness_root = compute_witness_root(&[]);
        let time = 1_700_000_000;

        let from_notify = get_commitment_hex(
            &prepared.commitment_prefix,
            time,
            &prepared.commitment_suffix,
            Some(&bitcoin_address),
            Some(share_address),
        );

        let commitment = ShareCommitment {
            prev_share_blockhash: prepared.prev_share_blockhash,
            uncles: prepared.uncles.clone(),
            miner_bitcoin_address: bitcoin_address,
            miner_address: share_address,
            share_witness_root,
            bits: prepared.bits,
            time,
            donation_address: prepared.donation_address.clone(),
            donation: prepared.donation,
            fee_address: prepared.fee_address.clone(),
            fee: prepared.fee,
            coinbase_value: prepared.template.coinbasevalue,
        };
        let from_struct = hex::encode(commitment.hash().as_byte_array());

        assert_eq!(from_notify, from_struct);
    }

    #[test]
    fn test_different_share_addresses_produce_different_hashes() {
        let template = Arc::new(test_template());
        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let bitcoin_address = test_address();
        let share_address1 = make_test_share_program(1);
        let share_address2 = make_test_share_program(2);
        assert_ne!(share_address1, share_address2);

        let time = 1_700_000_000;
        let hash1 = get_commitment_hex(
            &prepared.commitment_prefix,
            time,
            &prepared.commitment_suffix,
            Some(&bitcoin_address),
            Some(share_address1),
        );
        let hash2 = get_commitment_hex(
            &prepared.commitment_prefix,
            time,
            &prepared.commitment_suffix,
            Some(&bitcoin_address),
            Some(share_address2),
        );

        assert_ne!(
            hash1, hash2,
            "the share address must reach the commitment hash"
        );
    }

    #[test]
    fn test_placeholder_offsets_produce_correct_overwrite() {
        let template = Arc::new(test_template());
        let prepared = test_notify_params_builder(template, true)
            .build()
            .expect("build should succeed");

        // Manually overwrite placeholders and verify JSON remains valid
        let mut json = prepared.json_template.clone();
        let test_job_id = "abcdef0123456789";
        // Build a test coinbase2 of the correct length
        let test_coinbase2 = "f".repeat(prepared.coinbase2_placeholder_len);
        json.replace_range(
            prepared.job_id_offset..prepared.job_id_offset + 16,
            test_job_id,
        );
        json.replace_range(
            prepared.coinbase2_offset
                ..prepared.coinbase2_offset + prepared.coinbase2_placeholder_len,
            &test_coinbase2,
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("Overwritten JSON should still be valid");
        let params = parsed["params"].as_array().unwrap();
        assert_eq!(params[0].as_str().unwrap(), test_job_id);
        // coinbase2 should be the test value
        let coinbase2 = params[3].as_str().unwrap();
        assert_eq!(coinbase2, test_coinbase2);
        // clean_jobs should be true
        assert!(params[8].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_build_notify_from_prepared_with_none_address() {
        let template = Arc::new(test_template());
        let tracker_handle = start_tracker_actor();

        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let notify_json = build_notify_from_prepared(&prepared, None, None, &tracker_handle)
            .expect("build_notify_from_prepared with None address should succeed");

        // Verify the result is valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&notify_json).expect("notify JSON should be valid");
        assert_eq!(parsed["method"], "mining.notify");

        // Verify job_id was filled in (not zeros)
        let params = parsed["params"].as_array().unwrap();
        let job_id_str = params[0].as_str().unwrap();
        assert_ne!(job_id_str, "0000000000000000");

        // Verify nsecs and the commitment output were placed in coinbase2.
        // Format: "08" + 16 hex nsecs + middle + "6a20" + 64 hex hash + 8 hex locktime
        let coinbase2 = params[3].as_str().unwrap();
        assert!(
            coinbase2.starts_with("08"),
            "coinbase2 should start with the nsecs push opcode"
        );
        let commitment_script_start = coinbase2.len() - 8 - 64 - 4;
        assert_eq!(
            &coinbase2[commitment_script_start..commitment_script_start + 4],
            "6a20",
            "coinbase2 should end with the OP_RETURN commitment output and locktime"
        );

        // Verify job was inserted in tracker with no share_commitment
        let job_id = JobId(u64::from_str_radix(job_id_str, 16).unwrap());
        let details = tracker_handle
            .get_job(job_id)
            .expect("Job should be in tracker");
        assert!(
            details.share_commitment.is_none(),
            "share_commitment should be None for solo mode"
        );
    }

    #[test]
    fn test_split_coinbase2_separates_middle_and_locktime() {
        let dummy_commitment_hash = hashes::sha256::Hash::from_byte_array([0xab_u8; 32]);
        let coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: test_address(),
                amount: bitcoin::Amount::from_sat(5_000_000_000),
            }],
            100,
            bitcoin::script::PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(dummy_commitment_hash),
            0,
            None,
        )
        .unwrap();
        let (_coinbase1, coinbase2) = split_coinbase(&coinbase).unwrap();
        let dummy_commitment_hex = hex::encode(dummy_commitment_hash.as_byte_array());

        let (middle, locktime) = split_coinbase2(&coinbase2, &dummy_commitment_hex).unwrap();

        assert_eq!(
            format!(
                "{}{middle}{dummy_commitment_hex}{locktime}",
                &coinbase2[..18]
            ),
            coinbase2
        );
        assert_eq!(locktime, hex::encode(99u32.to_le_bytes()));
        assert!(middle.ends_with("6a20"));
    }

    /// A coinbase without the commitment output cannot carry a per-miner
    /// commitment, so the split refuses it rather than slicing payout bytes.
    #[test]
    fn test_split_coinbase2_rejects_coinbase_without_commitment_output() {
        let coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: test_address(),
                amount: bitcoin::Amount::from_sat(5_000_000_000),
            }],
            100,
            bitcoin::script::PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            None,
            0,
            None,
        )
        .unwrap();
        let (_coinbase1, coinbase2) = split_coinbase(&coinbase).unwrap();

        let result = split_coinbase2(&coinbase2, &hex::encode([0xab_u8; 32]));

        assert!(result.is_err());
    }

    #[test]
    fn test_split_coinbase2_rejects_short_coinbase2() {
        let result = split_coinbase2("08", &hex::encode([0xab_u8; 32]));
        assert!(result.unwrap_err().message.contains("too short"));
    }
}
