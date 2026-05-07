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

use super::block_template::{BlockTemplate, parse_flags};
use super::coinbase::{build_bitcoin_coinbase_transaction, get_timestamp_bytes, split_coinbase};
use super::error::WorkError;
use super::gbt::build_merkle_branches_for_template;
use super::tracker::JobTracker;
use crate::accounting::OutputPair;
use crate::shares::share_commitment::ShareCommitment;
use crate::shares::witness_commitment::WitnessCommitment;
use crate::stratum::util::{reverse_four_byte_chunks, to_be_hex};
use crate::utils::time_provider::SystemTimeProvider;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{self, Hash};
use bitcoin::transaction::Version;
use bitcoin::{Address, BlockHash, CompactTarget};
use std::sync::Arc;

/// Pre-serialized notify message with placeholders for per-miner fields.
///
/// coinbase1 is static (same for all miners): [height][aux_flags][EXTRANONCE_SEPARATOR]
/// coinbase2 is built per-miner: [commitment_hash][nsecs][pool_sig][sequence][outputs][locktime]
///
/// The JSON template has fixed-size placeholders for job_id and the full coinbase2.
/// Also contains pre-serialized commitment binary prefix -- all fields except
/// miner_bitcoin_address -- so that per-miner hashing only needs to append the
/// address bytes.
pub struct PreparedNotifyParams {
    /// Pre-serialized JSON notify string with placeholder job_id and coinbase2
    json_template: String,
    /// Byte offset of the 16-char job_id placeholder in json_template
    job_id_offset: usize,
    /// Byte offset of the coinbase2 placeholder in json_template
    coinbase2_offset: usize,
    /// Length of the coinbase2 placeholder in json_template
    coinbase2_placeholder_len: usize,
    /// Pre-serialized commitment binary: all fields except miner_bitcoin_address.
    /// Miner address is appended per-miner to compute the commitment hash.
    commitment_prefix: Vec<u8>,
    /// Previous share block hash (for building ShareCommitment struct)
    prev_share_blockhash: BlockHash,
    /// Uncle block hashes (for building ShareCommitment struct)
    uncles: Vec<BlockHash>,
    /// Share chain difficulty target (for building ShareCommitment struct)
    bits: CompactTarget,
    /// Commitment timestamp (for building ShareCommitment struct)
    time: u32,
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
    /// Coinbase2 suffix hex: [pool_sig][sequence][outputs][locktime]
    /// Per-miner coinbase2 = commitment_hash_script + nsecs_script + coinbase2_suffix
    coinbase2_suffix: String,
    /// Merkle branches for the template transactions (excluding coinbase).
    /// Passed through to JobDetails so validators can verify the bitcoin merkle root.
    merkle_branches: Vec<bitcoin::TxMerkleNode>,
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
    time: u32,
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
            time: 0,
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

    pub fn time(mut self, time: u32) -> Self {
        self.time = time;
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
    /// Build the PreparedNotifyParams by constructing the coinbase transaction,
    /// splitting it, and constructing the pre-serialized JSON template.
    ///
    /// coinbase1 is static (same for all miners). coinbase2 is split into a
    /// per-miner prefix (commitment_hash + nsecs) and a static suffix.
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
        // After split_coinbase, coinbase1 is fully static and coinbase2 starts
        // with [commitment_hash_push][nsecs_push][pool_sig_push]...
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

        // Strip the commitment_hash push (33 bytes = 66 hex) and nsecs push
        // (9 bytes = 18 hex) from the front of coinbase2 to get the static suffix.
        let per_miner_prefix_hex_len = 66 + 18;
        let coinbase2_suffix = coinbase2_full[per_miner_prefix_hex_len..].to_string();

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

        // Pre-serialize commitment prefix for fast per-miner hashing.
        // ShareCommitment::consensus_encode encodes all fields except
        // miner_bitcoin_address, which is exactly the shared prefix we need.
        let commitment_without_address = ShareCommitment {
            prev_share_blockhash: self.prev_share_blockhash,
            uncles: self.uncles.clone(),
            miner_bitcoin_address: self.output_distribution[0].address.clone(),
            bits: self.bits,
            time: self.time,
            donation_address: self.donation_address.clone(),
            donation: self.donation,
            fee_address: self.fee_address.clone(),
            fee: self.fee,
            coinbase_value: self.template.coinbasevalue,
        };
        let mut commitment_prefix = Vec::with_capacity(128);
        commitment_without_address
            .consensus_encode(&mut commitment_prefix)
            .expect("encoding commitment prefix should never fail");

        Ok(PreparedNotifyParams {
            json_template,
            job_id_offset,
            coinbase2_offset,
            coinbase2_placeholder_len,
            commitment_prefix,
            prev_share_blockhash: self.prev_share_blockhash,
            uncles: self.uncles,
            bits: self.bits,
            time: self.time,
            donation_address: self.donation_address,
            donation: self.donation,
            fee_address: self.fee_address,
            fee: self.fee,
            template: self.template,
            coinbase1,
            coinbase2_suffix,
            merkle_branches: merkle_branches_raw
                .into_iter()
                .map(bitcoin::TxMerkleNode::from_raw_hash)
                .collect(),
        })
    }
}

/// Compute the hex-encoded commitment hash for a miner address.
///
/// When an address is provided, appends its script pubkey to the
/// pre-built commitment prefix. When None (solo mode), hashes the
/// prefix with empty pubkey bytes.
fn get_commitment_hex(
    commitment_prefix: &[u8],
    miner_address: Option<&Address>,
) -> Result<String, WorkError> {
    let mut commitment_binary = Vec::with_capacity(commitment_prefix.len() + 64);
    commitment_binary.extend_from_slice(commitment_prefix);

    if let Some(address) = miner_address {
        address
            .script_pubkey()
            .consensus_encode(&mut commitment_binary)
            .map_err(|error| WorkError {
                message: format!("Failed to encode miner address script_pubkey: {error}"),
            })?;
    }

    let commitment_hash = hashes::sha256::Hash::hash(&commitment_binary);
    Ok(hex::encode(commitment_hash.as_byte_array()))
}

/// Build a per-miner coinbase2 hex from commitment hash, fresh timestamp,
/// and the static suffix.
fn build_per_miner_coinbase2(
    commitment_hash_hex: &str,
    nsecs: u64,
    coinbase2_suffix: &str,
) -> String {
    // commitment_hash push: 0x20 opcode + 32 bytes hash = 66 hex chars
    // nsecs push: 0x08 opcode + 8 bytes LE = 18 hex chars
    let nsecs_bytes = nsecs.to_le_bytes();
    let mut coinbase2 = String::with_capacity(66 + 18 + coinbase2_suffix.len());
    coinbase2.push_str("20");
    coinbase2.push_str(commitment_hash_hex);
    coinbase2.push_str("08");
    coinbase2.push_str(&hex::encode(nsecs_bytes));
    coinbase2.push_str(coinbase2_suffix);
    coinbase2
}

/// Build a per-miner notify message from the prepared template.
///
/// Computes the miner-specific commitment hash, assembles per-miner coinbase2,
/// overwrites placeholders in the pre-built JSON, and inserts the job into the tracker.
/// When miner_address is None (solo mode), a commitment hash is still
/// computed from the prefix alone.
pub(crate) fn build_notify_from_prepared(
    prepared: &PreparedNotifyParams,
    miner_address: Option<&Address>,
    tracker_handle: &JobTracker,
) -> Result<String, WorkError> {
    let commitment_hash_hex = get_commitment_hex(&prepared.commitment_prefix, miner_address)?;
    let nsecs = get_timestamp_bytes(&SystemTimeProvider);

    // Build per-miner coinbase2
    let coinbase2 =
        build_per_miner_coinbase2(&commitment_hash_hex, nsecs, &prepared.coinbase2_suffix);

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

    // Build ShareCommitment only when a miner address is available
    let share_commitment = miner_address.map(|address| ShareCommitment {
        prev_share_blockhash: prepared.prev_share_blockhash,
        uncles: prepared.uncles.clone(),
        miner_bitcoin_address: address.clone(),
        bits: prepared.bits,
        time: prepared.time,
        donation_address: prepared.donation_address.clone(),
        donation: prepared.donation,
        fee_address: prepared.fee_address.clone(),
        fee: prepared.fee,
        coinbase_value: prepared.template.coinbasevalue,
    });

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
            .time(1700000000u32)
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

        let notify_json = build_notify_from_prepared(&prepared, Some(&address), &tracker_handle)
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
        let time = 1700000000u32;
        let tracker_handle = start_tracker_actor();
        let coinbase_value = template.coinbasevalue;

        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let notify_json = build_notify_from_prepared(&prepared, Some(&address), &tracker_handle)
            .expect("build_notify_from_prepared should succeed");

        // Parse job_id from JSON to look up the tracker entry
        let parsed: serde_json::Value = serde_json::from_str(&notify_json).unwrap();
        let job_id_str = parsed["params"][0].as_str().unwrap();
        let job_id = JobId(u64::from_str_radix(job_id_str, 16).unwrap());
        let details = tracker_handle.get_job(job_id).unwrap();
        let commitment = details.share_commitment.as_ref().unwrap();

        // Build the same commitment directly and compare hashes
        let direct_commitment = ShareCommitment {
            prev_share_blockhash: BlockHash::all_zeros(),
            uncles: Vec::new(),
            miner_bitcoin_address: address,
            bits,
            time,
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            coinbase_value,
        };

        assert_eq!(commitment.hash(), direct_commitment.hash());
    }

    #[tokio::test]
    async fn test_different_addresses_produce_different_hashes() {
        let template = Arc::new(test_template());
        let tracker_handle = start_tracker_actor();

        let prepared = test_notify_params_builder(template, false)
            .build()
            .expect("build should succeed");

        let address1 = test_address();
        let other_pubkey: CompressedPublicKey =
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
                .parse()
                .unwrap();
        let address2 = Address::p2wpkh(&other_pubkey, Network::Signet);

        let notify1 =
            build_notify_from_prepared(&prepared, Some(&address1), &tracker_handle).unwrap();
        let notify2 =
            build_notify_from_prepared(&prepared, Some(&address2), &tracker_handle).unwrap();

        // Different addresses must produce different notify JSON (different coinbase2 content)
        assert_ne!(notify1, notify2);
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

        let notify_json = build_notify_from_prepared(&prepared, None, &tracker_handle)
            .expect("build_notify_from_prepared with None address should succeed");

        // Verify the result is valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&notify_json).expect("notify JSON should be valid");
        assert_eq!(parsed["method"], "mining.notify");

        // Verify job_id was filled in (not zeros)
        let params = parsed["params"].as_array().unwrap();
        let job_id_str = params[0].as_str().unwrap();
        assert_ne!(job_id_str, "0000000000000000");

        // Verify commitment hash was computed and placed in coinbase2.
        // The per-miner coinbase2 starts with [commitment_hash_push][nsecs_push]...
        let coinbase2 = params[3].as_str().unwrap();
        let expected_hash = get_commitment_hex(&prepared.commitment_prefix, None).unwrap();
        assert!(
            coinbase2.contains(&expected_hash),
            "coinbase2 should contain the commitment hash for None address"
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
}
