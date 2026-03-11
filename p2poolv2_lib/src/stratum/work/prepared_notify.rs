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

use super::block_template::BlockTemplate;
use super::coinbase::{build_coinbase_transaction, split_coinbase};
use super::error::WorkError;
use super::gbt::build_merkle_branches_for_template;
use super::tracker::JobTracker;
use crate::accounting::OutputPair;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::util::{reverse_four_byte_chunks, to_be_hex};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::{self, Hash};
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use bitcoin::{Address, BlockHash, CompactTarget, TxMerkleNode};
use std::sync::Arc;

/// Pre-serialized notify message with placeholders for per-miner fields.
///
/// Contains the fully built JSON notify string with fixed-size placeholders
/// for job_id (16 hex chars) and commitment_hash (64 hex chars in coinbase1).
/// Also contains pre-serialized commitment binary prefix -- all fields except
/// miner_address -- so that per-miner hashing only needs to append the
/// address bytes.
pub struct PreparedNotifyParams {
    /// Pre-serialized JSON notify string with placeholder job_id and commitment hash
    json_template: String,
    /// Byte offset of the 16-char job_id placeholder in json_template
    job_id_offset: usize,
    /// Byte offset of the 64-char commitment hash placeholder in json_template
    commitment_hash_offset: usize,
    /// Pre-serialized commitment binary: all fields except miner_address.
    /// Miner address is appended per-miner to compute the commitment hash.
    commitment_prefix: Vec<u8>,
    /// Previous share block hash (for building ShareCommitment struct)
    prev_share_blockhash: BlockHash,
    /// Uncle block hashes (for building ShareCommitment struct)
    uncles: Vec<BlockHash>,
    /// Transaction merkle root (for building ShareCommitment struct)
    merkle_root: Option<TxMerkleNode>,
    /// Share chain difficulty target (for building ShareCommitment struct)
    bits: CompactTarget,
    /// Commitment timestamp (for building ShareCommitment struct)
    time: u32,
    /// Shared block template
    template: Arc<BlockTemplate>,
    /// Coinbase1 hex before the commitment hash
    coinbase1_before_hash: String,
    /// Coinbase1 hex after the commitment hash
    coinbase1_after_hash: String,
    /// Coinbase2 hex (identical for all miners)
    coinbase2: String,
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
/// Returns the JSON string and the byte offsets of the job_id and
/// commitment_hash placeholders.
fn build_json_template(
    coinbase1_before_hash: &str,
    coinbase1_after_hash: &str,
    coinbase2: &str,
    prevhash_byte_swapped: &str,
    merkle_branches: &[String],
    version_hex: &str,
    nbits: &str,
    ntime_hex: &str,
    clean_jobs: bool,
) -> (String, usize, usize) {
    // Estimate capacity: typical notify JSON is 500-1500 bytes
    let estimated_capacity = 256
        + coinbase1_before_hash.len()
        + coinbase1_after_hash.len()
        + coinbase2.len()
        + merkle_branches.len() * 68;
    let mut json = String::with_capacity(estimated_capacity);

    json.push_str(r#"{"method":"mining.notify","params":[""#);
    let job_id_offset = json.len();
    json.push_str("0000000000000000"); // 16-char placeholder for job_id
    json.push_str(r#"",""#);
    json.push_str(prevhash_byte_swapped);
    json.push_str(r#"",""#);
    json.push_str(coinbase1_before_hash);
    let commitment_hash_offset = json.len();
    // 64-char placeholder for commitment hash (32 bytes hex-encoded)
    json.push_str("0000000000000000000000000000000000000000000000000000000000000000");
    json.push_str(coinbase1_after_hash);
    json.push_str(r#"",""#);
    json.push_str(coinbase2);
    json.push_str(r#"","#);
    json.push_str(&serialize_merkle_branches_json(merkle_branches));
    json.push_str(r#","#);
    json.push_str(r#"""#);
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

    (json, job_id_offset, commitment_hash_offset)
}

/// Prepare a notify template with pre-computed shared fields.
///
/// By serializing notify params once, we avoid needing to serialize
/// for each stratum client. Instead, we pick up the prepared notify
/// params and use the miner address to build share commitment, thus
/// the coinbase1 for each individual client.
///
/// Builds the coinbase transaction with a dummy commitment hash,
/// splits it, and constructs the pre-serialized JSON.
///
/// The commitment prefix and suffix are pre-encoded for fast
/// per-miner hash computation.
pub(crate) fn prepare_notify_params(
    template: &Arc<BlockTemplate>,
    output_distribution: Vec<OutputPair>,
    pool_signature: &[u8],
    prev_share_blockhash: BlockHash,
    uncles: Vec<BlockHash>,
    merkle_root: Option<TxMerkleNode>,
    bits: CompactTarget,
    time: u32,
    clean_jobs: bool,
) -> Result<PreparedNotifyParams, WorkError> {
    // Build a coinbase with a distinctive dummy commitment hash to locate
    // where the hash appears in the hex-encoded coinbase1 string.
    // We use 0xab repeated 32 times -- hex "abab...ab" (64 chars) --
    // which cannot appear naturally in hex-encoded transaction data.
    let dummy_hash_bytes = [0xab_u8; 32];
    let dummy_commitment_hash = hashes::sha256::Hash::from_byte_array(dummy_hash_bytes);
    let dummy_hash_hex = hex::encode(dummy_hash_bytes);

    let coinbase = build_coinbase_transaction(
        Version::TWO,
        output_distribution.as_slice(),
        template.height as i64,
        parse_flags(template.coinbaseaux.get("flags").cloned()),
        template.default_witness_commitment.clone(),
        pool_signature,
        Some(dummy_commitment_hash),
    )?;

    let (coinbase1_full, coinbase2) = split_coinbase(&coinbase)?;

    // Simple string search for the dummy hash in the hex-encoded coinbase1
    let commitment_hash_position =
        coinbase1_full
            .find(&dummy_hash_hex)
            .ok_or_else(|| WorkError {
                message: "Could not locate commitment hash placeholder in coinbase1".to_string(),
            })?;

    let coinbase1_before_hash = coinbase1_full[..commitment_hash_position].to_string();
    let coinbase1_after_hash = coinbase1_full[commitment_hash_position + 64..].to_string();

    // Pre-compute merkle branches
    let merkle_branches: Vec<String> = build_merkle_branches_for_template(template)
        .iter()
        .map(|branch| to_be_hex(&branch.to_string()))
        .collect();

    let prevhash_byte_swapped =
        reverse_four_byte_chunks(&template.previousblockhash).map_err(|error| WorkError {
            message: format!("Failed to reverse previous block hash: {error}"),
        })?;

    let version_hex = hex::encode(template.version.to_be_bytes());
    let ntime_hex = hex::encode(template.curtime.to_be_bytes());

    // Build the JSON template by concatenation
    let (json_template, job_id_offset, commitment_hash_offset) = build_json_template(
        &coinbase1_before_hash,
        &coinbase1_after_hash,
        &coinbase2,
        &prevhash_byte_swapped,
        &merkle_branches,
        &version_hex,
        &template.bits,
        &ntime_hex,
        clean_jobs,
    );

    // Pre-serialize commitment prefix for fast per-miner hashing.
    // ShareCommitment::consensus_encode encodes all fields except miner_address,
    // which is exactly the shared prefix we need. We build a dummy commitment
    // (address is ignored by consensus_encode) to get the prefix bytes.
    let commitment_without_address = ShareCommitment {
        prev_share_blockhash,
        uncles: uncles.clone(),
        miner_address: output_distribution[0].address.clone(),
        merkle_root,
        bits,
        time,
    };
    let mut commitment_prefix = Vec::with_capacity(128);
    commitment_without_address
        .consensus_encode(&mut commitment_prefix)
        .expect("encoding commitment prefix should never fail");

    Ok(PreparedNotifyParams {
        json_template,
        job_id_offset,
        commitment_hash_offset,
        commitment_prefix,
        prev_share_blockhash,
        uncles,
        merkle_root,
        bits,
        time,
        template: Arc::clone(template),
        coinbase1_before_hash,
        coinbase1_after_hash,
        coinbase2,
    })
}

/// Compute the hex-encoded commitment hash for a miner address.
///
/// When an address is provided, appends its consensus-encoded form to the
/// pre-built commitment prefix. When None (solo mode), hashes the prefix
/// with empty address bytes.
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

/// Build a per-miner notify message from the prepared template.
///
/// Computes the miner-specific commitment hash, overwrites the placeholders
/// in the pre-built JSON, and inserts the job into the tracker.
/// When miner_address is None (solo mode), a commitment hash is still
/// computed from the prefix alone.
pub(crate) fn build_notify_from_prepared(
    prepared: &PreparedNotifyParams,
    miner_address: Option<&Address>,
    tracker_handle: &JobTracker,
) -> Result<String, WorkError> {
    let commitment_hash_hex = get_commitment_hex(&prepared.commitment_prefix, miner_address)?;

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
        prepared.commitment_hash_offset..prepared.commitment_hash_offset + 64,
        &commitment_hash_hex,
    );

    // Build coinbase1 with the actual commitment hash
    let coinbase1 = format!(
        "{}{}{}",
        prepared.coinbase1_before_hash, commitment_hash_hex, prepared.coinbase1_after_hash
    );

    // Build ShareCommitment only when a miner address is available
    let share_commitment = miner_address.map(|address| ShareCommitment {
        prev_share_blockhash: prepared.prev_share_blockhash,
        uncles: prepared.uncles.clone(),
        miner_address: address.clone(),
        merkle_root: prepared.merkle_root,
        bits: prepared.bits,
        time: prepared.time,
    });

    // Insert job into tracker
    tracker_handle.insert_job(
        Arc::clone(&prepared.template),
        coinbase1,
        prepared.coinbase2.clone(),
        share_commitment,
        job_id,
    );

    Ok(notify_json)
}

/// Extract flags from template coinbaseaux and convert to PushBytesBuf.
/// If flags are empty, use a single byte with value 0.
fn parse_flags(flags: Option<String>) -> PushBytesBuf {
    match flags {
        Some(flags) if flags.is_empty() => PushBytesBuf::from(&[0u8]),
        Some(flags) => PushBytesBuf::try_from(hex::decode(flags).unwrap()).unwrap(),
        None => PushBytesBuf::from(&[0u8]),
    }
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

    #[test]
    fn test_prepare_notify_params_produces_valid_json() {
        let template = Arc::new(test_template());
        let output_distribution = test_output_distribution(&template);
        let prev_share_blockhash = BlockHash::all_zeros();
        let uncles = Vec::new();
        let merkle_root = template.get_merkle_root_without_coinbase();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let time = 1700000000u32;

        let prepared = prepare_notify_params(
            &template,
            output_distribution,
            b"test_pool",
            prev_share_blockhash,
            uncles,
            merkle_root,
            bits,
            time,
            false,
        )
        .expect("prepare_notify_params should succeed");

        // Verify the JSON is parseable
        let parsed: serde_json::Value =
            serde_json::from_str(&prepared.json_template).expect("JSON should be valid");
        assert_eq!(parsed["method"], "mining.notify");
        let params = parsed["params"].as_array().expect("params should be array");
        assert_eq!(params.len(), 9);

        // Verify offsets are within bounds
        assert!(prepared.job_id_offset + 16 <= prepared.json_template.len());
        assert!(prepared.commitment_hash_offset + 64 <= prepared.json_template.len());
    }

    #[tokio::test]
    async fn test_build_notify_from_prepared_produces_valid_notify() {
        let template = Arc::new(test_template());
        let output_distribution = test_output_distribution(&template);
        let address = test_address();
        let prev_share_blockhash = BlockHash::all_zeros();
        let uncles = Vec::new();
        let merkle_root = template.get_merkle_root_without_coinbase();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let time = 1700000000u32;
        let tracker_handle = start_tracker_actor();

        let prepared = prepare_notify_params(
            &template,
            output_distribution,
            b"test_pool",
            prev_share_blockhash,
            uncles,
            merkle_root,
            bits,
            time,
            false,
        )
        .expect("prepare_notify_params should succeed");

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
        assert_eq!(commitment.miner_address, address);
        assert_eq!(commitment.prev_share_blockhash, BlockHash::all_zeros());
    }

    #[tokio::test]
    async fn test_commitment_hash_matches_struct_hash() {
        let template = Arc::new(test_template());
        let output_distribution = test_output_distribution(&template);
        let address = test_address();
        let prev_share_blockhash = BlockHash::all_zeros();
        let uncles = Vec::new();
        let merkle_root = template.get_merkle_root_without_coinbase();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let time = 1700000000u32;
        let tracker_handle = start_tracker_actor();

        let prepared = prepare_notify_params(
            &template,
            output_distribution,
            b"test_pool",
            prev_share_blockhash,
            uncles.clone(),
            merkle_root,
            bits,
            time,
            false,
        )
        .expect("prepare_notify_params should succeed");

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
            prev_share_blockhash,
            uncles,
            miner_address: address,
            merkle_root,
            bits,
            time,
        };

        assert_eq!(commitment.hash(), direct_commitment.hash());
    }

    #[tokio::test]
    async fn test_different_addresses_produce_different_hashes() {
        let template = Arc::new(test_template());
        let output_distribution = test_output_distribution(&template);
        let prev_share_blockhash = BlockHash::all_zeros();
        let uncles = Vec::new();
        let merkle_root = template.get_merkle_root_without_coinbase();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let time = 1700000000u32;
        let tracker_handle = start_tracker_actor();

        let prepared = prepare_notify_params(
            &template,
            output_distribution,
            b"test_pool",
            prev_share_blockhash,
            uncles,
            merkle_root,
            bits,
            time,
            false,
        )
        .expect("prepare_notify_params should succeed");

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

        // Different addresses must produce different notify JSON (different coinbase1 content)
        assert_ne!(notify1, notify2);
    }

    #[test]
    fn test_placeholder_offsets_produce_correct_overwrite() {
        let template = Arc::new(test_template());
        let output_distribution = test_output_distribution(&template);
        let prev_share_blockhash = BlockHash::all_zeros();
        let uncles = Vec::new();
        let merkle_root = template.get_merkle_root_without_coinbase();
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let time = 1700000000u32;

        let prepared = prepare_notify_params(
            &template,
            output_distribution,
            b"test_pool",
            prev_share_blockhash,
            uncles,
            merkle_root,
            bits,
            time,
            true,
        )
        .expect("prepare_notify_params should succeed");

        // Manually overwrite placeholders and verify JSON remains valid
        let mut json = prepared.json_template.clone();
        let test_job_id = "abcdef0123456789";
        let test_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        json.replace_range(
            prepared.job_id_offset..prepared.job_id_offset + 16,
            test_job_id,
        );
        json.replace_range(
            prepared.commitment_hash_offset..prepared.commitment_hash_offset + 64,
            test_hash,
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("Overwritten JSON should still be valid");
        let params = parsed["params"].as_array().unwrap();
        assert_eq!(params[0].as_str().unwrap(), test_job_id);
        // The commitment hash should appear within coinbase1
        let coinbase1 = params[2].as_str().unwrap();
        assert!(coinbase1.contains(test_hash));
        // clean_jobs should be true
        assert!(params[8].as_bool().unwrap());
    }
}
