// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::stratum::error::Error;
use crate::stratum::messages::SimpleRequest;
use crate::stratum::session::EXTRANONCE2_SIZE;
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use crate::stratum::work::tracker::JobDetails;
use bitcoin::blockdata::block::Header;
use hex::FromHex;
use std::str::FromStr;
use tracing::{debug, info};

/// Share validation result
///
/// Captures the header and coinbase, with a boolean to signal if block meets bitcoin difficulty
pub struct ValidationResult {
    /// The block header built from the share components
    pub header: Header,
    /// The coinbase transaction built from share components
    pub coinbase: bitcoin::Transaction,
    /// Does the block meet bitcoin difficulty
    pub meets_bitcoin_difficulty: bool,
}

/// Build coinbase from the submitted share and block template components.
pub fn build_coinbase_from_components(
    coinbase1: &str,
    enonce1: &str,
    enonce2: &str,
    coinbase2: &str,
) -> Result<bitcoin::Transaction, Error> {
    // Add detailed logging to debug the issue
    let complete_tx = format!("{coinbase1}{enonce1}{enonce2}{coinbase2}");

    let tx_bytes = Vec::from_hex(&complete_tx)
        .map_err(|_| Error::InvalidParams("Invalid coinbase hex".into()))?;
    bitcoin::consensus::deserialize(&tx_bytes)
        .map_err(|_e| Error::InvalidParams("Failed to decode coinbase transaction".into()))
}

/// Applies version mask received with submission, if the version_bits is compatible with version_mask from session
/// If params don't include version_bits, it returns the original header version
fn apply_version_mask(
    header_version: i32,
    version_mask: i32,
    params: &[Option<String>],
) -> Result<i32, Error> {
    if params.len() > 5 {
        let version_bits_hex = params[5]
            .as_ref()
            .ok_or_else(|| Error::InvalidParams("Missing version bits".into()))?;
        let bits = i32::from_be_bytes(
            hex::decode(version_bits_hex)
                .map_err(|_| Error::InvalidParams("Failed to decode version bits hex".into()))?
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidParams("Invalid version bits length".into()))?,
        );
        Ok((header_version & !version_mask) | (bits & version_mask))
    } else {
        Ok(header_version)
    }
}

/// Validate the difficulty of a submitted share against the block template
///
/// We build the block header from received submission and the corresponding block template.
/// Then we check if the header's difficulty meets the target specified in the block template.
///
/// Returns ValidationResult if validation was error free, else the error.
pub fn validate_bitcoin_difficulty(
    job: &JobDetails,
    submission: &SimpleRequest<'_>,
    enonce1_hex: &str,
    version_mask: i32,
) -> Result<ValidationResult, Error> {
    let compact_target = bitcoin::CompactTarget::from_unprefixed_hex(&job.blocktemplate.bits)
        .map_err(|_| Error::InvalidParams("Failed to parse compact target".into()))?;
    let target = bitcoin::Target::from_compact(compact_target);

    let enonce2 = submission.params[2]
        .as_ref()
        .ok_or_else(|| Error::InvalidParams("Missing enonce2".into()))?
        .as_str();

    if enonce2.len() != EXTRANONCE2_SIZE * 2 {
        return Err(Error::InvalidParams(format!(
            "extranonce2 must be {EXTRANONCE2_SIZE} bytes"
        )));
    }

    // build coinbase from submission
    let coinbase =
        build_coinbase_from_components(&job.coinbase1, enonce1_hex, enonce2, &job.coinbase2)
            .map_err(|_| Error::InvalidParams("Failed to build coinbase transaction".into()))?;

    debug!("Coinbase transaction: {:?}", coinbase);

    // Compute merkle root by walking the pre-computed branches along with the coinbase txid.
    let merkle_root =
        compute_merkle_root_from_branches(coinbase.compute_txid(), &job.template_merkle_branches);

    let ntime_str = submission.params[3]
        .as_ref()
        .ok_or_else(|| Error::InvalidParams("Missing ntime".into()))?;
    let n_time =
        u32::from_str_radix(ntime_str, 16).map_err(|_| Error::InvalidParams("Bad nTime".into()))?;

    let version = apply_version_mask(job.blocktemplate.version, version_mask, &submission.params)?;

    // build the block header from the block template and submission
    let header = Header {
        version: bitcoin::block::Version::from_consensus(version),
        prev_blockhash: bitcoin::BlockHash::from_str(&job.blocktemplate.previousblockhash).unwrap(),
        merkle_root,
        time: n_time,
        bits: compact_target,
        nonce: u32::from_str_radix(
            submission.params[4]
                .as_ref()
                .ok_or_else(|| Error::InvalidParams("Missing nonce".into()))?,
            16,
        )
        .map_err(|_| Error::InvalidParams("Bad nonce".into()))?,
    };

    let meets_bitcoin_difficulty = match header.validate_pow(target) {
        Ok(_) => {
            info!("Header meets current bitcoin target");
            true
        }
        Err(e) => {
            debug!("Header does not meet the bitcoin target: {}", e);
            false
        }
    };

    Ok(ValidationResult {
        header,
        coinbase,
        meets_bitcoin_difficulty,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn sample_transaction() -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_build_coinbase_from_components_rejects_trailing_bytes() {
        let tx = sample_transaction();
        let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));

        // Split the serialized transaction into the four components the
        // function concatenates. The split points are arbitrary; only the
        // concatenation matters.
        let coinbase1 = &tx_hex[..8];
        let enonce1 = &tx_hex[8..16];
        let enonce2 = &tx_hex[16..32];
        let coinbase2 = &tx_hex[32..];

        let decoded = build_coinbase_from_components(coinbase1, enonce1, enonce2, coinbase2)
            .expect("exact transaction must decode");
        assert_eq!(decoded, tx);

        // One extra byte after the transaction must be rejected.
        let coinbase2_with_trailing = format!("{coinbase2}00");
        let result =
            build_coinbase_from_components(coinbase1, enonce1, enonce2, &coinbase2_with_trailing);
        assert!(
            matches!(result, Err(Error::InvalidParams(_))),
            "trailing bytes must be rejected with InvalidParams"
        );
    }
}
