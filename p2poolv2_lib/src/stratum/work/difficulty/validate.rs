// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::stratum::error::Error;
use crate::stratum::messages::SimpleRequest;
use crate::stratum::session::EXTRANONCE2_SIZE;
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use crate::stratum::work::tracker::JobDetails;
use bitcoin::blockdata::block::Header;
use bitcoin::consensus::deserialize;
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
///
/// Returns an invalid params error if the concatenated hex is not valid, or
/// does not decode to exactly one transaction with no trailing bytes.
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
    deserialize(&tx_bytes)
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
/// The submitted extranonce2 must be exactly EXTRANONCE2_SIZE bytes, else an
/// invalid params error is returned before the coinbase is built.
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
    use crate::test_utils::load_valid_stratum_work_components;

    #[test]
    fn test_build_coinbase_from_components_rejects_trailing_bytes() {
        let (_template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");
        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1 = enonce1.as_str().unwrap();
        let enonce2 = submit.params[2].as_ref().unwrap();

        //* The job's real coinbase parts plus the miner's extranonces decode
        //* to exactly one transaction.
        let decoded = build_coinbase_from_components(
            &notify.params.coinbase1,
            enonce1,
            enonce2,
            &notify.params.coinbase2,
        )
        .expect("exact transaction must decode");
        assert!(decoded.is_coinbase());

        //* One extra byte after that transaction must be rejected, not ignored.
        let coinbase2_with_trailing = format!("{}00", notify.params.coinbase2);
        let result = build_coinbase_from_components(
            &notify.params.coinbase1,
            enonce1,
            enonce2,
            &coinbase2_with_trailing,
        );
        assert!(
            matches!(result, Err(Error::InvalidParams(_))),
            "trailing bytes must be rejected with InvalidParams"
        );
    }
}
