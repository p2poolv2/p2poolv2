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

use crate::stratum::error::Error;
use crate::stratum::messages::SimpleRequest;
use crate::stratum::work::block_template::BlockTemplate;
use crate::stratum::work::tracker::JobDetails;
use bitcoin::blockdata::block::{Block, Header};
use bitcoin::consensus::Decodable;
use bitcoin::hex::DisplayHex;
use hex::FromHex;
use std::str::FromStr;
use tracing::{debug, info};

/// Share validation result
///
/// Captures the block and boolens to signal if block meets bitcoin and job difficult
pub struct ValidationResult {
    /// The block built with the share components
    pub block: Block,
    /// Does the block meet bitcoin difficulty
    pub meets_bitcoin_difficulty: bool,
}

/// parse all transactions from block template with data and txid
fn decode_txids(blocktemplate: &BlockTemplate) -> Result<Vec<bitcoin::Txid>, Error> {
    blocktemplate
        .transactions
        .iter()
        .map(|tx| {
            bitcoin::Txid::from_str(&tx.txid).map_err(|_| Error::InvalidParams("Bad txid".into()))
        })
        .collect()
}

/// Build coinbase from the submitted share and block template components.
pub fn build_coinbase_from_components(
    coinbase1: &str,
    enonce1: &str,
    enonce2: &str,
    coinbase2: &str,
) -> Result<bitcoin::Transaction, Error> {
    // Add detailed logging to debug the issue
    debug!("Building coinbase with coinb1: {}", coinbase1);

    let complete_tx = format!("{coinbase1}{enonce1}{enonce2}{coinbase2}");
    debug!("Complete coinbase tx hex: {}", complete_tx);

    let tx_bytes = Vec::from_hex(&complete_tx).unwrap();
    bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes))
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
        debug!("Applying version mask from params: {:?}", params[5]);
        let bits = i32::from_be_bytes(
            hex::decode(params[5].as_ref().unwrap())
                .map_err(|_| Error::InvalidParams("Failed to decode hex".into()))?
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidParams("Failed to decode hex".into()))?,
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
pub fn validate_submission_difficulty(
    job: &JobDetails,
    submission: &SimpleRequest<'_>,
    enonce1_hex: &str,
    version_mask: i32,
    _session_difficulty: u64,
    _network: bitcoin::Network,
) -> Result<ValidationResult, Error> {
    let compact_target = bitcoin::CompactTarget::from_unprefixed_hex(&job.blocktemplate.bits)
        .map_err(|_| Error::InvalidParams("Failed to parse compact target".into()))?;
    let target = bitcoin::Target::from_compact(compact_target);

    let enonce2 = submission.params[2].as_ref().unwrap().as_str();

    debug!(
        "Coinbase components coinbase1: {} enonce1: {}, enonce2: {}, coinbase2: {}",
        &job.coinbase1, enonce1_hex, enonce2, &job.coinbase2
    );

    // build coinbase from submission
    let coinbase =
        build_coinbase_from_components(&job.coinbase1, enonce1_hex, enonce2, &job.coinbase2)
            .map_err(|_| Error::InvalidParams("Failed to build coinbase transaction".into()))?;

    debug!("Coinbase transaction: {:?}", coinbase);

    // decode txids for making merkle root
    let txids = decode_txids(&job.blocktemplate)
        .map_err(|_| Error::InvalidParams("Failed to decode txids".into()))?;

    let mut all_txids = vec![coinbase.compute_txid()];
    all_txids.extend(txids);

    let hashes = all_txids.iter().map(|obj| obj.to_raw_hash());
    let merkle_root: bitcoin::TxMerkleNode = bitcoin::merkle_tree::calculate_root(hashes)
        .map(|h| h.into())
        .unwrap();

    debug!("Merkle root: {}", merkle_root);

    let n_time = u32::from_str_radix(submission.params[3].as_ref().unwrap(), 16)
        .map_err(|_| Error::InvalidParams("Bad nTime".into()))?;

    let version = apply_version_mask(job.blocktemplate.version, version_mask, &submission.params)?;

    // build the block header from the block template and submission
    let header = Header {
        version: bitcoin::block::Version::from_consensus(version),
        prev_blockhash: bitcoin::BlockHash::from_str(&job.blocktemplate.previousblockhash).unwrap(),
        merkle_root,
        time: n_time,
        bits: compact_target,
        nonce: u32::from_str_radix(submission.params[4].as_ref().unwrap(), 16).unwrap(),
    };

    debug!(
        "Header hex : {}",
        bitcoin::consensus::serialize(&header).to_lower_hex_string()
    );
    debug!("Header hash : {}", header.block_hash().to_string());

    let meets_bitcoin_difficulty = match header.validate_pow(target) {
        Ok(_) => {
            info!("Header meets current bitcoin target");
            true
        }
        Err(e) => {
            debug!("Header does not meet the target: {}", e);
            false
        }
    };

    // Decode transactions from the block template
    let transactions: Vec<bitcoin::transaction::Transaction> = job
        .blocktemplate
        .transactions
        .iter()
        .map(|tx| {
            let tx_bytes = hex::decode(&tx.data).unwrap();
            bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes)).unwrap()
        })
        .collect();

    let mut all_transactions = Vec::with_capacity(transactions.len() + 1);
    all_transactions.push(coinbase);
    all_transactions.extend(transactions);

    let block = Block {
        header,
        txdata: all_transactions,
    };

    Ok(ValidationResult {
        block,
        meets_bitcoin_difficulty,
    })
}
