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

use crate::error::Error;
use crate::messages::Request;
use crate::work::gbt::BlockTemplate;
use crate::work::tracker::JobDetails;
use bitcoin::blockdata::block::{Block, Header};
use bitcoin::consensus::Decodable;
use bitcoin::hex::DisplayHex;
use std::str::FromStr;
use tracing::info;

/// parse all transactions from block template with data and txid
fn decode_txids(blocktemplate: &BlockTemplate) -> Result<Vec<bitcoin::Txid>, Error> {
    blocktemplate
        .transactions
        .iter()
        .map(|tx| bitcoin::Txid::from_str(&tx.txid).map_err(|_| Error::InvalidParams))
        .collect()
}

/// Build coinbase from the submitted share and block template.
pub fn build_coinbase_from_submission(
    job: &JobDetails,
    submission: &Request<'_>,
    enonce1: &str,
) -> Result<bitcoin::Transaction, Error> {
    use hex::FromHex;

    let coinb1 = &job.coinbase1;
    let coinb2 = &job.coinbase2;
    let enonce2 = &submission.params[2];

    let complete_tx = format!("{}{}{}{}", coinb1, enonce1, enonce2, coinb2);

    let tx_bytes = Vec::from_hex(&complete_tx).unwrap();
    bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes))
        .map_err(|_| Error::InvalidParams)
}

/// Validate the difficulty of a submitted share against the block template
///
/// We build the block header from received submission and the corresponding block template.
/// Then we check if the header's difficulty meets the target specified in the block template.
///
/// Returns result with optional header if the PoW is met. Else returns an error.
pub fn validate_submission_difficulty(
    job: &JobDetails,
    submission: &Request<'_>,
    enonce1: &str,
) -> Result<Block, Error> {
    let compact_target = bitcoin::CompactTarget::from_unprefixed_hex(&job.blocktemplate.bits)
        .map_err(|_| Error::InvalidParams)?;
    let target = bitcoin::Target::from_compact(compact_target);

    // build coinbase from submission
    let coinbase = build_coinbase_from_submission(job, submission, enonce1)
        .map_err(|_| Error::InvalidParams)?;

    info!(
        "Coinbase: {}",
        bitcoin::consensus::serialize::<bitcoin::Transaction>(&coinbase).as_hex()
    );
    info!("Coinbase is coinbase: {}", coinbase.is_coinbase());
    info!("Coinbase txid: {}", coinbase.compute_txid());

    // decode txids for making merkle root
    let txids = decode_txids(&job.blocktemplate).map_err(|_| Error::InvalidParams)?;

    let mut all_txids = vec![coinbase.compute_txid()];
    all_txids.extend(txids);

    let hashes = all_txids.iter().map(|obj| obj.to_raw_hash());
    let merkle_root: bitcoin::TxMerkleNode = bitcoin::merkle_tree::calculate_root(hashes)
        .map(|h| h.into())
        .unwrap();

    info!("Merkle root: {}", merkle_root);

    let n_time =
        u32::from_str_radix(&submission.params[3], 16).map_err(|_| Error::InvalidParams)?;

    // build the block header from the block template and submission
    let header = Header {
        version: bitcoin::block::Version::from_consensus(job.blocktemplate.version),
        prev_blockhash: bitcoin::BlockHash::from_str(&job.blocktemplate.previousblockhash).unwrap(),
        merkle_root,
        time: n_time,
        bits: bitcoin::pow::CompactTarget::from_unprefixed_hex(&job.blocktemplate.bits).unwrap(),
        nonce: u32::from_str_radix(&submission.params[4], 16).unwrap(),
    };

    info!("Header hash : {}", header.block_hash().to_string());
    // info!("Target      : {}", hex::encode(target));

    match header.validate_pow(target) {
        Ok(_) => info!("Header meets the target"),
        Err(e) => {
            info!("Header does not meet the target: {}", e);
            return Err(Error::InsufficientWork);
        }
    }

    // Decode transactions from the block template
    let transactions = job
        .blocktemplate
        .transactions
        .iter()
        .map(|tx| {
            let tx_bytes = hex::decode(&tx.data).unwrap();
            bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes)).unwrap()
        })
        .collect();

    let block = Block {
        header,
        txdata: transactions,
    };
    Ok(block)
}
