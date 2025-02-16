// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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

use crate::shares::miner_message::MinerShare;
use crate::shares::miner_message::MinerWorkbase;
use crate::shares::miner_message::WorkbaseTxn;
use bitcoin::consensus::Decodable;
use std::error::Error;

/// Decodes a hex string into a value of type T using the bitcoin consensus encoding
/// We use the hex crate to decode the hex string into a byte vector
/// Then we use the bitcoin consensus encoding to decode the byte vector into a value of type T
/// Returns an error if the hex string is invalid
pub fn decode_little_endian_hex<T: Decodable>(
    hex_string: &str,
) -> Result<T, Box<dyn std::error::Error>> {
    let hex_bytes = hex::decode(hex_string).unwrap();
    let value = bitcoin::consensus::encode::deserialize(&hex_bytes).unwrap();
    Ok(value)
}

pub fn build_coinbase_from_share(
    workbase: &MinerWorkbase,
    share: &MinerShare,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    use hex::FromHex;

    let coinb1 = &workbase.coinb1;
    let coinb2 = &workbase.coinb2;
    let enonce1 = &share.enonce1;
    let nonce2 = &share.nonce2;
    let txnbinlen = &workbase.txnbinlen;
    let txnbin = &workbase.txnbin;
    let coinb3 = &workbase.coinb3;

    let complete_tx = format!(
        "{}{}{}{}{}{}{}",
        coinb1, enonce1, nonce2, coinb2, txnbinlen, txnbin, coinb3
    );

    // Try to deserialize
    let tx_bytes = Vec::from_hex(&complete_tx).unwrap();
    bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Decodes a vector of WorkbaseTxn into a vector of bitcoin::Transaction
/// Returns an error if any transaction fails to decode
fn decode_transactions(
    txns: &Vec<WorkbaseTxn>,
) -> Result<Vec<bitcoin::Transaction>, Box<dyn Error>> {
    txns.iter()
        .map(|tx| {
            let tx_bytes = hex::decode(&tx.data).map_err(|e| Box::new(e) as Box<dyn Error>)?;
            bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes))
                .map_err(|e| Box::new(e) as Box<dyn Error>)
        })
        .collect()
}

/// Compute the transaction merkle root from vector of transactions
///
/// The header in Gbt does not have the coinbase transaction, so we need to compute the merkle root
/// with the vector of transactions built by using coinbase from share and rest of the transactions
/// from workbase
pub fn compute_merkle_root(txns: &Vec<bitcoin::Transaction>) -> Option<bitcoin::TxMerkleNode> {
    let hashes = txns.iter().map(|obj| obj.compute_txid().to_raw_hash());
    bitcoin::merkle_tree::calculate_root(hashes).map(|h| h.into())
}

/// Builds a bitcoin block header from a workbase and a share
/// TOOD: Update nonce and ntime from MinerShare
fn build_header(
    workbase: &MinerWorkbase,
    share: &MinerShare,
    txns: &Vec<bitcoin::Transaction>,
) -> Result<bitcoin::block::Header, Box<dyn Error>> {
    let header_bytes = hex::decode(&workbase.header)?;
    let mut header =
        bitcoin::block::Header::consensus_decode(&mut std::io::Cursor::new(header_bytes))?;
    header.version = bitcoin::block::Version::from_consensus(workbase.gbt.version);
    header.time = share.ntime.to_consensus_u32();
    header.nonce = u32::from_str_radix(&share.nonce, 16)?;
    header.merkle_root = compute_merkle_root(txns).ok_or("Failed to compute merkle root")?;
    Ok(header)
}

/// Builds a bitcoin block from a workbase and a share
/// Returns an error if any transaction fails to decode
/// Returns an error if the block header fails to decode
/// Returns an error if the coinbase transaction fails to decode
pub fn build_bitcoin_block(
    workbase: &MinerWorkbase,
    share: &MinerShare,
) -> Result<bitcoin::Block, Box<dyn Error>> {
    let coinbase = build_coinbase_from_share(&workbase, &share)?;
    let mut txns = vec![coinbase];
    txns.extend(decode_transactions(&workbase.txns)?);
    let header = build_header(workbase, share, &txns)?;
    let block = bitcoin::Block {
        header,
        txdata: txns,
    };
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::miner_message::CkPoolMessage;

    #[test]
    fn test_build_bitcoin_block() {
        // Read test data file
        let test_data =
            std::fs::read_to_string("tests/test_data/validation/workbases_and_shares.json")
                .unwrap();
        let messages: Vec<CkPoolMessage> = serde_json::from_str(&test_data).unwrap();

        // Group workbases and shares
        let mut workbase_share_pairs = Vec::new();
        let mut current_workbase: Option<MinerWorkbase> = None;

        for message in messages {
            match message {
                CkPoolMessage::Workbase(workbase) => {
                    current_workbase = Some(workbase);
                }
                CkPoolMessage::Share(share) => {
                    if let Some(workbase) = current_workbase.clone() {
                        workbase_share_pairs.push((workbase, share));
                    }
                }
            }
        }

        // Build and validate blocks for each workbase-share pair
        for (workbase, share) in workbase_share_pairs {
            let share_ntime = share.ntime.to_consensus_u32();
            let workbase_version = workbase.gbt.version;

            let block = build_bitcoin_block(&workbase, &share).unwrap();

            assert_eq!(block.txdata.len(), 1); // Only coinbase transaction
            assert_eq!(
                block.header.version,
                bitcoin::block::Version::from_consensus(workbase_version)
            );
            assert_eq!(
                block.header.nonce,
                u32::from_str_radix(&share.nonce, 16).unwrap()
            );

            assert_eq!(
                block.header.bits,
                decode_little_endian_hex::<bitcoin::pow::CompactTarget>(&workbase.gbt.bits)
                    .unwrap()
            );
            assert_eq!(block.header.time, share_ntime);

            assert!(block.check_merkle_root());
            assert!(block.check_witness_commitment());
        }
    }
}
