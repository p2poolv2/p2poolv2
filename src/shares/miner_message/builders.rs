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
use crate::shares::miner_message::UserWorkbase;
use crate::shares::miner_message::WorkbaseTxn;
use bitcoin::consensus::Decodable;
use std::error::Error;
use std::str::FromStr;

/// Build coinbase from the share received from ckpool
/// We do not validate the coinbase transaction, as ckpool does it for us.
/// For shares received from peers, we will validate the entire block later.
pub fn build_coinbase_from_share(
    userworkbase: &UserWorkbase,
    share: &MinerShare,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    use hex::FromHex;

    let coinb1 = &userworkbase.params.coinb1;
    let coinb2 = &userworkbase.params.coinb2;
    let enonce1 = &share.enonce1;
    let nonce2 = &share.nonce2;

    let complete_tx = format!("{}{}{}{}", coinb1, enonce1, nonce2, coinb2);

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

/// Decodes a vector of WorkbaseTxn into a vector of bitcoin::Txid
/// Returns an error if any txid fails to decode
fn decode_txids(txns: &Vec<WorkbaseTxn>) -> Result<Vec<bitcoin::Txid>, Box<dyn Error>> {
    txns.iter()
        .map(|tx| bitcoin::Txid::from_str(&tx.txid).map_err(|e| Box::new(e) as Box<dyn Error>))
        .collect()
}

/// Compute merkle root from the txids
pub fn compute_merkle_root_from_txids(txids: &Vec<bitcoin::Txid>) -> Option<bitcoin::TxMerkleNode> {
    let hashes = txids.iter().map(|obj| obj.to_raw_hash());
    bitcoin::merkle_tree::calculate_root(hashes).map(|h| h.into())
}

/// Builds a bitcoin block header from a workbase and a share
/// TOOD: Update nonce and ntime from MinerShare
pub fn build_bitcoin_header(
    workbase: &MinerWorkbase,
    share: &MinerShare,
    merkle_root: bitcoin::TxMerkleNode,
) -> Result<bitcoin::block::Header, Box<dyn Error>> {
    let header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(workbase.gbt.version),
        prev_blockhash: bitcoin::BlockHash::from_str(&workbase.gbt.previousblockhash)?,
        merkle_root,
        time: share.ntime.to_consensus_u32(),
        bits: bitcoin::pow::CompactTarget::from_unprefixed_hex(&workbase.gbt.bits)?,
        nonce: u32::from_str_radix(&share.nonce, 16)?,
    };
    Ok(header)
}

/// Builds a bitcoin block from a workbase and a share
/// Returns an error if any transaction fails to decode
/// Returns an error if the block header fails to decode
/// Returns an error if the coinbase transaction fails to decode
pub fn build_bitcoin_block(
    workbase: &MinerWorkbase,
    userworkbase: &UserWorkbase,
    share: &MinerShare,
) -> Result<bitcoin::Block, Box<dyn Error>> {
    let coinbase = build_coinbase_from_share(&userworkbase, &share)?;
    let mut txns = vec![coinbase.clone()];
    txns.extend(decode_transactions(&workbase.txns)?);

    let mut txids = vec![coinbase.compute_txid()];
    txids.extend(decode_txids(&workbase.txns)?);
    let merkle_root =
        compute_merkle_root_from_txids(&txids).ok_or("Failed to compute merkle root")?;

    let header = build_bitcoin_header(workbase, share, merkle_root)?;
    let block = bitcoin::Block {
        header,
        txdata: txns,
    };
    Ok(block)
}

/// Builds a ShareHeader from a workbase and a share
/// The prev_share_blockhash and uncles fields are set to None and empty vec respectively
/// since they need to be set by the chain actor
#[allow(dead_code)]
pub fn build_share_header(
    workbase: &MinerWorkbase,
    share: &MinerShare,
    userworkbase: &UserWorkbase,
    miner_pubkey: bitcoin::PublicKey,
) -> Result<crate::shares::ShareHeader, Box<dyn Error>> {
    // TODO[pool2win/P0] - The coinbase for the share should be the one paying miner pubkey
    let coinbase = build_coinbase_from_share(userworkbase, share)?;
    let mut txids = vec![coinbase.compute_txid()];
    txids.extend(decode_txids(&workbase.txns)?);

    let merkle_root =
        compute_merkle_root_from_txids(&txids).ok_or("Failed to compute merkle root")?;

    Ok(crate::shares::ShareHeader {
        miner_share: share.clone(),
        prev_share_blockhash: None,
        uncles: vec![],
        miner_pubkey,
        merkle_root,
    })
}

/// Builds a ShareBlock from a workbase, share and header
/// Returns an error if any transaction fails to decode
/// Returns an error if the coinbase transaction fails to decode
#[allow(dead_code)]
pub fn build_share_block(
    workbase: &MinerWorkbase,
    userworkbase: &UserWorkbase,
    share: &MinerShare,
    header: crate::shares::ShareHeader,
) -> Result<crate::shares::ShareBlock, Box<dyn Error>> {
    let coinbase = build_coinbase_from_share(userworkbase, share)?;
    let mut transactions = vec![coinbase];
    transactions.extend(decode_transactions(&workbase.txns)?);

    Ok(crate::shares::ShareBlock {
        header,
        transactions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::load_valid_workbases_userworkbases_and_shares;
    // btcaddress from ckpool-solo.json
    const USER_PAYOUT_ADDRESS: &str = "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d";
    const DONATION_ADDRESS: &str = "tb1q5fyv7tue73y4zxezh2c685qpwx0cfngfxlrgxh";

    #[test]
    fn test_build_coinbase() {
        let (_workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        // Build coinbase
        let coinbase = build_coinbase_from_share(&userworkbases[0], &shares[0]).unwrap();

        // Verify it's a coinbase transaction
        assert!(coinbase.is_coinbase());

        assert_eq!(coinbase.input.len(), 1);
        assert_eq!(coinbase.output.len(), 3);

        assert_eq!(coinbase.version, bitcoin::transaction::Version::ONE);
        assert_eq!(
            coinbase.lock_time,
            bitcoin::locktime::absolute::LockTime::ZERO
        );

        // Mining reward output
        assert_eq!(
            coinbase.output[0].value,
            bitcoin::Amount::from_sat(4900000000)
        );
        assert_eq!(
            &coinbase.output[0].script_pubkey,
            bitcoin::Script::from_bytes(
                &hex::decode("00148f1b6f0d5a0422afad259ec03977bdf2c74a0376").unwrap()
            )
        );
        let address = bitcoin::Address::from_script(
            &coinbase.output[0].script_pubkey,
            bitcoin::Network::Signet,
        )
        .unwrap()
        .to_string();
        assert_eq!(address, USER_PAYOUT_ADDRESS);

        // Donation output
        assert_eq!(
            coinbase.output[1].value,
            bitcoin::Amount::from_sat(100000000)
        );
        assert_eq!(
            &coinbase.output[1].script_pubkey,
            bitcoin::Script::from_bytes(
                &hex::decode("0014a248cf2f99f449511b22bab1a3d001719f84cd09").unwrap()
            )
        );
        let address = bitcoin::Address::from_script(
            &coinbase.output[1].script_pubkey,
            bitcoin::Network::Signet,
        )
        .unwrap()
        .to_string();
        assert_eq!(address, DONATION_ADDRESS);

        // Witness commitment output
        assert_eq!(coinbase.output[2].value, bitcoin::Amount::from_sat(0));
        assert_eq!(
            coinbase.output[2].script_pubkey.to_hex_string(),
            "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
        );

        assert_eq!(
            coinbase.compute_txid().to_string(),
            "186d34fc6257b8f327e41abe5ec5ee29022af3772b1233b5eb152a85e23aad04"
        );
    }

    #[test]
    fn test_build_bitcoin_header() {
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        // Build coinbase and merkle root
        let coinbase = build_coinbase_from_share(&userworkbases[0], &shares[0]).unwrap();
        let mut txids = vec![coinbase.compute_txid()];
        txids.extend(decode_txids(&workbases[0].txns).unwrap());
        let merkle_root = compute_merkle_root_from_txids(&txids).unwrap();

        assert_eq!(
            merkle_root.to_string(),
            "186d34fc6257b8f327e41abe5ec5ee29022af3772b1233b5eb152a85e23aad04"
        );

        // Build header
        let header = build_bitcoin_header(&workbases[0], &shares[0], merkle_root).unwrap();

        // Verify header fields by comparing string representations
        assert_eq!(header.version.to_consensus(), 536870912);
        assert_eq!(
            header.prev_blockhash.to_string(),
            "00000000863a9563ff5d87f94b9db355a53326456301fcaf8f665af26d600f56"
        );
        assert_eq!(hex::encode(header.time.to_be_bytes()), "67b6f938");
        assert_eq!(
            hex::encode(header.bits.to_consensus().to_be_bytes()),
            "1e0377ae"
        );
        assert_eq!(hex::encode(header.nonce.to_be_bytes()), "f15f1590");

        assert_eq!(
            header.block_hash().to_string(),
            "000000000822bbfaf34d53fc43d0c1382054d3aafe31893020c315db8b0a19f9"
        );
    }

    #[test]
    fn test_build_bitcoin_block_and_validation() {
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        // Build and validate blocks for each workbase-share pair
        for ((workbase, userworkbase), share) in workbases
            .iter()
            .zip(userworkbases.iter())
            .zip(shares.iter())
        {
            let share_ntime = share.ntime.to_consensus_u32();
            let workbase_version = workbase.gbt.version;

            let block = build_bitcoin_block(&workbase, &userworkbase, &share).unwrap();

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
                bitcoin::pow::CompactTarget::from_unprefixed_hex(&workbase.gbt.bits).unwrap()
            );
            assert_eq!(block.header.time, share_ntime);

            assert!(block.check_merkle_root());
            assert!(block.check_witness_commitment());

            let compact_target =
                bitcoin::pow::CompactTarget::from_unprefixed_hex(&userworkbase.params.nbit)
                    .unwrap();
            let required_target = bitcoin::Target::from_compact(compact_target);
            assert_eq!(block.header.target(), required_target);

            assert_eq!(
                block.header.block_hash().to_string(),
                "000000000822bbfaf34d53fc43d0c1382054d3aafe31893020c315db8b0a19f9"
            );
            let pow_result = block.header.validate_pow(required_target);
            assert!(pow_result.is_ok());
        }
    }

    #[test]
    fn test_decode_transactions() {
        let hex_tx = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2c017b000438f9b667049c0fc52d0cfdf8b66700000000000000000a636b706f6f6c0a2f7032706f6f6c76322fffffffff0300111024010000001600148f1b6f0d5a0422afad259ec03977bdf2c74a037600e1f50500000000160014a248cf2f99f449511b22bab1a3d001719f84cd090000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000";
        let txs = vec![WorkbaseTxn {
            data: hex_tx.to_string(),
            txid: "d5ada3c7b0fb6e9e8a8c5c2f36f3e3134d0cf5d6eb6b14c0c70a53e13b4c5d9f".to_string(),
        }];

        let decoded = decode_transactions(&txs).unwrap();

        assert_eq!(decoded.len(), 1);
        let tx = &decoded[0];

        // Verify transaction details
        assert_eq!(tx.version, bitcoin::transaction::Version::ONE);
        assert_eq!(tx.lock_time, bitcoin::absolute::LockTime::ZERO);

        // Check inputs
        assert_eq!(tx.input.len(), 1);
        let input = &tx.input[0];
        assert_eq!(
            input.previous_output.txid,
            bitcoin::Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap()
        );
        assert_eq!(input.previous_output.vout, 4294967295);
        assert_eq!(input.sequence, bitcoin::Sequence::MAX);

        // Check outputs
        assert_eq!(tx.output.len(), 3);

        // Verify the transaction can be serialized back
        let serialized = bitcoin::consensus::encode::serialize(&tx);
        let hex_serialized = hex::encode(serialized);
        assert_eq!(hex_serialized, hex_tx.to_lowercase());
    }
}
