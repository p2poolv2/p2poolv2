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
use crate::shares::{ShareBlock, ShareHeader};
use bitcoin::BlockHash;
use bitcoin::Transaction;
#[cfg(test)]
use rand;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

#[cfg(test)]
/// Build a simple miner share with consant values
pub fn simple_miner_share(
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
) -> MinerShare {
    MinerShare {
        workinfoid: workinfoid.unwrap_or(7452731920372203525),
        clientid: clientid.unwrap_or(1),
        enonce1: "336c6d67".to_string(),
        nonce2: "0000000000000000".to_string(),
        nonce: "2eb7b82b".to_string(),
        ntime: bitcoin::absolute::Time::from_hex("676d6caa").unwrap(),
        diff: diff.unwrap_or(dec!(1.0)),
        sdiff: sdiff.unwrap_or(dec!(1.9041854952356509)),
        hash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".to_string(),
        result: true,
        errn: 0,
        createdate: "1735224559,536904211".to_string(),
        createby: "code".to_string(),
        createcode: "parse_submit".to_string(),
        createinet: "0.0.0.0:3333".to_string(),
        workername: "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
        username: "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
        address: "172.19.0.4".to_string(),
        agent: "cpuminer/2.5.1".to_string(),
    }
}

#[cfg(test)]
pub fn simple_miner_workbase() -> MinerWorkbase {
    let json_str = r#"{"gbt":{"capabilities":["proposal"],"version":536870912,"rules":["csv","!segwit","!signet","taproot"],"vbavailable":{},"vbrequired":0,"previousblockhash":"00000000790ba17d9c06acf8749166014eb1499c8ea6dd598060dbec7eeae808","transactions":[],"coinbaseaux":{},"coinbasevalue":5000000000,"longpollid":"00000000790ba17d9c06acf8749166014eb1499c8ea6dd598060dbec7eeae8084","target":"00000377ae000000000000000000000000000000000000000000000000000000","mintime":1736686858,"mutable":["time","transactions","prevblock"],"noncerange":"00000000ffffffff","sigoplimit":80000,"sizelimit":4000000,"weightlimit":4000000,"curtime":1736694495,"bits":"1e0377ae","height":98,"signet_challenge":"51","default_witness_commitment":"6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9","diff":0.001126515290698186,"ntime":"6783dadf","bbversion":"20000000","nbit":"1e0377ae"},"workinfoid":7459044800742817807}"#;
    serde_json::from_str(&json_str).unwrap()
}

#[cfg(test)]
pub const TEST_BLOCKHASHES: [&str; 16] = [
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb0",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb8",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb9",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bba",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbb",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbc",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbd",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbe",
    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bbf",
];

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
    use rand::{thread_rng, Rng};

    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..length / 2]);
    // Set the specified number of leading bytes to zero
    for i in 0..leading_zeroes {
        bytes[i] = 0;
    }
    bytes[..length / 2]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
pub fn test_coinbase_transaction() -> bitcoin::Transaction {
    let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
        .parse::<bitcoin::PublicKey>()
        .unwrap();

    crate::shares::transactions::coinbase::create_coinbase_transaction(
        &pubkey,
        bitcoin::Network::Regtest,
    )
}

#[cfg(test)]
pub fn test_share_block(
    blockhash: Option<&str>,
    prev_share_blockhash: Option<&str>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<&str>,
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
    include_transactions: &mut Vec<Transaction>,
) -> ShareBlock {
    let prev_share_blockhash = match prev_share_blockhash {
        Some(prev_share_blockhash) => Some(prev_share_blockhash.parse().unwrap()),
        None => None,
    };
    let miner_pubkey = match miner_pubkey {
        Some(miner_pubkey) => miner_pubkey.parse().unwrap(),
        None => "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap(),
    };
    let mut transactions = vec![test_coinbase_transaction()];
    transactions.append(include_transactions);
    ShareBlock {
        header: ShareHeader {
            blockhash: blockhash
                .unwrap_or("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
                .parse()
                .unwrap(),
            prev_share_blockhash,
            uncles,
            miner_pubkey,
            merkle_root: bitcoin::merkle_tree::calculate_root(
                transactions.iter().map(Transaction::compute_txid),
            )
            .unwrap()
            .into(),
        },
        miner_share: simple_miner_share(workinfoid, clientid, diff, sdiff),
        transactions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_hex_string() {
        // Generate two random strings
        let str1 = random_hex_string(64, 8);
        let str2 = random_hex_string(64, 8);

        // Verify length is 64 characters
        assert_eq!(str1.len(), 64);
        assert_eq!(str2.len(), 64);

        // Verify strings are different (extremely unlikely to be equal)
        assert_ne!(str1, str2);

        // Verify strings only contain valid hex characters
        let is_hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
        assert!(is_hex(&str1));
        assert!(is_hex(&str2));
    }
}
