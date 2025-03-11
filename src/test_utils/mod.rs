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

use crate::shares::miner_message::{CkPoolMessage, MinerShare, MinerWorkbase, UserWorkbase};
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
    blockhash: Option<&str>,
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
        hash: blockhash
            .unwrap_or("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .parse::<BlockHash>()
            .unwrap(),
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
    let json_str = include_str!("../../tests/test_data/simple_miner_workbase.json");
    serde_json::from_str(&json_str).unwrap()
}

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
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
pub fn load_valid_workbases_userworkbases_and_shares(
) -> (Vec<MinerWorkbase>, Vec<UserWorkbase>, Vec<MinerShare>) {
    let workbases_str = include_str!("../../tests/test_data/validation/workbases.json");
    let shares_str = include_str!("../../tests/test_data/validation/shares.json");
    let userworkbases_str = include_str!("../../tests/test_data/validation/userworkbases.json");
    let workbases: Vec<CkPoolMessage> = serde_json::from_str(&workbases_str).unwrap();
    let shares: Vec<CkPoolMessage> = serde_json::from_str(&shares_str).unwrap();
    let userworkbases: Vec<CkPoolMessage> = serde_json::from_str(&userworkbases_str).unwrap();
    let workbases = workbases
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::Workbase(w) => Some(w),
            _ => None,
        })
        .collect::<Vec<MinerWorkbase>>();

    let userworkbases = userworkbases
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::UserWorkbase(w) => Some(w),
            _ => None,
        })
        .collect::<Vec<UserWorkbase>>();

    let shares = shares
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::Share(s) => Some(s),
            _ => None,
        })
        .collect::<Vec<MinerShare>>();

    (workbases, userworkbases, shares)
}

#[cfg(test)]
pub struct TestBlockBuilder {
    blockhash: Option<String>,
    prev_share_blockhash: Option<String>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<String>,
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
    transactions: Vec<Transaction>,
}

#[cfg(test)]
impl TestBlockBuilder {
    pub fn new() -> Self {
        Self {
            blockhash: None,
            prev_share_blockhash: None,
            uncles: Vec::new(),
            miner_pubkey: None,
            workinfoid: None,
            clientid: None,
            diff: None,
            sdiff: None,
            transactions: Vec::new(),
        }
    }

    pub fn blockhash(mut self, blockhash: &str) -> Self {
        self.blockhash = Some(blockhash.to_string());
        self
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: &str) -> Self {
        self.prev_share_blockhash = Some(prev_share_blockhash.to_string());
        self
    }

    pub fn uncles(mut self, uncles: Vec<BlockHash>) -> Self {
        self.uncles = uncles;
        self
    }

    pub fn miner_pubkey(mut self, miner_pubkey: &str) -> Self {
        self.miner_pubkey = Some(miner_pubkey.to_string());
        self
    }

    pub fn workinfoid(mut self, workinfoid: u64) -> Self {
        self.workinfoid = Some(workinfoid);
        self
    }

    pub fn clientid(mut self, clientid: u64) -> Self {
        self.clientid = Some(clientid);
        self
    }

    pub fn diff(mut self, diff: Decimal) -> Self {
        self.diff = Some(diff);
        self
    }

    pub fn sdiff(mut self, sdiff: Decimal) -> Self {
        self.sdiff = Some(sdiff);
        self
    }

    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn build(mut self) -> ShareBlock {
        test_share_block(
            self.blockhash.as_deref(),
            self.prev_share_blockhash.as_deref(),
            self.uncles,
            self.miner_pubkey.as_deref(),
            self.workinfoid,
            self.clientid,
            self.diff,
            self.sdiff,
            &mut self.transactions,
        )
    }
}

#[cfg(test)]
fn test_share_block(
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
            miner_share: simple_miner_share(blockhash, workinfoid, clientid, diff, sdiff),
            prev_share_blockhash,
            uncles,
            miner_pubkey,
            merkle_root: bitcoin::merkle_tree::calculate_root(
                transactions.iter().map(Transaction::compute_txid),
            )
            .unwrap()
            .into(),
        },
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
