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

#[cfg(test)]
use crate::shares::share_block::{ShareBlock, ShareHeader};
#[cfg(test)]
use crate::shares::transactions::coinbase::create_coinbase_transaction;

use crate::stratum::messages::Notify;
use crate::stratum::messages::Response;
#[cfg(test)]
use crate::stratum::messages::SimpleRequest;
use crate::stratum::work::block_template::BlockTemplate;
use bitcoin::CompactTarget;
#[cfg(test)]
use bitcoin::PublicKey;
#[cfg(test)]
use bitcoin::Transaction;
#[cfg(test)]
use bitcoin::block::{BlockHash, Header};
use bitcoin::hashes::Hash;
use rand;
use std::str::FromStr;

pub fn genesis_for_tests() -> ShareBlock {
    TestShareBlockBuilder::new().build()
}

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
    use rand::{Rng, thread_rng};

    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..length / 2]);
    // Set the specified number of leading bytes to zero
    bytes.iter_mut().take(leading_zeroes).for_each(|b| *b = 0);
    bytes[..length / 2]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
pub fn test_coinbase_transaction() -> bitcoin::Transaction {
    let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
        .parse::<bitcoin::PublicKey>()
        .unwrap();

    create_coinbase_transaction(&pubkey, bitcoin::Network::Signet)
}

#[cfg(test)]
pub fn load_valid_stratum_work_components(
    path: &str,
) -> (BlockTemplate, Notify, SimpleRequest, Response<'static>) {
    use crate::stratum::{self, messages::SimpleRequest};

    let notify_file = std::fs::File::open(format!("{path}/notify.json")).unwrap();
    let notify: Notify = serde_json::from_reader(notify_file).unwrap();

    let template_file = std::fs::File::open(format!("{path}/template.json")).unwrap();
    let template: BlockTemplate = serde_json::from_reader(template_file).unwrap();

    let submit_file = std::fs::File::open(format!("{path}/submit.json")).unwrap();
    let submit_json: serde_json::Value = serde_json::from_reader(submit_file).unwrap();

    let submit = SimpleRequest {
        method: "mining.submit".to_string().into(),
        params: std::borrow::Cow::Owned(
            submit_json["params"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| Some(v.as_str().unwrap().to_string()))
                .collect(),
        ),
        id: Some(stratum::messages::Id::Number(
            submit_json["id"].as_u64().unwrap(),
        )),
    };

    let authorize_file = std::fs::File::open(format!("{path}/authorize_response.json")).unwrap();
    let authorize_json: serde_json::Value = serde_json::from_reader(authorize_file).unwrap();
    let authorize_response = Response {
        id: Some(stratum::messages::Id::Number(
            authorize_json["id"].as_u64().unwrap(),
        )),
        result: authorize_json.get("result").cloned(),
        error: None,
    };

    (template, notify, submit, authorize_response)
}

#[cfg(test)]
pub fn build_block_from_work_components(path: &str) -> ShareBlock {
    let (template, _notify, submit, _authorize) = load_valid_stratum_work_components(path);

    let coinbase = test_coinbase_transaction();

    let share_merkle_root =
        bitcoin::merkle_tree::calculate_root([coinbase.clone()].iter().map(|tx| tx.compute_txid()))
            .unwrap()
            .into();

    let mut bitcoin_transactions: Vec<Transaction> = template
        .transactions
        .iter()
        .map(bitcoin::Transaction::from)
        .collect();

    // For the tests use the same coinbase as share block, i.e. using the same pubkey. This is so we don't have empty transactions and end up with a None merkle root.
    bitcoin_transactions.insert(0, coinbase);

    let bitcoin_merkle_root = bitcoin::merkle_tree::calculate_root(
        bitcoin_transactions.iter().map(|tx| tx.compute_txid()),
    )
    .unwrap()
    .into();

    let bitcoin_header = Header {
        version: bitcoin::block::Version::from_consensus(template.version),
        prev_blockhash: BlockHash::from_str(&template.previousblockhash).unwrap(),
        merkle_root: bitcoin_merkle_root,
        time: u32::from_str_radix(submit.params[3].as_ref().unwrap(), 16).unwrap(),
        bits: CompactTarget::from_unprefixed_hex(&template.bits).unwrap(),
        nonce: u32::from_str_radix(submit.params[4].as_ref().unwrap(), 16).unwrap(),
    };

    let share_header = ShareHeader {
        prev_share_blockhash: BlockHash::all_zeros(),
        uncles: vec![],
        miner_pubkey: PublicKey::from_str(
            "020202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap(),
        merkle_root: share_merkle_root,
        bitcoin_header,
    };

    ShareBlock {
        header: share_header,
        transactions: bitcoin_transactions,
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestShareBlockBuilder {
    bitcoin_header: Option<Header>,
    prev_share_blockhash: Option<String>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<String>,
    transactions: Vec<Transaction>,
    diff_multiplier: Option<u32>,
    nonce: Option<u32>,
}

#[cfg(test)]
impl TestShareBlockBuilder {
    pub fn new() -> Self {
        Self {
            bitcoin_header: None,
            prev_share_blockhash: None,
            uncles: Vec::new(),
            miner_pubkey: None,
            transactions: Vec::new(),
            diff_multiplier: None,
            nonce: None,
        }
    }

    pub fn bitcoin_header(mut self, bitcoin_header: Header) -> Self {
        self.bitcoin_header = Some(bitcoin_header);
        self
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: String) -> Self {
        self.prev_share_blockhash = Some(prev_share_blockhash);
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

    pub fn nonce(mut self, nonce: u32) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn diff(mut self, diff_multiplier: u32) -> Self {
        self.diff_multiplier = Some(diff_multiplier);
        self
    }

    pub fn build(self) -> ShareBlock {
        let coinbase = match self.miner_pubkey {
            Some(ref pk) => {
                let pubkey = PublicKey::from_str(pk).unwrap();
                create_coinbase_transaction(&pubkey, bitcoin::Network::Signet)
            }
            None => test_coinbase_transaction(),
        };
        let all_transactions = {
            let mut txs = vec![coinbase];
            txs.extend(self.transactions);
            txs
        };
        test_share_block(
            self.bitcoin_header,
            self.prev_share_blockhash
                .unwrap_or(BlockHash::all_zeros().to_string())
                .as_str(),
            self.uncles,
            self.miner_pubkey
                .unwrap_or(
                    "020202020202020202020202020202020202020202020202020202020202020202".into(),
                )
                .as_str(),
            all_transactions,
            self.diff_multiplier,
            self.nonce,
        )
    }
}

#[cfg(test)]
fn multiply_difficulty(bits: u32, multiplier: u32) -> CompactTarget {
    // Extract mantissa and exponent
    let mantissa = bits & 0x00FFFFFF;
    let exponent = (bits >> 24) & 0xFF;

    // Divide the mantissa to multiply the difficulty
    let new_mantissa = mantissa / multiplier;

    // Reconstruct the bits
    let new_bits = (exponent << 24) | new_mantissa;
    CompactTarget::from_consensus(new_bits)
}

#[cfg(test)]
fn test_share_block(
    bitcoin_header: Option<Header>,
    prev_share_blockhash: &str,
    uncles: Vec<BlockHash>,
    miner_pubkey: &str,
    transactions: Vec<Transaction>,
    diff_multiplier: Option<u32>,
    nonce: Option<u32>,
) -> ShareBlock {
    let coinbase = test_coinbase_transaction();

    let share_merkle_root =
        bitcoin::merkle_tree::calculate_root(vec![coinbase].iter().map(|tx| tx.compute_txid()))
            .unwrap()
            .into();

    let bitcoin_header = match bitcoin_header {
        Some(header) => header,
        None => Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: share_merkle_root,
            time: 0x01e0377ae,
            bits: multiply_difficulty(0x1e0377ae, diff_multiplier.unwrap_or(1)),
            nonce: nonce.unwrap_or(0xe9695791),
        },
    };

    let header = ShareHeader {
        prev_share_blockhash: BlockHash::from_str(prev_share_blockhash).unwrap(),
        uncles,
        miner_pubkey: PublicKey::from_str(miner_pubkey).unwrap(),
        merkle_root: share_merkle_root,
        bitcoin_header,
    };

    ShareBlock {
        header,
        transactions,
    }
}

/// Builder for creating test ShareHeader instances
#[cfg(test)]
pub struct TestShareHeaderBuilder {
    prev_share_blockhash: Option<BlockHash>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<PublicKey>,
    transactions: Vec<Transaction>,
}

#[cfg(test)]
impl Default for TestShareHeaderBuilder {
    fn default() -> Self {
        Self {
            prev_share_blockhash: None,
            uncles: Vec::new(),
            miner_pubkey: None,
            transactions: Vec::new(),
        }
    }
}

#[cfg(test)]
impl TestShareHeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: BlockHash) -> Self {
        self.prev_share_blockhash = Some(prev_share_blockhash);
        self
    }

    pub fn uncles(mut self, uncles: Vec<BlockHash>) -> Self {
        self.uncles = uncles;
        self
    }

    pub fn add_uncle(mut self, uncle: BlockHash) -> Self {
        self.uncles.push(uncle);
        self
    }

    pub fn miner_pubkey(mut self, miner_pubkey: PublicKey) -> Self {
        self.miner_pubkey = Some(miner_pubkey);
        self
    }

    pub fn transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    pub fn build(self) -> ShareHeader {
        let default_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();

        let default_merkle_root = {
            let tx = test_coinbase_transaction();
            bitcoin::merkle_tree::calculate_root(std::iter::once(tx.compute_txid()))
                .unwrap()
                .into()
        };

        let share_merkle_root = bitcoin::merkle_tree::calculate_root(
            self.transactions.iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();

        ShareHeader {
            prev_share_blockhash: self.prev_share_blockhash.unwrap_or(BlockHash::all_zeros()),
            uncles: self.uncles,
            miner_pubkey: self.miner_pubkey.unwrap_or(default_pubkey),
            merkle_root: share_merkle_root,
            bitcoin_header: Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: default_merkle_root,
                time: 1700000000u32,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
        }
    }
}
