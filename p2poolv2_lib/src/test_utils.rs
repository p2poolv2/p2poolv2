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

// Imports for setup_test_chain_store_handle (available with test-utils feature)
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(any(test, feature = "test-utils"))]
use crate::store::Store;
#[cfg(any(test, feature = "test-utils"))]
use crate::store::writer::{StoreHandle, StoreWriter, write_channel};
#[cfg(any(test, feature = "test-utils"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-utils"))]
use tempfile::{TempDir, tempdir};

// Imports for TestShareBlockBuilder and related helpers (available with test-utils feature)
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::share_block::{ShareBlock, ShareHeader, ShareTransaction};
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::transactions::coinbase::create_coinbase_transaction;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::CompressedPublicKey;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::hashes::Hash;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::{Block, BlockHash, CompactTarget, Transaction, block::Header};
#[cfg(any(test, feature = "test-utils"))]
use std::str::FromStr;

// Imports only needed for internal tests
#[cfg(test)]
use crate::shares::share_commitment::ShareCommitment;
#[cfg(test)]
use crate::stratum::messages::Notify;
#[cfg(test)]
use crate::stratum::messages::Response;
#[cfg(test)]
use crate::stratum::messages::SimpleRequest;
#[cfg(test)]
use crate::stratum::work::block_template::BlockTemplate;
#[cfg(test)]
use bitcoin::TxMerkleNode;

/// Setup returns both chain handle and tempdir (tempdir must stay alive)
///
/// Optionally starts the writer background task. Some tests that use
/// single threaded tokio runtime for timeout testing don't want to
/// start the bg task
#[cfg(any(test, feature = "test-utils"))]
pub async fn setup_test_chain_store_handle(start_writer: bool) -> (ChainStoreHandle, TempDir) {
    let temp_dir = tempdir().unwrap();
    let store = Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
    let (write_tx, write_rx) = write_channel();

    // Spawn store writer
    let store_writer = StoreWriter::new(store.clone(), write_rx);
    if start_writer {
        tokio::task::spawn_blocking(move || store_writer.run());
    }

    let store_handle = StoreHandle::new(store, write_tx);
    let chain_handle = ChainStoreHandle::new(store_handle, bitcoin::Network::Signet);
    (chain_handle, temp_dir)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn genesis_for_tests() -> ShareBlock {
    TestShareBlockBuilder::new().build()
}

#[cfg(test)]
pub fn create_test_commitment() -> ShareCommitment {
    ShareCommitment {
        prev_share_blockhash: BlockHash::from_str(
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
        )
        .unwrap(),
        uncles: vec![],
        miner_pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap(),
        merkle_root: Some(TxMerkleNode::all_zeros()),
        bits: CompactTarget::from_consensus(0x207fffff),
        time: 1700000000,
    }
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

#[cfg(any(test, feature = "test-utils"))]
pub fn test_coinbase_transaction() -> bitcoin::Transaction {
    let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
        .parse::<bitcoin::CompressedPublicKey>()
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
    use bitcoin::TxMerkleNode;

    let (template, _notify, submit, _authorize) = load_valid_stratum_work_components(path);

    let coinbase = test_coinbase_transaction();

    let share_merkle_root: TxMerkleNode =
        bitcoin::merkle_tree::calculate_root([coinbase.clone()].iter().map(|tx| tx.compute_txid()))
            .unwrap()
            .into();

    let mut bitcoin_transactions: Vec<Transaction> = template
        .transactions
        .iter()
        .map(bitcoin::Transaction::from)
        .collect();

    // For the tests use the same coinbase as share block, i.e. using the same pubkey. This is so we don't have empty transactions and end up with a None merkle root.
    bitcoin_transactions.insert(0, coinbase.clone());

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
        miner_pubkey: CompressedPublicKey::from_str(
            "020202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap(),
        merkle_root: share_merkle_root,
        bitcoin_header,
        time: 1700000000u32,
        bits: CompactTarget::from_consensus(0x207fffff),
    };

    ShareBlock {
        header: share_header,
        transactions: vec![ShareTransaction(coinbase)],
        bitcoin_transactions,
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Default)]
pub struct TestShareBlockBuilder {
    bitcoin_block: Option<Block>,
    prev_share_blockhash: Option<String>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<String>,
    transactions: Vec<Transaction>,
    work: Option<u32>,
    nonce: Option<u32>,
    bits: Option<CompactTarget>,
}

#[cfg(any(test, feature = "test-utils"))]
impl TestShareBlockBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bitcoin_header(mut self, bitcoin_block: Block) -> Self {
        self.bitcoin_block = Some(bitcoin_block);
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

    pub fn work(mut self, work: u32) -> Self {
        self.work = Some(work);
        self
    }

    pub fn bits(mut self, bits: CompactTarget) -> Self {
        self.bits = Some(bits);
        self
    }

    pub fn build(self) -> ShareBlock {
        let coinbase = match self.miner_pubkey {
            Some(ref pk) => {
                let pubkey = CompressedPublicKey::from_str(pk).unwrap();
                create_coinbase_transaction(&pubkey, bitcoin::Network::Signet)
            }
            None => test_coinbase_transaction(),
        };
        let all_transactions: Vec<ShareTransaction> = {
            let mut txs = vec![ShareTransaction(coinbase)];
            txs.extend(self.transactions.into_iter().map(ShareTransaction));
            txs
        };
        test_share_block(
            self.bitcoin_block,
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
            self.work,
            self.nonce,
            self.bits,
        )
    }
}

/// Load share headers test data from the JSON fixture file.
#[cfg(test)]
pub fn load_share_headers_test_data() -> serde_json::Value {
    let json_string =
        std::fs::read_to_string("../p2poolv2_tests/test_data/validation/share_headers.json")
            .expect("Failed to read share_headers.json");
    serde_json::from_str(&json_string).unwrap()
}

/// Build a ShareBlock from a header with empty transactions.
#[cfg(test)]
pub fn empty_share_block_from_header(header: ShareHeader) -> ShareBlock {
    ShareBlock {
        header,
        transactions: Vec::new(),
        bitcoin_transactions: Vec::new(),
    }
}

/// Build a ShareBlock with valid PoW from the fixture "valid_header".
#[cfg(test)]
pub fn valid_share_block_from_fixture() -> ShareBlock {
    let test_data = load_share_headers_test_data();
    let header: ShareHeader = serde_json::from_value(test_data["valid_header"].clone()).unwrap();
    ShareBlock {
        header,
        transactions: Vec::new(),
        bitcoin_transactions: Vec::new(),
    }
}

#[cfg(test)]
pub fn multiplied_compact_target_as_work(bits: u32, multiplier: u32) -> bitcoin::Work {
    bitcoin::Target::from_compact(CompactTarget::from_consensus(bits * multiplier)).to_work()
}

#[cfg(any(test, feature = "test-utils"))]
fn test_share_block(
    bitcoin_block: Option<Block>,
    prev_share_blockhash: &str,
    uncles: Vec<BlockHash>,
    miner_pubkey: &str,
    transactions: Vec<ShareTransaction>,
    work: Option<u32>,
    nonce: Option<u32>,
    bits: Option<CompactTarget>,
) -> ShareBlock {
    let coinbase = test_coinbase_transaction();

    let share_merkle_root =
        bitcoin::merkle_tree::calculate_root([coinbase.clone()].iter().map(|tx| tx.compute_txid()))
            .unwrap()
            .into();

    let (bitcoin_header, bitcoin_transactions) = match bitcoin_block {
        Some(block) => (block.header, block.txdata),
        None => (
            Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: share_merkle_root,
                time: 0x01e0377ae,
                bits: CompactTarget::from_consensus(0x01e0377ae),
                nonce: nonce.unwrap_or(0xe9695791),
            },
            vec![coinbase], // list of transactions with a copy of the pool coinbase, just to provide some test data
        ),
    };

    let share_bits = bits.unwrap_or(CompactTarget::from_consensus(
        0x01e0377ae * work.unwrap_or(1),
    ));

    let header = ShareHeader {
        prev_share_blockhash: BlockHash::from_str(prev_share_blockhash).unwrap(),
        uncles,
        miner_pubkey: CompressedPublicKey::from_str(miner_pubkey).unwrap(),
        merkle_root: share_merkle_root,
        bitcoin_header,
        time: 1700000000u32,
        bits: share_bits,
    };

    ShareBlock {
        header,
        transactions,
        bitcoin_transactions,
    }
}

/// Builder for creating test ShareHeader instances
#[cfg(test)]
pub struct TestShareHeaderBuilder {
    prev_share_blockhash: Option<BlockHash>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<CompressedPublicKey>,
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

    pub fn miner_pubkey(mut self, miner_pubkey: CompressedPublicKey) -> Self {
        self.miner_pubkey = Some(miner_pubkey);
        self
    }

    pub fn transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    pub fn build(self) -> ShareHeader {
        let default_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();

        let default_merkle_root = {
            let tx = test_coinbase_transaction();
            bitcoin::merkle_tree::calculate_root(std::iter::once(tx.compute_txid()))
                .unwrap()
                .into()
        };

        let share_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
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
            time: 1700000000u32,
            bits: CompactTarget::from_consensus(0x207fffff),
        }
    }
}
