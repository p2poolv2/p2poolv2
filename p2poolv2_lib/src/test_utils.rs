// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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
use crate::pool_difficulty::PoolDifficulty;
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::extranonce::Extranonce;
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::share_block::{ShareBlock, ShareHeader, ShareTransaction};
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::transactions::coinbase::build_sharechain_coinbase_transaction;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::hashes::Hash;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::{
    Address, Block, BlockHash, CompactTarget, CompressedPublicKey, Transaction, block::Header,
};
#[cfg(any(test, feature = "test-utils"))]
use std::str::FromStr;

// Imports only needed for internal tests
#[cfg(any(test, feature = "test-utils"))]
use crate::accounting::OutputPair;
#[cfg(test)]
use crate::pool_difficulty::MockPoolDifficulty;
#[cfg(test)]
use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
#[cfg(test)]
use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::share_commitment::ShareCommitment;
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::witness_commitment::WitnessCommitment;
#[cfg(test)]
use crate::store::block_tx_metadata::{BlockMetadata, Status};
#[cfg(test)]
use crate::stratum;
#[cfg(test)]
use crate::stratum::messages::Notify;
#[cfg(test)]
use crate::stratum::messages::Response;
#[cfg(test)]
use crate::stratum::messages::SimpleRequest;
#[cfg(test)]
use crate::stratum::work::block_template::BlockTemplate;
#[cfg(any(test, feature = "test-utils"))]
use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
#[cfg(test)]
use crate::stratum::work::gbt::build_merkle_branches_for_template;
#[cfg(test)]
use bitcoin::TxMerkleNode;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::script::PushBytesBuf;
#[cfg(test)]
use rand::{Rng, thread_rng};

/// Well-known secp256k1 compressed public keys (multiples of the generator G).
/// Use these when constructing test share blocks that need distinct, valid miner keys.
#[cfg(any(test, feature = "test-utils"))]
pub const PUBKEY_G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
#[cfg(any(test, feature = "test-utils"))]
pub const PUBKEY_2G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
#[cfg(any(test, feature = "test-utils"))]
pub const PUBKEY_3G: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
#[cfg(any(test, feature = "test-utils"))]
pub const PUBKEY_4G: &str = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";
#[cfg(any(test, feature = "test-utils"))]
pub const PUBKEY_5G: &str = "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4";

#[cfg(any(test, feature = "test-utils"))]
pub fn make_test_address(index: usize) -> Address {
    let pubkey_hex = match index {
        1 => PUBKEY_G,
        2 => PUBKEY_2G,
        3 => PUBKEY_3G,
        4 => PUBKEY_4G,
        _ => panic!("index must be 1-4"),
    };
    let pubkey: bitcoin::CompressedPublicKey = pubkey_hex.parse().unwrap();
    Address::p2wpkh(&pubkey, bitcoin::Network::Regtest)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn test_coinbase_transaction(index: usize) -> bitcoin::Transaction {
    let address = make_test_address(index);
    build_sharechain_coinbase_transaction(&address, &[])
}

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

/// Build a share header with a specific miner pubkey and work level.
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_header(
    prev_hash: &str,
    miner_pubkey: &str,
    work: u32,
) -> crate::shares::share_block::ShareHeader {
    TestShareBlockBuilder::new()
        .prev_share_blockhash(prev_hash.to_string())
        .miner_pubkey(miner_pubkey)
        .work(work)
        .build()
        .header
}

/// Build a share header that references uncles.
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_header_with_uncles(
    prev_hash: &str,
    miner_pubkey: &str,
    work: u32,
    uncles: Vec<BlockHash>,
) -> crate::shares::share_block::ShareHeader {
    TestShareBlockBuilder::new()
        .prev_share_blockhash(prev_hash.to_string())
        .miner_pubkey(miner_pubkey)
        .work(work)
        .uncles(uncles)
        .build()
        .header
}

/// Parse a bitcoin address string into a checked Address for tests.
#[cfg(any(test, feature = "test-utils"))]
pub fn parse_address_from_string(address_str: &str) -> bitcoin::Address {
    address_str
        .parse::<bitcoin::Address<_>>()
        .unwrap()
        .assume_checked()
}

#[cfg(any(test, feature = "test-utils"))]
pub const TEST_ANCHOR_TIME: u32 = 1_700_000_000;

/// On-schedule tip time for height 1: anchor_time + ideal_block_time * (height_delta + 1) = anchor_time + 20
#[cfg(any(test, feature = "test-utils"))]
pub const TEST_TIP_TIME: u32 = TEST_ANCHOR_TIME + 20;

/// Realistic coinbase timestamp for tests: Jan 1 2020 00:00:00 UTC in nanoseconds
#[cfg(any(test, feature = "test-utils"))]
pub const TEST_COINBASE_NSECS: u64 = 1_577_836_800_000_000_000;

/// Build a PoolDifficulty anchored on-schedule so that
/// calculate_target(TEST_TIP_TIME, 1) returns the anchor target (0x1b4188f5).
#[cfg(any(test, feature = "test-utils"))]
pub fn on_schedule_pool_difficulty() -> PoolDifficulty {
    PoolDifficulty::new(
        CompactTarget::from_consensus(0x1b4188f5),
        TEST_ANCHOR_TIME,
        0,
    )
}

/// Set up mock expectations on a MockChainStoreHandle and MockPoolDifficulty
/// for validate_with_pool_difficulty.
///
/// Configures get_share_header and get_block_metadata on the chain
/// store to return a genesis parent at height 0, and calculate_target
/// on the pool difficulty (called with parent_height=0) to return the
/// given target_bits.
#[cfg(test)]
pub fn setup_pool_difficulty_mocks(
    chain_store_handle: &mut MockChainStoreHandle,
    pool_difficulty: &mut MockPoolDifficulty,
    parent_hash: BlockHash,
    target_bits: u32,
) {
    chain_store_handle
        .expect_get_share_header()
        .with(mockall::predicate::eq(parent_hash))
        .returning(move |_| Ok(genesis_for_tests().header));

    chain_store_handle
        .expect_get_block_metadata()
        .with(mockall::predicate::eq(parent_hash))
        .returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: bitcoin::Work::from_hex("0x00").unwrap(),
                status: Status::Confirmed,
            })
        });

    pool_difficulty
        .expect_calculate_target_clamped()
        .returning(move |_, _| CompactTarget::from_consensus(target_bits));
}

#[cfg(test)]
use crate::shares::share_block::MAX_POOL_TARGET;

/// Set up mock expectations on a MockChainStoreHandle for
/// validate_header_chain in handle_share_headers.
///
/// Configures get_genesis_header, get_share_header, and get_block_metadata
/// to return genesis-like data at height 0 with zero chain work. This allows
/// single-header batches with bits = MAX_POOL_TARGET to pass ASERT validation.
#[cfg(test)]
pub fn setup_header_chain_validation_mocks(chain_store_handle: &mut MockChainStoreHandle) {
    let mut genesis_header = genesis_for_tests().header;
    genesis_header.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

    let genesis_for_genesis = genesis_header.clone();
    chain_store_handle
        .expect_get_genesis_header()
        .returning(move || Ok(genesis_for_genesis.clone()));

    let genesis_for_parent = genesis_header.clone();
    chain_store_handle
        .expect_get_share_header()
        .returning(move |_| Ok(genesis_for_parent.clone()));

    chain_store_handle
        .expect_get_block_metadata()
        .returning(|_| {
            Ok(BlockMetadata {
                expected_height: Some(0),
                chain_work: bitcoin::Work::from_hex("0x00").unwrap(),
                status: Status::Confirmed,
            })
        });

    chain_store_handle
        .expect_get_block_metadata_batch()
        .returning(|hashes| {
            hashes
                .iter()
                .map(|hash| {
                    (
                        *hash,
                        BlockMetadata {
                            expected_height: Some(0),
                            chain_work: bitcoin::Work::from_hex("0x00").unwrap(),
                            status: Status::Confirmed,
                        },
                    )
                })
                .collect()
        });
}

#[cfg(test)]
pub fn create_test_commitment() -> ShareCommitment {
    let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
        .parse::<CompressedPublicKey>()
        .unwrap();
    let btcaddress = Address::p2wpkh(&pubkey, bitcoin::Network::Signet);
    ShareCommitment {
        prev_share_blockhash: BlockHash::from_str(
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
        )
        .unwrap(),
        uncles: vec![],
        miner_bitcoin_address: btcaddress,
        // Use signet-easy target so test bitcoin headers can meet pool difficulty.
        // In production, calculate_target_clamped ensures pool target is never
        // harder than bitcoin difficulty.
        bits: CompactTarget::from_consensus(0x1e0377ae),
        time: 1700000000,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        coinbase_value: 100_000_000,
    }
}

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
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
pub fn load_valid_stratum_work_components(
    path: &str,
) -> (BlockTemplate, Notify, SimpleRequest, Response<'static>) {
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
pub fn build_block_from_work_components(path: &str, nsecs: u64) -> ShareBlock {
    let (template, _notify, submit, _authorize) = load_valid_stratum_work_components(path);

    let share_coinbase = test_coinbase_transaction(1);

    let share_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
        [share_coinbase.clone()].iter().map(|tx| tx.compute_txid()),
    )
    .unwrap()
    .into();

    let miner_bitcoin_address = make_test_address(1);

    // Build template (non-coinbase) bitcoin transactions
    let template_transactions: Vec<Transaction> = template
        .transactions
        .iter()
        .map(bitcoin::Transaction::from)
        .collect();

    // Build the share commitment and compute its hash
    let share_commitment = ShareCommitment {
        prev_share_blockhash: BlockHash::all_zeros(),
        uncles: vec![],
        miner_bitcoin_address: miner_bitcoin_address.clone(),
        bits: CompactTarget::from_consensus(0x1b4188f5),
        time: 1700000000u32,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        coinbase_value: template.coinbasevalue,
    };
    let commitment_hash = share_commitment.hash();

    // Build bitcoin coinbase with the commitment hash embedded in scriptSig
    let bitcoin_coinbase = build_bitcoin_coinbase_transaction(
        bitcoin::transaction::Version::TWO,
        &[OutputPair {
            address: miner_bitcoin_address.clone(),
            amount: bitcoin::Amount::from_sat(template.coinbasevalue),
        }],
        template.height as i64,
        PushBytesBuf::from(&[0u8]),
        template
            .default_witness_commitment
            .as_deref()
            .and_then(|hex_str| WitnessCommitment::from_hex(hex_str).ok())
            .as_ref(),
        b"P2Poolv2",
        Some(commitment_hash),
        nsecs,
        Some(Extranonce::default().as_bytes()),
    )
    .expect("Failed to build bitcoin coinbase for test");

    let mut bitcoin_transactions = Vec::with_capacity(template_transactions.len() + 1);
    bitcoin_transactions.push(bitcoin_coinbase);
    bitcoin_transactions.extend(template_transactions);

    let merkle_root = bitcoin::merkle_tree::calculate_root(
        bitcoin_transactions.iter().map(|tx| tx.compute_txid()),
    )
    .unwrap()
    .into();

    let bitcoin_header = Header {
        version: bitcoin::block::Version::from_consensus(template.version),
        prev_blockhash: BlockHash::from_str(&template.previousblockhash).unwrap(),
        merkle_root,
        time: u32::from_str_radix(submit.params[3].as_ref().unwrap(), 16).unwrap(),
        bits: CompactTarget::from_unprefixed_hex(&template.bits).unwrap(),
        nonce: u32::from_str_radix(submit.params[4].as_ref().unwrap(), 16).unwrap(),
    };

    let share_header = ShareHeader {
        prev_share_blockhash: BlockHash::all_zeros(),
        uncles: vec![],
        miner_bitcoin_address,
        merkle_root: share_merkle_root,
        bitcoin_header,
        time: 1700000000u32,
        bits: CompactTarget::from_consensus(0x1b4188f5),
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        coinbase_value: template.coinbasevalue,
        coinbaseaux_flags: template
            .coinbaseaux
            .get("flags")
            .and_then(|flags| hex::decode(flags).ok())
            .map(|bytes| CoinbaseAuxFlags::new(&bytes)),
        witness_commitment: template
            .default_witness_commitment
            .as_deref()
            .and_then(|hex_str| WitnessCommitment::from_hex(hex_str).ok()),
        bitcoin_height: template.height as u64,
        coinbase_nsecs: TEST_COINBASE_NSECS,
        extranonce: Extranonce::default(),
    };

    let template_merkle_branches = build_merkle_branches_for_template(&template)
        .into_iter()
        .map(TxMerkleNode::from_raw_hash)
        .collect();

    ShareBlock {
        header: share_header,
        transactions: vec![ShareTransaction(share_coinbase)],
        template_merkle_branches,
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
    time: Option<u32>,
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

    pub fn miner_pubkey(mut self, pubkey_hex: &str) -> Self {
        self.miner_pubkey = Some(pubkey_hex.to_string());
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

    pub fn time(mut self, time: u32) -> Self {
        self.time = Some(time);
        self
    }

    pub fn with_easy_target(self) -> Self {
        let easy_target = bitcoin::CompactTarget::from_consensus(0x2100ffff);
        self.bits(easy_target)
    }

    pub fn build(self) -> ShareBlock {
        let default_pubkey_hex =
            "020202020202020202020202020202020202020202020202020202020202020202";
        let pubkey_hex = self.miner_pubkey.as_deref().unwrap_or(default_pubkey_hex);
        let pubkey = CompressedPublicKey::from_str(pubkey_hex).unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, bitcoin::Network::Signet);

        let other_share_transactions: Vec<ShareTransaction> = self
            .transactions
            .into_iter()
            .map(ShareTransaction)
            .collect();
        let coinbase =
            build_sharechain_coinbase_transaction(&btcaddress, &other_share_transactions);
        let all_transactions: Vec<ShareTransaction> = {
            let mut txs = Vec::with_capacity(1 + other_share_transactions.len());
            txs.push(ShareTransaction(coinbase));
            txs.extend(other_share_transactions);
            txs
        };
        test_share_block(
            self.bitcoin_block,
            self.prev_share_blockhash
                .unwrap_or(BlockHash::all_zeros().to_string())
                .as_str(),
            self.uncles,
            &btcaddress,
            all_transactions,
            self.work,
            self.nonce,
            self.bits,
            self.time,
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
        template_merkle_branches: vec![],
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
        template_merkle_branches: vec![],
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
    btcaddress: &Address,
    transactions: Vec<ShareTransaction>,
    work: Option<u32>,
    nonce: Option<u32>,
    bits: Option<CompactTarget>,
    time: Option<u32>,
) -> ShareBlock {
    let share_merkle_root =
        bitcoin::merkle_tree::calculate_root(transactions.iter().map(|tx| tx.compute_txid()))
            .unwrap()
            .into();

    let share_bits = bits.unwrap_or(CompactTarget::from_consensus(
        0x01e0377ae * work.unwrap_or(1),
    ));
    let share_time = time.unwrap_or(1700000000u32);
    let prev_blockhash = BlockHash::from_str(prev_share_blockhash).unwrap();

    let (bitcoin_header, _bitcoin_transactions) = match bitcoin_block {
        Some(block) => (block.header, block.txdata),
        None => {
            // Build a commitment matching the share header fields
            let commitment = ShareCommitment {
                prev_share_blockhash: prev_blockhash,
                uncles: uncles.clone(),
                miner_bitcoin_address: btcaddress.clone(),
                bits: share_bits,
                time: share_time,
                donation_address: None,
                donation: None,
                fee_address: None,
                fee: None,
                coinbase_value: 5_000_000_000,
            };

            let bitcoin_coinbase = build_bitcoin_coinbase_transaction(
                bitcoin::transaction::Version::TWO,
                &[OutputPair {
                    address: btcaddress.clone(),
                    amount: bitcoin::Amount::from_sat(5_000_000_000),
                }],
                1,
                PushBytesBuf::from(&[0u8]),
                None,
                b"P2Poolv2",
                Some(commitment.hash()),
                TEST_COINBASE_NSECS,
                None,
            )
            .expect("Failed to build bitcoin coinbase for test");

            let template_merkle_root = bitcoin::merkle_tree::calculate_root(
                [bitcoin_coinbase.clone()]
                    .iter()
                    .map(|tx| tx.compute_txid()),
            )
            .unwrap()
            .into();

            (
                Header {
                    version: bitcoin::block::Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: template_merkle_root,
                    time: 0x01e0377ae,
                    bits: share_bits,
                    nonce: nonce.unwrap_or(0xe9695791),
                },
                vec![bitcoin_coinbase],
            )
        }
    };

    let header = ShareHeader {
        prev_share_blockhash: prev_blockhash,
        uncles,
        miner_bitcoin_address: btcaddress.clone(),
        merkle_root: share_merkle_root,
        bitcoin_header,
        time: share_time,
        bits: share_bits,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        coinbase_value: 5_000_000_000,
        coinbaseaux_flags: None,
        witness_commitment: None,
        bitcoin_height: 1,
        coinbase_nsecs: TEST_COINBASE_NSECS,
        extranonce: Extranonce::default(),
    };

    ShareBlock {
        header,
        transactions,
        template_merkle_branches: vec![],
    }
}

/// Builder for creating test ShareHeader instances
#[cfg(test)]
pub struct TestShareHeaderBuilder {
    prev_share_blockhash: Option<BlockHash>,
    uncles: Vec<BlockHash>,
    btcaddress: Option<Address>,
    transactions: Vec<Transaction>,
}

#[cfg(test)]
impl Default for TestShareHeaderBuilder {
    fn default() -> Self {
        Self {
            prev_share_blockhash: None,
            uncles: Vec::new(),
            btcaddress: None,
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

    pub fn btcaddress(mut self, btcaddress: Address) -> Self {
        self.btcaddress = Some(btcaddress);
        self
    }

    pub fn transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self
    }

    pub fn build(self) -> ShareHeader {
        let default_address = make_test_address(1);

        let default_merkle_root = {
            let tx = test_coinbase_transaction(1);
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
            miner_bitcoin_address: self.btcaddress.unwrap_or(default_address),
            merkle_root: share_merkle_root,
            bitcoin_header: Header {
                version: bitcoin::block::Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: default_merkle_root,
                time: 1700000000u32,
                bits: CompactTarget::from_consensus(0x1b4188f5),
                nonce: 0,
            },
            time: 1700000000u32,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            coinbase_value: 100_000_000,
            coinbaseaux_flags: None,
            witness_commitment: None,
            bitcoin_height: 1,
            coinbase_nsecs: TEST_COINBASE_NSECS,
            extranonce: Extranonce::default(),
        }
    }
}
