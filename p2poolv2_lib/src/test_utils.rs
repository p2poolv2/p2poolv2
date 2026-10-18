// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
use crate::shares::coinbase_proof::CoinbaseProof;
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::share_block::{
    ShareBlock, ShareHeader, ShareTransaction, empty_bitcoin_coinbase,
};
#[cfg(any(test, feature = "test-utils"))]
use crate::shares::transactions::coinbase::build_sharechain_coinbase_transaction;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::hashes::Hash;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::{
    Address, Block, BlockHash, CompactTarget, CompressedPublicKey, Transaction, block::Header,
};
#[cfg(any(test, feature = "test-utils"))]
use p2poolv2_wallet::share_owner::ShareOwner;
#[cfg(any(test, feature = "test-utils"))]
use std::str::FromStr;

// Imports only needed for internal tests
#[cfg(any(test, feature = "test-utils"))]
use crate::accounting::OutputPair;
#[cfg(test)]
use crate::accounting::payout::payout_distribution::build_pplns_outputs;
#[cfg(test)]
use crate::accounting::stats::metrics;
#[cfg(any(test, feature = "test-utils"))]
use crate::address::Address as P2PoolAddress;
#[cfg(test)]
use crate::config::{Chain, PoolMode};
#[cfg(test)]
use crate::config::{StratumConfig, Sv2Authority};
#[cfg(test)]
use crate::pool_difficulty::MockPoolDifficulty;
#[cfg(test)]
use crate::shares::auxpow::{AuxPowProof, AuxiliaryTree, AuxiliaryWork};
#[cfg(test)]
use crate::shares::bch_coinbase::BchCoinbase;
#[cfg(test)]
use crate::shares::chain::chain_store_handle::MockChainStoreHandle;
#[cfg(test)]
use crate::shares::merge_mining::MergeMiningCommitment;
use crate::shares::share_commitment::ShareCommitment;
use crate::shares::transactions::coinbase::compute_witness_root;
#[cfg(test)]
use crate::shares::witness_commitment::WitnessCommitment;
#[cfg(test)]
use crate::store::block_tx_metadata::{BlockMetadata, ChainMembership, Status};
#[cfg(test)]
use crate::stratum;
#[cfg(test)]
use crate::stratum::emission::EmissionReceiver;
#[cfg(test)]
use crate::stratum::messages::Notify;
#[cfg(test)]
use crate::stratum::messages::Response;
#[cfg(test)]
use crate::stratum::messages::SimpleRequest;
#[cfg(test)]
use crate::stratum::server::StratumContext;
#[cfg(test)]
use crate::stratum::session::{EXTRANONCE1_SIZE, EXTRANONCE2_SIZE};
#[cfg(test)]
use crate::stratum::sv2::{Declaration, DeclaredJob, encode_message};
#[cfg(test)]
use crate::stratum::sv2::{NoiseTransport, decode_plain_frames};
#[cfg(test)]
use crate::stratum::work::block_template::BlockTemplate;
#[cfg(test)]
use crate::stratum::work::block_template::TemplateTransaction;
#[cfg(any(test, feature = "test-utils"))]
use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
#[cfg(test)]
use crate::stratum::work::coinbase::{EXTRANONCE_SEPARATOR, build_declared_coinbase};
#[cfg(test)]
use crate::stratum::work::gbt::build_merkle_branches_for_template;
#[cfg(test)]
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
#[cfg(test)]
use crate::stratum::work::prepared_notify::{PreparedNotifyParams, PreparedNotifyParamsBuilder};
#[cfg(test)]
use crate::stratum::work::tracker::start_tracker_actor;
#[cfg(test)]
use binary_sv2::{B064K, B0255, Deserialize, GetSize, Seq0255, Serialize, U256};
#[cfg(test)]
use bitcoin::TxMerkleNode;
#[cfg(test)]
use bitcoin::consensus::{deserialize, serialize};
#[cfg(test)]
use bitcoin::hashes::sha256d;
#[cfg(test)]
use bitcoin::script::Builder;
#[cfg(any(test, feature = "test-utils"))]
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Secp256k1;
#[cfg(test)]
use bitcoindrpc::BitcoindRpcClient;
#[cfg(test)]
use codec_sv2::{
    Decoder, Decrypted, Handshake, NoiseDecoder, NoiseEncoder, TransportDecryptState,
    TransportEncryptState,
};
#[cfg(test)]
use common_messages_sv2::{Protocol, SetupConnection};
#[cfg(test)]
use framing_sv2::framing::SerializedFrame;
#[cfg(test)]
use mining_sv2::{
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_SET_TARGET, SetCustomMiningJob,
};
#[cfg(test)]
use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
#[cfg(test)]
use p2poolv2_wallet::bch_share::BchShareNetwork;
#[cfg(test)]
use rand::{RngExt, rng};
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use template_distribution_sv2::{
    NewTemplateOwned, RequestTransactionDataSuccessOwned, SetNewPrevHashOwned,
};
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use tokio::net::TcpListener;
#[cfg(test)]
use tokio::net::TcpStream;
#[cfg(test)]
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::time::timeout;

/// Reference-codec client for tests of the authenticated SV2 wire exchange.
#[cfg(test)]
pub(crate) struct TestSv2Client {
    stream: TcpStream,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
    encrypt: TransportEncryptState,
    decrypt: Option<TransportDecryptState>,
}

#[cfg(test)]
impl TestSv2Client {
    /// Encode a typed message with the protocol's channel bit before sending.
    pub(crate) async fn send_message<T: Serialize + GetSize>(
        &mut self,
        message_type: u8,
        message: T,
    ) {
        self.send(encode_message(message, message_type).unwrap())
            .await;
    }

    /// Connect and authenticate the server against its configured authority.
    pub(crate) async fn connect(address: SocketAddr, authority_public_key: [u8; 32]) -> Self {
        timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let initiator = Initiator::from_raw_k(authority_public_key).unwrap();
            let (hello, waiting) = Handshake::initiator(initiator).step_0().unwrap();
            let mut encoder = NoiseEncoder::new();
            stream
                .write_all(encoder.encode_handshake(hello).as_ref())
                .await
                .unwrap();
            let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
            stream.read_exact(&mut reply).await.unwrap();
            let (encrypt, decrypt) = waiting.step_2(reply).unwrap().split();
            Self {
                stream,
                encoder,
                decoder: NoiseDecoder::new(),
                encrypt,
                decrypt: Some(decrypt),
            }
        })
        .await
        .expect("SV2 handshake timed out")
    }

    /// Send a frame with a separate first-byte write.
    pub(crate) async fn send(&mut self, frame: Vec<u8>) {
        timeout(Duration::from_secs(5), async {
            let frame = SerializedFrame::<Vec<u8>>::from_bytes(frame).unwrap();
            let wire: Vec<u8> = self
                .encoder
                .encode_transport(frame, &mut self.encrypt)
                .unwrap();
            self.stream.write_all(&wire[..1]).await.unwrap();
            tokio::task::yield_now().await;
            self.stream.write_all(&wire[1..]).await.unwrap();
        })
        .await
        .expect("SV2 write timed out");
    }

    /// Send adjacent encrypted frames in one socket write.
    pub(crate) async fn send_pair(&mut self, first: Vec<u8>, second: Vec<u8>) {
        timeout(Duration::from_secs(5), async {
            let first = SerializedFrame::<Vec<u8>>::from_bytes(first).unwrap();
            let second = SerializedFrame::<Vec<u8>>::from_bytes(second).unwrap();
            let mut wire: Vec<u8> = self
                .encoder
                .encode_transport(first, &mut self.encrypt)
                .unwrap();
            let next: Vec<u8> = self
                .encoder
                .encode_transport(second, &mut self.encrypt)
                .unwrap();
            wire.extend_from_slice(&next);
            self.stream.write_all(&wire).await.unwrap();
        })
        .await
        .expect("SV2 write timed out");
    }

    /// Read the expected message, allowing unsolicited mining job notifications.
    pub(crate) async fn receive(&mut self, expected_type: u8) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            loop {
                self.stream
                    .read_exact(self.decoder.writable())
                    .await
                    .unwrap();
                let state = self.decrypt.take().unwrap();
                match self.decoder.next_transport_frame(state).unwrap() {
                    Decrypted::Frame(mut frame, state) => {
                        self.decrypt = Some(state);
                        if frame.header().msg_type() == expected_type {
                            return frame.payload().to_vec();
                        }
                        assert!(
                            matches!(
                                frame.header().msg_type(),
                                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
                                    | MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB
                                    | MESSAGE_TYPE_NEW_MINING_JOB
                                    | MESSAGE_TYPE_SET_TARGET
                            ),
                            "unexpected SV2 message {} while waiting for {expected_type}",
                            frame.header().msg_type()
                        );
                    }
                    Decrypted::Incomplete(_, state) => self.decrypt = Some(state),
                }
            }
        })
        .await
        .expect("SV2 response timed out")
    }
}

/// Server side of one Stratum V2 test connection, unencrypted or over Noise:
/// a stand-in Template Provider, for example.
#[cfg(test)]
pub(crate) struct TestSv2Server {
    stream: TcpStream,
    noise: Option<NoiseTransport>,
    decoder: Decoder,
    inbox: Vec<u8>,
    received: VecDeque<(u8, Vec<u8>)>,
}

#[cfg(test)]
impl TestSv2Server {
    /// Accept the next connection on `listener`. With `authority`, answer
    /// its Noise handshake signed by that key first.
    pub(crate) async fn accept(listener: &TcpListener, authority: Option<&Sv2Authority>) -> Self {
        timeout(Duration::from_secs(5), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let noise = match authority {
                Some(authority) => Some(
                    NoiseTransport::accept(&mut stream, authority)
                        .await
                        .unwrap(),
                ),
                None => None,
            };
            Self {
                stream,
                noise,
                decoder: Decoder::new(),
                inbox: Vec::new(),
                received: VecDeque::new(),
            }
        })
        .await
        .expect("SV2 test client did not connect")
    }

    /// Send one typed message.
    pub(crate) async fn send_message<T: Serialize + GetSize>(
        &mut self,
        message_type: u8,
        message: T,
    ) {
        let frame = encode_message(message, message_type).unwrap();
        let wire = match self.noise.as_mut() {
            Some(noise) => noise.encrypt(frame).unwrap(),
            None => frame,
        };
        timeout(Duration::from_secs(5), self.stream.write_all(&wire))
            .await
            .expect("SV2 test write timed out")
            .unwrap();
    }

    /// The payload of the client's next message, which must be of
    /// `expected_type`.
    pub(crate) async fn receive(&mut self, expected_type: u8) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            let mut buffer = vec![0u8; 64 * 1024];
            while self.received.is_empty() {
                let count = self.stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0, "SV2 test client closed the connection");
                let messages = match self.noise.as_mut() {
                    Some(noise) => noise.decode(&buffer[..count]).unwrap(),
                    None => {
                        decode_plain_frames(&mut self.decoder, &mut self.inbox, &buffer[..count])
                            .unwrap()
                    }
                };
                self.received.extend(messages);
            }
            let (message_type, payload) = self.received.pop_front().unwrap();
            assert_eq!(message_type, expected_type, "unexpected SV2 message type");
            payload
        })
        .await
        .expect("SV2 test message timed out")
    }
}

/// The `NewTemplate` a Bitcoin Cash Template Provider sends for a BCHN
/// `template`: the specification's height push as the coinbase prefix, no
/// required coinbase outputs, and its transactions' merkle path.
#[cfg(test)]
pub(crate) fn test_tdp_new_template(
    template_id: u64,
    future: bool,
    template: &BlockTemplate,
) -> NewTemplateOwned {
    let prefix = Builder::new()
        .push_int(i64::from(template.height))
        .into_script()
        .into_bytes();
    let merkle_path = build_merkle_branches_for_template(template)
        .unwrap()
        .into_iter()
        .map(|branch| branch.to_byte_array().into())
        .collect::<Vec<_>>();
    NewTemplateOwned {
        template_id,
        future_template: future,
        version: template.version as u32,
        coinbase_tx_version: 2,
        coinbase_prefix: prefix.try_into().unwrap(),
        coinbase_tx_input_sequence: u32::MAX,
        coinbase_tx_value_remaining: template.coinbasevalue,
        coinbase_tx_outputs_count: 0,
        coinbase_tx_outputs: Vec::new().try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: merkle_path.try_into().unwrap(),
    }
}

/// The `SetNewPrevHash` that activates `template_id` for a BCHN `template`.
#[cfg(test)]
pub(crate) fn test_tdp_set_new_prev_hash(
    template_id: u64,
    template: &BlockTemplate,
) -> SetNewPrevHashOwned {
    let prev_hash = BlockHash::from_str(&template.previousblockhash).unwrap();
    let bits = CompactTarget::from_unprefixed_hex(&template.bits).unwrap();
    SetNewPrevHashOwned {
        template_id,
        prev_hash: prev_hash.to_byte_array().into(),
        header_timestamp: template.curtime,
        n_bits: bits.to_consensus(),
        target: bitcoin::Target::from_compact(bits).to_le_bytes().into(),
    }
}

/// `RequestTransactionData.Success` with a BCHN `template`'s transactions.
#[cfg(test)]
pub(crate) fn test_tdp_transaction_data(
    template_id: u64,
    template: &BlockTemplate,
) -> RequestTransactionDataSuccessOwned {
    let transactions = template
        .transactions
        .iter()
        .map(|transaction| hex::decode(&transaction.data).unwrap().try_into().unwrap())
        .collect::<Vec<_>>();
    RequestTransactionDataSuccessOwned {
        template_id,
        excess_data: Vec::new().try_into().unwrap(),
        transaction_list: transactions.try_into().unwrap(),
    }
}

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

/// Share chain address for a well known test pubkey, via the BIP086 tweak.
///
/// The value differs from `make_test_address` for the same index because the
/// taproot output key is not just the pubkey hash, so tests cannot accidentally
/// pass one where the other belongs.
#[cfg(any(test, feature = "test-utils"))]
pub fn make_test_share_address(index: usize, network: bitcoin::Network) -> P2PoolAddress {
    let pubkey_hex = match index {
        1 => PUBKEY_G,
        2 => PUBKEY_2G,
        3 => PUBKEY_3G,
        4 => PUBKEY_4G,
        5 => PUBKEY_5G,
        _ => panic!("index must be 1-5"),
    };
    let pubkey: bitcoin::CompressedPublicKey = pubkey_hex.parse().unwrap();
    let secp = Secp256k1::verification_only();
    P2PoolAddress::from_internal_key(pubkey.0.x_only_public_key().0, None, network, &secp).unwrap()
}

/// The witness program of a well known test share chain address.
///
/// Takes no network, and that is the point: the program is what a
/// `ShareHeader` stores, and it is identical on every network. Anything that
/// needs the bech32m spelling wants [`make_test_share_address`] instead.
#[cfg(any(test, feature = "test-utils"))]
pub fn make_test_share_program(index: usize) -> bitcoin::WitnessProgram {
    make_test_share_address(index, bitcoin::Network::Signet).witness_program()
}

/// A share coinbase for a well known test miner.
///
/// The weak block hash is derived from `index` so that two miners get two
/// distinct coinbases, and so that this helper keeps the property the real
/// coinbase has: its txid is a function of the share, not of the miner alone.
#[cfg(any(test, feature = "test-utils"))]
pub fn test_coinbase_transaction(index: usize) -> bitcoin::Transaction {
    build_sharechain_coinbase_transaction(
        &ShareOwner::Taproot(make_test_share_program(index)),
        BlockHash::from_byte_array([index as u8; 32]),
        &[],
    )
}

/// A non-coinbase, non-witness transaction for template parser checks.
#[cfg(test)]
pub fn bch_template_transaction(index: u32) -> TemplateTransaction {
    let mut transaction = test_coinbase_transaction(1);
    transaction.input[0].previous_output.vout = index;
    transaction.input[0].witness.clear();
    transaction.output.truncate(1);
    let txid = transaction.compute_txid().to_string();
    TemplateTransaction {
        data: bitcoin::consensus::encode::serialize_hex(&transaction),
        txid: txid.clone(),
        hash: txid,
        depends: Vec::new(),
        fee: 0,
        sigops: 0,
        weight: 0,
    }
}

/// A BCH payout snapshot with distinct weights.
#[cfg(test)]
pub fn test_bch_prepared() -> Arc<PreparedNotifyParams> {
    let template: BlockTemplate = serde_json::from_str(include_str!(
        "../../bitcoindrpc/test_data/bchn-regtest-template.json"
    ))
    .unwrap();
    test_bch_prepared_for_template(template)
}

/// Apply the reusable BCH payout snapshot to an externally supplied template.
#[cfg(test)]
pub fn test_bch_prepared_for_template(template: BlockTemplate) -> Arc<PreparedNotifyParams> {
    let first = Address::p2pkh(
        bitcoin::PubkeyHash::from_byte_array([1; 20]),
        bitcoin::Network::Regtest,
    );
    let second = Address::p2pkh(
        bitcoin::PubkeyHash::from_byte_array([2; 20]),
        bitcoin::Network::Regtest,
    );
    let weights = HashMap::from([(first, 1), (second, 3)]);
    let outputs =
        build_pplns_outputs(template.coinbasevalue, &weights, &None, None, &None, None).unwrap();
    Arc::new(
        PreparedNotifyParamsBuilder::new(Arc::new(template), outputs, b"P2Poolv2", true)
            .pplns_weights(Some(weights))
            .prev_share_blockhash(BlockHash::from_byte_array([0x33; 32]))
            .bits(CompactTarget::from_consensus(0x2100ffff))
            .include_merge_mining(true)
            .build()
            .unwrap(),
    )
}

/// Build the client side of a BCH declared job, with miner-chosen aux data.
#[cfg(test)]
pub(crate) fn test_bch_custom_job(
    prepared: Arc<PreparedNotifyParams>,
    token: Vec<u8>,
    transactions: Vec<Transaction>,
    full: bool,
    value: u64,
) -> (Vec<u8>, DeclaredJob) {
    test_bch_custom_job_with_aux(
        prepared,
        token,
        transactions,
        full,
        value,
        MergeMiningCommitment {
            merkle_root: [0x77; 32],
            tree_size: 2,
            nonce: 9,
        },
    )
}

/// A declared job with a caller-selected auxiliary commitment.
#[cfg(test)]
pub(crate) fn test_bch_custom_job_with_aux(
    prepared: Arc<PreparedNotifyParams>,
    token: Vec<u8>,
    transactions: Vec<Transaction>,
    full: bool,
    value: u64,
    merge_mining: MergeMiningCommitment,
) -> (Vec<u8>, DeclaredJob) {
    let template = prepared.template();
    let payout = Address::p2pkh(
        bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
        bitcoin::Network::Regtest,
    );
    let mut commitment =
        ShareCommitment::from_mining_job_token(&token, payout, ShareOwner::CashP2pkh([0x22; 20]))
            .unwrap();
    let descriptor = BchCoinbase {
        prefix: Builder::new()
            .push_int(i64::from(template.height))
            .push_slice(b"miner")
            .into_script()
            .into_bytes(),
        merge_mining,
    };
    commitment.bch_coinbase = Some(descriptor.clone());
    let coinbase = build_declared_coinbase(
        &prepared.declared_outputs(value).unwrap(),
        u64::from(template.height),
        commitment.hash(),
        &EXTRANONCE_SEPARATOR,
        &descriptor,
    )
    .unwrap();
    let bytes = serialize(&coinbase);
    let nonce_offset = 42 + descriptor.prefix.len();
    let declaration = Declaration {
        version: template.version as u32,
        prefix: bytes[..nonce_offset].to_vec(),
        suffix: bytes[nonce_offset + 12..].to_vec(),
    };
    let mut selected = template.as_ref().clone();
    selected.transactions = transactions
        .iter()
        .map(|tx| TemplateTransaction {
            data: hex::encode(serialize(tx)),
            txid: tx.compute_txid().to_string(),
            hash: tx.compute_wtxid().to_string(),
            depends: vec![],
            fee: 0,
            sigops: 0,
            weight: 0,
        })
        .collect();
    let path_hashes = build_merkle_branches_for_template(&selected)
        .unwrap()
        .into_iter()
        .map(|hash| hash.to_byte_array())
        .collect::<Vec<_>>();
    let path = path_hashes
        .iter()
        .map(|hash| U256::new(hash).unwrap())
        .collect();
    let prev_hash = BlockHash::from_str(&template.previousblockhash)
        .unwrap()
        .to_byte_array();
    let outputs = serialize(&coinbase.output);
    let request = SetCustomMiningJob {
        channel_id: 1,
        request_id: 9,
        token: B0255::new(&token).unwrap(),
        version: template.version as u32,
        prev_hash: U256::new(&prev_hash).unwrap(),
        min_ntime: template.curtime,
        nbits: CompactTarget::from_unprefixed_hex(&template.bits)
            .unwrap()
            .to_consensus(),
        coinbase_tx_version: 2,
        coinbase_prefix: B0255::new(&descriptor.prefix).unwrap(),
        coinbase_tx_input_n_sequence: 0xffff_fffe,
        coinbase_tx_outputs: B064K::new(&outputs).unwrap(),
        coinbase_tx_locktime: template.height - 1,
        merkle_path: Seq0255::new(path).unwrap(),
    };
    (
        binary_sv2::to_bytes(request).unwrap(),
        DeclaredJob {
            prepared,
            transactions: full.then(|| Arc::new(transactions)),
            declaration: full.then_some(declaration),
        },
    )
}

/// A mined regtest parent with two selected auxiliary work commitments.
#[cfg(test)]
pub fn test_bch_auxpow() -> (AuxPowProof, AuxiliaryWork) {
    let work = AuxiliaryWork {
        chain_id: 1,
        hash: sha256d::Hash::hash(b"token-A"),
    };
    let other = AuxiliaryWork {
        chain_id: 2,
        hash: sha256d::Hash::hash(b"token-B"),
    };
    let tree = AuxiliaryTree::build(&[work, other], 0).unwrap();
    let prepared = test_bch_prepared();
    let token = prepared
        .mining_job_token([1; 32], prepared.template().curtime)
        .unwrap();
    let value = prepared.template().coinbasevalue;
    let (mut request, _) =
        test_bch_custom_job_with_aux(prepared, token, vec![], false, value, tree.commitment);
    let request = SetCustomMiningJob::from_bytes(&mut request).unwrap();
    (
        AuxPowProof {
            parent_header: test_bch_solve_custom_job(&request, &[1; 4]),
            coinbase: test_bch_custom_coinbase(&request, &[1; 4]),
            coinbase_branch: vec![],
            auxiliary: tree.proofs[0].clone(),
        },
        work,
    )
}

/// Disposable BCH mining context; keep the returned directories alive until the test ends.
#[cfg(test)]
pub(crate) async fn test_bch_stratum_context(
    rpc_url: &str,
) -> (StratumContext, EmissionReceiver, [TempDir; 2]) {
    let (emissions_tx, emissions_rx) = mpsc::channel(10);
    let stats_dir = tempdir().unwrap();
    let metrics = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
        .await
        .unwrap();
    let (chain_store_handle, store_dir) = setup_test_chain_store_handle(true).await;
    let ctx = StratumContext {
        tracker_handle: start_tracker_actor(),
        bitcoindrpc_client: BitcoindRpcClient::new(rpc_url, "user", "pass").unwrap(),
        start_difficulty: 1,
        minimum_difficulty: 1,
        maximum_difficulty: None,
        ignore_difficulty: true,
        validate_addresses: true,
        emissions_tx,
        network: bitcoin::Network::Regtest,
        metrics,
        chain_store_handle,
        mode: PoolMode::P2poolv2,
        miner_address: None,
        share_chain: Chain::BitcoinCash,
        bch_share_network: Some(BchShareNetwork::Regtest),
        cash_share: Some([0x22; 20]),
        template_refresh_tx: None,
    };
    (ctx, emissions_rx, [stats_dir, store_dir])
}

#[cfg(test)]
pub fn test_sv2_setup(protocol: Protocol, flags: u32) -> SetupConnection<'static> {
    SetupConnection {
        protocol,
        min_version: 2,
        max_version: 2,
        flags,
        endpoint_host: "127.0.0.1".try_into().unwrap(),
        endpoint_port: 0,
        vendor: "p2poolv2".try_into().unwrap(),
        hardware_version: "test".try_into().unwrap(),
        firmware: "test".try_into().unwrap(),
        device_id: "".try_into().unwrap(),
    }
}

/// Public disposable authority vectors, never an operator's signing key.
#[cfg(test)]
pub fn test_sv2_authority() -> Sv2Authority {
    let mut config = StratumConfig::new_for_test_default();
    config.sv2_port = Some(3336);
    config.sv2_authority_public_key =
        Some("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan".to_string());
    config.sv2_authority_secret_key =
        Some("zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi".to_string());
    config.parse().unwrap().sv2_authority().unwrap()
}

/// Reconstruct the declared coinbase with a zero-filled downstream extranonce.
#[cfg(test)]
pub fn test_bch_custom_coinbase(
    request: &SetCustomMiningJob,
    extranonce_prefix: &[u8],
) -> Transaction {
    let mut script = request.coinbase_prefix.as_bytes().to_vec();
    script.extend_from_slice(extranonce_prefix);
    script.extend_from_slice(&[0; 8]);
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_consensus(request.coinbase_tx_locktime),
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(script),
            sequence: bitcoin::Sequence(request.coinbase_tx_input_n_sequence),
            witness: bitcoin::Witness::new(),
        }],
        output: deserialize(request.coinbase_tx_outputs.as_bytes()).unwrap(),
    }
}

/// Reconstruct and solve the declared regtest header as an extended-channel miner.
#[cfg(test)]
pub fn test_bch_solve_custom_job(request: &SetCustomMiningJob, extranonce_prefix: &[u8]) -> Header {
    let coinbase = test_bch_custom_coinbase(request, extranonce_prefix);
    let branches = request
        .merkle_path
        .iter()
        .map(|hash| TxMerkleNode::from_byte_array(*hash.as_array()))
        .collect::<Vec<_>>();
    let mut header = Header {
        version: bitcoin::block::Version::from_consensus(request.version as i32),
        prev_blockhash: BlockHash::from_byte_array(*request.prev_hash.as_array()),
        merkle_root: compute_merkle_root_from_branches(coinbase.compute_txid(), &branches),
        time: request.min_ntime,
        bits: CompactTarget::from_consensus(request.nbits),
        nonce: 0,
    };
    while !bitcoin::Target::from_compact(header.bits).is_met_by(header.block_hash()) {
        header.nonce = header.nonce.checked_add(1).unwrap();
        assert!(
            header.nonce < 10000,
            "fixture must use the easy regtest target"
        );
    }
    header
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
                status: Status::BlockValid,
                chain: ChainMembership::Confirmed,
            })
        });

    pool_difficulty
        .expect_calculate_target_clamped()
        .returning(move |_, _| CompactTarget::from_consensus(target_bits));
    pool_difficulty
        .expect_target_ceiling()
        .return_const(CompactTarget::from_consensus(MAX_POOL_TARGET));
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
                status: Status::BlockValid,
                chain: ChainMembership::Confirmed,
            })
        });

    chain_store_handle
        .expect_get_block_metadata_batch()
        .returning(|hashes| {
            Ok(hashes
                .iter()
                .map(|hash| {
                    (
                        *hash,
                        BlockMetadata {
                            expected_height: Some(0),
                            chain_work: bitcoin::Work::from_hex("0x00").unwrap(),
                            status: Status::BlockValid,
                            chain: ChainMembership::Confirmed,
                        },
                    )
                })
                .collect())
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
        miner_address: make_test_share_program(1).into(),
        share_witness_root: compute_witness_root(&[]),
        // Use signet-easy target so test bitcoin headers can meet pool difficulty.
        // In production, calculate_target_clamped ensures pool target is never
        // harder than bitcoin difficulty.
        bits: CompactTarget::from_consensus(0x1e0377ae),
        time: 1700000000,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        bch_coinbase: None,
    }
}

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
    let mut rng = rng();
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
) -> (
    BlockTemplate,
    Notify,
    SimpleRequest<'static>,
    Response<'static>,
) {
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

    let miner_bitcoin_address = make_test_address(1);

    // Build template (non-coinbase) bitcoin transactions
    let template_transactions = template.decode_transactions().unwrap();

    // Build the share commitment and compute its hash
    let share_commitment = ShareCommitment {
        prev_share_blockhash: BlockHash::all_zeros(),
        uncles: vec![],
        miner_bitcoin_address: miner_bitcoin_address.clone(),
        miner_address: make_test_share_program(1).into(),
        share_witness_root: compute_witness_root(&[]),
        bits: CompactTarget::from_consensus(0x1b4188f5),
        time: 1700000000u32,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        bch_coinbase: None,
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
        Some(&[0u8; EXTRANONCE1_SIZE + EXTRANONCE2_SIZE]),
    )
    .expect("Failed to build bitcoin coinbase for test");
    let coinbase_proof = CoinbaseProof::from_coinbase(&bitcoin_coinbase, compute_witness_root(&[]))
        .expect("Failed to build coinbase proof for test");

    let mut bitcoin_transactions = Vec::with_capacity(template_transactions.len() + 1);
    bitcoin_transactions.push(bitcoin_coinbase.clone());
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
        miner_address: make_test_share_program(1).into(),
        bitcoin_header,
        time: 1700000000u32,
        bits: CompactTarget::from_consensus(0x1b4188f5),
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        bitcoin_height: template.height as u64,
        coinbase_proof,
        bch_coinbase: None,
    };

    let template_merkle_branches = build_merkle_branches_for_template(&template)
        .unwrap()
        .into_iter()
        .map(TxMerkleNode::from_raw_hash)
        .collect();

    ShareBlock {
        header: share_header,
        transactions: vec![ShareTransaction(share_coinbase)],
        template_merkle_branches,
        bitcoin_coinbase,
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Default)]
pub struct TestShareBlockBuilder {
    bitcoin_block: Option<Block>,
    prev_share_blockhash: Option<String>,
    uncles: Vec<BlockHash>,
    miner_pubkey: Option<String>,
    share_owner: Option<ShareOwner>,
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

    /// Use this share owner instead of the taproot owner derived from the
    /// miner pubkey, e.g. a Bitcoin Cash P2PKH owner.
    pub fn share_owner(mut self, share_owner: ShareOwner) -> Self {
        self.share_owner = Some(share_owner);
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
        let secp = Secp256k1::verification_only();
        let share_owner = self.share_owner.unwrap_or_else(|| {
            P2PoolAddress::from_internal_key(
                pubkey.0.x_only_public_key().0,
                None,
                bitcoin::Network::Signet,
                &secp,
            )
            .unwrap()
            .witness_program()
            .into()
        });

        // The share coinbase is built inside test_share_block, not here: it
        // carries the weak block hash, so it cannot exist until the bitcoin
        // header does. Hand over the non-coinbase transactions only.
        let other_share_transactions: Vec<ShareTransaction> = self
            .transactions
            .into_iter()
            .map(ShareTransaction)
            .collect();
        test_share_block(
            self.bitcoin_block,
            self.prev_share_blockhash
                .unwrap_or(BlockHash::all_zeros().to_string())
                .as_str(),
            self.uncles,
            &btcaddress,
            &share_owner,
            other_share_transactions,
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

/// Wrap headers in a `ShareHeaderBatch` where every header has an empty
/// coinbase merkle branch: the branch of a block template holding only the
/// coinbase, as every `TestShareBlockBuilder` block is.
#[cfg(test)]
pub fn share_header_batch_with_empty_branches(
    headers: Vec<ShareHeader>,
) -> crate::node::messages::ShareHeaderBatch {
    crate::node::messages::ShareHeaderBatch::from_headers_with_branches(
        headers
            .into_iter()
            .map(|header| (header, Vec::new()))
            .collect(),
    )
}

/// Build a ShareBlock from a header with empty transactions.
#[cfg(test)]
pub fn empty_share_block_from_header(header: ShareHeader) -> ShareBlock {
    ShareBlock {
        header,
        transactions: Vec::new(),
        template_merkle_branches: vec![],
        bitcoin_coinbase: empty_bitcoin_coinbase(),
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
        bitcoin_coinbase: empty_bitcoin_coinbase(),
    }
}

#[cfg(test)]
pub fn multiplied_compact_target_as_work(bits: u32, multiplier: u32) -> bitcoin::Work {
    bitcoin::Target::from_compact(CompactTarget::from_consensus(bits * multiplier)).to_work()
}

#[cfg(any(test, feature = "test-utils"))]
#[allow(clippy::too_many_arguments)] // wiring constructor: each parameter is a distinct collaborator, a params struct would only move the list
fn test_share_block(
    bitcoin_block: Option<Block>,
    prev_share_blockhash: &str,
    uncles: Vec<BlockHash>,
    btcaddress: &Address,
    share_owner: &ShareOwner,
    other_share_transactions: Vec<ShareTransaction>,
    work: Option<u32>,
    nonce: Option<u32>,
    bits: Option<CompactTarget>,
    time: Option<u32>,
) -> ShareBlock {
    let share_bits = bits.unwrap_or(CompactTarget::from_consensus(
        0x01e0377ae * work.unwrap_or(1),
    ));
    let share_time = time.unwrap_or(1700000000u32);
    let prev_blockhash = BlockHash::from_str(prev_share_blockhash).unwrap();

    let (bitcoin_header, coinbase_proof, bitcoin_coinbase) = match bitcoin_block {
        // A caller-supplied bitcoin block has no share commitment in its
        // coinbase, so there is nothing for a proof to show.
        Some(block) => {
            let bitcoin_coinbase = block
                .txdata
                .first()
                .cloned()
                .unwrap_or_else(empty_bitcoin_coinbase);
            (block.header, CoinbaseProof::default(), bitcoin_coinbase)
        }
        None => {
            // Build a commitment matching the share header fields. Both the
            // owner and the share witness root are taken from what this block
            // actually carries: they are digested now, so a builder that
            // hardcoded either would produce blocks that fail
            // validate_bitcoin_coinbase for a reason unrelated to the test.
            let commitment = ShareCommitment {
                prev_share_blockhash: prev_blockhash,
                uncles: uncles.clone(),
                miner_bitcoin_address: btcaddress.clone(),
                miner_address: *share_owner,
                share_witness_root: compute_witness_root(&other_share_transactions),
                bits: share_bits,
                time: share_time,
                donation_address: None,
                donation: None,
                fee_address: None,
                fee: None,
                bch_coinbase: None,
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
            let coinbase_proof = CoinbaseProof::from_coinbase(
                &bitcoin_coinbase,
                compute_witness_root(&other_share_transactions),
            )
            .expect("Failed to build coinbase proof for test");

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
                coinbase_proof,
                bitcoin_coinbase,
            )
        }
    };

    // The coinbase can only be built now, once the bitcoin header exists,
    // and the share merkle root only after that.
    let share_coinbase = build_sharechain_coinbase_transaction(
        share_owner,
        bitcoin_header.block_hash(),
        &other_share_transactions,
    );
    let mut transactions = Vec::with_capacity(1 + other_share_transactions.len());
    transactions.push(ShareTransaction(share_coinbase));
    transactions.extend(other_share_transactions);

    let header = ShareHeader {
        prev_share_blockhash: prev_blockhash,
        uncles,
        miner_bitcoin_address: btcaddress.clone(),
        miner_address: *share_owner,
        bitcoin_header,
        time: share_time,
        bits: share_bits,
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        bitcoin_height: 1,
        coinbase_proof,
        bch_coinbase: None,
    };

    ShareBlock {
        header,
        transactions,
        template_merkle_branches: vec![],
        bitcoin_coinbase,
    }
}

/// Builder for creating test ShareHeader instances
#[cfg(test)]
#[derive(Default)]
pub struct TestShareHeaderBuilder {
    prev_share_blockhash: Option<BlockHash>,
    uncles: Vec<BlockHash>,
    btcaddress: Option<Address>,
    transactions: Vec<Transaction>,
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
        let share_address = make_test_share_program(1);

        let default_merkle_root = {
            let tx = test_coinbase_transaction(1);
            bitcoin::merkle_tree::calculate_root(std::iter::once(tx.compute_txid()))
                .unwrap()
                .into()
        };

        ShareHeader {
            prev_share_blockhash: self.prev_share_blockhash.unwrap_or(BlockHash::all_zeros()),
            uncles: self.uncles,
            miner_bitcoin_address: self.btcaddress.unwrap_or(default_address),
            miner_address: share_address.into(),
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
            bitcoin_height: 1,
            coinbase_proof: CoinbaseProof::default(),
            bch_coinbase: None,
        }
    }
}

// Bitcoin Cash share-transfer fixtures, signed offline by BCHN 29.2.0
// `bitcoin-tx -regtest` with one key over two P2PKH prevouts (0.0005 and
// 0.0007 BCH): input 0 spends 1111...:0 and input 1 spends 2222...:3 with
// sequence 0xfffffffe; the outputs pay 0.0006 BCH back to the key and
// 0.00005 BCH to OP_RETURN. `-signschnorr` picked the algorithm and
// `sign=` the sighash flags.
pub const BCH_TRANSFER_SCRIPT_PUBKEY: &str = "76a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac";
pub const BCH_TRANSFER_UNCOMPRESSED_SCRIPT_PUBKEY: &str =
    "76a914dd51b25d7d8555950a798d7d8b43ca4e91d809d788ac";
pub const BCH_TRANSFER_SCHNORR_ALL: &str = "02000000021111111111111111111111111111111111111111111111111111111111111111000000006441a7db708a74008fe9d8648cebd1dddc5228e223740a9d5111ea3d6b64e40f37516eb0c0ae302e2d8a7da875c1bce28ae1a99a7d0ee1388c010f62660575977b294121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff22222222222222222222222222222222222222222222222222222222222222220300000064412bb20123b4c8dc8a47287e101eff575e794032ad523f82161280c45980ec8c741ce7fada51c1a5aa18b5617753bcbff82383ffcda9162ff8f8f2ff7562dca5014121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
pub const BCH_TRANSFER_ECDSA_ALL: &str = "02000000021111111111111111111111111111111111111111111111111111111111111111000000006a473044022018e8ab413053a477071eef973bb34ff98f000dd2f95c5abd7fbe5dda070b3b650220325cc7dfd298c5ab0347021fe81031a758fceff3299be8bf3c5d1ae7051e1ccc4121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff2222222222222222222222222222222222222222222222222222222222222222030000006a47304402204ff01a81fd940b1306cd190af1259a0a6a32c81ebabd6e4f2c3eca13aeae40250220749bfcdcd0241f451e18fb8cbbf0041c997871029375646e4570340f8721a7de4121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
pub const BCH_TRANSFER_ECDSA_NONE: &str = "02000000021111111111111111111111111111111111111111111111111111111111111111000000006a473044022057a0ab386933ce006dad50f9a61cea75315fb814209d9a9bf38b5d6ae080c8e702204f772c32edd5db0bf75fbcbcf502af91dd698924fcbbde8422fe3e5e4438776e4221036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff2222222222222222222222222222222222222222222222222222222222222222030000006a47304402204fd375682769d1d7eba1b9928c9893d137793daa5e969080f53fd10559f8d54702202c2f8a84b6288989c1364b8b5fb57d1af4c7ae2022a5ff650fa816a532eb26c44221036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
pub const BCH_TRANSFER_SCHNORR_SINGLE: &str = "020000000211111111111111111111111111111111111111111111111111111111111111110000000064414c3dded8448f9912dd5096ff7a49f6db55943b90459b3794a84f2d3d201c4655987cbbc2c02ffb65f41c41d113acbc34cf4e3b0844195461547abd3cd8fc3c684321036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff2222222222222222222222222222222222222222222222222222222222222222030000006441bd96640b54aee4b000a9767ec44c3fc42a16cf6ef90ae9dadf455b7030e52e7f6c385ed8e8a19c03af48e0ddc085d3c7ea6693e75b3c81251546a7c5306eeaff4321036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
pub const BCH_TRANSFER_SCHNORR_ALL_ANYONE_CAN_PAY: &str = "0200000002111111111111111111111111111111111111111111111111111111111111111100000000644116f79dd7e52c183fbf37136d0a9baec22b915470b500faa240c699af355d14ef9fe03f6fa83c2e0303aa52bcf23dea93fc3487d7385a1f256f09781fe49d22bec121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff22222222222222222222222222222222222222222222222222222222222222220300000064414efa2637e15d9e6ba98bce5af2e89b90a84ac83024361e15be64eba6f60d63f6483d045f92fefc3493ad75ddef41005086ae9e994c32100d033789bd19abcf0ec121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
pub const BCH_TRANSFER_ECDSA_ALL_UNCOMPRESSED: &str = "02000000021111111111111111111111111111111111111111111111111111111111111111000000008a473044022066a79aa34efe00584fe13319e68a2603b5b4515b1ec2d487501a0c5d2c6ccf64022062f4b2705fcc4a6559ec55014a557de89affd28d3bf2873f61177bfb4db5e24d4141046abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d173739060b128a9b4ede8c494a88d554185050346e2c84b04ff981f6fec341ac2be26975ffffffff2222222222222222222222222222222222222222222222222222222222222222030000008a473044022012df0d62b17324dbac449f4ccf42245516618df5622eda534959d0f40b6b9770022067edab590f53ac818f3b2c404b97e38da7c9433feb418e943c8390ca206547274141046abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d173739060b128a9b4ede8c494a88d554185050346e2c84b04ff981f6fec341ac2be26975feffffff0260ea0000000000001976a914dd51b25d7d8555950a798d7d8b43ca4e91d809d788ac8813000000000000016a00000000";
pub const BCH_TRANSFER_SCHNORR_ALL_UNCOMPRESSED: &str = "0200000002111111111111111111111111111111111111111111111111111111111111111100000000844162e08427e8d97160b476e4f2ee0a9f6fb2b675addabea4c4befa923fb81a606db0d99d342a0906efe6928c04f654ef01e11f0caad52c34323e08f57451d8fe684141046abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d173739060b128a9b4ede8c494a88d554185050346e2c84b04ff981f6fec341ac2be26975ffffffff22222222222222222222222222222222222222222222222222222222222222220300000084412e1d0273dbbde057a37537be3b250e3df71d539199782f8f05d1302874d5a5476a4845df7ac89b5fd166ad590b50b888a5db50f13a305b8348f4368a2688f6fd4141046abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d173739060b128a9b4ede8c494a88d554185050346e2c84b04ff981f6fec341ac2be26975feffffff0260ea0000000000001976a914dd51b25d7d8555950a798d7d8b43ca4e91d809d788ac8813000000000000016a00000000";
/// Same transaction signed with plain SIGHASH_ALL, as a Bitcoin wallet would.
pub const BCH_TRANSFER_ECDSA_ALL_WITHOUT_FORK_ID: &str = "02000000021111111111111111111111111111111111111111111111111111111111111111000000006a473044022079405c5f28850faaaaba9334004ed4bdda2acf6eaa0d1ab299eb4cf1436e960c022032061ddfa3a47ef57623afda44eaed3cab0b18b35fa144e09610433463b43ce90121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906ffffffff2222222222222222222222222222222222222222222222222222222222222222030000006a47304402203cb29b30ad15f9df714e36f912400a167f790fdd1b46294bf26d0c6412aa2b06022040e76dc10848070ab48ef64f88ab4b3f90e8d2f9a96bccf5df77fb7bdebcb26c0121036abbb610b315c17ddc6ab3f855f02bc6ac95690dee2b1ff88da99b6d17373906feffffff0260ea0000000000001976a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7488ac8813000000000000016a00000000";
