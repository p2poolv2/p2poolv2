// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stratum V2 Template Distribution client: block templates from a Template
//! Provider instead of the node's `getblocktemplate`.
//!
//! The node connects to the configured provider, over Noise when the
//! provider's authority key is pinned, sets up the Template Distribution
//! Protocol and declares in `CoinbaseOutputConstraints` the most coinbase
//! output bytes it can ever add. The provider then sends `NewTemplate` and
//! `SetNewPrevHash`, and the node asks for each template's transactions with
//! `RequestTransactionData`. Once a template's parent and transactions are
//! both known it becomes a [`BlockTemplate`], passes the checks a BCHN
//! template passes (CTOR, no witness data, target and bits), and goes to the
//! notifier exactly as a template fetched over RPC does. SV1 and SV2 jobs,
//! share emission and PPLNS payouts therefore do not change.
//!
//! A block found on a provided template goes back with `SubmitSolution`.
//! The protocol has no reply to it, so whenever the provider cannot take the
//! solution (its connection is gone, or the coinbase does not fit the
//! message) the block goes to the node over RPC instead.
//!
//! The coinbase is the share chain's: version 2, input sequence `0xfffffffe`
//! and lock time height - 1, which peers check when they validate a share. A
//! provider's own values for these fields are only logged; Bitcoin Cash
//! accepts any. The provider's `coinbase_prefix` is checked: it must be the
//! minimal BIP34 height push this coinbase starts with, written as the push
//! (the specification's form) or as the pushed bytes alone (the form
//! bchn-sv2-bridge sends, which checks submissions against the push). The
//! height comes from the node over RPC, as the parent's height plus one, so a
//! provider on another chain than the node's gets no work mined.
//!
//! Only Bitcoin Cash templates are mapped: a provider that requires coinbase
//! outputs (a Bitcoin provider's segwit commitment) is refused.

use super::noise::NoiseTransport;
use super::session::{decode_plain_frames, encode_frame};
use crate::config::{BitcoinCashNetwork, TemplateProvider};
use crate::stratum::message_handlers::submit::submit_block;
use crate::stratum::work::block_template::{BlockTemplate, TemplateTransaction};
use crate::stratum::work::error::WorkError;
use crate::stratum::work::gbt::build_merkle_branches_for_template;
use crate::stratum::work::notify::{NotifyCmd, NotifySender};
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use binary_sv2::{B064K, Deserialize};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Target, Transaction};
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use codec_sv2::Decoder;
use common_messages_sv2::{
    MESSAGE_TYPE_RECONNECT, MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, Reconnect, SetupConnection,
    SetupConnectionError,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use template_distribution_sv2::{
    CoinbaseOutputConstraints, MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION, NewTemplate, RequestTransactionData, RequestTransactionDataError,
    RequestTransactionDataSuccess, SetNewPrevHash, SubmitSolution,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

/// Template Distribution Protocol version this client speaks.
const PROTOCOL_VERSION: u16 = 2;

/// Largest coinbase `SubmitSolution` can carry: its `coinbase_tx` is a B0_64K.
const MAX_SUBMITTED_COINBASE: u32 = 65_535;

/// Coinbase bytes outside its outputs when its script is the 100 bytes a
/// provider must assume: version 4, input count 1, previous output 36,
/// script length 1, script 100, sequence 4 and lock time 4.
const COINBASE_WITHOUT_OUTPUTS: u32 = 150;

/// Bytes of the largest output count the coinbase can need, a CompactSize.
/// The provider accounts for it itself, so it is not part of the reserve.
const OUTPUT_COUNT_SIZE: u32 = 3;

/// `coinbase_output_max_additional_size`: every output byte of the largest
/// coinbase `SubmitSolution` can carry. The PPLNS payouts grow with the
/// miners in the window, so the node declares this bound once instead of a
/// size that a later template could outgrow.
pub(crate) const COINBASE_OUTPUT_RESERVE: u32 =
    MAX_SUBMITTED_COINBASE - COINBASE_WITHOUT_OUTPUTS - OUTPUT_COUNT_SIZE;

/// Size of a P2PKH output: the smallest output this coinbase pays that has a
/// signature operation. P2SH payouts and the OP_RETURN commitments have none.
const P2PKH_OUTPUT_SIZE: u32 = 34;

/// `coinbase_output_max_additional_sigops`: one legacy sigop for every P2PKH
/// payout that fits the reserve.
pub(crate) const COINBASE_OUTPUT_SIGOPS: u16 = (COINBASE_OUTPUT_RESERVE / P2PKH_OUTPUT_SIZE) as u16;

/// Block bytes per SigCheck a Bitcoin Cash block may use.
const BYTES_PER_SIGCHECK: u32 = 141;

/// Block header bytes plus the largest transaction count CompactSize.
const HEADER_AND_COUNT_SIZE: u32 = 80 + 9;

/// Templates kept while they wait for their transactions or their
/// `SetNewPrevHash`. Template ids only grow, so the oldest go first.
const MAX_PENDING_TEMPLATES: usize = 16;

/// Found blocks queued for one provider connection.
const SOLUTION_QUEUE: usize = 16;

/// How long the provider has to answer `SetupConnection`.
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// First wait before reconnecting to the provider; it doubles up to
/// [`MAX_RECONNECT_DELAY`] while connections keep failing.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

/// A provider can hear of a block a moment before the node does, so the
/// parent's height is asked for this many times, this far apart.
const HEIGHT_ATTEMPTS: u32 = 10;
const HEIGHT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Bytes read from the provider socket at a time.
const READ_BUFFER_SIZE: usize = 64 * 1024;

/// A block found on a provided template, on its way back to the provider.
#[derive(Debug)]
pub(crate) struct Solution {
    template_id: u64,
    /// Height of the block, the provided template's.
    height: u64,
    block: Block,
}

/// A template that came from a Template Provider, and the way back to the
/// provider connection that sent it.
#[derive(Debug, Clone)]
pub struct ProvidedTemplate {
    template_id: u64,
    height: u64,
    solutions: mpsc::Sender<Solution>,
}

impl ProvidedTemplate {
    /// Queue `block` for the provider connection that sent this template.
    ///
    /// Gives the block back when that connection has closed or its queue is
    /// full, so the caller can submit it over RPC instead.
    #[cfg_attr(feature = "sim", allow(dead_code))]
    pub(crate) fn submit(&self, block: Block) -> Result<(), Block> {
        self.solutions
            .try_send(Solution {
                template_id: self.template_id,
                height: self.height,
                block,
            })
            .map_err(|refused| refused.into_inner().block)
    }
}

/// The provider's latest `SetNewPrevHash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProviderTip {
    template_id: u64,
    prev_hash: BlockHash,
    header_timestamp: u32,
    bits: u32,
    /// Little-endian, as the message carries it.
    target: [u8; 32],
}

/// A `NewTemplate` kept until it can be mined.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AnnouncedTemplate {
    template_id: u64,
    future: bool,
    version: u32,
    coinbase_tx_version: u32,
    coinbase_prefix: Vec<u8>,
    coinbase_tx_input_sequence: u32,
    coinbase_value: u64,
    coinbase_outputs_count: u32,
    coinbase_outputs: Vec<u8>,
    coinbase_tx_locktime: u32,
    merkle_path: Vec<[u8; 32]>,
    /// `None` until `RequestTransactionData.Success` arrives.
    transactions: Option<Vec<Transaction>>,
}

impl AnnouncedTemplate {
    fn from_message(message: &NewTemplate<'_>) -> Self {
        let merkle_path = message
            .merkle_path
            .iter()
            .map(|branch| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(branch.as_bytes());
                bytes
            })
            .collect::<Vec<_>>();
        // A template with no merkle path has no transactions to ask for.
        let transactions = merkle_path.is_empty().then(Vec::new);
        Self {
            template_id: message.template_id,
            future: message.future_template,
            version: message.version,
            coinbase_tx_version: message.coinbase_tx_version,
            coinbase_prefix: message.coinbase_prefix.as_bytes().to_vec(),
            coinbase_tx_input_sequence: message.coinbase_tx_input_sequence,
            coinbase_value: message.coinbase_tx_value_remaining,
            coinbase_outputs_count: message.coinbase_tx_outputs_count,
            coinbase_outputs: message.coinbase_tx_outputs.as_bytes().to_vec(),
            coinbase_tx_locktime: message.coinbase_tx_locktime,
            merkle_path,
            transactions,
        }
    }
}

/// A template whose parent and transactions are both known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadyTemplate {
    announced: AnnouncedTemplate,
    tip: ProviderTip,
}

/// What handling one provider message asks the connection to do.
#[derive(Debug, PartialEq, Eq)]
enum SessionAction {
    /// Send this unencrypted frame to the provider.
    Send(Vec<u8>),
    /// Map this template and hand it to the notifier.
    Ready(ReadyTemplate),
    /// The provider's `Reconnect`: an empty host or a zero port mean its own.
    Reconnect { host: String, port: u16 },
}

/// The Template Distribution state of one provider connection, without I/O.
#[derive(Default)]
struct ProviderSession {
    tip: Option<ProviderTip>,
    pending: BTreeMap<u64, AnnouncedTemplate>,
}

impl ProviderSession {
    /// Handle one message from the provider.
    ///
    /// A malformed message is an error, which ends the connection. Messages
    /// this client does not use are ignored.
    fn on_message(
        &mut self,
        message_type: u8,
        payload: &mut [u8],
    ) -> Result<Vec<SessionAction>, String> {
        match message_type {
            MESSAGE_TYPE_NEW_TEMPLATE => {
                let message =
                    NewTemplate::from_bytes(payload).map_err(|error| format!("{error:?}"))?;
                self.on_new_template(&message)
            }
            MESSAGE_TYPE_SET_NEW_PREV_HASH => {
                let message =
                    SetNewPrevHash::from_bytes(payload).map_err(|error| format!("{error:?}"))?;
                Ok(self.on_set_new_prev_hash(&message))
            }
            MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS => {
                let message = RequestTransactionDataSuccess::from_bytes(payload)
                    .map_err(|error| format!("{error:?}"))?;
                Ok(self.on_transactions(&message))
            }
            MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR => {
                let message = RequestTransactionDataError::from_bytes(payload)
                    .map_err(|error| format!("{error:?}"))?;
                self.on_transaction_error(&message);
                Ok(Vec::new())
            }
            MESSAGE_TYPE_RECONNECT => {
                let message =
                    Reconnect::from_bytes(payload).map_err(|error| format!("{error:?}"))?;
                Ok(vec![SessionAction::Reconnect {
                    host: message.new_host.as_utf8_or_hex(),
                    port: message.new_port,
                }])
            }
            other => {
                debug!("Ignoring Template Distribution message type {other:#04x}");
                Ok(Vec::new())
            }
        }
    }

    /// Keep the template and ask for its transactions.
    ///
    /// A template for the current parent is refused before any
    /// `SetNewPrevHash`, which it would relate to.
    fn on_new_template(&mut self, message: &NewTemplate<'_>) -> Result<Vec<SessionAction>, String> {
        let announced = AnnouncedTemplate::from_message(message);
        if !announced.future && self.tip.is_none() {
            warn!(
                "Template Provider sent current template {} before any SetNewPrevHash",
                announced.template_id
            );
            return Ok(Vec::new());
        }
        let template_id = announced.template_id;
        let needs_transactions = announced.transactions.is_none();
        self.pending.insert(template_id, announced);
        while self.pending.len() > MAX_PENDING_TEMPLATES {
            self.pending.pop_first();
        }
        let mut actions = Vec::with_capacity(1);
        if needs_transactions {
            actions.push(SessionAction::Send(encode_frame(
                RequestTransactionData { template_id },
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA,
            )?));
        }
        actions.extend(self.take_ready(template_id));
        Ok(actions)
    }

    /// Move to the new parent. Templates for the old one, and future
    /// templates this message did not activate, can no longer be mined.
    fn on_set_new_prev_hash(&mut self, message: &SetNewPrevHash<'_>) -> Vec<SessionAction> {
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(message.prev_hash.as_bytes());
        let mut target = [0u8; 32];
        target.copy_from_slice(message.target.as_bytes());
        let tip = ProviderTip {
            template_id: message.template_id,
            prev_hash: BlockHash::from_byte_array(prev_hash),
            header_timestamp: message.header_timestamp,
            bits: message.n_bits,
            target,
        };
        self.tip = Some(tip);
        self.pending
            .retain(|template_id, _| *template_id == tip.template_id);
        if self.pending.is_empty() {
            warn!(
                "Template Provider activated template {}, which it never announced",
                tip.template_id
            );
        }
        self.take_ready(tip.template_id).into_iter().collect()
    }

    fn on_transactions(
        &mut self,
        message: &RequestTransactionDataSuccess<'_>,
    ) -> Vec<SessionAction> {
        let template_id = message.template_id;
        let Some(announced) = self.pending.get_mut(&template_id) else {
            debug!("Transactions for Template Provider template {template_id}, no longer pending");
            return Vec::new();
        };
        let decoded = message
            .transaction_list
            .iter()
            .map(|raw| deserialize::<Transaction>(raw.as_bytes()))
            .collect::<Result<Vec<_>, _>>();
        match decoded {
            Ok(transactions) => {
                announced.transactions = Some(transactions);
                self.take_ready(template_id).into_iter().collect()
            }
            Err(decode_error) => {
                error!(
                    "Template Provider template {template_id} has a malformed transaction: {decode_error}"
                );
                self.pending.remove(&template_id);
                Vec::new()
            }
        }
    }

    fn on_transaction_error(&mut self, message: &RequestTransactionDataError<'_>) {
        warn!(
            "Template Provider refused transactions for template {}: {}",
            message.template_id,
            message.error_code.as_utf8_or_hex()
        );
        self.pending.remove(&message.template_id);
    }

    /// The template, if it can be mined now: its transactions are known and
    /// it is either the template the latest `SetNewPrevHash` activated or a
    /// template for the current parent. Older pending templates go with it.
    fn take_ready(&mut self, template_id: u64) -> Option<SessionAction> {
        let tip = self.tip?;
        let announced = self.pending.get(&template_id)?;
        let active = !announced.future || tip.template_id == template_id;
        if !active || announced.transactions.is_none() {
            return None;
        }
        let announced = self.pending.remove(&template_id)?;
        self.pending
            .retain(|pending_id, _| *pending_id > template_id);
        Some(SessionAction::Ready(ReadyTemplate { announced, tip }))
    }
}

/// Block size a provided template is checked against: the network's
/// default excessive block size, the floor of the adaptive block size limit,
/// which BCHN 29.2.0 reports as `sizelimit` (32 MB on mainnet and regtest,
/// 2 MB on chipnet). Template Distribution does not carry the limit, and a
/// block within the floor is never too large.
fn block_size_floor(network: BitcoinCashNetwork) -> u32 {
    match network {
        BitcoinCashNetwork::Mainnet | BitcoinCashNetwork::Regtest => 32_000_000,
        BitcoinCashNetwork::Chipnet => 2_000_000,
    }
}

/// The scriptSig start of every coinbase this pool builds at `height`: the
/// minimal BIP34 height push.
fn height_push(height: u64) -> Result<Vec<u8>, WorkError> {
    let height = i64::try_from(height).map_err(|_| WorkError {
        message: format!("block height {height} does not fit a script number"),
    })?;
    Ok(Builder::new().push_int(height).into_script().into_bytes())
}

/// Whether a coinbase starting with `push` satisfies the provider's
/// `prefix`: as the specification writes it, or as the pushed bytes that
/// bchn-sv2-bridge sends and expects behind their length.
fn prefix_matches_height_push(prefix: &[u8], push: &[u8]) -> bool {
    let length_prefixed = u8::try_from(prefix.len())
        .is_ok_and(|length| push.split_first() == Some((&length, prefix)));
    prefix == push || length_prefixed
}

/// Build the [`BlockTemplate`] for `ready` at `height` on `network` and
/// check it as a BCHN template is checked.
///
/// `now` (seconds since the epoch) refreshes the time of a template that came
/// after its `SetNewPrevHash`. `solutions` is the queue of the connection
/// the template came on.
fn provided_block_template(
    ready: ReadyTemplate,
    height: u64,
    network: BitcoinCashNetwork,
    now: u32,
    solutions: mpsc::Sender<Solution>,
) -> Result<BlockTemplate, WorkError> {
    let template_id = ready.announced.template_id;
    let invalid = |message: &str| WorkError {
        message: format!("Template Provider template {template_id}: {message}"),
    };
    let announced = ready.announced;
    let tip = ready.tip;
    if announced.coinbase_outputs_count != 0 || !announced.coinbase_outputs.is_empty() {
        return Err(invalid(
            "requires coinbase outputs, which a Bitcoin Cash share chain coinbase cannot carry",
        ));
    }
    if !prefix_matches_height_push(&announced.coinbase_prefix, &height_push(height)?) {
        return Err(invalid(&format!(
            "coinbase prefix {} is not the height push for height {height}",
            hex::encode(&announced.coinbase_prefix)
        )));
    }
    if announced.coinbase_tx_version != 2
        || announced.coinbase_tx_input_sequence != 0xffff_fffe
        || u64::from(announced.coinbase_tx_locktime) + 1 != height
    {
        debug!(
            "Template Provider template {} asks for coinbase version {}, sequence {:#x} and lock time {}; the share chain coinbase keeps version 2, sequence 0xfffffffe and lock time height - 1",
            template_id,
            announced.coinbase_tx_version,
            announced.coinbase_tx_input_sequence,
            announced.coinbase_tx_locktime
        );
    }
    let transactions = announced.transactions.unwrap_or_default();
    let transaction_bytes = transactions
        .iter()
        .map(|transaction| transaction.total_size() as u64)
        .sum::<u64>();
    let size_limit = block_size_floor(network);
    if transaction_bytes + u64::from(HEADER_AND_COUNT_SIZE) + u64::from(MAX_SUBMITTED_COINBASE)
        > u64::from(size_limit)
    {
        return Err(invalid("transactions leave no room for the coinbase"));
    }
    let target = Target::from_le_bytes(tip.target);
    let template = BlockTemplate {
        version: announced.version as i32,
        rules: Vec::new(),
        vbavailable: HashMap::with_capacity(0),
        vbrequired: 0,
        previousblockhash: tip.prev_hash.to_string(),
        transactions: transactions
            .iter()
            .map(|transaction| TemplateTransaction {
                data: hex::encode(serialize(transaction)),
                txid: transaction.compute_txid().to_string(),
                hash: transaction.compute_txid().to_string(),
                depends: Vec::new(),
                fee: 0,
                sigops: 0,
                weight: 0,
            })
            .collect(),
        coinbaseaux: HashMap::with_capacity(0),
        coinbasevalue: announced.coinbase_value,
        longpollid: template_id.to_string(),
        target: hex::encode(target.to_be_bytes()),
        mintime: tip.header_timestamp,
        mutable: Vec::new(),
        noncerange: "00000000ffffffff".to_string(),
        sigoplimit: size_limit / BYTES_PER_SIGCHECK,
        sizelimit: size_limit,
        weightlimit: 0,
        curtime: tip.header_timestamp.max(now),
        bits: format!("{:08x}", tip.bits),
        height: u32::try_from(height).map_err(|_| invalid("height does not fit 32 bits"))?,
        default_witness_commitment: None,
        provided: Some(ProvidedTemplate {
            template_id,
            height,
            solutions,
        }),
    };
    template.validate_bch()?;
    let branches = build_merkle_branches_for_template(&template)?
        .into_iter()
        .map(|branch| branch.to_byte_array())
        .collect::<Vec<_>>();
    if branches != announced.merkle_path {
        return Err(invalid("merkle path does not match its transactions"));
    }
    Ok(template)
}

/// The `SetupConnection` for the Template Distribution Protocol.
fn setup_connection_frame(provider: &TemplateProvider) -> Result<Vec<u8>, String> {
    let (host, port) = provider
        .address
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
        .ok_or("template provider address is not HOST:PORT")?;
    encode_frame(
        SetupConnection {
            protocol: Protocol::TemplateDistributionProtocol,
            min_version: PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            flags: 0,
            endpoint_host: host
                .try_into()
                .map_err(|error| format!("endpoint host: {error:?}"))?,
            endpoint_port: port,
            vendor: "p2poolv2"
                .try_into()
                .map_err(|error| format!("vendor: {error:?}"))?,
            hardware_version: ""
                .try_into()
                .map_err(|error| format!("hardware version: {error:?}"))?,
            firmware: env!("CARGO_PKG_VERSION")
                .try_into()
                .map_err(|error| format!("firmware: {error:?}"))?,
            device_id: ""
                .try_into()
                .map_err(|error| format!("device id: {error:?}"))?,
        },
        MESSAGE_TYPE_SETUP_CONNECTION,
    )
}

/// `CoinbaseOutputConstraints` sized for the largest PPLNS coinbase.
fn coinbase_output_constraints_frame() -> Result<Vec<u8>, String> {
    encode_frame(
        CoinbaseOutputConstraints {
            coinbase_output_max_additional_size: COINBASE_OUTPUT_RESERVE,
            coinbase_output_max_additional_sigops: COINBASE_OUTPUT_SIGOPS,
        },
        MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
    )
}

/// `SubmitSolution` for `solution`, or `None` when its coinbase does not fit
/// the message.
fn submit_solution_frame(solution: &Solution) -> Option<Vec<u8>> {
    let coinbase = serialize(solution.block.txdata.first()?);
    encode_frame(
        SubmitSolution {
            template_id: solution.template_id,
            version: solution.block.header.version.to_consensus() as u32,
            header_timestamp: solution.block.header.time,
            header_nonce: solution.block.header.nonce,
            coinbase_tx: B064K::new(&coinbase).ok()?,
        },
        MESSAGE_TYPE_SUBMIT_SOLUTION,
    )
    .ok()
}

/// Frames to and from the provider, encrypted when its key is pinned.
enum Transport {
    Plain { decoder: Decoder, inbox: Vec<u8> },
    Noise(Box<NoiseTransport>),
}

impl Transport {
    /// Complete messages in `incoming`: type and payload.
    fn decode(&mut self, incoming: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
        match self {
            Transport::Plain { decoder, inbox } => decode_plain_frames(decoder, inbox, incoming),
            Transport::Noise(noise) => noise.decode(incoming),
        }
    }

    /// Bytes to write for one unencrypted frame.
    fn wire(&mut self, frame: Vec<u8>) -> Result<Vec<u8>, String> {
        match self {
            Transport::Plain { .. } => Ok(frame),
            Transport::Noise(noise) => noise.encrypt(frame),
        }
    }
}

/// Why a provider connection ended.
#[derive(Debug, PartialEq, Eq)]
enum ConnectionEnd {
    /// The notifier is gone, so the node is stopping.
    NotifierClosed,
    /// The provider sent `Reconnect`: the next connection goes there.
    Redirected(TemplateProvider),
    /// Anything else: the client reconnects.
    Failed(String),
}

/// Start the task that takes templates from `provider` and sends them to
/// the notifier, in place of `start_gbt`.
///
/// The task keeps reconnecting while the node runs, waiting longer after
/// each failed connection up to [`MAX_RECONNECT_DELAY`]; miners keep the
/// last template meanwhile, as they do when `getblocktemplate` fails. It
/// ends when the notifier's receiver is dropped. `bitcoin_config` is the
/// node templates are checked against and blocks fall back to.
pub async fn start_template_provider(
    provider: TemplateProvider,
    bitcoin_config: BitcoinRpcConfig,
    notify_tx: NotifySender,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bitcoind = BitcoindRpcClient::new(
        &bitcoin_config.url,
        &bitcoin_config.username,
        &bitcoin_config.password,
    )
    .map_err(|error| WorkError {
        message: format!("Failed to create the bitcoind client: {error}"),
    })?;
    info!(
        "Taking block templates from the Stratum V2 Template Provider at {} ({})",
        provider.address,
        if provider.authority_public_key.is_some() {
            "Noise, pinned authority key"
        } else {
            "unencrypted, loopback"
        }
    );
    tokio::spawn(async move {
        keep_connected(&provider, &bitcoind, &notify_tx).await;
    });
    Ok(())
}

/// Run provider connections one after another until the notifier is gone.
///
/// A `Reconnect` sends the next connection to the address it names, after
/// [`RECONNECT_DELAY`]; any other end of a connection returns to the
/// configured provider, which may redirect again.
async fn keep_connected(
    provider: &TemplateProvider,
    bitcoind: &BitcoindRpcClient,
    notify_tx: &NotifySender,
) {
    let mut target = provider.clone();
    let mut delay = RECONNECT_DELAY;
    let mut running = true;
    while running {
        let (end, published) = serve_provider(&target, bitcoind, notify_tx).await;
        match end {
            ConnectionEnd::NotifierClosed => {
                info!("Notifier closed, stopping the Template Provider client");
                running = false;
            }
            ConnectionEnd::Redirected(next) => {
                info!(
                    "Template Provider at {} redirected the node to {}",
                    target.address, next.address
                );
                target = next;
                delay = RECONNECT_DELAY;
                sleep(RECONNECT_DELAY).await;
            }
            ConnectionEnd::Failed(reason) => {
                if published {
                    delay = RECONNECT_DELAY;
                }
                warn!(
                    "Template Provider connection to {} ended: {reason}; reconnecting to {} in {}s",
                    target.address,
                    provider.address,
                    delay.as_secs()
                );
                target = provider.clone();
                sleep(delay).await;
                delay = (delay * 2).min(MAX_RECONNECT_DELAY);
            }
        }
    }
}

/// Serve one provider connection until it ends.
///
/// Returns why it ended and whether it published a template. Solutions
/// still queued for it then go to the node over RPC.
async fn serve_provider(
    provider: &TemplateProvider,
    bitcoind: &BitcoindRpcClient,
    notify_tx: &NotifySender,
) -> (ConnectionEnd, bool) {
    let (solutions_tx, mut solutions_rx) = mpsc::channel(SOLUTION_QUEUE);
    let (end, published) = match open_connection(provider).await {
        Ok((transport, stream, early_messages)) => {
            let (mut reader, writer) = stream.into_split();
            let mut connection = ProviderConnection {
                provider,
                bitcoind,
                notify_tx,
                transport,
                writer,
                session: ProviderSession::default(),
                parent_height: None,
                found_block: None,
                solutions_tx,
                published: false,
            };
            let end = connection
                .run(&mut reader, &mut solutions_rx, early_messages)
                .await;
            (end, connection.published)
        }
        Err(reason) => (ConnectionEnd::Failed(reason), false),
    };
    solutions_rx.close();
    while let Ok(solution) = solutions_rx.try_recv() {
        submit_block(&solution.block, bitcoind).await;
    }
    (end, published)
}

/// Connect, run the Noise handshake when the key is pinned, and set up the
/// Template Distribution Protocol with the coinbase output constraints.
///
/// Also returns any messages that arrived with the setup reply.
async fn open_connection(
    provider: &TemplateProvider,
) -> Result<(Transport, TcpStream, Vec<(u8, Vec<u8>)>), String> {
    let mut stream = timeout(SETUP_TIMEOUT, TcpStream::connect(&provider.address))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|error| format!("connect: {error}"))?;
    if let Err(nodelay_error) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY for the Template Provider: {nodelay_error}");
    }
    let mut transport = match provider.authority_public_key {
        Some(key) => Transport::Noise(Box::new(NoiseTransport::connect(&mut stream, key).await?)),
        None => Transport::Plain {
            decoder: Decoder::new(),
            inbox: Vec::with_capacity(READ_BUFFER_SIZE),
        },
    };
    let setup = transport.wire(setup_connection_frame(provider)?)?;
    stream
        .write_all(&setup)
        .await
        .map_err(|error| format!("write: {error}"))?;
    let early_messages = timeout(SETUP_TIMEOUT, read_setup_reply(&mut stream, &mut transport))
        .await
        .map_err(|_| "no SetupConnection reply".to_string())??;
    let constraints = transport.wire(coinbase_output_constraints_frame()?)?;
    stream
        .write_all(&constraints)
        .await
        .map_err(|error| format!("write: {error}"))?;
    info!(
        "Template Provider at {} set up; reserved {COINBASE_OUTPUT_RESERVE} coinbase output bytes and {COINBASE_OUTPUT_SIGOPS} sigops",
        provider.address
    );
    Ok((transport, stream, early_messages))
}

/// Read until the provider answers `SetupConnection`, and return the
/// messages that came after the answer.
async fn read_setup_reply(
    stream: &mut TcpStream,
    transport: &mut Transport,
) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut buffer = vec![0u8; 4096];
    let mut messages = Vec::new();
    while messages.is_empty() {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| format!("read: {error}"))?;
        if count == 0 {
            return Err("closed before answering SetupConnection".to_string());
        }
        messages = transport.decode(&buffer[..count])?;
    }
    let (message_type, mut payload) = messages.remove(0);
    match message_type {
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS => Ok(messages),
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR => {
            let refusal = SetupConnectionError::from_bytes(&mut payload)
                .map_err(|error| format!("{error:?}"))?;
            Err(format!(
                "SetupConnection refused: {}",
                refusal.error_code.as_utf8_or_hex()
            ))
        }
        other => Err(format!(
            "expected a SetupConnection reply, got message type {other:#04x}"
        )),
    }
}

/// One set-up provider connection.
struct ProviderConnection<'a> {
    provider: &'a TemplateProvider,
    bitcoind: &'a BitcoindRpcClient,
    notify_tx: &'a NotifySender,
    transport: Transport,
    writer: OwnedWriteHalf,
    session: ProviderSession,
    /// The parent's hash and the height of a block on it, from the node.
    parent_height: Option<(BlockHash, u64)>,
    /// The last block this node sent the provider, and the height of a
    /// block on it: when the provider names it as the parent, the height is
    /// known without asking the node, which may not have the block yet.
    found_block: Option<(BlockHash, u64)>,
    /// Given to every template published from this connection.
    solutions_tx: mpsc::Sender<Solution>,
    /// Whether a template from this connection reached the notifier.
    published: bool,
}

impl ProviderConnection<'_> {
    /// Exchange templates and solutions until the connection ends,
    /// starting with `early_messages`.
    async fn run(
        &mut self,
        reader: &mut OwnedReadHalf,
        solutions_rx: &mut mpsc::Receiver<Solution>,
        early_messages: Vec<(u8, Vec<u8>)>,
    ) -> ConnectionEnd {
        let mut end = self.handle_messages(early_messages).await.err();
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];
        while end.is_none() {
            tokio::select! {
                read = reader.read(&mut buffer) => {
                    end = match read {
                        Ok(0) => Some(ConnectionEnd::Failed("closed by the provider".to_string())),
                        Err(read_error) => Some(ConnectionEnd::Failed(format!("read: {read_error}"))),
                        Ok(count) => match self.transport.decode(&buffer[..count]) {
                            Ok(messages) => self.handle_messages(messages).await.err(),
                            Err(reason) => Some(ConnectionEnd::Failed(reason)),
                        },
                    };
                }
                Some(solution) = solutions_rx.recv() => {
                    end = self.send_solution(solution).await.err();
                }
            }
        }
        end.unwrap_or_else(|| ConnectionEnd::Failed("ended".to_string()))
    }

    /// Answer the provider and publish the templates `messages` make ready.
    async fn handle_messages(&mut self, messages: Vec<(u8, Vec<u8>)>) -> Result<(), ConnectionEnd> {
        for (message_type, mut payload) in messages {
            let actions = self
                .session
                .on_message(message_type, &mut payload)
                .map_err(|reason| ConnectionEnd::Failed(format!("malformed message: {reason}")))?;
            for action in actions {
                match action {
                    SessionAction::Send(frame) => self.write_frame(frame).await?,
                    SessionAction::Ready(ready) => self.publish(ready).await?,
                    SessionAction::Reconnect { host, port } => {
                        return Err(match self.provider.redirected(&host, port) {
                            Ok(next) => ConnectionEnd::Redirected(next),
                            Err(refused) => ConnectionEnd::Failed(refused.message),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    async fn write_frame(&mut self, frame: Vec<u8>) -> Result<(), ConnectionEnd> {
        let wire = self.transport.wire(frame).map_err(ConnectionEnd::Failed)?;
        self.writer
            .write_all(&wire)
            .await
            .map_err(|error| ConnectionEnd::Failed(format!("write: {error}")))
    }

    /// Map `ready` and send it to the notifier. A template that fails the
    /// checks is logged and skipped; the provider's next one may pass.
    async fn publish(&mut self, ready: ReadyTemplate) -> Result<(), ConnectionEnd> {
        let prev_hash = ready.tip.prev_hash;
        let height = match (self.parent_height, self.found_block) {
            (Some((known, height)), _) if known == prev_hash => height,
            (_, Some((found, height))) if found == prev_hash => {
                self.parent_height = Some((prev_hash, height));
                height
            }
            _ => match lookup_parent_height(self.bitcoind, prev_hash).await {
                Ok(parent) => {
                    self.parent_height = Some((prev_hash, parent + 1));
                    parent + 1
                }
                Err(reason) => {
                    error!("Template Provider template on parent {prev_hash} skipped: {reason}");
                    return Ok(());
                }
            },
        };
        let template_id = ready.announced.template_id;
        let now = SystemTimeProvider.seconds_since_epoch() as u32;
        match provided_block_template(
            ready,
            height,
            self.provider.network,
            now,
            self.solutions_tx.clone(),
        ) {
            Ok(template) => {
                info!(
                    "Template Provider template {template_id} at height {height} with {} transactions",
                    template.transactions.len()
                );
                self.notify_tx
                    .send(NotifyCmd::SendToAll {
                        template: Arc::new(template),
                    })
                    .await
                    .map_err(|_| ConnectionEnd::NotifierClosed)?;
                self.published = true;
            }
            Err(invalid) => error!("{invalid}"),
        }
        Ok(())
    }

    /// Send `solution` to the provider, or to the node over RPC when it
    /// cannot go to the provider. A write that fails ends the connection.
    ///
    /// After the solution the coinbase output constraints are declared
    /// again. The specification lets a client send them at any time, and a
    /// provider that answers them with a fresh template (bchn-sv2-bridge
    /// does) announces the block's successor at once instead of at its next
    /// tip poll, so miners leave the old parent before they find a
    /// same-height sibling. Template Distribution has no message that asks
    /// for a template.
    async fn send_solution(&mut self, solution: Solution) -> Result<(), ConnectionEnd> {
        let block_hash = solution.block.block_hash();
        let Some(frame) = submit_solution_frame(&solution) else {
            warn!("Block {block_hash} does not fit SubmitSolution; submitting it over RPC");
            submit_block(&solution.block, self.bitcoind).await;
            return Ok(());
        };
        match self.write_frame(frame).await {
            Ok(()) => {
                info!(
                    "Sent block {block_hash} to the Template Provider for template {}",
                    solution.template_id
                );
                self.found_block = Some((block_hash, solution.height + 1));
                let constraints =
                    coinbase_output_constraints_frame().map_err(ConnectionEnd::Failed)?;
                self.write_frame(constraints).await
            }
            Err(failed) => {
                warn!(
                    "Block {block_hash} could not reach the Template Provider; submitting it over RPC"
                );
                submit_block(&solution.block, self.bitcoind).await;
                Err(failed)
            }
        }
    }
}

/// Height of `prev_hash` on the node, retried while the node catches up.
async fn lookup_parent_height(
    bitcoind: &BitcoindRpcClient,
    prev_hash: BlockHash,
) -> Result<u64, String> {
    let hash = prev_hash.to_string();
    let mut result = bitcoind.get_block_height(&hash).await;
    let mut attempt = 1;
    while result.is_err() && attempt < HEIGHT_ATTEMPTS {
        sleep(HEIGHT_RETRY_DELAY).await;
        result = bitcoind.get_block_height(&hash).await;
        attempt += 1;
    }
    result.map_err(|error| format!("the node does not know the parent: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        TestSv2Server, test_coinbase_transaction, test_sv2_authority, test_tdp_new_template,
        test_tdp_set_new_prev_hash, test_tdp_transaction_data,
    };
    use binary_sv2::to_bytes;
    use bitcoin::block::{Header, Version};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::{CompactTarget, ScriptBuf, TxMerkleNode, TxOut};
    use common_messages_sv2::SetupConnectionSuccess;
    use std::str::FromStr;
    // Found blocks are not submitted under the `sim` feature, so the tests
    // that follow a block to its provider are left out of that build.
    #[cfg(not(feature = "sim"))]
    use crate::config::DEFAULT_VERSION_MASK;
    #[cfg(not(feature = "sim"))]
    use crate::stratum::message_handlers::submit::submit_found_block;
    #[cfg(not(feature = "sim"))]
    use crate::stratum::sv2::mining::MiningChannels;
    #[cfg(not(feature = "sim"))]
    use crate::stratum::work::tracker::JobDetails;
    #[cfg(not(feature = "sim"))]
    use crate::test_utils::{test_bch_prepared_for_template, test_bch_stratum_context};
    #[cfg(not(feature = "sim"))]
    use binary_sv2::{B032, U256};
    #[cfg(not(feature = "sim"))]
    use mining_sv2::{
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        NewExtendedMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
        SetNewPrevHash as MiningSetNewPrevHash, SubmitSharesExtended,
    };
    #[cfg(not(feature = "sim"))]
    use p2poolv2_wallet::bch_share::{BchShareNetwork, encode_payout_address};
    use template_distribution_sv2::RequestTransactionDataSuccessOwned;
    use tokio::net::TcpListener;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const REGTEST_TEMPLATE: &str =
        include_str!("../../../../bitcoindrpc/test_data/bchn-regtest-template.json");
    const CHIPNET_TEMPLATE: &str =
        include_str!("../../../../bitcoindrpc/test_data/bchn-chipnet-template.json");

    #[test]
    fn a_future_template_waits_for_its_set_new_prev_hash() {
        let template: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        let announced = session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &template)).unwrap(),
            )
            .unwrap();
        assert!(announced.is_empty());
        let activated = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &template)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            activated.as_slice(),
            [SessionAction::Ready(ready)] if ready.announced.template_id == 5
        ));
    }

    #[test]
    fn a_new_template_with_transactions_asks_for_them() {
        let template: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        let actions = session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(9, true, &template)).unwrap(),
            )
            .unwrap();
        let request = encode_frame(
            RequestTransactionData { template_id: 9 },
            MESSAGE_TYPE_REQUEST_TRANSACTION_DATA,
        )
        .unwrap();
        assert_eq!(actions, vec![SessionAction::Send(request)]);
    }

    #[test]
    fn a_template_is_ready_once_its_transactions_follow_its_set_new_prev_hash() {
        let template: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(9, true, &template)).unwrap(),
            )
            .unwrap();
        let activated = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(activated.is_empty());
        let ready = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            ready.as_slice(),
            [SessionAction::Ready(ready)]
                if ready.announced.transactions.as_ref().map(Vec::len) == Some(65)
        ));
    }

    #[test]
    fn transactions_that_arrive_before_set_new_prev_hash_wait_for_it() {
        let template: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(9, true, &template)).unwrap(),
            )
            .unwrap();
        let early = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(early.is_empty());
        let activated = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            activated.as_slice(),
            [SessionAction::Ready(ready)] if ready.announced.template_id == 9
        ));
    }

    #[test]
    fn a_current_template_is_ready_when_its_transactions_arrive() {
        let regtest: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let chipnet: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(6, false, &chipnet)).unwrap(),
            )
            .unwrap();
        let ready = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(6, &chipnet)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            ready.as_slice(),
            [SessionAction::Ready(ready)]
                if ready.announced.template_id == 6 && ready.tip.template_id == 5
        ));
    }

    #[test]
    fn a_current_template_before_any_set_new_prev_hash_is_ignored() {
        let template: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        let actions = session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, false, &template)).unwrap(),
            )
            .unwrap();
        assert!(actions.is_empty());
        assert!(session.pending.is_empty());
    }

    #[test]
    fn a_new_parent_drops_templates_for_the_old_one() {
        let regtest: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let chipnet: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(6, false, &chipnet)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(7, true, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(7, &regtest)).unwrap(),
            )
            .unwrap();
        let stale = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(6, &chipnet)).unwrap(),
            )
            .unwrap();
        assert!(stale.is_empty());
    }

    #[test]
    fn a_published_template_drops_older_pending_templates() {
        let regtest: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let chipnet: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &regtest)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(6, false, &chipnet)).unwrap(),
            )
            .unwrap();
        let newer = session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(7, false, &regtest)).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            newer.as_slice(),
            [SessionAction::Ready(ready)] if ready.announced.template_id == 7
        ));
        let older = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(6, &chipnet)).unwrap(),
            )
            .unwrap();
        assert!(older.is_empty());
    }

    #[test]
    fn a_transaction_data_error_drops_the_template() {
        let template: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(9, true, &template)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
                &mut to_bytes(RequestTransactionDataError {
                    template_id: 9,
                    error_code: "template-id-not-found".try_into().unwrap(),
                })
                .unwrap(),
            )
            .unwrap();
        let activated = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(activated.is_empty());
    }

    #[test]
    fn a_malformed_transaction_drops_the_template() {
        let template: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(9, true, &template)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(9, &template)).unwrap(),
            )
            .unwrap();
        let malformed = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(RequestTransactionDataSuccessOwned {
                    template_id: 9,
                    excess_data: Vec::new().try_into().unwrap(),
                    transaction_list: vec![vec![0xff, 0x00].try_into().unwrap()]
                        .try_into()
                        .unwrap(),
                })
                .unwrap(),
            )
            .unwrap();
        assert!(malformed.is_empty());
        let retried = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(9, &template)).unwrap(),
            )
            .unwrap();
        assert!(retried.is_empty());
    }

    #[test]
    fn an_unknown_message_is_ignored() {
        let mut session = ProviderSession::default();
        assert!(session.on_message(0x99, &mut []).unwrap().is_empty());
    }

    #[test]
    fn a_malformed_new_template_is_an_error() {
        let mut session = ProviderSession::default();
        assert!(
            session
                .on_message(MESSAGE_TYPE_NEW_TEMPLATE, &mut [1, 2, 3])
                .is_err()
        );
    }

    #[test]
    fn a_chipnet_template_round_trips_through_template_distribution() {
        let fixture: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(1, true, &fixture)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(1, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(1, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        let template = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Chipnet,
            fixture.curtime,
            solutions,
        )
        .unwrap();
        assert_eq!(template.previousblockhash, fixture.previousblockhash);
        assert_eq!(template.version, fixture.version);
        assert_eq!(template.bits, fixture.bits);
        assert_eq!(template.target, fixture.target);
        assert_eq!(template.coinbasevalue, fixture.coinbasevalue);
        assert_eq!(template.height, fixture.height);
        assert_eq!(template.curtime, fixture.curtime);
        assert_eq!(template.sizelimit, fixture.sizelimit);
        assert_eq!(template.sigoplimit, fixture.sigoplimit);
        assert_eq!(
            template
                .transactions
                .iter()
                .map(|transaction| (&transaction.txid, &transaction.data))
                .collect::<Vec<_>>(),
            fixture
                .transactions
                .iter()
                .map(|transaction| (&transaction.txid, &transaction.data))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_regtest_template_is_checked_against_the_regtest_block_size() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        let template = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime,
            solutions,
        )
        .unwrap();
        assert_eq!(template.sizelimit, fixture.sizelimit);
        assert_eq!(template.sigoplimit, fixture.sigoplimit);
    }

    #[test]
    fn a_provided_template_sends_its_solution_back_to_its_connection() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, mut queue) = mpsc::channel(1);
        let template = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime,
            solutions,
        )
        .unwrap();
        let block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: fixture.curtime,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 7,
            },
            txdata: vec![test_coinbase_transaction(1)],
        };
        template.provided.unwrap().submit(block.clone()).unwrap();
        let solution = queue.try_recv().unwrap();
        assert_eq!(solution.template_id, 5);
        assert_eq!(solution.block, block);
    }

    #[test]
    fn a_bridge_form_coinbase_prefix_is_accepted() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut announced = test_tdp_new_template(5, true, &fixture);
        // bchn-sv2-bridge sends the pushed height bytes without the push
        // opcode; height 102 is pushed as 01 66.
        announced.coinbase_prefix = vec![0x66].try_into().unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(MESSAGE_TYPE_NEW_TEMPLATE, &mut to_bytes(announced).unwrap())
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        assert!(
            provided_block_template(
                ready,
                u64::from(fixture.height),
                BitcoinCashNetwork::Regtest,
                fixture.curtime,
                solutions,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_coinbase_prefix_for_another_height_is_refused() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut announced = test_tdp_new_template(5, true, &fixture);
        announced.coinbase_prefix = vec![0x01, 0x67].try_into().unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(MESSAGE_TYPE_NEW_TEMPLATE, &mut to_bytes(announced).unwrap())
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        let refused = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime,
            solutions,
        )
        .unwrap_err();
        assert!(
            refused.message.contains("height push"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_coinbase_prefix_with_more_than_the_height_push_is_refused() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut announced = test_tdp_new_template(5, true, &fixture);
        announced.coinbase_prefix = vec![0x01, 0x66, 0x00].try_into().unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(MESSAGE_TYPE_NEW_TEMPLATE, &mut to_bytes(announced).unwrap())
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        assert!(
            provided_block_template(
                ready,
                u64::from(fixture.height),
                BitcoinCashNetwork::Regtest,
                fixture.curtime,
                solutions,
            )
            .is_err()
        );
    }

    #[test]
    fn required_coinbase_outputs_are_refused() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut announced = test_tdp_new_template(5, true, &fixture);
        // A Bitcoin provider's segwit commitment output.
        announced.coinbase_tx_outputs_count = 1;
        announced.coinbase_tx_outputs = serialize(&TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        })
        .try_into()
        .unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(MESSAGE_TYPE_NEW_TEMPLATE, &mut to_bytes(announced).unwrap())
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        let refused = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime,
            solutions,
        )
        .unwrap_err();
        assert!(
            refused.message.contains("coinbase outputs"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_merkle_path_that_does_not_match_the_transactions_is_refused() {
        let fixture: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(1, true, &fixture)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(1, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(1, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(mut ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        ready.announced.merkle_path[0] = [0u8; 32];
        let (solutions, _queue) = mpsc::channel(1);
        let refused = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Chipnet,
            fixture.curtime,
            solutions,
        )
        .unwrap_err();
        assert!(
            refused.message.contains("merkle path"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn transactions_out_of_ctor_order_are_refused() {
        let fixture: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(1, true, &fixture)).unwrap(),
            )
            .unwrap();
        session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(1, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                &mut to_bytes(test_tdp_transaction_data(1, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(mut ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        ready.announced.transactions.as_mut().unwrap().swap(0, 1);
        let (solutions, _queue) = mpsc::channel(1);
        let refused = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Chipnet,
            fixture.curtime,
            solutions,
        )
        .unwrap_err();
        assert!(refused.message.contains("CTOR"), "{}", refused.message);
    }

    #[test]
    fn a_target_that_disagrees_with_the_bits_is_refused() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(mut ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        ready.tip.target = [0x01; 32];
        let (solutions, _queue) = mpsc::channel(1);
        let refused = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime,
            solutions,
        )
        .unwrap_err();
        assert!(refused.message.contains("target"), "{}", refused.message);
    }

    #[test]
    fn a_template_after_its_set_new_prev_hash_takes_the_current_time() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let mut session = ProviderSession::default();
        session
            .on_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                &mut to_bytes(test_tdp_new_template(5, true, &fixture)).unwrap(),
            )
            .unwrap();
        let mut actions = session
            .on_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                &mut to_bytes(test_tdp_set_new_prev_hash(5, &fixture)).unwrap(),
            )
            .unwrap();
        let Some(SessionAction::Ready(ready)) = actions.pop() else {
            panic!("template was not ready");
        };
        let (solutions, _queue) = mpsc::channel(1);
        let template = provided_block_template(
            ready,
            u64::from(fixture.height),
            BitcoinCashNetwork::Regtest,
            fixture.curtime + 30,
            solutions,
        )
        .unwrap();
        assert_eq!(template.curtime, fixture.curtime + 30);
        assert_eq!(template.mintime, fixture.curtime);
    }

    #[test]
    fn coinbase_output_constraints_reserve_the_largest_coinbase_submit_solution_carries() {
        let frame = coinbase_output_constraints_frame().unwrap();
        let mut messages =
            decode_plain_frames(&mut Decoder::new(), &mut Vec::new(), &frame).unwrap();
        let (message_type, mut payload) = messages.remove(0);
        assert_eq!(message_type, MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS);
        let constraints = CoinbaseOutputConstraints::from_bytes(&mut payload).unwrap();
        assert_eq!(constraints.coinbase_output_max_additional_size, 65_382);
        assert_eq!(constraints.coinbase_output_max_additional_sigops, 1_923);
        assert_eq!(
            COINBASE_WITHOUT_OUTPUTS + OUTPUT_COUNT_SIZE + COINBASE_OUTPUT_RESERVE,
            u32::from(u16::MAX)
        );
    }

    #[test]
    fn setup_connection_asks_for_template_distribution_version_two() {
        let provider = TemplateProvider {
            address: "127.0.0.1:8442".to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let frame = setup_connection_frame(&provider).unwrap();
        let mut messages =
            decode_plain_frames(&mut Decoder::new(), &mut Vec::new(), &frame).unwrap();
        let (message_type, mut payload) = messages.remove(0);
        assert_eq!(message_type, MESSAGE_TYPE_SETUP_CONNECTION);
        let setup = SetupConnection::from_bytes(&mut payload).unwrap();
        assert_eq!(setup.protocol, Protocol::TemplateDistributionProtocol);
        assert_eq!(
            (setup.min_version, setup.max_version, setup.flags),
            (2, 2, 0)
        );
        assert_eq!(setup.endpoint_host.as_utf8_or_hex(), "127.0.0.1");
        assert_eq!(setup.endpoint_port, 8442);
    }

    #[test]
    fn submit_solution_carries_the_header_fields_and_the_coinbase() {
        let block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0004),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_791_754_400,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 99,
            },
            txdata: vec![test_coinbase_transaction(1)],
        };
        let frame = submit_solution_frame(&Solution {
            template_id: 77,
            height: 102,
            block: block.clone(),
        })
        .unwrap();
        let mut messages =
            decode_plain_frames(&mut Decoder::new(), &mut Vec::new(), &frame).unwrap();
        let (message_type, mut payload) = messages.remove(0);
        assert_eq!(message_type, MESSAGE_TYPE_SUBMIT_SOLUTION);
        let solution = SubmitSolution::from_bytes(&mut payload).unwrap();
        assert_eq!(solution.template_id, 77);
        assert_eq!(solution.version, 0x2000_0004);
        assert_eq!(solution.header_timestamp, 1_791_754_400);
        assert_eq!(solution.header_nonce, 99);
        assert_eq!(
            solution.coinbase_tx.as_bytes(),
            serialize(&block.txdata[0]).as_slice()
        );
    }

    #[test]
    fn a_coinbase_too_large_for_submit_solution_gets_no_frame() {
        let mut coinbase = test_coinbase_transaction(1);
        coinbase.output.push(TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a; 70_000]),
        });
        let block = Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        assert!(
            submit_solution_frame(&Solution {
                template_id: 1,
                height: 102,
                block,
            })
            .is_none()
        );
    }

    #[tokio::test]
    async fn templates_flow_from_an_unencrypted_provider_and_solutions_flow_back() {
        let fixture: BlockTemplate = serde_json::from_str(CHIPNET_TEMPLATE).unwrap();
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(serde_json::json!({
                "method": "getblockheader",
                "params": [fixture.previousblockhash, true],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {"height": fixture.height - 1},
                "error": null,
                "id": 0,
            })))
            .expect(1)
            .mount(&rpc)
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Chipnet,
        };
        let (notify_tx, mut notify_rx) = mpsc::channel(4);
        start_template_provider(
            provider,
            BitcoinRpcConfig {
                url: rpc.uri(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            notify_tx,
        )
        .await
        .unwrap();
        let mut server = TestSv2Server::accept(&listener, None).await;
        let mut setup_payload = server.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        let setup = SetupConnection::from_bytes(&mut setup_payload).unwrap();
        assert_eq!(setup.protocol, Protocol::TemplateDistributionProtocol);
        server
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .await;
        let mut constraints_payload = server
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        let constraints = CoinbaseOutputConstraints::from_bytes(&mut constraints_payload).unwrap();
        assert_eq!(
            constraints.coinbase_output_max_additional_size,
            COINBASE_OUTPUT_RESERVE
        );
        server
            .send_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                test_tdp_new_template(41, true, &fixture),
            )
            .await;
        server
            .send_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                test_tdp_set_new_prev_hash(41, &fixture),
            )
            .await;
        let mut request_payload = server.receive(MESSAGE_TYPE_REQUEST_TRANSACTION_DATA).await;
        let request = RequestTransactionData::from_bytes(&mut request_payload).unwrap();
        assert_eq!(request.template_id, 41);
        server
            .send_message(
                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                test_tdp_transaction_data(41, &fixture),
            )
            .await;
        let Some(NotifyCmd::SendToAll { template }) =
            timeout(Duration::from_secs(5), notify_rx.recv())
                .await
                .unwrap()
        else {
            panic!("expected a template for the notifier");
        };
        assert_eq!(template.height, fixture.height);
        assert_eq!(template.previousblockhash, fixture.previousblockhash);
        assert_eq!(template.transactions.len(), fixture.transactions.len());
        let block = Block {
            header: Header {
                version: Version::from_consensus(fixture.version),
                prev_blockhash: BlockHash::from_str(&fixture.previousblockhash).unwrap(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: fixture.curtime,
                bits: CompactTarget::from_unprefixed_hex(&fixture.bits).unwrap(),
                nonce: 1234,
            },
            txdata: vec![test_coinbase_transaction(1)],
        };
        template
            .provided
            .as_ref()
            .unwrap()
            .submit(block.clone())
            .unwrap();
        let mut solution_payload = server.receive(MESSAGE_TYPE_SUBMIT_SOLUTION).await;
        let solution = SubmitSolution::from_bytes(&mut solution_payload).unwrap();
        assert_eq!(solution.template_id, 41);
        assert_eq!(solution.header_nonce, 1234);
        assert_eq!(
            solution.coinbase_tx.as_bytes(),
            serialize(&block.txdata[0]).as_slice()
        );
    }

    #[tokio::test]
    async fn a_noise_provider_signed_by_the_pinned_key_sends_templates() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getblockheader"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {"height": fixture.height - 1},
                "error": null,
                "id": 0,
            })))
            .mount(&rpc)
            .await;
        let authority = test_sv2_authority();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: Some(authority.public_key),
            network: BitcoinCashNetwork::Regtest,
        };
        let (notify_tx, mut notify_rx) = mpsc::channel(4);
        start_template_provider(
            provider,
            BitcoinRpcConfig {
                url: rpc.uri(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            notify_tx,
        )
        .await
        .unwrap();
        let mut server = TestSv2Server::accept(&listener, Some(&authority)).await;
        server.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        server
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .await;
        server
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        server
            .send_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                test_tdp_new_template(3, true, &fixture),
            )
            .await;
        server
            .send_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                test_tdp_set_new_prev_hash(3, &fixture),
            )
            .await;
        let Some(NotifyCmd::SendToAll { template }) =
            timeout(Duration::from_secs(5), notify_rx.recv())
                .await
                .unwrap()
        else {
            panic!("expected a template for the notifier");
        };
        assert_eq!(template.height, fixture.height);
    }

    #[tokio::test]
    async fn a_provider_signed_by_another_authority_is_refused() {
        let authority = test_sv2_authority();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // The x-only key of secret 0x01..01: a valid key, but not the
        // provider's authority.
        let other_key = Keypair::from_seckey_slice(&Secp256k1::new(), &[1u8; 32])
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: Some(other_key),
            network: BitcoinCashNetwork::Regtest,
        };
        let (_server, opened) = tokio::join!(
            TestSv2Server::accept(&listener, Some(&authority)),
            open_connection(&provider)
        );
        let Err(refused) = opened else {
            panic!("a provider with another authority was accepted");
        };
        assert!(refused.contains("pinned authority"), "{refused}");
    }

    #[tokio::test]
    async fn a_refused_setup_connection_ends_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let refuse = async {
            let mut server = TestSv2Server::accept(&listener, None).await;
            server.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
            server
                .send_message(
                    MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
                    SetupConnectionError {
                        flags: 0,
                        error_code: "unsupported-protocol".try_into().unwrap(),
                    },
                )
                .await;
            server
        };
        let (_server, opened) = tokio::join!(refuse, open_connection(&provider));
        let Err(refused) = opened else {
            panic!("a refused setup opened the connection");
        };
        assert!(refused.contains("unsupported-protocol"), "{refused}");
    }

    #[cfg(not(feature = "sim"))]
    #[tokio::test]
    async fn a_block_on_a_provided_template_goes_to_its_provider_and_not_over_rpc() {
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "submitblock"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": null,
                "id": 0,
            })))
            .expect(0)
            .mount(&rpc)
            .await;
        let (ctx, _emissions, _dirs) = test_bch_stratum_context(&rpc.uri()).await;
        let (solutions, mut queue) = mpsc::channel(1);
        let mut template: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        template.provided = Some(ProvidedTemplate {
            template_id: 12,
            height: 102,
            solutions,
        });
        let job = JobDetails {
            block_available: true,
            blocktemplate: Arc::new(template),
            coinbase1: String::new(),
            coinbase2: String::new(),
            generation_timestamp: 0,
            share_commitment: None,
            coinbase_nsecs: 0,
            template_merkle_branches: Vec::new(),
        };
        let header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 5,
        };
        submit_found_block(&ctx, header, test_coinbase_transaction(1), &job)
            .await
            .unwrap();
        let solution = queue.try_recv().unwrap();
        assert_eq!(solution.template_id, 12);
        assert_eq!(solution.block.header, header);
    }

    #[cfg(not(feature = "sim"))]
    #[tokio::test]
    async fn a_block_whose_provider_connection_is_gone_goes_over_rpc() {
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "submitblock"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": null,
                "id": 0,
            })))
            .expect(1)
            .mount(&rpc)
            .await;
        let (ctx, _emissions, _dirs) = test_bch_stratum_context(&rpc.uri()).await;
        let (solutions, queue) = mpsc::channel(1);
        drop(queue);
        let mut template: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        template.provided = Some(ProvidedTemplate {
            template_id: 12,
            height: 102,
            solutions,
        });
        let job = JobDetails {
            block_available: true,
            blocktemplate: Arc::new(template),
            coinbase1: String::new(),
            coinbase2: String::new(),
            generation_timestamp: 0,
            share_commitment: None,
            coinbase_nsecs: 0,
            template_merkle_branches: Vec::new(),
        };
        let header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 5,
        };
        submit_found_block(&ctx, header, test_coinbase_transaction(1), &job)
            .await
            .unwrap();
    }

    #[cfg(not(feature = "sim"))]
    #[tokio::test]
    async fn an_extended_channel_block_on_a_provided_template_returns_as_submit_solution() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getblockheader"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {"height": fixture.height - 1},
                "error": null,
                "id": 0,
            })))
            .mount(&rpc)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "submitblock"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": null,
                "error": null,
                "id": 0,
            })))
            .expect(0)
            .mount(&rpc)
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let (notify_tx, mut notify_rx) = mpsc::channel(4);
        start_template_provider(
            provider,
            BitcoinRpcConfig {
                url: rpc.uri(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            notify_tx,
        )
        .await
        .unwrap();
        let mut server = TestSv2Server::accept(&listener, None).await;
        server.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        server
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .await;
        server
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        server
            .send_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                test_tdp_new_template(21, true, &fixture),
            )
            .await;
        server
            .send_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                test_tdp_set_new_prev_hash(21, &fixture),
            )
            .await;
        let Some(NotifyCmd::SendToAll { template }) =
            timeout(Duration::from_secs(5), notify_rx.recv())
                .await
                .unwrap()
        else {
            panic!("expected a template for the notifier");
        };
        let prepared = test_bch_prepared_for_template(template.as_ref().clone());
        let (ctx, mut emissions, _dirs) = test_bch_stratum_context(&rpc.uri()).await;
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let payout = bitcoin::Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            bitcoin::Network::Regtest,
        );
        let identity = encode_payout_address(&payout, BchShareNetwork::Regtest).unwrap();
        let mut open = to_bytes(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: identity.as_str().try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::new(&[0xff; 32]).unwrap(),
            min_extranonce_size: 8,
        })
        .unwrap();
        let opened = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut open,
                Some(Arc::clone(&prepared)),
            )
            .await
            .unwrap();
        let mut opened_messages =
            decode_plain_frames(&mut Decoder::new(), &mut Vec::new(), &opened.concat()).unwrap();
        let (_, mut success_payload) = opened_messages.remove(0);
        let success = OpenExtendedMiningChannelSuccess::from_bytes(&mut success_payload).unwrap();
        let (_, mut job_payload) = opened_messages.remove(0);
        let job = NewExtendedMiningJob::from_bytes(&mut job_payload).unwrap();
        let (_, mut prev_hash_payload) = opened_messages.remove(0);
        let prev_hash = MiningSetNewPrevHash::from_bytes(&mut prev_hash_payload).unwrap();
        let extranonce = [0x11u8; 8];
        let mut coinbase_bytes = job.coinbase_tx_prefix.as_bytes().to_vec();
        coinbase_bytes.extend_from_slice(success.extranonce_prefix.as_bytes());
        coinbase_bytes.extend_from_slice(&extranonce);
        coinbase_bytes.extend_from_slice(job.coinbase_tx_suffix.as_bytes());
        let coinbase: Transaction = deserialize(&coinbase_bytes).unwrap();
        let unsolved = Header {
            version: Version::from_consensus(job.version as i32),
            prev_blockhash: BlockHash::from_byte_array(*prev_hash.prev_hash.as_array()),
            merkle_root: TxMerkleNode::from_byte_array(coinbase.compute_txid().to_byte_array()),
            time: prev_hash.min_ntime,
            bits: CompactTarget::from_consensus(prev_hash.nbits),
            nonce: 0,
        };
        // Regtest bits: about every second nonce meets the network target.
        let nonce = (0..u32::MAX)
            .find(|nonce| {
                let header = Header {
                    nonce: *nonce,
                    ..unsolved
                };
                Target::from_compact(header.bits).is_met_by(header.block_hash())
            })
            .unwrap();
        let mut submit = to_bytes(SubmitSharesExtended {
            channel_id: success.channel_id,
            sequence_number: 1,
            job_id: job.job_id,
            nonce,
            ntime: prev_hash.min_ntime,
            version: job.version,
            extranonce: B032::new(&extranonce).unwrap(),
        })
        .unwrap();
        channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
            .await
            .unwrap();
        let mut solution_payload = server.receive(MESSAGE_TYPE_SUBMIT_SOLUTION).await;
        let solution = SubmitSolution::from_bytes(&mut solution_payload).unwrap();
        assert_eq!(solution.template_id, 21);
        assert_eq!(solution.version, job.version);
        assert_eq!(solution.header_timestamp, prev_hash.min_ntime);
        assert_eq!(solution.header_nonce, nonce);
        assert_eq!(solution.coinbase_tx.as_bytes(), coinbase_bytes.as_slice());
        assert_eq!(emissions.try_recv().unwrap().header.nonce, nonce);
    }

    #[test]
    fn a_reconnect_asks_for_a_connection_to_the_named_provider() {
        let mut session = ProviderSession::default();
        let actions = session
            .on_message(
                MESSAGE_TYPE_RECONNECT,
                &mut to_bytes(Reconnect {
                    new_host: "127.0.0.1".try_into().unwrap(),
                    new_port: 8443,
                })
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            actions,
            vec![SessionAction::Reconnect {
                host: "127.0.0.1".to_string(),
                port: 8443,
            }]
        );
    }

    #[tokio::test]
    async fn a_reconnect_moves_the_client_to_the_provider_it_names() {
        let rpc = MockServer::start().await;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: first.local_addr().unwrap().to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let (notify_tx, _notify_rx) = mpsc::channel(4);
        start_template_provider(
            provider,
            BitcoinRpcConfig {
                url: rpc.uri(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            notify_tx,
        )
        .await
        .unwrap();
        let mut redirecting = TestSv2Server::accept(&first, None).await;
        redirecting.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        redirecting
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .await;
        redirecting
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        redirecting
            .send_message(
                MESSAGE_TYPE_RECONNECT,
                Reconnect {
                    new_host: "".try_into().unwrap(),
                    new_port: second.local_addr().unwrap().port(),
                },
            )
            .await;
        let mut redirected = TestSv2Server::accept(&second, None).await;
        let mut setup_payload = redirected.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        let setup = SetupConnection::from_bytes(&mut setup_payload).unwrap();
        assert_eq!(setup.protocol, Protocol::TemplateDistributionProtocol);
        assert_eq!(setup.endpoint_port, second.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn the_successor_of_a_block_this_node_found_is_published_without_a_parent_lookup() {
        let fixture: BlockTemplate = serde_json::from_str(REGTEST_TEMPLATE).unwrap();
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getblockheader"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": {"height": fixture.height - 1},
                "error": null,
                "id": 0,
            })))
            .expect(1)
            .mount(&rpc)
            .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = TemplateProvider {
            address: listener.local_addr().unwrap().to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let (notify_tx, mut notify_rx) = mpsc::channel(4);
        start_template_provider(
            provider,
            BitcoinRpcConfig {
                url: rpc.uri(),
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            notify_tx,
        )
        .await
        .unwrap();
        let mut server = TestSv2Server::accept(&listener, None).await;
        server.receive(MESSAGE_TYPE_SETUP_CONNECTION).await;
        server
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0,
                },
            )
            .await;
        server
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        server
            .send_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                test_tdp_new_template(1, true, &fixture),
            )
            .await;
        server
            .send_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                test_tdp_set_new_prev_hash(1, &fixture),
            )
            .await;
        let Some(NotifyCmd::SendToAll { template }) =
            timeout(Duration::from_secs(5), notify_rx.recv())
                .await
                .unwrap()
        else {
            panic!("expected a template for the notifier");
        };
        let found = Block {
            header: Header {
                version: Version::from_consensus(fixture.version),
                prev_blockhash: BlockHash::from_str(&fixture.previousblockhash).unwrap(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: fixture.curtime,
                bits: CompactTarget::from_unprefixed_hex(&fixture.bits).unwrap(),
                nonce: 3,
            },
            txdata: vec![test_coinbase_transaction(1)],
        };
        template
            .provided
            .as_ref()
            .unwrap()
            .submit(found.clone())
            .unwrap();
        server.receive(MESSAGE_TYPE_SUBMIT_SOLUTION).await;
        let mut constraints_payload = server
            .receive(MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS)
            .await;
        let constraints = CoinbaseOutputConstraints::from_bytes(&mut constraints_payload).unwrap();
        assert_eq!(
            constraints.coinbase_output_max_additional_size,
            COINBASE_OUTPUT_RESERVE
        );
        let mut successor = fixture.clone();
        successor.previousblockhash = found.block_hash().to_string();
        successor.height = fixture.height + 1;
        server
            .send_message(
                MESSAGE_TYPE_NEW_TEMPLATE,
                test_tdp_new_template(2, true, &successor),
            )
            .await;
        server
            .send_message(
                MESSAGE_TYPE_SET_NEW_PREV_HASH,
                test_tdp_set_new_prev_hash(2, &successor),
            )
            .await;
        let Some(NotifyCmd::SendToAll { template }) =
            timeout(Duration::from_secs(5), notify_rx.recv())
                .await
                .unwrap()
        else {
            panic!("expected the successor template for the notifier");
        };
        assert_eq!(template.height, fixture.height + 1);
        assert_eq!(template.previousblockhash, found.block_hash().to_string());
    }
}
