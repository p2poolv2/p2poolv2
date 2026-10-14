// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One Stratum V2 connection and the job registry it shares with the others.
//!
//! A Job Declaration connection and a Mining connection are separate TCP
//! sessions. The registry is what lets a token allocated on the first be
//! presented on the second.

use super::sort_ctor;
use crate::shares::merge_mining::MergeMiningCommitment;
use binary_sv2::{B064K, B0255, Deserialize, Seq064K, Str0255};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, TxOut};
use codec_sv2::{Decoded, Decoder, Encoder};
use common_messages_sv2::{
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol, SetupConnection, SetupConnectionError,
    SetupConnectionSuccess, has_declare_tx_data, has_work_selection,
};
use framing_sv2::framing::MessageFrame;
#[cfg(test)]
use framing_sv2::framing::SerializedFrame;
use job_declaration_sv2::{
    AllocateMiningJobToken, AllocateMiningJobTokenSuccess, DeclareMiningJob, DeclareMiningJobError,
    DeclareMiningJobSuccess, ERROR_CODE_DECLARE_MINING_JOB_INVALID_JOB,
    ERROR_CODE_DECLARE_MINING_JOB_INVALID_MINING_JOB_TOKEN, MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
    MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS, MESSAGE_TYPE_DECLARE_MINING_JOB,
    MESSAGE_TYPE_DECLARE_MINING_JOB_ERROR, MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS,
    MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
    ProvideMissingTransactions, ProvideMissingTransactionsSuccess,
};
use mining_sv2::{
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
    MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
    MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, SetCustomMiningJob,
    SetCustomMiningJobError, SetCustomMiningJobSuccess,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

const PROTOCOL_VERSION: u16 = 2;
const WORK_SELECTION_FLAG: u32 = 0b10;

/// Which Job Declaration mode a connection negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobDeclarationMode {
    /// `DECLARE_TX_DATA` is clear. The pool template is the transaction set.
    CoinbaseOnly,
    /// `DECLARE_TX_DATA` is set. The client reveals every transaction.
    FullTemplate,
}

/// Transactions from the latest block template, kept in CTOR.
///
/// The lock is the only lock this cache takes.
#[derive(Clone)]
pub struct PoolTransactionCache {
    transactions: Arc<RwLock<Vec<Transaction>>>,
}

impl PoolTransactionCache {
    /// Empty cache. The notifier replaces it when a template arrives.
    pub fn new() -> Self {
        Self {
            transactions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Store `transactions` in canonical order.
    pub fn set(&self, mut transactions: Vec<Transaction>) {
        sort_ctor(&mut transactions);
        *self
            .transactions
            .write()
            .expect("pool transaction cache lock") = transactions;
    }

    fn get(&self) -> Vec<Transaction> {
        self.transactions
            .read()
            .expect("pool transaction cache lock")
            .clone()
    }
}

impl Default for PoolTransactionCache {
    fn default() -> Self {
        Self::new()
    }
}

enum TokenState {
    /// Allocated, and not yet given its transactions.
    Open { mode: JobDeclarationMode },
    /// Full-template declaration waiting for the raw transactions.
    AwaitingTransactions {
        request_id: u32,
        wtxids: Vec<[u8; 32]>,
    },
    /// Transactions in CTOR, ready to mine.
    Ready { transactions: Vec<Transaction> },
}

/// Tokens and the transaction set each one mines.
pub struct JobRegistry {
    cache: PoolTransactionCache,
    merge_mining: Option<MergeMiningCommitment>,
    next_token: u64,
    next_job_id: u32,
    tokens: HashMap<Vec<u8>, TokenState>,
}

impl JobRegistry {
    /// Registry for `cache`. `merge_mining` is included in every allocated
    /// token's coinbase outputs. `None` leaves that field empty, which is
    /// what a Bitcoin node sends.
    pub fn new(cache: PoolTransactionCache, merge_mining: Option<MergeMiningCommitment>) -> Self {
        Self {
            cache,
            merge_mining,
            next_token: 1,
            next_job_id: 1,
            tokens: HashMap::with_capacity(8),
        }
    }

    /// Transactions a ready token will mine, in CTOR.
    pub fn transactions_for_token(&self, token: &[u8]) -> Option<Vec<Transaction>> {
        match self.tokens.get(token) {
            Some(TokenState::Ready { transactions }) => Some(transactions.clone()),
            _ => None,
        }
    }
}

/// Bytes of one Stratum V2 connection.
pub struct Sv2Connection {
    registry: Arc<Mutex<JobRegistry>>,
    decoder: Decoder,
    inbox: Vec<u8>,
    mode: Option<JobDeclarationMode>,
    mining: bool,
    /// Full-Template declarations made on this connection that still wait
    /// for `ProvideMissingTransactionsSuccess`, by the client's request id.
    /// Request ids are chosen by each client, so two connections can use the
    /// same one; the token is looked up here, never across the registry.
    pending_declarations: HashMap<u32, Vec<u8>>,
}

impl Sv2Connection {
    /// Connection that shares `registry` with the node's other SV2 sessions.
    pub fn new(registry: Arc<Mutex<JobRegistry>>) -> Self {
        Self {
            registry,
            decoder: Decoder::new(),
            inbox: Vec::new(),
            mode: None,
            mining: false,
            pending_declarations: HashMap::with_capacity(4),
        }
    }

    /// Accept `incoming` and return the response frames it completed.
    ///
    /// Every message goes to [`Self::handle_message`]. The listener decodes
    /// with [`Self::decode`] instead, so it can route Mining Protocol channel
    /// messages to [`super::mining::MiningChannels`].
    pub fn accept(&mut self, incoming: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let messages = self.decode(incoming)?;
        let mut responses = Vec::with_capacity(messages.len());
        for (message_type, mut payload) in messages {
            responses.extend(self.handle_message(message_type, &mut payload)?);
        }
        Ok(responses)
    }

    /// Decode `incoming` into complete messages: type and payload.
    pub fn decode(&mut self, incoming: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, String> {
        self.inbox.extend_from_slice(incoming);
        let mut messages = Vec::new();
        let mut reading = true;
        while reading && self.inbox.len() >= self.decoder.writable_len() {
            let room = self.decoder.writable_len();
            self.decoder.writable().copy_from_slice(&self.inbox[..room]);
            self.inbox.drain(..room);
            messages.extend(self.read_frames()?);
            reading = self.decoder.writable_len() > 0;
        }
        Ok(messages)
    }

    /// Whether this connection set up the Mining Protocol.
    pub fn is_mining(&self) -> bool {
        self.mining
    }

    fn read_frames(&mut self) -> Result<Vec<(u8, Vec<u8>)>, String> {
        let mut messages = Vec::new();
        let mut reading = true;
        while reading {
            match self
                .decoder
                .next_frame()
                .map_err(|error| error.to_string())?
            {
                Decoded::Incomplete(_) => reading = false,
                Decoded::Frame(mut frame) => {
                    let message_type = frame.header().msg_type();
                    messages.push((message_type, frame.payload().to_vec()));
                }
            }
        }
        Ok(messages)
    }

    /// Handle one setup, Job Declaration, or custom-job message.
    pub fn handle_message(
        &mut self,
        message_type: u8,
        payload: &mut [u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        match message_type {
            MESSAGE_TYPE_SETUP_CONNECTION => {
                let setup =
                    SetupConnection::from_bytes(payload).map_err(|error| error.to_string())?;
                self.on_setup(&setup)
            }
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN => {
                let request = AllocateMiningJobToken::from_bytes(payload)
                    .map_err(|error| error.to_string())?;
                self.on_allocate(request.request_id)
            }
            MESSAGE_TYPE_DECLARE_MINING_JOB => {
                let request =
                    DeclareMiningJob::from_bytes(payload).map_err(|error| error.to_string())?;
                self.on_declare(&request)
            }
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS => {
                let request = ProvideMissingTransactionsSuccess::from_bytes(payload)
                    .map_err(|error| error.to_string())?;
                self.on_transactions(&request)
            }
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB => {
                let request =
                    SetCustomMiningJob::from_bytes(payload).map_err(|error| error.to_string())?;
                self.on_custom_job(&request)
            }
            _ => Err(format!(
                "unsupported Stratum V2 message type {message_type}"
            )),
        }
    }

    fn on_setup(&mut self, setup: &SetupConnection) -> Result<Vec<Vec<u8>>, String> {
        let version = setup.get_version(PROTOCOL_VERSION, PROTOCOL_VERSION);
        let Some(used_version) = version else {
            return self.respond(
                SetupConnectionError {
                    flags: 0,
                    error_code: string_field("protocol-version-mismatch")?,
                },
                MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            );
        };
        match setup.protocol {
            Protocol::JobDeclarationProtocol => {
                let mode = if has_declare_tx_data(setup.flags) {
                    JobDeclarationMode::FullTemplate
                } else {
                    JobDeclarationMode::CoinbaseOnly
                };
                self.mode = Some(mode);
                self.mining = false;
                let flags = match mode {
                    JobDeclarationMode::FullTemplate => 1,
                    JobDeclarationMode::CoinbaseOnly => 0,
                };
                self.respond(
                    SetupConnectionSuccess {
                        used_version,
                        flags,
                    },
                    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                )
            }
            Protocol::MiningProtocol => {
                self.mining = true;
                self.mode = None;
                let flags = if has_work_selection(setup.flags) {
                    WORK_SELECTION_FLAG
                } else {
                    0
                };
                self.respond(
                    SetupConnectionSuccess {
                        used_version,
                        flags,
                    },
                    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                )
            }
            Protocol::TemplateDistributionProtocol => self.respond(
                SetupConnectionError {
                    flags: 0,
                    error_code: string_field("unsupported-protocol")?,
                },
                MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            ),
        }
    }

    fn on_allocate(&mut self, request_id: u32) -> Result<Vec<Vec<u8>>, String> {
        let mode = self.mode.ok_or("job token requested before setup")?;
        let mut registry = self.registry.lock().expect("job registry lock");
        registry.next_token = registry.next_token.wrapping_add(1);
        let token = registry.next_token.to_le_bytes().to_vec();
        registry
            .tokens
            .insert(token.clone(), TokenState::Open { mode });
        let coinbase_outputs = registry
            .merge_mining
            .map(MergeMiningCommitment::coinbase_outputs_bytes)
            .unwrap_or_else(empty_output_list);
        drop(registry);
        self.respond(
            AllocateMiningJobTokenSuccess {
                request_id,
                mining_job_token: bytes_255(&token)?,
                coinbase_outputs: bytes_field(&coinbase_outputs)?,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS,
        )
    }

    fn on_declare(&mut self, request: &DeclareMiningJob) -> Result<Vec<Vec<u8>>, String> {
        if self.mode != Some(JobDeclarationMode::FullTemplate) {
            return self.declare_error(
                request.request_id,
                ERROR_CODE_DECLARE_MINING_JOB_INVALID_JOB,
            );
        }
        if self.pending_declarations.contains_key(&request.request_id) {
            return self.declare_error(
                request.request_id,
                ERROR_CODE_DECLARE_MINING_JOB_INVALID_JOB,
            );
        }
        let token = request.mining_job_token.as_bytes().to_vec();
        let mut registry = self.registry.lock().expect("job registry lock");
        let state = registry.tokens.get(&token);
        if !matches!(
            state,
            Some(TokenState::Open {
                mode: JobDeclarationMode::FullTemplate
            })
        ) {
            drop(registry);
            return self.declare_error(
                request.request_id,
                ERROR_CODE_DECLARE_MINING_JOB_INVALID_MINING_JOB_TOKEN,
            );
        }
        let wtxids = request
            .wtxid_list
            .iter()
            .map(|wtxid| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(wtxid.as_bytes());
                bytes
            })
            .collect::<Vec<_>>();
        let positions = (0..wtxids.len())
            .map(|index| {
                u16::try_from(index)
                    .map_err(|_| "declaration has more transactions than u16".to_string())
            })
            .collect::<Result<Vec<_>, String>>()?;
        registry.tokens.insert(
            token.clone(),
            TokenState::AwaitingTransactions {
                request_id: request.request_id,
                wtxids,
            },
        );
        drop(registry);
        self.pending_declarations.insert(request.request_id, token);
        self.respond(
            ProvideMissingTransactions {
                request_id: request.request_id,
                unknown_tx_position_list: Seq064K::new(positions)
                    .map_err(|error| error.to_string())?,
            },
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS,
        )
    }

    fn on_transactions(
        &mut self,
        request: &ProvideMissingTransactionsSuccess,
    ) -> Result<Vec<Vec<u8>>, String> {
        let token = self
            .pending_declarations
            .remove(&request.request_id)
            .ok_or("transactions arrived with no open declaration")?;
        let mut registry = self.registry.lock().expect("job registry lock");
        let wtxids = match registry.tokens.get(&token) {
            Some(TokenState::AwaitingTransactions { request_id, wtxids })
                if *request_id == request.request_id =>
            {
                wtxids.clone()
            }
            _ => return Err("transactions arrived with no open declaration".to_string()),
        };
        if request.transaction_list.len() != wtxids.len() {
            return Err("transaction list length does not match the declaration".to_string());
        }
        let mut transactions = Vec::with_capacity(wtxids.len());
        for (index, raw) in request.transaction_list.iter().enumerate() {
            let transaction: Transaction =
                deserialize(raw.as_bytes()).map_err(|error| error.to_string())?;
            let wtxid = transaction.compute_wtxid().to_byte_array();
            if wtxid != wtxids[index] {
                return Err("revealed transaction does not match its declared wtxid".to_string());
            }
            transactions.push(transaction);
        }
        sort_ctor(&mut transactions);
        let new_token = registry.next_token.wrapping_add(1);
        registry.next_token = new_token;
        let new_token_bytes = new_token.to_le_bytes().to_vec();
        registry.tokens.remove(&token);
        registry
            .tokens
            .insert(new_token_bytes.clone(), TokenState::Ready { transactions });
        drop(registry);
        self.respond(
            DeclareMiningJobSuccess {
                request_id: request.request_id,
                new_mining_job_token: bytes_255(&new_token_bytes)?,
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS,
        )
    }

    fn on_custom_job(&mut self, request: &SetCustomMiningJob) -> Result<Vec<Vec<u8>>, String> {
        if !self.mining {
            return Err("SetCustomMiningJob requires a mining connection".to_string());
        }
        let token = request.token.as_bytes().to_vec();
        let mut registry = self.registry.lock().expect("job registry lock");
        let ready = match registry.tokens.get(&token) {
            Some(TokenState::Ready { .. }) => true,
            Some(TokenState::Open {
                mode: JobDeclarationMode::CoinbaseOnly,
            }) => {
                let transactions = registry.cache.get();
                registry
                    .tokens
                    .insert(token.clone(), TokenState::Ready { transactions });
                true
            }
            _ => false,
        };
        if !ready {
            drop(registry);
            return self.respond(
                SetCustomMiningJobError {
                    channel_id: request.channel_id,
                    request_id: request.request_id,
                    error_code: string_field("invalid-mining-job-token")?,
                },
                MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
            );
        }
        let job_id = registry.next_job_id;
        registry.next_job_id = registry.next_job_id.wrapping_add(1);
        drop(registry);
        self.respond(
            SetCustomMiningJobSuccess {
                channel_id: request.channel_id,
                request_id: request.request_id,
                job_id,
            },
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
        )
    }

    fn declare_error(
        &mut self,
        request_id: u32,
        error_code: &'static str,
    ) -> Result<Vec<Vec<u8>>, String> {
        self.respond(
            DeclareMiningJobError {
                request_id,
                error_code: string_field(error_code)?,
                error_details: bytes_field(&[])?,
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB_ERROR,
        )
    }

    fn respond<T>(&mut self, message: T, message_type: u8) -> Result<Vec<Vec<u8>>, String>
    where
        T: binary_sv2::Serialize + binary_sv2::GetSize,
    {
        Ok(vec![encode_frame(message, message_type)?])
    }
}

/// Whether the specification sets the channel bit on frames of this type.
///
/// Messages addressed to one channel carry the bit in their extension type;
/// a client that dispatches by it would misroute a frame without it.
fn is_channel_message(message_type: u8) -> bool {
    matches!(
        message_type,
        MESSAGE_TYPE_NEW_MINING_JOB
            | MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB
            | MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
            | MESSAGE_TYPE_SET_TARGET
            | MESSAGE_TYPE_SUBMIT_SHARES_STANDARD
            | MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED
            | MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS
            | MESSAGE_TYPE_SUBMIT_SHARES_ERROR
            | MESSAGE_TYPE_SET_CUSTOM_MINING_JOB
            | MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS
            | MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR
    )
}

/// Encode `message` as one unencrypted Stratum V2 frame, setting the channel
/// bit where the specification requires it.
pub(crate) fn encode_frame<T>(message: T, message_type: u8) -> Result<Vec<u8>, String>
where
    T: binary_sv2::Serialize + binary_sv2::GetSize,
{
    let frame =
        MessageFrame::from_message(message, message_type, 0, is_channel_message(message_type))
            .map_err(|error| error.to_string())?;
    Encoder::new()
        .encode(frame)
        .map_err(|error| error.to_string())
}

pub(crate) fn string_field(value: &'static str) -> Result<Str0255<'static>, String> {
    value
        .try_into()
        .map_err(|error: binary_sv2::Error| error.to_string())
}

fn bytes_field(value: &[u8]) -> Result<B064K<'_>, String> {
    B064K::new(value).map_err(|error| error.to_string())
}

fn bytes_255(value: &[u8]) -> Result<B0255<'_>, String> {
    B0255::new(value).map_err(|error| error.to_string())
}

/// A CompactSize-prefixed output list with no outputs: the single byte zero.
fn empty_output_list() -> Vec<u8> {
    serialize(&Vec::<TxOut>::with_capacity(0))
}

/// Encode `message` as one unencrypted Stratum V2 frame.
#[cfg(test)]
pub fn encode_message<T>(message: T, message_type: u8) -> Result<Vec<u8>, String>
where
    T: binary_sv2::Serialize + binary_sv2::GetSize,
{
    encode_frame(message, message_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binary_sv2::{B016M, U256};
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::serialize;
    use bitcoin::script::Builder;
    use bitcoin::transaction::{Sequence, TxIn, TxOut, Version};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Witness};

    fn registry() -> Arc<Mutex<JobRegistry>> {
        Arc::new(Mutex::new(JobRegistry::new(
            PoolTransactionCache::new(),
            Some(MergeMiningCommitment::reserved()),
        )))
    }

    fn transaction_with_lock(lock_time: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(lock_time),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(i64::from(lock_time)).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn setup(flags: u32, protocol: Protocol) -> SetupConnection<'static> {
        SetupConnection {
            protocol,
            min_version: PROTOCOL_VERSION,
            max_version: PROTOCOL_VERSION,
            flags,
            endpoint_host: "127.0.0.1".try_into().unwrap(),
            endpoint_port: 0,
            vendor: "p2poolv2".try_into().unwrap(),
            hardware_version: "test".try_into().unwrap(),
            firmware: "test".try_into().unwrap(),
            device_id: "".try_into().unwrap(),
        }
    }

    fn accept_message<T>(
        connection: &mut Sv2Connection,
        message: T,
        message_type: u8,
    ) -> Vec<Vec<u8>>
    where
        T: binary_sv2::Serialize + binary_sv2::GetSize,
    {
        let frame = encode_message(message, message_type).unwrap();
        connection.accept(&frame).unwrap()
    }

    fn decode_success_flags(frame: &[u8]) -> u32 {
        let mut connection = Sv2Connection::new(registry());
        connection.inbox.extend_from_slice(frame);
        let room = connection.decoder.writable_len();
        connection
            .decoder
            .writable()
            .copy_from_slice(&connection.inbox[..room]);
        connection.inbox.drain(..room);
        let mut payload_frame = match connection.decoder.next_frame().unwrap() {
            Decoded::Frame(frame) => frame,
            Decoded::Incomplete(_) => {
                let room = connection.decoder.writable_len();
                connection
                    .decoder
                    .writable()
                    .copy_from_slice(&connection.inbox[..room]);
                connection.inbox.drain(..room);
                match connection.decoder.next_frame().unwrap() {
                    Decoded::Frame(frame) => frame,
                    Decoded::Incomplete(_) => panic!("response frame did not complete"),
                }
            }
        };
        let mut payload = payload_frame.payload().to_vec();
        let success = SetupConnectionSuccess::from_bytes(&mut payload).unwrap();
        success.flags
    }

    #[test]
    fn full_template_reorders_revealed_transactions_into_ctor() {
        let shared = registry();
        let mut connection = Sv2Connection::new(Arc::clone(&shared));
        let setup_response = accept_message(
            &mut connection,
            setup(1, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        assert_eq!(decode_success_flags(&setup_response[0]), 1);

        let allocate = accept_message(
            &mut connection,
            AllocateMiningJobToken {
                user_identifier: "miner".try_into().unwrap(),
                request_id: 7,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        assert_eq!(allocate.len(), 1);
        let mut payload = response_payload(&allocate[0]);
        let allocated = AllocateMiningJobTokenSuccess::from_bytes(&mut payload).unwrap();
        let outputs: Vec<TxOut> = deserialize(allocated.coinbase_outputs.as_bytes()).unwrap();
        assert_eq!(outputs, vec![MergeMiningCommitment::reserved().output()]);
        let token = allocated.mining_job_token.as_bytes().to_vec();

        let first = transaction_with_lock(1);
        let second = transaction_with_lock(2);
        let mut declared = vec![first.clone(), second.clone()];
        let reversed = ctor_is_reversed(&first, &second);
        if !reversed {
            declared = vec![second.clone(), first.clone()];
        }
        let wtxid_bytes = declared
            .iter()
            .map(|transaction| transaction.compute_wtxid().to_byte_array())
            .collect::<Vec<_>>();
        let wtxids = wtxid_bytes
            .iter()
            .map(|wtxid| U256::new(wtxid.as_slice()).unwrap())
            .collect::<Vec<_>>();
        let declared_response = accept_message(
            &mut connection,
            DeclareMiningJob {
                request_id: 8,
                mining_job_token: B0255::new(&token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(wtxids).unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );
        let mut missing_payload = response_payload(&declared_response[0]);
        let missing = ProvideMissingTransactions::from_bytes(&mut missing_payload).unwrap();
        assert_eq!(missing.unknown_tx_position_list.as_slice(), &[0, 1]);

        let serialized = declared.iter().map(serialize).collect::<Vec<_>>();
        let revealed = serialized
            .iter()
            .map(|bytes| B016M::new(bytes.as_slice()).unwrap())
            .collect::<Vec<_>>();
        let success = accept_message(
            &mut connection,
            ProvideMissingTransactionsSuccess {
                request_id: 8,
                transaction_list: Seq064K::new(revealed).unwrap(),
            },
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
        );
        let mut success_payload = response_payload(&success[0]);
        let accepted = DeclareMiningJobSuccess::from_bytes(&mut success_payload).unwrap();
        let stored = shared
            .lock()
            .unwrap()
            .transactions_for_token(accepted.new_mining_job_token.as_bytes())
            .unwrap();
        let declared_first = declared[0].lock_time;
        let mut expected = declared;
        sort_ctor(&mut expected);
        assert_eq!(stored, expected);
        assert_ne!(stored[0].lock_time, declared_first);
    }

    #[test]
    fn two_connections_reusing_a_request_id_keep_their_own_transactions() {
        let shared = registry();
        let mut first_connection = Sv2Connection::new(Arc::clone(&shared));
        let mut second_connection = Sv2Connection::new(Arc::clone(&shared));
        accept_message(
            &mut first_connection,
            setup(1, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        accept_message(
            &mut second_connection,
            setup(1, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        let first_allocate = accept_message(
            &mut first_connection,
            AllocateMiningJobToken {
                user_identifier: "first".try_into().unwrap(),
                request_id: 1,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let second_allocate = accept_message(
            &mut second_connection,
            AllocateMiningJobToken {
                user_identifier: "second".try_into().unwrap(),
                request_id: 1,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let mut first_payload = response_payload(&first_allocate[0]);
        let first_token = AllocateMiningJobTokenSuccess::from_bytes(&mut first_payload)
            .unwrap()
            .mining_job_token
            .as_bytes()
            .to_vec();
        let mut second_payload = response_payload(&second_allocate[0]);
        let second_token = AllocateMiningJobTokenSuccess::from_bytes(&mut second_payload)
            .unwrap()
            .mining_job_token
            .as_bytes()
            .to_vec();

        let first_transaction = transaction_with_lock(1);
        let second_transaction = transaction_with_lock(2);
        let first_wtxid = first_transaction.compute_wtxid().to_byte_array();
        let second_wtxid = second_transaction.compute_wtxid().to_byte_array();
        accept_message(
            &mut first_connection,
            DeclareMiningJob {
                request_id: 1,
                mining_job_token: B0255::new(&first_token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(vec![U256::new(first_wtxid.as_slice()).unwrap()]).unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );
        accept_message(
            &mut second_connection,
            DeclareMiningJob {
                request_id: 1,
                mining_job_token: B0255::new(&second_token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(vec![U256::new(second_wtxid.as_slice()).unwrap()])
                    .unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );

        let second_serialized = serialize(&second_transaction);
        let second_success = accept_message(
            &mut second_connection,
            ProvideMissingTransactionsSuccess {
                request_id: 1,
                transaction_list: Seq064K::new(vec![
                    B016M::new(second_serialized.as_slice()).unwrap(),
                ])
                .unwrap(),
            },
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
        );
        let first_serialized = serialize(&first_transaction);
        let first_success = accept_message(
            &mut first_connection,
            ProvideMissingTransactionsSuccess {
                request_id: 1,
                transaction_list: Seq064K::new(vec![
                    B016M::new(first_serialized.as_slice()).unwrap(),
                ])
                .unwrap(),
            },
            MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
        );

        let mut second_success_payload = response_payload(&second_success[0]);
        let second_ready = DeclareMiningJobSuccess::from_bytes(&mut second_success_payload)
            .unwrap()
            .new_mining_job_token
            .as_bytes()
            .to_vec();
        let mut first_success_payload = response_payload(&first_success[0]);
        let first_ready = DeclareMiningJobSuccess::from_bytes(&mut first_success_payload)
            .unwrap()
            .new_mining_job_token
            .as_bytes()
            .to_vec();
        let registry = shared.lock().unwrap();
        assert_eq!(
            registry.transactions_for_token(&first_ready).unwrap(),
            vec![first_transaction]
        );
        assert_eq!(
            registry.transactions_for_token(&second_ready).unwrap(),
            vec![second_transaction]
        );
    }

    #[test]
    fn a_second_declaration_with_a_pending_request_id_is_rejected() {
        let mut connection = Sv2Connection::new(registry());
        accept_message(
            &mut connection,
            setup(1, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        let first_allocate = accept_message(
            &mut connection,
            AllocateMiningJobToken {
                user_identifier: "miner".try_into().unwrap(),
                request_id: 1,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let second_allocate = accept_message(
            &mut connection,
            AllocateMiningJobToken {
                user_identifier: "miner".try_into().unwrap(),
                request_id: 2,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let mut first_payload = response_payload(&first_allocate[0]);
        let first_token = AllocateMiningJobTokenSuccess::from_bytes(&mut first_payload)
            .unwrap()
            .mining_job_token
            .as_bytes()
            .to_vec();
        let mut second_payload = response_payload(&second_allocate[0]);
        let second_token = AllocateMiningJobTokenSuccess::from_bytes(&mut second_payload)
            .unwrap()
            .mining_job_token
            .as_bytes()
            .to_vec();
        accept_message(
            &mut connection,
            DeclareMiningJob {
                request_id: 5,
                mining_job_token: B0255::new(&first_token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(vec![]).unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );
        let rejected = accept_message(
            &mut connection,
            DeclareMiningJob {
                request_id: 5,
                mining_job_token: B0255::new(&second_token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(vec![]).unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );
        let mut error_payload = response_payload(&rejected[0]);
        let error = DeclareMiningJobError::from_bytes(&mut error_payload).unwrap();
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            ERROR_CODE_DECLARE_MINING_JOB_INVALID_JOB
        );
    }

    #[test]
    fn bitcoin_tokens_carry_an_empty_output_list() {
        let shared = Arc::new(Mutex::new(JobRegistry::new(
            PoolTransactionCache::new(),
            None,
        )));
        let mut connection = Sv2Connection::new(shared);
        accept_message(
            &mut connection,
            setup(0, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        let allocate = accept_message(
            &mut connection,
            AllocateMiningJobToken {
                user_identifier: "miner".try_into().unwrap(),
                request_id: 1,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let mut payload = response_payload(&allocate[0]);
        let allocated = AllocateMiningJobTokenSuccess::from_bytes(&mut payload).unwrap();
        let outputs: Vec<TxOut> = deserialize(allocated.coinbase_outputs.as_bytes()).unwrap();
        assert!(outputs.is_empty());
    }

    fn ctor_is_reversed(first: &Transaction, second: &Transaction) -> bool {
        let mut pair = [first.clone(), second.clone()];
        sort_ctor(&mut pair);
        pair[0].lock_time != first.lock_time
    }

    fn response_payload(frame: &[u8]) -> Vec<u8> {
        let mut owned = frame.to_vec();
        let mut parsed = SerializedFrame::<Vec<u8>>::from_bytes(owned.clone()).unwrap();
        let _ = &mut owned;
        parsed.payload().to_vec()
    }

    #[test]
    fn coinbase_only_rejects_declare_and_mines_the_pool_template_in_ctor() {
        let cache = PoolTransactionCache::new();
        let first = transaction_with_lock(1);
        let second = transaction_with_lock(2);
        let mut pool = vec![first.clone(), second.clone()];
        sort_ctor(&mut pool);
        pool.reverse();
        cache.set(pool);
        let shared = Arc::new(Mutex::new(JobRegistry::new(
            cache,
            Some(MergeMiningCommitment::reserved()),
        )));

        let mut declaration = Sv2Connection::new(Arc::clone(&shared));
        let setup_response = accept_message(
            &mut declaration,
            setup(0, Protocol::JobDeclarationProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        assert_eq!(decode_success_flags(&setup_response[0]), 0);
        let allocate = accept_message(
            &mut declaration,
            AllocateMiningJobToken {
                user_identifier: "miner".try_into().unwrap(),
                request_id: 3,
            },
            MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        );
        let mut payload = response_payload(&allocate[0]);
        let allocated = AllocateMiningJobTokenSuccess::from_bytes(&mut payload).unwrap();
        let token = allocated.mining_job_token.as_bytes().to_vec();

        let rejected = accept_message(
            &mut declaration,
            DeclareMiningJob {
                request_id: 4,
                mining_job_token: B0255::new(&token).unwrap(),
                version: 1,
                coinbase_tx_prefix: B064K::new(&[]).unwrap(),
                coinbase_tx_suffix: B064K::new(&[]).unwrap(),
                wtxid_list: Seq064K::new(vec![]).unwrap(),
                excess_data: B064K::new(&[]).unwrap(),
            },
            MESSAGE_TYPE_DECLARE_MINING_JOB,
        );
        let mut error_payload = response_payload(&rejected[0]);
        let error = DeclareMiningJobError::from_bytes(&mut error_payload).unwrap();
        assert_eq!(
            error.error_code.as_utf8_or_hex(),
            ERROR_CODE_DECLARE_MINING_JOB_INVALID_JOB
        );

        let mut mining = Sv2Connection::new(shared);
        accept_message(
            &mut mining,
            setup(WORK_SELECTION_FLAG, Protocol::MiningProtocol),
            MESSAGE_TYPE_SETUP_CONNECTION,
        );
        let custom = accept_message(
            &mut mining,
            custom_job(&token),
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB,
        );
        let mut custom_payload = response_payload(&custom[0]);
        let accepted = SetCustomMiningJobSuccess::from_bytes(&mut custom_payload).unwrap();
        assert_eq!(accepted.request_id, 9);
        let stored = mining
            .registry
            .lock()
            .unwrap()
            .transactions_for_token(&token)
            .unwrap();
        let mut expected = vec![first, second];
        sort_ctor(&mut expected);
        assert_eq!(stored, expected);
    }

    fn custom_job(token: &[u8]) -> SetCustomMiningJob<'_> {
        SetCustomMiningJob {
            channel_id: 1,
            request_id: 9,
            token: B0255::new(token).unwrap(),
            version: 1,
            prev_hash: U256::new(&[0u8; 32]).unwrap(),
            min_ntime: 0,
            nbits: 0x1d00ffff,
            coinbase_tx_version: 2,
            coinbase_prefix: B0255::new(&[]).unwrap(),
            coinbase_tx_input_n_sequence: 0xffff_fffe,
            coinbase_tx_outputs: B064K::new(&[]).unwrap(),
            coinbase_tx_locktime: 0,
            merkle_path: binary_sv2::Seq0255::new(vec![]).unwrap(),
        }
    }
}
