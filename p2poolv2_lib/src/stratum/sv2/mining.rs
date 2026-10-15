// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stratum V2 Mining Protocol channels for a local miner.
//!
//! A channel reuses the SV1 machinery: its [`Session`] holds the extranonce
//! prefix, the miner identity and vardiff; each template becomes a tracker
//! job built by [`insert_miner_job`]; and a valid submission goes through the
//! same block submission and share-chain emission as an SV1 `mining.submit`.
//!
//! The coinbase this pool builds is `coinbase1 | enonce1 (4) | enonce2 (8) |
//! coinbase2`. An extended channel is given enonce1 as its extranonce prefix
//! and rolls the 8 enonce2 bytes itself; a standard channel is given all 12
//! bytes and mines the merkle root the pool computes from them.
//!
//! The channel's `user_identity` carries what an SV1 miner sends as username
//! and password: `<address>.<worker>`, then optionally a separator (comma,
//! space, tab or semicolon) and options in the SV1 password format. The
//! address is the miner's payout address. `p2p=<share address>` names the
//! owner of the channel's shares, with the SV1 rules: a share address the
//! node configures owns every share and a different `p2p=` is refused, and
//! without either a P2Poolv2 node refuses the channel. For example
//! `bchtest:qq...,p2p=tp2pool...` on chipnet.

use super::custom_job::validate_custom_job;
use super::session::DeclaredJob;
use super::session::{encode_frame, string_field};
use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::config::{BitcoinCashNetwork, Chain, PoolMode};
use crate::stratum::difficulty_adjuster::{DifficultyAdjuster, DifficultyAdjusterTrait};
use crate::stratum::message_handlers::authorize_response::{
    resolve_cash_share, resolve_share_address,
};
use crate::stratum::message_handlers::submit::{
    PoolShare, emit_pool_share, get_true_difficulty, submit_found_block,
};
use crate::stratum::parse_password::{extract_string_value, parse_password};
use crate::stratum::server::StratumContext;
use crate::stratum::session::Session;
use crate::stratum::validate_username;
use crate::stratum::work::difficulty::validate::build_coinbase_from_components;
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use crate::stratum::work::prepared_notify::{PreparedNotifyParams, insert_miner_job};
use crate::stratum::work::tracker::{JobDetails, JobId};
use binary_sv2::{B032, B064K, Deserialize, Seq0255, Sv2Option, U256};
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Network, Target, TxMerkleNode};
use mining_sv2::{
    CloseChannel, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, MESSAGE_TYPE_NEW_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
    MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
    MESSAGE_TYPE_UPDATE_CHANNEL, MESSAGE_TYPE_UPDATE_CHANNEL_ERROR, NewExtendedMiningJob,
    NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
    SetCustomMiningJob, SetCustomMiningJobError, SetCustomMiningJobSuccess, SetNewPrevHash,
    SetTarget, SubmitSharesError, SubmitSharesExtended, SubmitSharesStandard, SubmitSharesSuccess,
    UpdateChannel, UpdateChannelError,
};
use p2poolv2_wallet::share_owner::ShareOwner;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::time::timeout;
use tracing::{debug, error};

/// Bytes of extranonce a miner rolls on an extended channel (SV1 enonce2).
pub const EXTRANONCE_SIZE: u16 = 8;

/// Jobs a channel remembers. Older ones are dropped; the tracker keeps a job
/// for 15 minutes, far longer than this many templates take to arrive.
const MAX_CHANNEL_JOBS: usize = 32;

/// Channels one connection may open. Every template builds a job per
/// channel, so an unbounded count would let one client make the node do
/// unbounded work; a proxy aggregating many devices uses extended channels.
pub const MAX_CHANNELS_PER_CONNECTION: usize = 32;

/// Message types this module handles.
pub fn is_mining_channel_message(message_type: u8) -> bool {
    matches!(
        message_type,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL
            | MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL
            | MESSAGE_TYPE_SUBMIT_SHARES_STANDARD
            | MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED
            | MESSAGE_TYPE_UPDATE_CHANNEL
            | MESSAGE_TYPE_CLOSE_CHANNEL
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelKind {
    /// The pool fixes all 12 extranonce bytes and sends merkle roots.
    Standard,
    /// The miner rolls the 8 enonce2 bytes and builds the coinbase.
    Extended,
}

#[derive(Clone, Copy)]
struct ChannelJob {
    tracker_job_id: JobId,
    target: Target,
    difficulty: u64,
}

struct Channel {
    kind: ChannelKind,
    session: Session<DifficultyAdjuster>,
    /// enonce2 for a standard channel; unused on an extended one.
    standard_enonce2: [u8; 8],
    /// Easiest target the device accepts, from its latest open/update request.
    max_target: Target,
    /// Active jobs retain the target and credit assigned before hashing started.
    jobs: BTreeMap<u32, ChannelJob>,
    next_job_id: u32,
    last_prev_hash: Option<BlockHash>,
}

impl Channel {
    fn insert_job(&mut self, tracker_job_id: JobId) -> u32 {
        let job_id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        let target =
            target_for_difficulty(self.session.difficulty_adjuster.get_current_difficulty())
                .min(self.max_target);
        let difficulty = target
            .difficulty(Network::Bitcoin)
            .min(u128::from(u64::MAX)) as u64;
        self.jobs.insert(
            job_id,
            ChannelJob {
                tracker_job_id,
                target,
                difficulty,
            },
        );
        while self.jobs.len() > MAX_CHANNEL_JOBS {
            self.jobs.pop_first();
        }
        job_id
    }
}

/// The mining channels of one SV2 connection.
pub struct MiningChannels {
    ctx: StratumContext,
    version_mask: i32,
    channels: BTreeMap<u32, Channel>,
    next_channel_id: u32,
}

impl MiningChannels {
    /// Validate and install a declared BCH job before acknowledging reward eligibility.
    pub(crate) async fn install_custom_job(
        &mut self,
        request: &SetCustomMiningJob<'_>,
        declared: DeclaredJob,
        current: Option<Arc<PreparedNotifyParams>>,
    ) -> Result<Vec<Vec<u8>>, String> {
        if self.ctx.share_chain != Chain::BitcoinCash || self.ctx.mode != PoolMode::P2poolv2 {
            return custom_job_error(request, "unsupported-pool-mode");
        }
        let Some(channel) = self.channels.get_mut(&request.channel_id) else {
            return custom_job_error(request, "invalid-channel-id");
        };
        if channel.kind != ChannelKind::Extended {
            return custom_job_error(request, "invalid-channel-type");
        }
        let Some(current) = current else {
            return custom_job_error(request, "template-unavailable");
        };
        if current.template().previousblockhash != declared.prepared.template().previousblockhash {
            return custom_job_error(request, "stale-template");
        }
        let payout = channel
            .session
            .parsed_address
            .clone()
            .ok_or("authorized channel has no payout address")?;
        let owner = channel
            .session
            .share_owner
            .ok_or("authorized channel has no share owner")?;
        let (job, proposal) =
            match validate_custom_job(request, declared, payout, owner, self.version_mask) {
                Ok(validated) => validated,
                Err(reason) => {
                    debug!("Rejected SV2 custom job: {reason}");
                    return custom_job_error(request, "invalid-custom-job");
                }
            };
        if let Some(proposal) = proposal {
            match timeout(
                Duration::from_secs(10),
                self.ctx
                    .bitcoindrpc_client
                    .validate_block_proposal(&proposal),
            )
            .await
            {
                Ok(Ok(())) => (),
                rejected => {
                    debug!("Rejected declared BCH template: {rejected:?}");
                    return custom_job_error(request, "invalid-template");
                }
            }
        }
        let prev_hash = BlockHash::from_str(&job.blocktemplate.previousblockhash)
            .map_err(|error| error.to_string())?;
        if channel.last_prev_hash != Some(prev_hash) {
            channel.jobs.clear();
        }
        channel.last_prev_hash = Some(prev_hash);
        let tracker_job_id = self.ctx.tracker_handle.get_next_job_id();
        self.ctx
            .tracker_handle
            .insert_job_details(tracker_job_id, job);
        let job_id = channel.insert_job(tracker_job_id);
        Ok(vec![encode_frame(
            SetCustomMiningJobSuccess {
                channel_id: request.channel_id,
                request_id: request.request_id,
                job_id,
            },
            MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
        )?])
    }

    /// Channels for one connection, sharing the SV1 stratum context.
    pub(crate) fn new(ctx: StratumContext, version_mask: i32) -> Self {
        Self {
            ctx,
            version_mask,
            channels: BTreeMap::new(),
            next_channel_id: 1,
        }
    }

    /// Handle one mining channel message and return the response frames.
    ///
    /// `current` is the latest prepared template, used to send a newly
    /// opened channel its first job.
    pub async fn handle(
        &mut self,
        message_type: u8,
        payload: &mut [u8],
        current: Option<Arc<PreparedNotifyParams>>,
    ) -> Result<Vec<Vec<u8>>, String> {
        match message_type {
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
                let request = OpenStandardMiningChannel::from_bytes(payload)
                    .map_err(|error| error.to_string())?;
                self.open(
                    ChannelKind::Standard,
                    request.request_id,
                    request.user_identity.as_utf8_or_hex(),
                    request.max_target.as_bytes(),
                    0,
                    current,
                )
                .await
            }
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                let request = OpenExtendedMiningChannel::from_bytes(payload)
                    .map_err(|error| error.to_string())?;
                self.open(
                    ChannelKind::Extended,
                    request.request_id,
                    request.user_identity.as_utf8_or_hex(),
                    request.max_target.as_bytes(),
                    request.min_extranonce_size,
                    current,
                )
                .await
            }
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => {
                let request =
                    SubmitSharesStandard::from_bytes(payload).map_err(|error| error.to_string())?;
                let enonce2 = match self.channels.get(&request.channel_id) {
                    Some(channel) => channel.standard_enonce2,
                    None => [0u8; 8],
                };
                self.submit(Submission {
                    channel_id: request.channel_id,
                    sequence_number: request.sequence_number,
                    job_id: request.job_id,
                    nonce: request.nonce,
                    ntime: request.ntime,
                    version: request.version,
                    enonce2: enonce2.to_vec(),
                })
                .await
            }
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED => {
                let request =
                    SubmitSharesExtended::from_bytes(payload).map_err(|error| error.to_string())?;
                self.submit(Submission {
                    channel_id: request.channel_id,
                    sequence_number: request.sequence_number,
                    job_id: request.job_id,
                    nonce: request.nonce,
                    ntime: request.ntime,
                    version: request.version,
                    enonce2: request.extranonce.as_bytes().to_vec(),
                })
                .await
            }
            MESSAGE_TYPE_UPDATE_CHANNEL => {
                let request =
                    UpdateChannel::from_bytes(payload).map_err(|error| error.to_string())?;
                self.update(request.channel_id, request.maximum_target.as_bytes())
            }
            MESSAGE_TYPE_CLOSE_CHANNEL => {
                let request =
                    CloseChannel::from_bytes(payload).map_err(|error| error.to_string())?;
                self.close_channel(request.channel_id).await;
                Ok(Vec::new())
            }
            _ => Err(format!("not a mining channel message: {message_type}")),
        }
    }

    async fn close_channel(&mut self, channel_id: u32) {
        if let Some(channel) = self.channels.remove(&channel_id)
            && let Err(metrics_error) = self
                .ctx
                .metrics
                .decrement_worker_count(
                    channel.session.btcaddress,
                    channel.session.workername.unwrap_or_default(),
                )
                .await
        {
            error!("Failed to record closed SV2 worker: {metrics_error}");
        }
    }

    /// Release every authorized worker when the connection ends.
    pub(crate) async fn close_all(&mut self) {
        while let Some(channel_id) = self.channels.keys().next().copied() {
            self.close_channel(channel_id).await;
        }
    }

    /// Apply a device's new `maximum_target` and answer with the channel's
    /// target, capped by it. Proxies such as the reference translator send
    /// `UpdateChannel` as their hashrate changes. The nominal hashrate is not
    /// used: vardiff sets the target from submitted shares, as on SV1.
    fn update(&mut self, channel_id: u32, maximum_target: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return Ok(vec![encode_frame(
                UpdateChannelError {
                    channel_id,
                    error_code: string_field("invalid-channel-id")?,
                },
                MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
            )?]);
        };
        let maximum_target = device_max_target(maximum_target);
        if maximum_target == Target::ZERO {
            return Ok(vec![encode_frame(
                UpdateChannelError {
                    channel_id,
                    error_code: string_field("invalid-max-target")?,
                },
                MESSAGE_TYPE_UPDATE_CHANNEL_ERROR,
            )?]);
        }
        channel.max_target = maximum_target;
        let target =
            target_for_difficulty(channel.session.difficulty_adjuster.get_current_difficulty())
                .min(channel.max_target)
                .to_le_bytes();
        Ok(vec![encode_frame(
            SetTarget {
                channel_id,
                maximum_target: u256(&target)?,
            },
            MESSAGE_TYPE_SET_TARGET,
        )?])
    }

    /// Send every open channel a job for `prepared`.
    pub fn on_template(&mut self, prepared: &PreparedNotifyParams) -> Vec<Vec<u8>> {
        let channel_ids: Vec<u32> = self.channels.keys().copied().collect();
        let mut frames = Vec::with_capacity(channel_ids.len() * 2);
        for channel_id in channel_ids {
            match self.job_frames(channel_id, prepared) {
                Ok(job_frames) => frames.extend(job_frames),
                Err(job_error) => {
                    error!("Failed to build SV2 job for channel {channel_id}: {job_error}")
                }
            }
        }
        frames
    }

    async fn open(
        &mut self,
        kind: ChannelKind,
        request_id: u32,
        user_identity: String,
        max_target: &[u8],
        min_extranonce_size: u16,
        current: Option<Arc<PreparedNotifyParams>>,
    ) -> Result<Vec<Vec<u8>>, String> {
        if self.channels.len() >= MAX_CHANNELS_PER_CONNECTION {
            return open_error(request_id, "max-channels-reached");
        }
        if kind == ChannelKind::Extended && min_extranonce_size > EXTRANONCE_SIZE {
            return open_error(request_id, "min-extranonce-size-too-large");
        }
        let device_max_target = device_max_target(max_target);
        if device_max_target == Target::ZERO {
            return open_error(request_id, "invalid-max-target");
        }
        let mut session = Session::<DifficultyAdjuster>::new(
            self.ctx.start_difficulty,
            self.ctx.minimum_difficulty,
            self.ctx.maximum_difficulty,
            self.version_mask,
        );
        let (username, options) = split_user_identity(&user_identity);
        let validated = match validate_username::validate_for_chain(
            username,
            self.ctx.validate_addresses,
            self.ctx.network,
            self.ctx.share_chain,
            self.ctx
                .bch_share_network
                .map(BitcoinCashNetwork::from_share_network),
        ) {
            Ok(validated) => validated,
            Err(_) => return open_error(request_id, "invalid-user-identity"),
        };
        let share_owner = match self.resolve_share_owner(options) {
            Ok(share_owner) => share_owner,
            Err(reason) => {
                debug!("Refusing SV2 channel for {username}: {reason}");
                let code = if extract_string_value(options, "p2p=").is_some() {
                    "invalid-share-address"
                } else {
                    "share-address-required"
                };
                return open_error(request_id, code);
            }
        };
        let user_id = self
            .ctx
            .chain_store_handle
            .add_user(validated.address_str.to_string())
            .await
            .map_err(|error| format!("Failed to store user: {error}"))?;
        session.username = Some(username.to_string());
        session.btcaddress = Some(validated.address_str.to_string());
        session.workername = validated.worker_name.map(|name| name.to_string());
        session.parsed_address = validated.parsed_address;
        session.share_owner = share_owner;
        session.user_id = Some(user_id);
        session.subscribed = true;
        let channel_target =
            target_for_difficulty(session.difficulty_adjuster.get_current_difficulty())
                .min(device_max_target);
        let enonce1 = session.enonce1.to_le_bytes();
        let standard_enonce2 = standard_enonce2(self.next_channel_id);
        let channel_id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        let mut frames = Vec::with_capacity(3);
        let target_bytes = channel_target.to_le_bytes();
        match kind {
            ChannelKind::Standard => {
                let mut prefix = Vec::with_capacity(12);
                prefix.extend_from_slice(&enonce1);
                prefix.extend_from_slice(&standard_enonce2);
                frames.push(encode_frame(
                    OpenStandardMiningChannelSuccess {
                        request_id,
                        channel_id,
                        target: u256(&target_bytes)?,
                        extranonce_prefix: b032(&prefix)?,
                        group_channel_id: 0,
                    },
                    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                )?);
            }
            ChannelKind::Extended => {
                frames.push(encode_frame(
                    OpenExtendedMiningChannelSuccess {
                        request_id,
                        channel_id,
                        target: u256(&target_bytes)?,
                        extranonce_size: EXTRANONCE_SIZE,
                        extranonce_prefix: b032(&enonce1)?,
                        group_channel_id: 0,
                    },
                    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                )?);
            }
        }
        self.channels.insert(
            channel_id,
            Channel {
                kind,
                session,
                standard_enonce2,
                max_target: device_max_target,
                jobs: BTreeMap::new(),
                next_job_id: 1,
                last_prev_hash: None,
            },
        );
        if let Err(metrics_error) = self
            .ctx
            .metrics
            .increment_worker_count(
                validated.address_str.to_string(),
                validated.worker_name.unwrap_or_default().to_string(),
            )
            .await
        {
            error!("Failed to send increment worker count message: {metrics_error}");
        }
        if let Some(prepared) = current {
            frames.extend(self.job_frames(channel_id, &prepared)?);
        }
        Ok(frames)
    }

    /// Owner of a channel's shares from the node's configured share address
    /// and the identity's `p2p=` option, by the SV1 authorize rules.
    ///
    /// `Ok(None)` only in Hydrapool mode, which builds no share commitment.
    fn resolve_share_owner(&self, options: &str) -> Result<Option<ShareOwner>, String> {
        match self.ctx.share_chain {
            Chain::Bitcoin => {
                let parsed = parse_password(options);
                resolve_share_address(
                    self.ctx.miner_address,
                    parsed.miner_address.as_ref(),
                    self.ctx.network,
                    self.ctx.mode,
                )
                .map(|address| {
                    address.map(|address| ShareOwner::Taproot(address.witness_program()))
                })
            }
            Chain::BitcoinCash => {
                let network = self
                    .ctx
                    .bch_share_network
                    .ok_or("Bitcoin Cash share addresses need a network")?;
                resolve_cash_share(self.ctx.cash_share, Some(options), network, self.ctx.mode)
            }
        }
    }

    /// Insert a tracker job for `channel_id` and build its SV2 frames.
    fn job_frames(
        &mut self,
        channel_id: u32,
        prepared: &PreparedNotifyParams,
    ) -> Result<Vec<Vec<u8>>, String> {
        let is_hydrapool = self.ctx.mode == PoolMode::Hydrapool;
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or("job for an unknown channel")?;
        let (bitcoin_address, share_owner) = if is_hydrapool {
            (None, None)
        } else {
            (
                channel.session.parsed_address.as_ref(),
                channel.session.share_owner,
            )
        };
        let (tracker_job_id, _coinbase2) = insert_miner_job(
            prepared,
            bitcoin_address,
            share_owner,
            &self.ctx.tracker_handle,
        );
        let job = self
            .ctx
            .tracker_handle
            .get_job(tracker_job_id)
            .ok_or("tracker lost a job it just inserted")?;
        let template = &job.blocktemplate;
        let prev_hash =
            BlockHash::from_str(&template.previousblockhash).map_err(|error| error.to_string())?;
        let nbits = u32::from_str_radix(&template.bits, 16).map_err(|error| error.to_string())?;
        let version = template.version as u32;
        let new_prev_hash = channel.last_prev_hash != Some(prev_hash);
        if new_prev_hash {
            channel.jobs.clear();
        }
        let channel_job_id = channel.insert_job(tracker_job_id);
        channel.last_prev_hash = Some(prev_hash);
        let min_ntime = if new_prev_hash {
            Sv2Option::new(None)
        } else {
            Sv2Option::new(Some(template.curtime))
        };

        let mut frames = Vec::with_capacity(2);
        match channel.kind {
            ChannelKind::Standard => {
                let enonce1_hex = channel.session.enonce1_hex.clone();
                let merkle_root =
                    standard_merkle_root(&job, &enonce1_hex, &channel.standard_enonce2)?;
                frames.push(encode_frame(
                    NewMiningJob {
                        channel_id,
                        job_id: channel_job_id,
                        min_ntime,
                        version,
                        merkle_root: u256(merkle_root.as_byte_array())?,
                    },
                    MESSAGE_TYPE_NEW_MINING_JOB,
                )?);
            }
            ChannelKind::Extended => {
                let prefix = hex::decode(&job.coinbase1).map_err(|error| error.to_string())?;
                let suffix = hex::decode(&job.coinbase2).map_err(|error| error.to_string())?;
                let path = job
                    .template_merkle_branches
                    .iter()
                    .map(|branch| {
                        U256::new(branch.as_byte_array()).map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                frames.push(encode_frame(
                    NewExtendedMiningJob {
                        channel_id,
                        job_id: channel_job_id,
                        min_ntime,
                        version,
                        version_rolling_allowed: true,
                        merkle_path: Seq0255::new(path).map_err(|error| error.to_string())?,
                        coinbase_tx_prefix: B064K::new(&prefix)
                            .map_err(|error| error.to_string())?,
                        coinbase_tx_suffix: B064K::new(&suffix)
                            .map_err(|error| error.to_string())?,
                    },
                    MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                )?);
            }
        }
        if new_prev_hash {
            frames.push(encode_frame(
                SetNewPrevHash {
                    channel_id,
                    job_id: channel_job_id,
                    prev_hash: u256(prev_hash.as_byte_array())?,
                    min_ntime: template.curtime,
                    nbits,
                },
                MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
            )?);
        }
        Ok(frames)
    }

    async fn submit(&mut self, submission: Submission) -> Result<Vec<Vec<u8>>, String> {
        let Some(channel) = self.channels.get_mut(&submission.channel_id) else {
            return submit_error(&submission, "invalid-channel-id");
        };
        let Some(channel_job) = channel.jobs.get(&submission.job_id).copied() else {
            return submit_error(&submission, "invalid-job-id");
        };
        let tracker_job_id = channel_job.tracker_job_id;
        let Some(job) = self.ctx.tracker_handle.get_job(tracker_job_id) else {
            return submit_error(&submission, "stale-share");
        };
        if submission.enonce2.len() != usize::from(EXTRANONCE_SIZE) {
            return submit_error(&submission, "invalid-extranonce-size");
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_secs();
        if submission.ntime < job.blocktemplate.curtime || u64::from(submission.ntime) > now + 7200
        {
            return submit_error(&submission, "invalid-ntime");
        }
        let template_version = job.blocktemplate.version;
        let rolled = submission.version as i32;
        if (rolled ^ template_version) & !self.version_mask != 0 {
            return submit_error(&submission, "invalid-version");
        }
        let enonce2_hex = hex::encode(&submission.enonce2);
        let coinbase = build_coinbase_from_components(
            &job.coinbase1,
            &channel.session.enonce1_hex,
            &enonce2_hex,
            &job.coinbase2,
        )
        .map_err(|error| error.to_string())?;
        let header = Header {
            version: Version::from_consensus(rolled),
            prev_blockhash: BlockHash::from_str(&job.blocktemplate.previousblockhash)
                .map_err(|error| error.to_string())?,
            merkle_root: compute_merkle_root_from_branches(
                coinbase.compute_txid(),
                &job.template_merkle_branches,
            ),
            time: submission.ntime,
            bits: CompactTarget::from_unprefixed_hex(&job.blocktemplate.bits)
                .map_err(|error| error.to_string())?,
            nonce: submission.nonce,
        };
        let block_hash = header.block_hash();
        if !self
            .ctx
            .tracker_handle
            .add_share(tracker_job_id, block_hash)
        {
            return submit_error(&submission, "duplicate-share");
        }
        // As for SV1, a header that meets the network target is submitted
        // whatever the channel target, and a share that meets the pool target
        // goes to the share chain. The channel target only decides the reply
        // and the accounting below.
        if Target::from_compact(header.bits).is_met_by(block_hash) {
            submit_found_block(&self.ctx, header, coinbase.clone(), &job)
                .await
                .map_err(|error| error.to_string())?;
        }
        let difficulty = channel_job.difficulty;
        let share = SimplePplnsShare::new(
            channel.session.user_id.unwrap_or_default(),
            difficulty,
            channel.session.btcaddress.clone().unwrap_or_default(),
            channel.session.workername.clone().unwrap_or_default(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or_default(),
            format!("{:016x}", tracker_job_id.0),
            enonce2_hex.clone(),
            format!("{:08x}", submission.nonce),
        );
        emit_pool_share(
            &self.ctx,
            PoolShare {
                job_id: tracker_job_id,
                job: &job,
                header,
                block_hash,
                coinbase: &coinbase,
                share: share.clone(),
                enonce1_hex: &channel.session.enonce1_hex,
                enonce2_hex: &enonce2_hex,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        channel.session.last_share_time = Some(SystemTime::now());
        let truediff = get_true_difficulty(&block_hash);
        let meets_channel_target =
            self.ctx.ignore_difficulty || channel_job.target.is_met_by(block_hash);
        if meets_channel_target {
            let _ = self
                .ctx
                .metrics
                .record_share_accepted(share, truediff as u64)
                .await;
        } else {
            let _ = self.ctx.metrics.record_share_rejected().await;
        }
        let (new_difficulty, _is_first_share) = channel
            .session
            .difficulty_adjuster
            .record_share_submission(truediff, tracker_job_id.0, None, SystemTime::now());
        let mut frames = Vec::with_capacity(2);
        if meets_channel_target {
            frames.push(encode_frame(
                SubmitSharesSuccess {
                    channel_id: submission.channel_id,
                    last_sequence_number: submission.sequence_number,
                    new_submits_accepted_count: 1,
                    new_shares_sum: difficulty,
                },
                MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            )?);
        } else {
            frames.extend(submit_error(&submission, "difficulty-too-low")?);
        }
        if let Some(new_difficulty) = new_difficulty {
            let target = target_for_difficulty(new_difficulty)
                .min(channel.max_target)
                .to_le_bytes();
            frames.push(encode_frame(
                SetTarget {
                    channel_id: submission.channel_id,
                    maximum_target: u256(&target)?,
                },
                MESSAGE_TYPE_SET_TARGET,
            )?);
        }
        debug!(
            "SV2 share on channel {}: meets channel target {meets_channel_target}",
            submission.channel_id
        );
        Ok(frames)
    }
}

pub(crate) fn custom_job_error(
    request: &SetCustomMiningJob<'_>,
    code: &'static str,
) -> Result<Vec<Vec<u8>>, String> {
    Ok(vec![encode_frame(
        SetCustomMiningJobError {
            channel_id: request.channel_id,
            request_id: request.request_id,
            error_code: string_field(code)?,
        },
        MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR,
    )?])
}

struct Submission {
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
    enonce2: Vec<u8>,
}

/// Target for a stratum difficulty, as SV1 `mining.set_difficulty` means it:
/// difficulty 1 is the mainnet difficulty-1 target, and difficulty 0 is
/// treated as 1.
pub(crate) fn target_for_difficulty(difficulty: u64) -> Target {
    let divisor = u128::from(difficulty.max(1));
    let dividend = Target::MAX_ATTAINABLE_MAINNET.to_be_bytes();
    let mut quotient = [0u8; 32];
    let mut remainder: u128 = 0;
    for (index, byte) in dividend.iter().enumerate() {
        remainder = (remainder << 8) | u128::from(*byte);
        quotient[index] = (remainder / divisor) as u8;
        remainder %= divisor;
    }
    Target::from_be_bytes(quotient)
}

/// The `max_target` of an open request: a little-endian U256. A malformed
/// one (not 32 bytes) leaves the channel uncapped.
fn device_max_target(max_target: &[u8]) -> Target {
    match <[u8; 32]>::try_from(max_target) {
        Ok(bytes) => Target::from_le_bytes(bytes),
        Err(_) => Target::MAX_ATTAINABLE_MAINNET,
    }
}

/// Split a `user_identity` into the SV1-style username and its options.
///
/// The options start at the first token, after a comma, space, tab or
/// semicolon (the separators of the SV1 password options), that holds a
/// `key=value` pair. Everything before that separator is the username, so a
/// worker name containing a space keeps it, as before options existed. An
/// identity without such a token is all username.
fn split_user_identity(user_identity: &str) -> (&str, &str) {
    const SEPARATORS: [char; 4] = [',', ' ', '\t', ';'];
    for (separator, _) in user_identity.match_indices(SEPARATORS) {
        let rest = &user_identity[separator + 1..];
        let token_end = rest.find(SEPARATORS).unwrap_or(rest.len());
        if rest[..token_end].contains('=') {
            return (&user_identity[..separator], rest);
        }
    }
    (user_identity, "")
}

/// enonce2 the pool fixes for a standard channel. Each channel of a
/// connection has its own random enonce1, so this only has to differ between
/// channels on one connection.
fn standard_enonce2(channel_id: u32) -> [u8; 8] {
    u64::from(channel_id).to_le_bytes()
}

/// Merkle root a standard channel mines: the job's coinbase with the
/// channel's full 12-byte extranonce, folded with the template branches.
fn standard_merkle_root(
    job: &JobDetails,
    enonce1_hex: &str,
    enonce2: &[u8; 8],
) -> Result<TxMerkleNode, String> {
    let coinbase = build_coinbase_from_components(
        &job.coinbase1,
        enonce1_hex,
        &hex::encode(enonce2),
        &job.coinbase2,
    )
    .map_err(|error| error.to_string())?;
    Ok(compute_merkle_root_from_branches(
        coinbase.compute_txid(),
        &job.template_merkle_branches,
    ))
}

fn u256(bytes: &[u8]) -> Result<U256<'_>, String> {
    U256::new(bytes).map_err(|error| error.to_string())
}

fn b032(bytes: &[u8]) -> Result<B032<'_>, String> {
    B032::new(bytes).map_err(|error| error.to_string())
}

fn open_error(request_id: u32, error_code: &'static str) -> Result<Vec<Vec<u8>>, String> {
    Ok(vec![encode_frame(
        OpenMiningChannelError {
            request_id,
            error_code: string_field(error_code)?,
        },
        MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    )?])
}

fn submit_error(submission: &Submission, error_code: &'static str) -> Result<Vec<Vec<u8>>, String> {
    Ok(vec![encode_frame(
        SubmitSharesError {
            channel_id: submission.channel_id,
            sequence_number: submission.sequence_number,
            error_code: string_field(error_code)?,
        },
        MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    )?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::accounting::stats::metrics;
    use crate::stratum::sv2::session::encode_message;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::stratum::work::prepared_notify::PreparedNotifyParamsBuilder;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::{make_test_share_address, setup_test_chain_store_handle};
    use crate::test_utils::{
        test_bch_custom_job, test_bch_prepared, test_bch_solve_custom_job, test_bch_stratum_context,
    };
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::sha256d;
    use bitcoin::{Address, Amount, CompressedPublicKey, Network, Transaction};
    use bitcoindrpc::BitcoindRpcClient;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use p2poolv2_config::DEFAULT_VERSION_MASK;
    use p2poolv2_wallet::bch_share::encode_payout_address;
    use p2poolv2_wallet::bch_share::{BchShareAddress, BchShareNetwork};
    use tokio::sync::mpsc;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    const USERNAME: &str = "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d.rig1";
    /// Easier than almost every hash, so the test share meets the pool target.
    const EASY_POOL_BITS: u32 = 0x2100ffff;

    #[tokio::test]
    async fn zero_maximum_target_is_refused_at_channel_opening() {
        let (ctx, _emissions, _dirs) = test_bch_stratum_context("http://127.0.0.1:1").await;
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let mut request = binary_sv2::to_bytes(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: "unused".try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::new(&[0; 32]).unwrap(),
            min_extranonce_size: 8,
        })
        .unwrap();
        let rejected = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut request,
                None,
            )
            .await
            .unwrap();
        let mut rejected_payload = payload(&rejected[0]);
        let error = OpenMiningChannelError::from_bytes(&mut rejected_payload).unwrap();
        assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-max-target");
        assert!(channels.channels.is_empty());
    }

    #[tokio::test]
    async fn active_custom_job_keeps_its_share_credit_after_difficulty_changes() {
        let (mut ctx, mut emissions, _dirs) = test_bch_stratum_context("http://127.0.0.1:1").await;
        ctx.start_difficulty = 5;
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        let identity = encode_payout_address(&payout, BchShareNetwork::Regtest).unwrap();
        let mut open = binary_sv2::to_bytes(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: identity.as_str().try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::new(&[0xff; 32]).unwrap(),
            min_extranonce_size: 8,
        })
        .unwrap();
        let opened = channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();
        let mut open_payload = payload(&opened[0]);
        let opened = OpenExtendedMiningChannelSuccess::from_bytes(&mut open_payload).unwrap();
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([1; 32], prepared.template().curtime)
            .unwrap();
        let (mut bytes, declared) = test_bch_custom_job(
            Arc::clone(&prepared),
            token,
            vec![],
            false,
            prepared.template().coinbasevalue,
        );
        let request = SetCustomMiningJob::from_bytes(&mut bytes).unwrap();
        let installed = channels
            .install_custom_job(&request, declared, Some(prepared))
            .await
            .unwrap();
        let mut install_payload = payload(&installed[0]);
        let installed = SetCustomMiningJobSuccess::from_bytes(&mut install_payload).unwrap();
        channels
            .channels
            .get_mut(&1)
            .unwrap()
            .session
            .difficulty_adjuster
            .current_difficulty = 99;
        let next_target = target_for_difficulty(1000);
        channels.update(1, &next_target.to_le_bytes()).unwrap();
        assert_eq!(
            channels.channels[&1].jobs[&installed.job_id].target,
            target_for_difficulty(5)
        );
        let header = test_bch_solve_custom_job(&request, opened.extranonce_prefix.as_bytes());
        let mut submit = binary_sv2::to_bytes(SubmitSharesExtended {
            channel_id: 1,
            sequence_number: 1,
            job_id: installed.job_id,
            nonce: header.nonce,
            ntime: header.time,
            version: request.version,
            extranonce: B032::new(&[0; 8]).unwrap(),
        })
        .unwrap();
        let accepted = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
            .await
            .unwrap();
        let mut accepted_payload = payload(&accepted[0]);
        let accepted = SubmitSharesSuccess::from_bytes(&mut accepted_payload).unwrap();
        assert_eq!(accepted.new_shares_sum, 5);
        assert_eq!(emissions.try_recv().unwrap().pplns.difficulty, 5);
        channels.on_template(&test_bch_prepared());
        let next_job = channels.channels[&1].jobs.values().next_back().unwrap();
        assert_eq!(next_job.target, next_target);
        assert_eq!(next_job.difficulty, 1000);
    }

    #[tokio::test]
    async fn node_rejection_does_not_install_a_custom_job() {
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"result": "bad-cb-amount", "error": null, "id": 0}),
            ))
            .expect(1)
            .mount(&rpc)
            .await;
        let (ctx, _emissions, _dirs) = test_bch_stratum_context(&rpc.uri()).await;
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        let identity = encode_payout_address(&payout, BchShareNetwork::Regtest).unwrap();
        let mut open = binary_sv2::to_bytes(OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: identity.as_str().try_into().unwrap(),
            nominal_hash_rate: 1.0,
            max_target: U256::new(&[0xff; 32]).unwrap(),
            min_extranonce_size: 8,
        })
        .unwrap();
        channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([1; 32], prepared.template().curtime)
            .unwrap();
        let (mut bytes, declared) = test_bch_custom_job(
            Arc::clone(&prepared),
            token,
            vec![],
            true,
            prepared.template().coinbasevalue,
        );
        let request = SetCustomMiningJob::from_bytes(&mut bytes).unwrap();
        let rejected = channels
            .install_custom_job(&request, declared, Some(prepared))
            .await
            .unwrap();
        let mut error_payload = payload(&rejected[0]);
        let error = SetCustomMiningJobError::from_bytes(&mut error_payload).unwrap();
        assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-template");
        assert!(channels.channels[&1].jobs.is_empty());
    }

    fn frame_type(frame: &[u8]) -> u8 {
        frame[2]
    }

    fn frame_has_channel_bit(frame: &[u8]) -> bool {
        u16::from_le_bytes([frame[0], frame[1]]) & 0x8000 != 0
    }

    fn payload(frame: &[u8]) -> Vec<u8> {
        frame[6..].to_vec()
    }

    #[test]
    fn difficulty_one_is_the_mainnet_difficulty_one_target() {
        assert_eq!(target_for_difficulty(1), Target::MAX_ATTAINABLE_MAINNET);
        assert_eq!(target_for_difficulty(0), Target::MAX_ATTAINABLE_MAINNET);
    }

    #[test]
    fn difficulty_two_halves_the_target() {
        let half = target_for_difficulty(2).to_be_bytes();
        let full = Target::MAX_ATTAINABLE_MAINNET.to_be_bytes();
        assert_eq!(half[4], full[4] >> 1);
        assert_eq!(half[5], (full[4] << 7) | (full[5] >> 1));
    }

    #[tokio::test]
    async fn extended_channel_mines_the_job_it_is_sent_and_its_share_is_emitted() {
        let template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        let payout_key: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let prepared = Arc::new(
            PreparedNotifyParamsBuilder::new(
                Arc::new(template.clone()),
                vec![OutputPair {
                    address: Address::p2wpkh(&payout_key, Network::Signet),
                    amount: Amount::from_sat(template.coinbasevalue),
                }],
                b"P2Poolv2",
                true,
            )
            .bits(CompactTarget::from_consensus(EASY_POOL_BITS))
            .build()
            .unwrap(),
        );
        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);

        let mut open = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 5,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let opened = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut open,
                Some(Arc::clone(&prepared)),
            )
            .await
            .unwrap();
        assert_eq!(opened.len(), 3);
        assert_eq!(
            frame_type(&opened[0]),
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
        );
        assert_eq!(frame_type(&opened[1]), MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
        assert_eq!(
            frame_type(&opened[2]),
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH
        );
        assert!(!frame_has_channel_bit(&opened[0]));
        assert!(frame_has_channel_bit(&opened[1]));
        assert!(frame_has_channel_bit(&opened[2]));

        let mut success_payload = payload(&opened[0]);
        let success = OpenExtendedMiningChannelSuccess::from_bytes(&mut success_payload).unwrap();
        assert_eq!(success.request_id, 5);
        assert_eq!(success.extranonce_size, EXTRANONCE_SIZE);
        let channel_id = success.channel_id;
        let extranonce_prefix = success.extranonce_prefix.as_bytes().to_vec();
        let mut job_payload = payload(&opened[1]);
        let job = NewExtendedMiningJob::from_bytes(&mut job_payload).unwrap();
        assert!(job.min_ntime.clone().into_inner().is_none());
        let mut prev_hash_payload = payload(&opened[2]);
        let prev_hash = SetNewPrevHash::from_bytes(&mut prev_hash_payload).unwrap();
        assert_eq!(prev_hash.job_id, job.job_id);

        // Rebuild the header the way an SV2 miner does.
        let extranonce = [0x11u8; 8];
        let mut coinbase_bytes = job.coinbase_tx_prefix.as_bytes().to_vec();
        coinbase_bytes.extend_from_slice(&extranonce_prefix);
        coinbase_bytes.extend_from_slice(&extranonce);
        coinbase_bytes.extend_from_slice(job.coinbase_tx_suffix.as_bytes());
        let coinbase: Transaction = deserialize(&coinbase_bytes).unwrap();
        let path = job.merkle_path.clone().into_inner();
        let mut root = coinbase.compute_txid().to_byte_array();
        assert!(path.len() <= 1);
        if let Some(branch) = path.first() {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&root);
            combined.extend_from_slice(branch.as_bytes());
            root = sha256d::Hash::hash(&combined).to_byte_array();
        }
        let header = Header {
            version: Version::from_consensus(job.version as i32),
            prev_blockhash: BlockHash::from_byte_array(*prev_hash.prev_hash.as_array()),
            merkle_root: TxMerkleNode::from_byte_array(root),
            time: prev_hash.min_ntime,
            bits: CompactTarget::from_consensus(prev_hash.nbits),
            nonce: 7,
        };

        let mut submit = payload(
            &encode_message(
                SubmitSharesExtended {
                    channel_id,
                    sequence_number: 1,
                    job_id: job.job_id,
                    nonce: 7,
                    ntime: prev_hash.min_ntime,
                    version: job.version,
                    extranonce: B032::new(&extranonce).unwrap(),
                },
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            )
            .unwrap(),
        );
        let mut duplicate = submit.clone();
        channels
            .channels
            .get_mut(&channel_id)
            .unwrap()
            .session
            .difficulty_adjuster
            .current_difficulty = 77;
        let accepted = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
            .await
            .unwrap();
        assert_eq!(frame_type(&accepted[0]), MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
        let emission = emissions_rx.try_recv().unwrap();
        assert_eq!(emission.header, header);
        let mut accepted_payload = payload(&accepted[0]);
        assert_eq!(
            SubmitSharesSuccess::from_bytes(&mut accepted_payload)
                .unwrap()
                .new_shares_sum,
            1
        );
        assert_eq!(emission.pplns.difficulty, 1);
        assert_eq!(
            emission.pplns.btcaddress.as_deref(),
            Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d")
        );
        assert!(emission.share_commitment.is_some());
        assert!(emission.coinbase_proof.is_some());

        let repeated = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut duplicate, None)
            .await
            .unwrap();
        let mut repeated_payload = payload(&repeated[0]);
        let repeated_error = SubmitSharesError::from_bytes(&mut repeated_payload).unwrap();
        assert_eq!(
            repeated_error.error_code.as_utf8_or_hex(),
            "duplicate-share"
        );

        let mut unknown = payload(
            &encode_message(
                SubmitSharesExtended {
                    channel_id,
                    sequence_number: 2,
                    job_id: 99,
                    nonce: 1,
                    ntime: prev_hash.min_ntime,
                    version: job.version,
                    extranonce: B032::new(&extranonce).unwrap(),
                },
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            )
            .unwrap(),
        );
        let unknown_response = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut unknown, None)
            .await
            .unwrap();
        let mut unknown_payload = payload(&unknown_response[0]);
        let unknown_error = SubmitSharesError::from_bytes(&mut unknown_payload).unwrap();
        assert_eq!(unknown_error.error_code.as_utf8_or_hex(), "invalid-job-id");

        let mut rolled_outside_mask = payload(
            &encode_message(
                SubmitSharesExtended {
                    channel_id,
                    sequence_number: 3,
                    job_id: job.job_id,
                    nonce: 2,
                    ntime: prev_hash.min_ntime,
                    version: job.version ^ 0x0000_0001,
                    extranonce: B032::new(&extranonce).unwrap(),
                },
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            )
            .unwrap(),
        );
        let rolled_response = channels
            .handle(
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
                &mut rolled_outside_mask,
                None,
            )
            .await
            .unwrap();
        let mut rolled_payload = payload(&rolled_response[0]);
        let rolled_error = SubmitSharesError::from_bytes(&mut rolled_payload).unwrap();
        assert_eq!(rolled_error.error_code.as_utf8_or_hex(), "invalid-version");

        // Same tip: the next template is an active job with no new prev hash.
        let refreshed = channels.on_template(&prepared);
        assert_eq!(refreshed.len(), 1);
        assert_eq!(
            frame_type(&refreshed[0]),
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB
        );
        let mut refreshed_payload = payload(&refreshed[0]);
        let refreshed_job = NewExtendedMiningJob::from_bytes(&mut refreshed_payload).unwrap();
        assert_eq!(refreshed_job.min_ntime.into_inner(), Some(template.curtime));
    }

    #[tokio::test]
    async fn standard_channel_mines_the_merkle_root_it_is_sent() {
        let template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        let payout_key: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let prepared = Arc::new(
            PreparedNotifyParamsBuilder::new(
                Arc::new(template.clone()),
                vec![OutputPair {
                    address: Address::p2wpkh(&payout_key, Network::Signet),
                    amount: Amount::from_sat(template.coinbasevalue),
                }],
                b"P2Poolv2",
                true,
            )
            .bits(CompactTarget::from_consensus(EASY_POOL_BITS))
            .build()
            .unwrap(),
        );
        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);

        let mut open = payload(
            &encode_message(
                OpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                },
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let opened = channels
            .handle(
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
                &mut open,
                Some(Arc::clone(&prepared)),
            )
            .await
            .unwrap();
        assert_eq!(
            frame_type(&opened[0]),
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
        );
        let mut success_payload = payload(&opened[0]);
        let success = OpenStandardMiningChannelSuccess::from_bytes(&mut success_payload).unwrap();
        assert_eq!(success.extranonce_prefix.as_bytes().len(), 12);
        let channel_id = success.channel_id;
        assert_eq!(frame_type(&opened[1]), MESSAGE_TYPE_NEW_MINING_JOB);
        let mut job_payload = payload(&opened[1]);
        let job = NewMiningJob::from_bytes(&mut job_payload).unwrap();
        let mut prev_hash_payload = payload(&opened[2]);
        let prev_hash = SetNewPrevHash::from_bytes(&mut prev_hash_payload).unwrap();
        let header = Header {
            version: Version::from_consensus(job.version as i32),
            prev_blockhash: BlockHash::from_byte_array(*prev_hash.prev_hash.as_array()),
            merkle_root: TxMerkleNode::from_byte_array(*job.merkle_root.as_array()),
            time: prev_hash.min_ntime,
            bits: CompactTarget::from_consensus(prev_hash.nbits),
            nonce: 3,
        };

        let mut submit = payload(
            &encode_message(
                SubmitSharesStandard {
                    channel_id,
                    sequence_number: 1,
                    job_id: job.job_id,
                    nonce: 3,
                    ntime: prev_hash.min_ntime,
                    version: job.version,
                },
                MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            )
            .unwrap(),
        );
        let accepted = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, &mut submit, None)
            .await
            .unwrap();
        assert_eq!(frame_type(&accepted[0]), MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
        let emission = emissions_rx.try_recv().unwrap();
        assert_eq!(emission.header, header);
    }

    #[tokio::test]
    async fn a_share_below_the_channel_target_keeps_the_block_submission_policy() {
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        // A network target easier than almost every hash, so the share is a block.
        template.bits = "2100ffff".to_string();
        let payout_key: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let prepared = Arc::new(
            PreparedNotifyParamsBuilder::new(
                Arc::new(template.clone()),
                vec![OutputPair {
                    address: Address::p2wpkh(&payout_key, Network::Signet),
                    amount: Amount::from_sat(template.coinbasevalue),
                }],
                b"P2Poolv2",
                true,
            )
            .bits(CompactTarget::from_consensus(EASY_POOL_BITS))
            .build()
            .unwrap(),
        );
        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;
        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            // A channel target far harder than the test share.
            start_difficulty: 1_000_000_000_000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let mut open = payload(
            &encode_message(
                OpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                },
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let opened = channels
            .handle(
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
                &mut open,
                Some(Arc::clone(&prepared)),
            )
            .await
            .unwrap();
        let mut success_payload = payload(&opened[0]);
        let channel_id = OpenStandardMiningChannelSuccess::from_bytes(&mut success_payload)
            .unwrap()
            .channel_id;
        let mut job_payload = payload(&opened[1]);
        let job = NewMiningJob::from_bytes(&mut job_payload).unwrap();
        let mut prev_hash_payload = payload(&opened[2]);
        let prev_hash = SetNewPrevHash::from_bytes(&mut prev_hash_payload).unwrap();

        let mut submit = payload(
            &encode_message(
                SubmitSharesStandard {
                    channel_id,
                    sequence_number: 1,
                    job_id: job.job_id,
                    nonce: 0,
                    ntime: prev_hash.min_ntime,
                    version: job.version,
                },
                MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            )
            .unwrap(),
        );
        let response = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, &mut submit, None)
            .await
            .unwrap();
        let mut error_payload = payload(&response[0]);
        let error = SubmitSharesError::from_bytes(&mut error_payload).unwrap();
        assert_eq!(error.error_code.as_utf8_or_hex(), "difficulty-too-low");
        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), usize::from(!cfg!(feature = "sim")));
        if let Some(request) = requests.first() {
            assert!(String::from_utf8_lossy(&request.body).contains("submitblock"));
        }
        assert!(emissions_rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn a_connection_cannot_open_more_than_the_channel_cap() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let open = encode_message(
            OpenExtendedMiningChannel {
                request_id: 1,
                user_identity: USERNAME.try_into().unwrap(),
                nominal_hash_rate: 1.0,
                max_target: U256::new(&[0xff; 32]).unwrap(),
                min_extranonce_size: 8,
            },
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .unwrap();
        for _ in 0..MAX_CHANNELS_PER_CONNECTION {
            let mut request = payload(&open);
            let opened = channels
                .handle(
                    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                    &mut request,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                frame_type(&opened[0]),
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
            );
        }
        let mut one_more = payload(&open);
        let refused = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut one_more,
                None,
            )
            .await
            .unwrap();
        let mut refused_payload = payload(&refused[0]);
        let refusal = OpenMiningChannelError::from_bytes(&mut refused_payload).unwrap();
        assert_eq!(refusal.error_code.as_utf8_or_hex(), "max-channels-reached");
    }

    #[tokio::test]
    async fn channels_are_refused_without_a_share_address_or_a_valid_identity() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);

        let mut without_owner = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let refused = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut without_owner,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            frame_type(&refused[0]),
            MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR
        );
        let mut refused_payload = payload(&refused[0]);
        let refusal = OpenMiningChannelError::from_bytes(&mut refused_payload).unwrap();
        assert_eq!(
            refusal.error_code.as_utf8_or_hex(),
            "share-address-required"
        );

        let mut bad_identity = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 2,
                    user_identity: "not-an-address".try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let refused_identity = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut bad_identity,
                None,
            )
            .await
            .unwrap();
        let mut identity_payload = payload(&refused_identity[0]);
        let identity_refusal = OpenMiningChannelError::from_bytes(&mut identity_payload).unwrap();
        assert_eq!(
            identity_refusal.error_code.as_utf8_or_hex(),
            "invalid-user-identity"
        );

        let mut too_much_extranonce = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 3,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 16,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let refused_size = channels
            .handle(
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                &mut too_much_extranonce,
                None,
            )
            .await
            .unwrap();
        let mut size_payload = payload(&refused_size[0]);
        let size_refusal = OpenMiningChannelError::from_bytes(&mut size_payload).unwrap();
        assert_eq!(
            size_refusal.error_code.as_utf8_or_hex(),
            "min-extranonce-size-too-large"
        );
    }

    #[test]
    fn user_identity_splits_into_username_and_sv1_options() {
        assert_eq!(split_user_identity(USERNAME), (USERNAME, ""));
        assert_eq!(
            split_user_identity("address.rig1,p2p=share"),
            ("address.rig1", "p2p=share")
        );
        assert_eq!(
            split_user_identity("address.rig1 p2p=share;d=5"),
            ("address.rig1", "p2p=share;d=5")
        );
    }

    #[test]
    fn a_worker_name_with_a_space_stays_in_the_username() {
        assert_eq!(
            split_user_identity("address.my rig"),
            ("address.my rig", "")
        );
        assert_eq!(
            split_user_identity("address.my rig,p2p=share"),
            ("address.my rig", "p2p=share")
        );
    }

    #[tokio::test]
    async fn a_bitcoin_channel_takes_its_share_address_from_p2p() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let share_address = make_test_share_address(2, Network::Signet);
        let identity = format!("{USERNAME},p2p={share_address}");

        let mut open = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: identity.as_str().try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let opened = channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();

        assert_eq!(
            frame_type(&opened[0]),
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
        );
        let session = &channels.channels[&1].session;
        assert_eq!(
            session.share_owner,
            Some(ShareOwner::Taproot(share_address.witness_program()))
        );
        assert_eq!(session.username.as_deref(), Some(USERNAME));
    }

    #[tokio::test]
    async fn a_channel_naming_another_share_address_than_the_node_is_refused() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let identity = format!(
            "{USERNAME},p2p={}",
            make_test_share_address(2, Network::Signet)
        );

        let mut open = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: identity.as_str().try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let refused = channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();

        let mut refused_payload = payload(&refused[0]);
        let refusal = OpenMiningChannelError::from_bytes(&mut refused_payload).unwrap();
        assert_eq!(refusal.error_code.as_utf8_or_hex(), "invalid-share-address");
        assert!(channels.channels.is_empty());
    }

    #[tokio::test]
    async fn a_bitcoin_cash_channel_takes_its_share_hash_from_p2p() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
            share_chain: Chain::BitcoinCash,
            bch_share_network: Some(BchShareNetwork::Regtest),
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let share_address = BchShareAddress::new(BchShareNetwork::Regtest, [0x22; 20]).encode();
        let identity =
            format!("bchreg:qzh5k63rhy4jg6jtyssmzddju5kkng4jzu8ktcypfm.rig1,p2p={share_address}");

        let mut open = payload(
            &encode_message(
                OpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: identity.as_str().try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                },
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let opened = channels
            .handle(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();

        assert_eq!(
            frame_type(&opened[0]),
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS
        );
        assert_eq!(
            channels.channels[&1].session.share_owner,
            Some(ShareOwner::CashP2pkh([0x22; 20]))
        );
    }

    #[tokio::test]
    async fn a_bitcoin_cash_channel_with_a_taproot_share_address_is_refused() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
            share_chain: Chain::BitcoinCash,
            bch_share_network: Some(BchShareNetwork::Regtest),
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let identity = format!(
            "bchreg:qzh5k63rhy4jg6jtyssmzddju5kkng4jzu8ktcypfm.rig1,p2p={}",
            make_test_share_address(2, Network::Regtest)
        );

        let mut open = payload(
            &encode_message(
                OpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: identity.as_str().try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                },
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            )
            .unwrap(),
        );
        let refused = channels
            .handle(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();

        let mut refused_payload = payload(&refused[0]);
        let refusal = OpenMiningChannelError::from_bytes(&mut refused_payload).unwrap();
        assert_eq!(refusal.error_code.as_utf8_or_hex(), "invalid-share-address");
    }

    #[tokio::test]
    async fn update_channel_answers_with_a_target_capped_by_the_new_maximum() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let mut open = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();
        let mut lower_maximum = [0u8; 32];
        lower_maximum[..16].copy_from_slice(&[0xff; 16]);
        let mut update = payload(
            &encode_message(
                UpdateChannel {
                    channel_id: 1,
                    nominal_hash_rate: 1.0,
                    maximum_target: U256::new(&lower_maximum).unwrap(),
                },
                MESSAGE_TYPE_UPDATE_CHANNEL,
            )
            .unwrap(),
        );
        let answered = channels
            .handle(MESSAGE_TYPE_UPDATE_CHANNEL, &mut update, None)
            .await
            .unwrap();

        assert_eq!(answered.len(), 1);
        assert_eq!(frame_type(&answered[0]), MESSAGE_TYPE_SET_TARGET);
        assert!(frame_has_channel_bit(&answered[0]));
        let mut set_target_payload = payload(&answered[0]);
        let set_target = SetTarget::from_bytes(&mut set_target_payload).unwrap();
        assert_eq!(set_target.channel_id, 1);
        assert_eq!(set_target.maximum_target.as_bytes(), &lower_maximum);
        let rejected = channels.update(1, &[0; 32]).unwrap();
        let mut rejected_payload = payload(&rejected[0]);
        let error = UpdateChannelError::from_bytes(&mut rejected_payload).unwrap();
        assert_eq!(error.error_code.as_utf8_or_hex(), "invalid-max-target");
        assert_eq!(
            channels.channels[&1].max_target.to_le_bytes(),
            lower_maximum
        );
    }

    #[tokio::test]
    async fn update_channel_for_an_unknown_channel_gets_an_error_reply() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let mut update = payload(
            &encode_message(
                UpdateChannel {
                    channel_id: 7,
                    nominal_hash_rate: 1.0,
                    maximum_target: U256::new(&[0xff; 32]).unwrap(),
                },
                MESSAGE_TYPE_UPDATE_CHANNEL,
            )
            .unwrap(),
        );
        let answered = channels
            .handle(MESSAGE_TYPE_UPDATE_CHANNEL, &mut update, None)
            .await
            .unwrap();

        assert_eq!(frame_type(&answered[0]), MESSAGE_TYPE_UPDATE_CHANNEL_ERROR);
        let mut error_payload = payload(&answered[0]);
        let update_error = UpdateChannelError::from_bytes(&mut error_payload).unwrap();
        assert_eq!(
            update_error.error_code.as_utf8_or_hex(),
            "invalid-channel-id"
        );
    }

    #[tokio::test]
    async fn close_channel_removes_the_channel() {
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
        let mut open = payload(
            &encode_message(
                OpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: USERNAME.try_into().unwrap(),
                    nominal_hash_rate: 1.0,
                    max_target: U256::new(&[0xff; 32]).unwrap(),
                    min_extranonce_size: 8,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .unwrap(),
        );
        channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();
        assert_eq!(channels.channels.len(), 1);
        channels
            .handle(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, &mut open, None)
            .await
            .unwrap();
        assert_eq!(channels.channels.len(), 2);
        let mut close = payload(
            &encode_message(
                CloseChannel {
                    channel_id: 1,
                    reason_code: "done".try_into().unwrap(),
                },
                MESSAGE_TYPE_CLOSE_CHANNEL,
            )
            .unwrap(),
        );
        let answered = channels
            .handle(MESSAGE_TYPE_CLOSE_CHANNEL, &mut close, None)
            .await
            .unwrap();

        assert!(answered.is_empty());
        assert_eq!(channels.channels.len(), 1);
        let (address, _) = USERNAME.split_once('.').unwrap();
        assert!(channels.ctx.metrics.get_metrics().await.users[address].workers["rig1"].active);
        channels.close_all().await;
        assert!(channels.channels.is_empty());
        assert!(!channels.ctx.metrics.get_metrics().await.users[address].workers["rig1"].active);
        channels.close_all().await;
    }
}
