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
//! The miner's payout address is the channel's `user_identity`
//! (`<address>.<worker>`, as an SV1 username). Stratum V2 has no password to
//! carry `p2p=`, so on the share chain a channel's shares belong to the
//! node's configured `miner_address`; without one, a P2Poolv2 node refuses
//! to open the channel.

use super::session::{encode_frame, string_field};
use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::config::{BitcoinCashNetwork, Chain, PoolMode};
use crate::stratum::difficulty_adjuster::{DifficultyAdjuster, DifficultyAdjusterTrait};
use crate::stratum::message_handlers::submit::{
    PoolShare, emit_pool_share, get_true_difficulty, submit_found_block,
};
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
use bitcoin::{BlockHash, CompactTarget, Target, TxMerkleNode};
use mining_sv2::{
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, NewExtendedMiningJob,
    NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
    SetNewPrevHash, SetTarget, SubmitSharesError, SubmitSharesExtended, SubmitSharesStandard,
    SubmitSharesSuccess,
};
use p2poolv2_wallet::share_owner::ShareOwner;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error};

/// Bytes of extranonce a miner rolls on an extended channel (SV1 enonce2).
pub const EXTRANONCE_SIZE: u16 = 8;

/// Jobs a channel remembers. Older ones are dropped; the tracker keeps a job
/// for 15 minutes, far longer than this many templates take to arrive.
const MAX_CHANNEL_JOBS: usize = 32;

/// Message types this module handles.
pub fn is_mining_channel_message(message_type: u8) -> bool {
    matches!(
        message_type,
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL
            | MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL
            | MESSAGE_TYPE_SUBMIT_SHARES_STANDARD
            | MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelKind {
    /// The pool fixes all 12 extranonce bytes and sends merkle roots.
    Standard,
    /// The miner rolls the 8 enonce2 bytes and builds the coinbase.
    Extended,
}

struct Channel {
    kind: ChannelKind,
    session: Session<DifficultyAdjuster>,
    /// enonce2 for a standard channel; unused on an extended one.
    standard_enonce2: [u8; 8],
    /// Easiest target the device accepts, from the open request.
    max_target: Target,
    /// Channel job id to tracker job id.
    jobs: BTreeMap<u32, JobId>,
    next_job_id: u32,
    last_prev_hash: Option<BlockHash>,
}

/// The mining channels of one SV2 connection.
pub struct MiningChannels {
    ctx: StratumContext,
    version_mask: i32,
    channels: BTreeMap<u32, Channel>,
    next_channel_id: u32,
}

impl MiningChannels {
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
            _ => Err(format!("not a mining channel message: {message_type}")),
        }
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
        if kind == ChannelKind::Extended && min_extranonce_size > EXTRANONCE_SIZE {
            return open_error(request_id, "min-extranonce-size-too-large");
        }
        let mut session = Session::<DifficultyAdjuster>::new(
            self.ctx.start_difficulty,
            self.ctx.minimum_difficulty,
            self.ctx.maximum_difficulty,
            self.version_mask,
        );
        let validated = match validate_username::validate_for_chain(
            &user_identity,
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
        let share_owner = self.configured_share_owner();
        if self.ctx.mode == PoolMode::P2poolv2 && share_owner.is_none() {
            return open_error(request_id, "share-address-required");
        }
        let user_id = self
            .ctx
            .chain_store_handle
            .add_user(validated.address_str.to_string())
            .await
            .map_err(|error| format!("Failed to store user: {error}"))?;
        session.username = Some(user_identity.clone());
        session.btcaddress = Some(validated.address_str.to_string());
        session.workername = validated.worker_name.map(|name| name.to_string());
        session.parsed_address = validated.parsed_address;
        session.share_owner = share_owner;
        session.user_id = Some(user_id);
        session.subscribed = true;
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

        let device_max_target = device_max_target(max_target);
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
        if let Some(prepared) = current {
            frames.extend(self.job_frames(channel_id, &prepared)?);
        }
        Ok(frames)
    }

    fn configured_share_owner(&self) -> Option<ShareOwner> {
        match self.ctx.share_chain {
            Chain::Bitcoin => self
                .ctx
                .miner_address
                .map(|address| ShareOwner::Taproot(address.witness_program())),
            Chain::BitcoinCash => self.ctx.cash_share.map(ShareOwner::CashP2pkh),
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
        let channel_job_id = channel.next_job_id;
        channel.next_job_id = channel.next_job_id.wrapping_add(1);
        channel.jobs.insert(channel_job_id, tracker_job_id);
        while channel.jobs.len() > MAX_CHANNEL_JOBS {
            channel.jobs.pop_first();
        }
        let new_prev_hash = channel.last_prev_hash != Some(prev_hash);
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
        let Some(tracker_job_id) = channel.jobs.get(&submission.job_id).copied() else {
            return submit_error(&submission, "invalid-job-id");
        };
        let Some(job) = self.ctx.tracker_handle.get_job(tracker_job_id) else {
            return submit_error(&submission, "stale-share");
        };
        if submission.enonce2.len() != usize::from(EXTRANONCE_SIZE) {
            return submit_error(&submission, "invalid-extranonce-size");
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
        let difficulty = channel.session.difficulty_adjuster.get_current_difficulty();
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
            self.ctx.ignore_difficulty || target_for_difficulty(difficulty).is_met_by(block_hash);
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
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::sha256d;
    use bitcoin::{Address, Amount, CompressedPublicKey, Network, Transaction};
    use bitcoindrpc::BitcoindRpcClient;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use p2poolv2_config::DEFAULT_VERSION_MASK;
    use tokio::sync::mpsc;

    const USERNAME: &str = "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d.rig1";
    /// Easier than almost every hash, so the test share meets the pool target.
    const EASY_POOL_BITS: u32 = 0x2100ffff;

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
        let accepted = channels
            .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
            .await
            .unwrap();
        assert_eq!(frame_type(&accepted[0]), MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
        let emission = emissions_rx.try_recv().unwrap();
        assert_eq!(emission.header, header);
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
    async fn a_share_below_the_channel_target_still_submits_a_found_block() {
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
        assert_eq!(requests.len(), 1);
        assert!(String::from_utf8_lossy(&requests[0].body).contains("submitblock"));
        assert!(emissions_rx.try_recv().is_ok());
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
}
