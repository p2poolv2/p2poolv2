// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One miner's shares and weight in the share chain PPLNS window.
//!
//! Answers "which shares and PPLNS weight does this address have" from the
//! node's own payout window, so a share chain explorer or miner software
//! need not index the whole chain. The window is anchored where this node
//! mines, and walked and weighted by the same `PplnsWindow` code that builds
//! and validates coinbases.
//!
//! That window is shared with the payout and validation code, which take its
//! write lock for every template and share. `/miner` takes it at most once
//! per anchor, on a blocking thread: one walk records every miner's credits
//! (`MinerWindowSource`), and every lookup until the anchor moves reads that
//! snapshot alone. A stream of requests, for any addresses, therefore cannot
//! hold up job creation.

use crate::api::endpoints::MAX_NUM_SHARES_IN_RESPONSE;
use crate::api::error::ApiError;
use crate::api::server::{AppConfig, AppState};
use axum::{
    Json,
    extract::{Query, State},
};
use bitcoin::CompactTarget;
use bitcoin::{Address, BlockHash, Network};
use p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow;
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    MinerCredits, WindowCredit, WindowCredits, WindowError, bitcoin_block_difficulty,
};
use p2poolv2_lib::address::bch_share::{self, BchShareNetwork};
use p2poolv2_lib::address::share_owner::{ShareOwner, to_address_string};
use p2poolv2_lib::address_display::payout_address_string;
use p2poolv2_lib::config::{BitcoinCashNetwork, Chain, parse_payout_address, parse_share_address};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::writer::StoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;

/// Query parameters for the /miner endpoint.
#[derive(Deserialize)]
pub struct MinerQuery {
    /// The miner's payout address or share chain address.
    pub address: Option<String>,
    /// Maximum number of shares listed. Defaults to the maximum.
    pub limit: Option<u32>,
}

/// JSON response for the /miner endpoint.
///
/// Weights and difficulties are decimal strings: a window's total weight
/// exceeds the integers a JSON number carries exactly in most clients.
#[derive(Serialize)]
pub struct MinerResponse {
    /// The queried address as this node spells it.
    pub address: String,
    /// `payout` for a payout address, `share` for a share chain address.
    pub address_type: &'static str,
    /// The share this node mines on. The next share's coinbase pays the
    /// window below it.
    pub anchor: String,
    /// Height of the anchor.
    pub anchor_height: u32,
    /// The window as a whole.
    pub window: WindowSummary,
    /// Window shares this address mined.
    pub share_count: usize,
    /// Uncles this address mined that window shares include.
    pub uncle_count: usize,
    /// Sum of this address's weight in the window.
    pub weight: String,
    /// `share_count` over the window's share count: its share of the window.
    pub share_fraction: f64,
    /// `weight` over the window's weight: the fraction of the next block's
    /// PPLNS payout it would earn. The payout is what is left of the coinbase
    /// after the donation and fee the finding share's header sets.
    pub payout_fraction: f64,
    /// This address's shares and uncles, newest first, at most `limit`.
    pub shares: Vec<MinerShare>,
}

/// The PPLNS window the miner is part of.
#[derive(Serialize)]
pub struct WindowSummary {
    /// Height of the newest share in the window, below the shares not yet
    /// mature for payout.
    pub newest_height: Option<u32>,
    /// Height of the oldest share in the window.
    pub oldest_height: Option<u32>,
    /// Number of shares in the window.
    pub share_count: usize,
    /// Sum of every weight in the window.
    pub weight: String,
}

/// One share or uncle the miner earns weight from.
#[derive(Serialize)]
pub struct MinerShare {
    /// The share or uncle that earned the weight.
    pub blockhash: String,
    /// Height of the window share carrying the weight. An uncle is credited
    /// at the height of the share that includes it.
    pub height: u32,
    /// The window share that includes this uncle, or null for a share.
    pub nephew: Option<String>,
    /// Share difficulty before weighting.
    pub difficulty: String,
    /// Weight credited.
    pub weight: String,
    /// Payout address the weight is paid to, as named by the share.
    pub payout_address: String,
}

/// The node's share chain PPLNS window, and the snapshot of it `/miner`
/// answers from.
pub(crate) struct MinerWindowSource {
    /// The window the payout and validation code share.
    window: Arc<RwLock<PplnsWindow>>,
    /// Every miner's credits at the last anchor asked about. One entry is
    /// enough, since the anchor only moves with the chain, and a window's
    /// credits at one anchor never change. Holding this async lock while a
    /// snapshot is built makes concurrent requests at a new anchor build it
    /// once.
    snapshot: Mutex<Option<(BlockHash, Arc<WindowCredits>)>>,
    preparation: Mutex<Option<PreparationSnapshot>>,
}

struct PreparationSnapshot {
    anchor: BlockHash,
    bits: u32,
    weights: Arc<HashMap<Address, u128>>,
}

impl MinerWindowSource {
    pub(crate) fn new(window: Arc<RwLock<PplnsWindow>>) -> Self {
        Self {
            window,
            snapshot: Mutex::new(None),
            preparation: Mutex::new(None),
        }
    }

    /// Exact payout weights use the selected paying block's bits, never the
    /// dashboard's estimate from an older anchor header. Cache one snapshot;
    /// lock ordering is preparation-cache then window, only on a blocking task.
    pub(crate) async fn preparation_weights(
        &self,
        anchor: BlockHash,
        bits: u32,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<Arc<HashMap<Address, u128>>, ApiError> {
        let mut cache = self.preparation.lock().await;
        if let Some(snapshot) = cache.as_ref()
            && (snapshot.anchor, snapshot.bits) == (anchor, bits)
        {
            return Ok(Arc::clone(&snapshot.weights));
        }
        let window = Arc::clone(&self.window);
        let store = chain_store_handle.clone();
        let weights = tokio::task::spawn_blocking(move || {
            let mut window = window
                .write()
                .map_err(|_| ApiError::ServiceUnavailable("PPLNS window unavailable".into()))?;
            let difficulty =
                bitcoin_block_difficulty(CompactTarget::from_consensus(bits), window.network());
            window
                .get_distribution_from_start_hash(anchor, difficulty, &store)
                .map_err(window_error)
        })
        .await
        .map_err(|_| ApiError::ServiceUnavailable("PPLNS preparation task failed".into()))??;
        let weights = Arc::new(weights);
        *cache = Some(PreparationSnapshot {
            anchor,
            bits,
            weights: Arc::clone(&weights),
        });
        Ok(weights)
    }

    /// Every miner's credits at `anchor`: the snapshot when it is for
    /// `anchor`, otherwise a new one built on a blocking thread, which
    /// replaces it.
    pub(crate) async fn credits_at(
        &self,
        anchor: BlockHash,
        chain_store_handle: &ChainStoreHandle,
    ) -> Result<Arc<WindowCredits>, ApiError> {
        let mut snapshot = self.snapshot.lock().await;
        if let Some((snapshot_anchor, credits)) = snapshot.as_ref()
            && *snapshot_anchor == anchor
        {
            return Ok(Arc::clone(credits));
        }

        let window = Arc::clone(&self.window);
        let chain_store_handle = chain_store_handle.clone();
        let credits = tokio::task::spawn_blocking(move || {
            build_window_credits(&window, anchor, &chain_store_handle)
        })
        .await
        .map_err(|error| ApiError::ServerError(format!("PPLNS window task failed: {error}")))??;

        let credits = Arc::new(credits);
        *snapshot = Some((anchor, Arc::clone(&credits)));
        Ok(credits)
    }
}

/// Walk the window once for `anchor`, under its write lock. Blocks, so it
/// runs on a blocking thread.
///
/// On Bitcoin Cash the window is sized by the paying block's difficulty, and
/// the next block has no header yet. The anchor share's own bitcoin header
/// carries the bits this node last mined on, which the next share carries too
/// unless a new bitcoin block arrives first, so the view is sized from them.
/// The fixed Bitcoin window does not read them.
fn build_window_credits(
    window: &RwLock<PplnsWindow>,
    anchor: BlockHash,
    chain_store_handle: &ChainStoreHandle,
) -> Result<WindowCredits, ApiError> {
    let anchor_bits = chain_store_handle
        .get_share_header(&anchor)
        .map_err(|error| {
            ApiError::ServerError(format!("Failed to read the anchor share: {error}"))
        })?
        .bitcoin_header
        .bits;
    let mut window = window
        .write()
        .map_err(|_| ApiError::ServerError("PPLNS window lock poisoned".to_string()))?;
    if window.is_empty() {
        return Err(ApiError::ServiceUnavailable(
            "PPLNS window is not loaded yet".to_string(),
        ));
    }
    let paying_block_difficulty = bitcoin_block_difficulty(anchor_bits, window.network());
    window
        .get_window_credits_from_start_hash(
            anchor,
            paying_block_difficulty,
            chain_store_handle,
            MAX_NUM_SHARES_IN_RESPONSE as usize,
        )
        .map_err(window_error)
}

/// Which of a share header's two addresses a query names.
enum MinerAddress {
    /// The payout address, `miner_bitcoin_address`.
    Payout(Address),
    /// The share owner, `miner_address`: the share chain address.
    ShareOwner(ShareOwner),
}

/// Returns one miner's shares and weight in the PPLNS window the next share
/// this node mines would pay.
///
/// Accepts the payout address (a CashAddr with or without its prefix on
/// Bitcoin Cash, a Bitcoin address on Bitcoin) or the share chain address.
/// An address with nothing in the window gets zero counts and no shares.
pub(crate) async fn miner(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MinerQuery>,
) -> Result<Json<MinerResponse>, ApiError> {
    let address = query
        .address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .ok_or_else(|| ApiError::BadRequest("address is required".to_string()))?;
    let limit = query.limit.unwrap_or(MAX_NUM_SHARES_IN_RESPONSE);
    if !(1..=MAX_NUM_SHARES_IN_RESPONSE).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_NUM_SHARES_IN_RESPONSE}, got {limit}"
        )));
    }
    Ok(Json(miner_report(&state, address, limit as usize).await?))
}

/// What `/miner` answers for `address`, listing at most `limit` shares.
/// Shared with the dashboard's miner page, so both read the same snapshot.
pub(crate) async fn miner_report(
    state: &AppState,
    address: &str,
    limit: usize,
) -> Result<MinerResponse, ApiError> {
    let miner = parse_miner(address, &state.app_config)?;

    let window_source = state.pplns_window.as_ref().ok_or_else(|| {
        ApiError::NotFound("This node does not pay from the share chain PPLNS window".to_string())
    })?;
    let anchor = state
        .chain_store_handle
        .get_mining_base()
        .map_err(|error| match error {
            StoreError::NotFound(_) => {
                ApiError::NotFound("No share chain tip to anchor the window on".to_string())
            }
            error => ApiError::ServerError(format!("Failed to get the mining base: {error}")),
        })?;
    let window_credits = window_source
        .credits_at(anchor, &state.chain_store_handle)
        .await?;

    Ok(build_response(
        &miner,
        anchor,
        &window_credits,
        limit,
        &state.app_config,
    ))
}

/// Read `address` as either of the two addresses a share header carries,
/// for the chain this node mines. A share chain address is tried first: its
/// prefix and checksum keep it from also decoding as a payout.
fn parse_miner(address: &str, app_config: &AppConfig) -> Result<MinerAddress, ApiError> {
    match app_config.cash_network {
        Some(share_network) => parse_bitcoin_cash_miner(address, share_network),
        None => parse_bitcoin_miner(address, app_config.network),
    }
}

/// A `p2pool:`, `tp2pool:` or `rp2pool:` share address, or a CashAddr
/// payout. A payout's prefix (`bitcoincash:`, `bchtest:`, `bchreg:`) may be
/// left out, as in a stratum username; the network's prefix is then assumed
/// and the checksum still has to match it.
fn parse_bitcoin_cash_miner(
    address: &str,
    share_network: BchShareNetwork,
) -> Result<MinerAddress, ApiError> {
    let share_error = match bch_share::parse(address, share_network) {
        Ok(share_address) => {
            return Ok(MinerAddress::ShareOwner(ShareOwner::CashP2pkh(
                share_address.hash,
            )));
        }
        Err(error) => error,
    };
    let cash_network = BitcoinCashNetwork::from_share_network(share_network);
    let prefixed_address = if address.contains(':') {
        address.to_string()
    } else {
        format!("{}:{address}", cash_network.cashaddr_prefix())
    };
    parse_payout_address(
        &prefixed_address,
        Chain::BitcoinCash,
        cash_network.legacy_network(),
        Some(cash_network),
    )
    .map(MinerAddress::Payout)
    .map_err(|payout_error| {
        ApiError::BadRequest(format!(
            "Invalid address '{address}': not a share address ({share_error}) nor a payout address ({})",
            payout_error.message
        ))
    })
}

/// A share chain address for `network`, or a Bitcoin payout address.
fn parse_bitcoin_miner(address: &str, network: Network) -> Result<MinerAddress, ApiError> {
    let share_error = match parse_share_address(address, network) {
        Ok(share_address) => {
            return Ok(MinerAddress::ShareOwner(ShareOwner::from(
                share_address.witness_program(),
            )));
        }
        Err(error) => error,
    };
    parse_payout_address(address, Chain::Bitcoin, network, None)
        .map(MinerAddress::Payout)
        .map_err(|payout_error| {
            ApiError::BadRequest(format!(
                "Invalid address '{address}': not a share address ({}) nor a payout address ({})",
                share_error.message, payout_error.message
            ))
        })
}

/// Map a window failure to a response. A truncated window is this node's
/// cache falling short of the anchor, which the next anchor clears; a read
/// failure is a server error.
fn window_error(error: WindowError) -> ApiError {
    match error {
        WindowError::InsufficientEntries { .. } => ApiError::ServiceUnavailable(error.to_string()),
        WindowError::ReadFailure(_) => {
            ApiError::ServerError(format!("Failed to read the PPLNS window: {error}"))
        }
    }
}

/// Shape a miner's credits for the wire, listing at most `limit` shares and
/// rendering every address for this node's chain. A miner the window does
/// not credit gets zeros.
fn build_response(
    miner: &MinerAddress,
    anchor: BlockHash,
    window_credits: &WindowCredits,
    limit: usize,
    app_config: &AppConfig,
) -> MinerResponse {
    let (address, address_type, miner_credits) = match miner {
        MinerAddress::Payout(address) => (
            payout_address_string(address, app_config.cash_network),
            "payout",
            window_credits.by_payout_address.get(address),
        ),
        MinerAddress::ShareOwner(owner) => (
            to_address_string(owner, app_config.network, app_config.cash_network),
            "share",
            window_credits.by_share_owner.get(owner),
        ),
    };
    let no_credits = MinerCredits::default();
    let miner_credits = miner_credits.unwrap_or(&no_credits);
    let shares = miner_credits
        .credits
        .iter()
        .take(limit)
        .map(|credit| miner_share(credit, app_config.cash_network))
        .collect();

    MinerResponse {
        address,
        address_type,
        anchor: anchor.to_string(),
        anchor_height: window_credits.anchor_height,
        window: WindowSummary {
            newest_height: window_credits.newest_height,
            oldest_height: window_credits.oldest_height,
            share_count: window_credits.window_share_count,
            weight: window_credits.window_weight.to_string(),
        },
        share_count: miner_credits.share_count,
        uncle_count: miner_credits.uncle_count,
        weight: miner_credits.weight.to_string(),
        share_fraction: fraction(
            miner_credits.share_count as u128,
            window_credits.window_share_count as u128,
        ),
        payout_fraction: fraction(miner_credits.weight, window_credits.window_weight),
        shares,
    }
}

/// One credit as the wire shows it.
fn miner_share(credit: &WindowCredit, cash_network: Option<BchShareNetwork>) -> MinerShare {
    MinerShare {
        blockhash: credit.blockhash.to_string(),
        height: credit.height,
        nephew: credit.nephew.map(|nephew| nephew.to_string()),
        difficulty: credit.difficulty.to_string(),
        weight: credit.weight.to_string(),
        payout_address: payout_address_string(&credit.payout_address, cash_network),
    }
}

/// `part / whole` as a float, or zero for an empty whole.
fn fraction(part: u128, whole: u128) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, AppState};
    use axum::extract::{Query, State};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::address::bch_share::BchShareAddress;
    use p2poolv2_lib::config::bitcoin_cash_donation_cashaddr;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::shares::share_block::ShareBlock;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::{
        PUBKEY_G, TestShareBlockBuilder, genesis_for_tests, setup_test_chain_store_handle,
    };

    use axum::Json;
    use bitcoin::hashes::Hash;
    use bitcoin::script::Builder;
    use p2poolv2_lib::address::share_owner::ShareOwner as WalletOwner;
    use p2poolv2_lib::shares::bch_coinbase::BchCoinbase;
    use p2poolv2_lib::shares::merge_mining::MergeMiningCommitment;
    use p2poolv2_lib::shares::share_commitment::ShareCommitment;
    use p2poolv2_lib::stratum::sv2::preparation::prepare_coinbase;
    use p2poolv2_lib::test_utils::test_bch_job_token_and_template;

    /// Hash of the Bitcoin Cash share owner the BCH test genesis names.
    const CASH_SHARE_HASH: [u8; 20] = [0x22; 20];

    async fn build_test_state(
        network: Network,
        cash_network: Option<BchShareNetwork>,
        pplns_window: Option<Arc<RwLock<PplnsWindow>>>,
    ) -> (Arc<AppState>, tempfile::TempDir) {
        let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let metrics_temp = tempfile::tempdir().unwrap();
        let metrics_handle =
            metrics::start_metrics(metrics_temp.path().to_str().unwrap().to_string())
                .await
                .unwrap();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 0,
                network,
                cash_network,
                cors_allowed: false,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle: start_tracker_actor(),
            node_handle: NodeHandle::new_for_test(),
            monitoring_event_sender: create_monitoring_event_channel().0,
            auth_user: None,
            auth_token: None,
            pplns_window: pplns_window.map(|window| Arc::new(MinerWindowSource::new(window))),
        });
        (state, temp_dir)
    }

    /// Confirm `share` on top of the chain, as the organise worker would.
    async fn confirm_share(state: &AppState, share: &ShareBlock) {
        state
            .chain_store_handle
            .add_share_block_and_organise_header(share.clone())
            .await
            .unwrap();
        state
            .chain_store_handle
            .mark_block_valid(share.block_hash())
            .await
            .unwrap();
        state.chain_store_handle.organise_block().await.unwrap();
    }

    /// Bring the shared window up to the confirmed tip, as the organise
    /// worker does after each promotion.
    fn update_window(state: &AppState) {
        state
            .pplns_window
            .as_ref()
            .unwrap()
            .window
            .write()
            .unwrap()
            .update(&state.chain_store_handle)
            .unwrap();
    }

    fn query(address: &str) -> Query<MinerQuery> {
        Query(MinerQuery {
            address: Some(address.to_string()),
            limit: None,
        })
    }

    /// A chipnet genesis paying the chipnet donation CashAddr, owned by
    /// `CASH_SHARE_HASH`.
    fn bitcoin_cash_genesis() -> ShareBlock {
        let mut genesis = genesis_for_tests();
        genesis.header.miner_bitcoin_address = parse_payout_address(
            bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet),
            Chain::BitcoinCash,
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BitcoinCashNetwork::Chipnet),
        )
        .unwrap();
        genesis.header.miner_address = ShareOwner::CashP2pkh(CASH_SHARE_HASH);
        genesis
    }

    #[tokio::test]
    async fn bitcoin_payout_address_reports_its_shares_and_fractions() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        let genesis = genesis_for_tests();
        let genesis_payout = genesis.header.miner_bitcoin_address.to_string();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_G)
            .build();
        confirm_share(&state, &share).await;
        update_window(&state);

        let response = miner(State(state), query(&genesis_payout)).await.unwrap().0;

        assert_eq!(response.address, genesis_payout);
        assert_eq!(response.address_type, "payout");
        assert_eq!(response.anchor, share.block_hash().to_string());
        assert_eq!(response.anchor_height, 1);
        assert_eq!(response.window.newest_height, Some(1));
        assert_eq!(response.window.oldest_height, Some(0));
        assert_eq!(response.window.share_count, 2);
        assert_eq!(response.share_count, 1);
        assert_eq!(response.uncle_count, 0);
        assert_eq!(response.share_fraction, 0.5);
        assert_eq!(response.payout_fraction, 0.5);
        assert_eq!(response.shares.len(), 1);
        assert_eq!(
            response.shares[0].blockhash,
            genesis.block_hash().to_string()
        );
        assert_eq!(response.shares[0].height, 0);
        assert_eq!(response.shares[0].nephew, None);
        assert_eq!(response.shares[0].weight, response.weight);
        assert_eq!(response.shares[0].payout_address, genesis_payout);
    }

    #[tokio::test]
    async fn bitcoin_share_address_matches_the_share_owner() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        let genesis = genesis_for_tests();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_G)
            .build();
        confirm_share(&state, &share).await;
        update_window(&state);
        let share_address = to_address_string(&share.header.miner_address, Network::Signet, None);

        let response = miner(State(state), query(&share_address)).await.unwrap().0;

        assert!(
            share_address.starts_with("sp2pool1"),
            "expected a signet share address, got {share_address}"
        );
        assert_eq!(response.address, share_address);
        assert_eq!(response.address_type, "share");
        assert_eq!(response.share_count, 1);
        assert_eq!(response.shares.len(), 1);
        assert_eq!(response.shares[0].blockhash, share.block_hash().to_string());
        assert_eq!(response.shares[0].height, 1);
        assert_eq!(
            response.shares[0].payout_address,
            share.header.miner_bitcoin_address.to_string()
        );
    }

    #[tokio::test]
    async fn preparation_uses_exact_selected_bits_and_refuses_tip_or_identity_changes() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        let genesis = bitcoin_cash_genesis();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        update_window(&state);
        let (mut token, template) = test_bch_job_token_and_template();
        state.tracker_handle.insert_job(
            Arc::clone(&template),
            String::new(),
            String::new(),
            None,
            0,
            vec![],
            state.tracker_handle.get_latest_job_id(),
        );
        token[33..65].copy_from_slice(genesis.block_hash().as_byte_array());
        let payout = bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet);
        let owner = BchShareAddress {
            network: BchShareNetwork::Chipnet,
            hash: CASH_SHARE_HASH,
        }
        .encode();
        let prefix = Builder::new()
            .push_int(i64::from(template.height))
            .into_bytes();
        let mut body = serde_json::json!({"version":1,"token":hex::encode(&token),"payout":payout,
            "share_owner":owner,"height":template.height,"nbits":u32::from_str_radix(&template.bits,16).unwrap(),
            "previous_hash":template.previousblockhash,"coinbase_value":template.coinbasevalue,"script_prefix":hex::encode(&prefix),
            "auxiliary":{"merkle_root":vec![0u8;32],"tree_size":0,"nonce":0}});
        let response = super::super::jd_prepare::prepare(
            State(Arc::clone(&state)),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        let response = serde_json::to_value(response.0).unwrap();
        let bits = u32::from_str_radix(&template.bits, 16).unwrap();
        let weights = state
            .pplns_window
            .as_ref()
            .unwrap()
            .preparation_weights(genesis.block_hash(), bits, &state.chain_store_handle)
            .await
            .unwrap();
        let commitment = ShareCommitment::from_mining_job_token(
            &token,
            genesis.header.miner_bitcoin_address.clone(),
            WalletOwner::CashP2pkh(CASH_SHARE_HASH),
        )
        .unwrap();
        let expected = prepare_coinbase(
            &token,
            commitment,
            &weights,
            template.coinbasevalue,
            template.height,
            BchCoinbase {
                prefix,
                merge_mining: MergeMiningCommitment::reserved(),
            },
        )
        .unwrap();
        assert_eq!(response["coinbase_prefix"], hex::encode(expected.prefix));
        assert_eq!(response["coinbase_suffix"], hex::encode(expected.suffix));
        body["previous_hash"] = serde_json::json!("00".repeat(32));
        assert!(
            super::super::jd_prepare::prepare(
                State(Arc::clone(&state)),
                Json(serde_json::from_value(body.clone()).unwrap())
            )
            .await
            .is_err()
        );
        body["previous_hash"] = serde_json::json!(template.previousblockhash);
        body["nbits"] = serde_json::json!(bits ^ 1);
        assert!(
            super::super::jd_prepare::prepare(
                State(Arc::clone(&state)),
                Json(serde_json::from_value(body.clone()).unwrap())
            )
            .await
            .is_err()
        );
        body["nbits"] = serde_json::json!(bits);
        body["share_owner"] = serde_json::json!("p2pool:wrong-network");
        assert!(
            super::super::jd_prepare::prepare(
                State(state),
                Json(serde_json::from_value(body).unwrap())
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn bitcoin_cash_payout_address_with_prefix() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        let genesis = bitcoin_cash_genesis();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        update_window(&state);
        let cashaddr = bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet);

        let response = miner(State(state), query(cashaddr)).await.unwrap().0;

        assert_eq!(response.address, cashaddr);
        assert_eq!(response.address_type, "payout");
        assert_eq!(response.window.share_count, 1);
        assert_eq!(response.share_count, 1);
        assert_eq!(response.payout_fraction, 1.0);
        assert_eq!(
            response.shares[0].blockhash,
            genesis.block_hash().to_string()
        );
        assert_eq!(response.shares[0].payout_address, cashaddr);
    }

    #[tokio::test]
    async fn bitcoin_cash_payout_address_without_prefix() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        state
            .chain_store_handle
            .init_or_setup_genesis(bitcoin_cash_genesis())
            .await
            .unwrap();
        update_window(&state);
        let cashaddr = bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet);
        let without_prefix = cashaddr.strip_prefix("bchtest:").unwrap();

        let response = miner(State(state), query(without_prefix)).await.unwrap().0;

        assert_eq!(response.address, cashaddr);
        assert_eq!(response.address_type, "payout");
        assert_eq!(response.share_count, 1);
    }

    #[tokio::test]
    async fn bitcoin_cash_share_address_matches_the_share_owner() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        state
            .chain_store_handle
            .init_or_setup_genesis(bitcoin_cash_genesis())
            .await
            .unwrap();
        update_window(&state);
        let share_address =
            BchShareAddress::new(BchShareNetwork::Chipnet, CASH_SHARE_HASH).encode();

        let response = miner(State(state), query(&share_address)).await.unwrap().0;

        assert!(
            share_address.starts_with("tp2pool:"),
            "expected a chipnet share address, got {share_address}"
        );
        assert_eq!(response.address, share_address);
        assert_eq!(response.address_type, "share");
        assert_eq!(response.share_count, 1);
        assert_eq!(
            response.shares[0].payout_address,
            bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet)
        );
    }

    #[tokio::test]
    async fn bitcoin_cash_share_address_for_another_network_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        let mainnet_share_address =
            BchShareAddress::new(BchShareNetwork::Mainnet, CASH_SHARE_HASH).encode();

        let result = miner(State(state), query(&mainnet_share_address)).await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn bitcoin_cash_payout_for_another_network_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;
        let mainnet_cashaddr = bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Mainnet);

        let result = miner(State(state), query(mainnet_cashaddr)).await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn unknown_address_gets_an_empty_view_of_the_window() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis_for_tests())
            .await
            .unwrap();
        update_window(&state);

        let response = miner(
            State(state),
            query("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d"),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.address_type, "payout");
        assert_eq!(response.window.share_count, 1);
        assert_ne!(response.window.weight, "0");
        assert_eq!(response.share_count, 0);
        assert_eq!(response.uncle_count, 0);
        assert_eq!(response.weight, "0");
        assert_eq!(response.share_fraction, 0.0);
        assert_eq!(response.payout_fraction, 0.0);
        assert!(response.shares.is_empty());
    }

    #[tokio::test]
    async fn malformed_address_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;

        let result = miner(State(state), query("not-an-address")).await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn malformed_cashaddr_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(
            BitcoinCashNetwork::Chipnet.legacy_network(),
            Some(BchShareNetwork::Chipnet),
            Some(window),
        )
        .await;

        // The chipnet donation CashAddr with its last checksum character changed.
        let result = miner(
            State(state),
            query("bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn3"),
        )
        .await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn bitcoin_address_for_another_network_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;

        let result = miner(
            State(state),
            query("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        )
        .await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn missing_address_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;

        let result = miner(
            State(state),
            Query(MinerQuery {
                address: None,
                limit: None,
            }),
        )
        .await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn limit_above_max_is_rejected() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;

        let result = miner(
            State(state),
            Query(MinerQuery {
                address: Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string()),
                limit: Some(MAX_NUM_SHARES_IN_RESPONSE + 1),
            }),
        )
        .await;

        assert!(matches!(result, Err(ApiError::BadRequest(_))));
    }

    #[tokio::test]
    async fn limit_caps_the_listed_shares_but_not_the_counts() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        let genesis = genesis_for_tests();
        let genesis_payout = genesis.header.miner_bitcoin_address.to_string();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        // Same default miner as the genesis.
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .build();
        confirm_share(&state, &share).await;
        update_window(&state);

        let response = miner(
            State(state),
            Query(MinerQuery {
                address: Some(genesis_payout),
                limit: Some(1),
            }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.share_count, 2);
        assert_eq!(response.payout_fraction, 1.0);
        assert_eq!(response.shares.len(), 1);
        assert_eq!(response.shares[0].blockhash, share.block_hash().to_string());
    }

    #[tokio::test]
    async fn node_without_share_chain_window_returns_not_found() {
        let (state, _temp_dir) = build_test_state(Network::Signet, None, None).await;
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis_for_tests())
            .await
            .unwrap();

        let result = miner(
            State(state),
            query("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d"),
        )
        .await;

        assert!(matches!(result, Err(ApiError::NotFound(_))));
    }

    #[tokio::test]
    async fn window_not_loaded_yet_returns_service_unavailable() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis_for_tests())
            .await
            .unwrap();

        let result = miner(
            State(state),
            query("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d"),
        )
        .await;

        assert!(matches!(result, Err(ApiError::ServiceUnavailable(_))));
    }

    /// After the first request at an anchor the window is replaced by an
    /// empty one. Rebuilding would now answer 503, so a second request at the
    /// same anchor, for another address, can only succeed from the snapshot:
    /// it neither walks nor locks the window.
    #[tokio::test]
    async fn a_second_request_at_the_same_anchor_reuses_the_snapshot() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) =
            build_test_state(Network::Signet, None, Some(Arc::clone(&window))).await;
        let genesis = genesis_for_tests();
        let genesis_payout = genesis.header.miner_bitcoin_address.to_string();
        let genesis_share_address =
            to_address_string(&genesis.header.miner_address, Network::Signet, None);
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis)
            .await
            .unwrap();
        update_window(&state);
        let first = miner(State(Arc::clone(&state)), query(&genesis_payout))
            .await
            .unwrap()
            .0;

        *window.write().unwrap() = PplnsWindow::new(Network::Signet);
        let second = miner(State(state), query(&genesis_share_address))
            .await
            .unwrap()
            .0;

        assert_eq!(second.anchor, first.anchor);
        assert_eq!(second.window.weight, first.window.weight);
        assert_eq!(second.address_type, "share");
        assert_eq!(second.share_count, 1);
    }

    #[tokio::test]
    async fn a_new_anchor_rebuilds_the_snapshot() {
        let window = Arc::new(RwLock::new(PplnsWindow::new(Network::Signet)));
        let (state, _temp_dir) = build_test_state(Network::Signet, None, Some(window)).await;
        let genesis = genesis_for_tests();
        let genesis_payout = genesis.header.miner_bitcoin_address.to_string();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();
        update_window(&state);
        let first = miner(State(Arc::clone(&state)), query(&genesis_payout))
            .await
            .unwrap()
            .0;
        let share = TestShareBlockBuilder::new()
            .prev_share_blockhash(genesis.block_hash().to_string())
            .miner_pubkey(PUBKEY_G)
            .build();
        confirm_share(&state, &share).await;
        update_window(&state);

        let second = miner(State(state), query(&genesis_payout)).await.unwrap().0;

        assert_eq!(first.anchor_height, 0);
        assert_eq!(first.window.share_count, 1);
        assert_eq!(second.anchor, share.block_hash().to_string());
        assert_eq!(second.anchor_height, 1);
        assert_eq!(second.window.share_count, 2);
        assert_eq!(second.payout_fraction, 0.5);
    }
}
