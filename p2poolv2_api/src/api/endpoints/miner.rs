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

use crate::api::endpoints::MAX_NUM_SHARES_IN_RESPONSE;
use crate::api::error::ApiError;
use crate::api::server::{AppConfig, AppState};
use axum::{
    Json,
    extract::{Query, State},
};
use bitcoin::Network;
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    MinerWindow, WindowCredit, WindowError, WindowMiner,
};
use p2poolv2_lib::address::bch_share::{self, BchShareNetwork};
use p2poolv2_lib::address::share_owner::{ShareOwner, to_address_string};
use p2poolv2_lib::address_display::payout_address_string;
use p2poolv2_lib::config::{BitcoinCashNetwork, Chain, parse_payout_address, parse_share_address};
use p2poolv2_lib::store::writer::StoreError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    let miner = parse_miner(address, &state.app_config)?;

    let pplns_window = state.pplns_window.as_ref().ok_or_else(|| {
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

    let miner_window = {
        let mut window = pplns_window
            .write()
            .map_err(|_| ApiError::ServerError("PPLNS window lock poisoned".to_string()))?;
        if window.is_empty() {
            return Err(ApiError::ServiceUnavailable(
                "PPLNS window is not loaded yet".to_string(),
            ));
        }
        window
            .get_miner_window_from_start_hash(
                anchor,
                &state.chain_store_handle,
                &miner,
                limit as usize,
            )
            .map_err(window_error)?
    };

    Ok(Json(build_response(
        &miner,
        anchor,
        miner_window,
        &state.app_config,
    )))
}

/// Read `address` as either of the two addresses a share header carries,
/// for the chain this node mines. A share chain address is tried first: its
/// prefix and checksum keep it from also decoding as a payout.
fn parse_miner(address: &str, app_config: &AppConfig) -> Result<WindowMiner, ApiError> {
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
) -> Result<WindowMiner, ApiError> {
    let share_error = match bch_share::parse(address, share_network) {
        Ok(share_address) => {
            return Ok(WindowMiner::ShareOwner(ShareOwner::CashP2pkh(
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
    .map(WindowMiner::Payout)
    .map_err(|payout_error| {
        ApiError::BadRequest(format!(
            "Invalid address '{address}': not a share address ({share_error}) nor a payout address ({})",
            payout_error.message
        ))
    })
}

/// A share chain address for `network`, or a Bitcoin payout address.
fn parse_bitcoin_miner(address: &str, network: Network) -> Result<WindowMiner, ApiError> {
    let share_error = match parse_share_address(address, network) {
        Ok(share_address) => {
            return Ok(WindowMiner::ShareOwner(ShareOwner::from(
                share_address.witness_program(),
            )));
        }
        Err(error) => error,
    };
    parse_payout_address(address, Chain::Bitcoin, network, None)
        .map(WindowMiner::Payout)
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

/// Shape a miner's window view for the wire, rendering every address for
/// this node's chain.
fn build_response(
    miner: &WindowMiner,
    anchor: bitcoin::BlockHash,
    miner_window: MinerWindow,
    app_config: &AppConfig,
) -> MinerResponse {
    let (address, address_type) = match miner {
        WindowMiner::Payout(address) => (
            payout_address_string(address, app_config.cash_network),
            "payout",
        ),
        WindowMiner::ShareOwner(owner) => (
            to_address_string(owner, app_config.network, app_config.cash_network),
            "share",
        ),
    };
    let shares = miner_window
        .credits
        .iter()
        .map(|credit| miner_share(credit, app_config.cash_network))
        .collect();

    MinerResponse {
        address,
        address_type,
        anchor: anchor.to_string(),
        anchor_height: miner_window.anchor_height,
        window: WindowSummary {
            newest_height: miner_window.newest_height,
            oldest_height: miner_window.oldest_height,
            share_count: miner_window.window_share_count,
            weight: miner_window.window_weight.to_string(),
        },
        share_count: miner_window.share_count,
        uncle_count: miner_window.uncle_count,
        weight: miner_window.weight.to_string(),
        share_fraction: fraction(
            miner_window.share_count as u128,
            miner_window.window_share_count as u128,
        ),
        payout_fraction: fraction(miner_window.weight, miner_window.window_weight),
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
    use p2poolv2_lib::accounting::payout::sharechain_pplns::PplnsWindow;
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
    use std::sync::RwLock;

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
            pplns_window,
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
}
