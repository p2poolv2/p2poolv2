// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node's web dashboard, rendered in Rust.
//!
//! Pages are HTML built on the server from the same store, PPLNS window and
//! metrics the JSON API reads, so the dashboard and the API cannot disagree.
//! The browser runs no script. The routes sit behind the API's
//! authentication unless `[api] public_dashboard` opens them: a node with
//! `auth_user` set answers with a Basic challenge, which browsers turn into
//! their own login prompt.

pub(crate) mod chart;
pub(crate) mod history;
pub(crate) mod pages;
pub(crate) mod style;

use crate::api::endpoints::miner::miner_report;
use crate::api::endpoints::share::build_share_output;
use crate::api::error::ApiError;
use crate::api::server::AppState;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use bitcoin::BlockHash;
use history::{HashrateHistory, is_block, newest_shares, pool_hashrate, work_from_bits};
use p2poolv2_lib::address::bch_share::BchShareNetwork;
use p2poolv2_lib::address_display::ShareInfoDisplay;
use p2poolv2_lib::address_display::payout_address_string;
use pages::{FoundBlockRow, MinerView, Overview, RecentShare, ShareView};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Shares listed on the overview.
const RECENT_SHARES: u32 = 25;

/// Shares a miner's hashrate is estimated from.
const MINER_HASHRATE_SHARES: u32 = 500;

/// Most window shares listed on a miner's page.
const MINER_SHARES_LISTED: usize = 100;

/// Most found blocks listed on the overview.
const BLOCKS_LISTED: usize = 50;

/// What the dashboard handlers share: the API's state and the history its
/// sampler fills.
pub(crate) struct DashboardState {
    pub(crate) app: Arc<AppState>,
    pub(crate) history: Arc<HashrateHistory>,
}

/// The dashboard's routes, ready to merge into the API's share chain
/// routes.
pub(crate) fn router(app: Arc<AppState>, history: Arc<HashrateHistory>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/dashboard", get(overview))
        .route("/dashboard/miner", get(miner))
        .route("/dashboard/share/{hash}", get(share))
        .with_state(Arc::new(DashboardState { app, history }))
}

/// How the dashboard names the chain this node mines.
fn network_name(state: &AppState) -> String {
    match state.app_config.cash_network {
        Some(BchShareNetwork::Mainnet) => "Bitcoin Cash mainnet".to_string(),
        Some(BchShareNetwork::Chipnet) => "Bitcoin Cash chipnet".to_string(),
        Some(BchShareNetwork::Regtest) => "Bitcoin Cash regtest".to_string(),
        None => format!("Bitcoin {}", state.app_config.network),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Run a synchronous store read on a blocking thread.
async fn read_store<T: Send + 'static>(
    state: &Arc<AppState>,
    read: impl FnOnce(&AppState) -> T + Send + 'static,
) -> Result<T, ApiError> {
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || read(&state))
        .await
        .map_err(|error| ApiError::ServerError(format!("Store read failed: {error}")))
}

/// An error as a dashboard page with the matching status.
fn error_page(state: &AppState, error: ApiError) -> Response {
    let (status, message) = match error {
        ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
        ApiError::NotFound(message) => (StatusCode::NOT_FOUND, message),
        ApiError::ServiceUnavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message),
        ApiError::ServerError(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    (
        status,
        Html(pages::error(&network_name(state), &message).into_string()),
    )
        .into_response()
}

/// The newest confirmed shares, newest first, with the tip height.
fn recent_shares(state: &AppState) -> (Option<u32>, Vec<RecentShare>) {
    let shares = newest_shares(state, RECENT_SHARES);
    let store = state.chain_store_handle.store_handle().store();
    let tip = shares.last().map(|share| share.height);
    let recent = shares
        .iter()
        .rev()
        .map(|share| {
            let display = ShareInfoDisplay::from_share_info(
                share,
                Some(state.app_config.network),
                state.app_config.cash_network,
            );
            RecentShare {
                height: share.height,
                blockhash: share.blockhash.to_string(),
                time: share.timestamp,
                payout_address: display.miner_bitcoin_address,
                is_block: store
                    .get_share_header(&share.blockhash)
                    .ok()
                    .flatten()
                    .is_some_and(|header| is_block(&header.bitcoin_header)),
            }
        })
        .collect();
    (tip, recent)
}

/// Blocks the pool found, as the store records them on confirmation: how
/// many in all, and the newest few, newest first.
fn found_blocks(state: &AppState) -> (usize, Vec<FoundBlockRow>) {
    let found = match state.chain_store_handle.get_found_blocks() {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!("Dashboard could not read found blocks: {error}");
            return (0, Vec::new());
        }
    };
    let rows = found
        .iter()
        .rev()
        .take(BLOCKS_LISTED)
        .map(|block| FoundBlockRow {
            height: block.bitcoin_height,
            block_hash: block.bitcoin_blockhash,
            share_hash: block.share_blockhash,
            time: block.bitcoin_time,
            payout_address: payout_address_display(state, &block.miner_bitcoin_address),
        })
        .collect();
    (found.len(), rows)
}

/// A payout address the store keeps in Bitcoin's spelling, spelled for the
/// chain this node mines. One that does not parse is shown as it is.
fn payout_address_display(state: &AppState, stored: &str) -> String {
    match bitcoin::Address::from_str(stored) {
        Ok(address) => {
            payout_address_string(&address.assume_checked(), state.app_config.cash_network)
        }
        Err(_) => stored.to_string(),
    }
}

async fn overview(State(dashboard): State<Arc<DashboardState>>) -> Response {
    let state = &dashboard.app;
    let chain = read_store(state, |state| {
        (
            recent_shares(state),
            pool_hashrate(state),
            found_blocks(state),
        )
    })
    .await;
    let ((tip_height, recent_shares), pool_hashrate, (blocks_found, blocks)) = match chain {
        Ok(chain) => chain,
        Err(error) => return error_page(state, error),
    };
    let metrics = state.metrics_handle.get_metrics().await;
    let miners_online = metrics
        .users
        .values()
        .filter(|user| user.workers.values().any(|worker| worker.active))
        .count();
    let workers_online = metrics
        .users
        .values()
        .map(|user| user.workers.values().filter(|worker| worker.active).count())
        .sum();
    let network_difficulty = state.tracker_handle.get_network_difficulty();
    let samples = dashboard.history.samples();
    let local_hashrate = samples.iter().rev().find_map(|sample| sample.local);

    let page = pages::overview(&Overview {
        network: network_name(state),
        now: unix_now(),
        tip_height,
        pool_hashrate,
        local_hashrate,
        network_hashrate: network_difficulty.map(history::network_hashrate),
        network_difficulty,
        miners_online,
        workers_online,
        samples,
        blocks_found,
        blocks,
        recent_shares,
    });
    Html(page.into_string()).into_response()
}

#[derive(Deserialize)]
struct MinerPageQuery {
    address: Option<String>,
}

/// A miner's hashrate from its share of the work in the newest shares: its
/// shares' work over the time those shares span, with how many shares and
/// seconds that was.
fn miner_hashrate(state: &AppState, address: &str) -> Option<(f64, usize, u32)> {
    let shares = newest_shares(state, MINER_HASHRATE_SHARES);
    let oldest = shares.first()?.timestamp;
    let newest = shares.last()?.timestamp;
    let span = newest.checked_sub(oldest).filter(|span| *span > 0)?;
    let work: f64 = shares
        .iter()
        .skip(1)
        .filter(|share| {
            let display = ShareInfoDisplay::from_share_info(
                share,
                Some(state.app_config.network),
                state.app_config.cash_network,
            );
            display.miner_bitcoin_address == address || display.miner_address == address
        })
        .map(|share| work_from_bits(share.bits))
        .sum();
    Some((work / f64::from(span), shares.len(), span))
}

async fn miner(
    State(dashboard): State<Arc<DashboardState>>,
    Query(query): Query<MinerPageQuery>,
) -> Response {
    let state = &dashboard.app;
    let Some(address) = query
        .address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
    else {
        return error_page(
            state,
            ApiError::BadRequest("Enter a payout or share chain address.".to_string()),
        );
    };
    let report = match miner_report(state, address, MINER_SHARES_LISTED).await {
        Ok(report) => report,
        Err(error) => return error_page(state, error),
    };
    let reported_address = report.address.clone();
    let estimate = read_store(state, move |state| miner_hashrate(state, &reported_address))
        .await
        .ok()
        .flatten();
    let page = pages::miner(&MinerView {
        network: network_name(state),
        report,
        hashrate: estimate.map(|(hashrate, _, _)| hashrate),
        recent_window: estimate.map(|(_, shares, seconds)| (shares, seconds)),
    });
    Html(page.into_string()).into_response()
}

async fn share(State(dashboard): State<Arc<DashboardState>>, Path(hash): Path<String>) -> Response {
    let state = &dashboard.app;
    let blockhash = match BlockHash::from_str(&hash) {
        Ok(blockhash) => blockhash,
        Err(error) => {
            return error_page(
                state,
                ApiError::BadRequest(format!("Not a share hash: {error}")),
            );
        }
    };
    let found = read_store(state, move |state| {
        let output = build_share_output(
            &state.chain_store_handle,
            &blockhash,
            false,
            state.app_config.network,
            state.app_config.cash_network,
        )?;
        let is_block = state
            .chain_store_handle
            .store_handle()
            .store()
            .get_share_header(&blockhash)
            .ok()
            .flatten()
            .is_some_and(|header| is_block(&header.bitcoin_header));
        Ok::<_, ApiError>((output, is_block))
    })
    .await
    .and_then(|found| found);
    match found {
        Ok((share, is_block)) => Html(
            pages::share(&ShareView {
                network: network_name(state),
                share,
                is_block,
            })
            .into_string(),
        )
        .into_response(),
        Err(error) => error_page(state, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::{AppConfig, WebOptions, build_router_with_history};
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, header};
    use p2poolv2_lib::accounting::stats::metrics;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::node::actor::NodeHandle;
    use p2poolv2_lib::stratum::work::tracker::start_tracker_actor;
    use p2poolv2_lib::test_utils::{genesis_for_tests, setup_test_chain_store_handle};
    use tower::ServiceExt;

    async fn build_state(
        auth: Option<(&str, &str)>,
        cash_network: Option<BchShareNetwork>,
    ) -> (Arc<AppState>, tempfile::TempDir, tempfile::TempDir) {
        let (chain_store_handle, store_dir) = setup_test_chain_store_handle(true).await;
        let metrics_dir = tempfile::tempdir().unwrap();
        let metrics_handle =
            metrics::start_metrics(metrics_dir.path().to_str().unwrap().to_string())
                .await
                .unwrap();
        let state = Arc::new(AppState {
            app_config: AppConfig {
                pool_signature_length: 0,
                network: bitcoin::Network::Signet,
                cash_network,
                cors_allowed: false,
            },
            chain_store_handle,
            metrics_handle,
            tracker_handle: start_tracker_actor(),
            node_handle: NodeHandle::new_for_test(),
            monitoring_event_sender: create_monitoring_event_channel().0,
            auth_user: auth.map(|(user, _)| user.to_string()),
            auth_token: auth.map(|(_, token)| token.to_string()),
            pplns_window: None,
        });
        (state, store_dir, metrics_dir)
    }

    async fn get(state: &Arc<AppState>, uri: &str) -> (StatusCode, String, HeaderMap) {
        get_with(state, uri, WebOptions::default()).await
    }

    async fn get_with(
        state: &Arc<AppState>,
        uri: &str,
        web: WebOptions,
    ) -> (StatusCode, String, HeaderMap) {
        let app = build_router_with_history(
            Arc::clone(state),
            state.app_config.clone(),
            Arc::new(HashrateHistory::default()),
            web,
        );
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            headers,
        )
    }

    fn public() -> WebOptions {
        WebOptions {
            public: true,
            web_root: None,
        }
    }

    /// A frontend build: an index page and a WebAssembly module.
    fn frontend() -> tempfile::TempDir {
        let web_root = tempfile::tempdir().unwrap();
        std::fs::write(web_root.path().join("index.html"), "<p>frontend</p>").unwrap();
        std::fs::write(web_root.path().join("app.wasm"), b"\0asm").unwrap();
        web_root
    }

    #[tokio::test]
    async fn the_overview_is_html_without_script() {
        let (state, _store, _metrics) = build_state(None, Some(BchShareNetwork::Chipnet)).await;
        let (status, body, _) = get(&state, "/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.starts_with("<!DOCTYPE html>"));
        assert!(body.contains("Bitcoin Cash chipnet"));
        assert!(body.contains("Share chain height"));
        assert!(!body.contains("<script"));
    }

    #[tokio::test]
    async fn a_known_share_has_a_page() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let genesis_block = genesis_for_tests();
        let genesis = genesis_block.block_hash();
        state
            .chain_store_handle
            .init_or_setup_genesis(genesis_block)
            .await
            .unwrap();
        let (status, body, _) = get(&state, &format!("/dashboard/share/{genesis}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains(&genesis.to_string()));
        assert!(body.contains("Bitcoin Cash header"));
    }

    #[tokio::test]
    async fn a_bad_share_hash_is_a_400_page() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let (status, body, _) = get(&state, "/dashboard/share/not-a-hash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("Not a share hash"));
    }

    #[tokio::test]
    async fn an_unknown_share_is_a_404_page() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let missing = "00".repeat(32);
        let (status, _, _) = get(&state, &format!("/dashboard/share/{missing}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_miner_page_needs_an_address() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let (status, body, _) = get(&state, "/dashboard/miner?address=").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("Enter a payout or share chain address."));
    }

    #[tokio::test]
    async fn a_node_with_credentials_challenges_the_browser() {
        let (state, _store, _metrics) = build_state(Some(("operator", "secret-token")), None).await;
        let (status, _, headers) = get(&state, "/dashboard").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let challenge = headers.get(header::WWW_AUTHENTICATE).unwrap();
        assert!(challenge.to_str().unwrap().starts_with("Basic"));
    }

    #[tokio::test]
    async fn a_public_node_opens_its_share_chain_but_not_its_own_routes() {
        let (state, _store, _metrics) = build_state(Some(("operator", "secret-token")), None).await;
        let (status, body, _) = get_with(&state, "/dashboard", public()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Share chain height"));
        // A bad address is the handler's 400, not the login's 401.
        let (status, _, _) = get_with(&state, "/miner?address=not-an-address", public()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        for own_route in ["/metrics", "/peers", "/blocked_ips"] {
            let (status, _, headers) = get_with(&state, own_route, public()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{own_route}");
            assert!(headers.contains_key(header::WWW_AUTHENTICATE));
        }
    }

    #[tokio::test]
    async fn the_root_opens_the_dashboard_without_a_frontend() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let (status, _, headers) = get(&state, "/").await;
        assert!(status.is_redirection());
        assert_eq!(headers.get(header::LOCATION).unwrap(), "/dashboard");
    }

    #[tokio::test]
    async fn a_web_root_serves_its_frontend_beside_the_api() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let web_root = frontend();
        let web = || WebOptions {
            public: false,
            web_root: Some(web_root.path().to_path_buf()),
        };
        let (status, body, _) = get_with(&state, "/", web()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>frontend</p>");
        let (status, _, headers) = get_with(&state, "/app.wasm", web()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/wasm"
        );
        // A path of the frontend's own routing gets its index page.
        let (status, body, _) = get_with(&state, "/miners/someone", web()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>frontend</p>");
        // The API and the built-in dashboard keep their paths.
        let (_, body, _) = get_with(&state, "/health", web()).await;
        assert_eq!(body, "OK");
        let (_, body, _) = get_with(&state, "/dashboard", web()).await;
        assert!(body.contains("Share chain height"));
    }

    #[tokio::test]
    async fn a_web_root_follows_the_login() {
        let (state, _store, _metrics) = build_state(Some(("operator", "secret-token")), None).await;
        let web_root = frontend();
        let web = |public| WebOptions {
            public,
            web_root: Some(web_root.path().to_path_buf()),
        };
        let (status, _, headers) = get_with(&state, "/", web(false)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key(header::WWW_AUTHENTICATE));
        let (status, body, _) = get_with(&state, "/", web(true)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<p>frontend</p>");
    }

    #[tokio::test]
    async fn the_old_static_files_are_gone() {
        let (state, _store, _metrics) = build_state(None, None).await;
        let (status, _, _) = get(&state, "/static/dashboard.js").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
