// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dashboard views. All numbers come from the node's API; the browser only
//! formats and draws them.

use crate::api::{
    self, ChainInfo, Connection, FoundBlock, Hashrate, HashratePoint, Miner, Share, ShareDetail,
    Shares,
};
use crate::chart::HashrateChart;
use crate::format;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Seconds between polls of the REST endpoints.
const REFRESH_MS: u32 = 15_000;
/// Recent shares kept in the live list.
const RECENT_SHARES: usize = 50;
/// Hashrate chart windows offered, in seconds.
const WINDOWS: [(u64, &str); 4] = [
    (3600, "1h"),
    (6 * 3600, "6h"),
    (24 * 3600, "24h"),
    (600, "10m"),
];

#[derive(Clone, Debug, PartialEq)]
enum Page {
    Overview,
    Share(String),
    Miner(String),
}

#[derive(Clone, Copy)]
struct Ctx {
    connection: RwSignal<Connection>,
    page: RwSignal<Page>,
    /// Bumped on a timer; resources that should refresh read it.
    tick: RwSignal<u64>,
}

fn ctx() -> Ctx {
    expect_context::<Ctx>()
}

fn now() -> u64 {
    (js_sys_now() / 1000.0) as u64
}

fn js_sys_now() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.time_origin() + p.now())
        .unwrap_or_default()
}

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok()?
}

fn stored(storage: Option<web_sys::Storage>, key: &str) -> Option<String> {
    storage?.get_item(key).ok()?
}

fn store(storage: Option<web_sys::Storage>, key: &str, value: &str) {
    if let Some(storage) = storage {
        let _ = storage.set_item(key, value);
    }
}

/// Initial connection: `?api=` in the page URL, then the saved base, then the
/// page's own origin (the node serving `/app`). The password lives only in
/// session storage so it is gone when the tab closes.
fn initial_connection() -> Connection {
    let location = web_sys::window().map(|w| w.location());
    let origin = location
        .as_ref()
        .and_then(|l| l.origin().ok())
        .unwrap_or_default();
    let from_query = location.and_then(|l| l.search().ok()).and_then(|search| {
        search
            .trim_start_matches('?')
            .split('&')
            .find_map(|pair| pair.strip_prefix("api=").map(str::to_string))
    });
    let base = from_query
        .or_else(|| stored(local_storage(), "p2pool.api"))
        .unwrap_or(origin);
    Connection {
        base: base.trim_end_matches('/').to_string(),
        user: stored(local_storage(), "p2pool.user").unwrap_or_default(),
        password: stored(session_storage(), "p2pool.password").unwrap_or_default(),
    }
}

/// A resource that refetches when the connection changes or the timer ticks.
fn polled<T>(path: impl Fn() -> String + 'static) -> LocalResource<Result<T, String>>
where
    T: serde::de::DeserializeOwned + 'static,
{
    let Ctx {
        connection, tick, ..
    } = ctx();
    LocalResource::new(move || {
        tick.track();
        let connection = connection.get();
        let path = path();
        async move { connection.get::<T>(&path).await }
    })
}

#[component]
pub fn App() -> impl IntoView {
    let ctx = Ctx {
        connection: RwSignal::new(initial_connection()),
        page: RwSignal::new(Page::Overview),
        tick: RwSignal::new(0),
    };
    provide_context(ctx);
    gloo_timers::callback::Interval::new(REFRESH_MS, move || ctx.tick.update(|t| *t += 1)).forget();

    let recent = RwSignal::new(Vec::<Share>::new());
    let live = RwSignal::new(false);
    start_live_feed(ctx.connection, recent, live);
    let show_settings = RwSignal::new(false);

    let nav = move |page: Page, label: &'static str| {
        let target = page.clone();
        view! {
            <button
                class:active=move || {
                    std::mem::discriminant(&ctx.page.get()) == std::mem::discriminant(&page)
                }
                on:click=move |_| ctx.page.set(target.clone())
            >
                {label}
            </button>
        }
    };

    view! {
        <header>
            <h1>"P2Pool"</h1>
            <nav>
                {nav(Page::Overview, "Overview")}
                {nav(Page::Miner(String::new()), "Miner lookup")}
            </nav>
            <span class="status" class:live=live>
                {move || if live.get() { "● live" } else { "○ offline" }}
            </span>
            <button on:click=move |_| show_settings.update(|s| *s = !*s)>"Settings"</button>
        </header>
        <Show when=move || show_settings.get()>
            <Settings />
        </Show>
        <main>
            {move || match ctx.page.get() {
                Page::Overview => view! { <Overview recent=recent /> }.into_any(),
                Page::Share(hash) => view! { <ShareView hash=hash /> }.into_any(),
                Page::Miner(address) => view! { <MinerView initial=address /> }.into_any(),
            }}
        </main>
    }
}

/// Keep `recent` filled: seed from `/shares`, then prepend `/ws` share
/// events. Reconnects with a delay, and restarts when the connection changes.
fn start_live_feed(
    connection: RwSignal<Connection>,
    recent: RwSignal<Vec<Share>>,
    live: RwSignal<bool>,
) {
    Effect::new(move |generation: Option<u64>| {
        let generation = generation.map_or(0, |g| g + 1);
        let current = connection.get();
        let watched = current.clone();
        let still_current = move || connection.with_untracked(|c| *c == watched);
        spawn_local(async move {
            if let Ok(seed) = current
                .get::<Shares>(&format!("/shares?num={RECENT_SHARES}"))
                .await
            {
                let mut shares = seed.shares;
                shares.sort_by_key(|share| std::cmp::Reverse(share.height));
                recent.set(shares);
            }
            while still_current() {
                if let Ok(socket) = WebSocket::open(&current.websocket_url()) {
                    let (mut sink, mut stream) = socket.split();
                    if sink
                        .send(Message::Text(api::SUBSCRIBE_SHARES.into()))
                        .await
                        .is_ok()
                    {
                        live.set(true);
                        while let Some(Ok(message)) = stream.next().await {
                            if !still_current() {
                                break;
                            }
                            if let Message::Text(text) = message
                                && let Some(share) = api::parse_share_event(&text)
                            {
                                recent.update(|shares| {
                                    if shares.iter().all(|s| s.blockhash != share.blockhash) {
                                        shares.insert(0, share);
                                        shares.truncate(RECENT_SHARES);
                                    }
                                });
                            }
                        }
                    }
                }
                live.set(false);
                gloo_timers::future::TimeoutFuture::new(5_000).await;
            }
        });
        generation
    });
}

#[component]
fn Settings() -> impl IntoView {
    let connection = ctx().connection;
    let current = connection.get_untracked();
    let base = RwSignal::new(current.base);
    let user = RwSignal::new(current.user);
    let password = RwSignal::new(current.password);
    let save = move |_| {
        let updated = Connection {
            base: base
                .get_untracked()
                .trim()
                .trim_end_matches('/')
                .to_string(),
            user: user.get_untracked().trim().to_string(),
            password: password.get_untracked(),
        };
        store(local_storage(), "p2pool.api", &updated.base);
        store(local_storage(), "p2pool.user", &updated.user);
        store(session_storage(), "p2pool.password", &updated.password);
        connection.set(updated);
    };
    view! {
        <section class="card settings">
            <label>"API URL" <input bind:value=base placeholder="http://127.0.0.1:46884" /></label>
            <label>"User" <input bind:value=user autocomplete="username" /></label>
            <label>
                "Password"
                <input type="password" bind:value=password autocomplete="current-password" />
            </label>
            <button on:click=save>"Save"</button>
            <p class="muted">
                "User and password are only needed when the node sets api auth. "
                "The password is kept for this browser tab only."
            </p>
        </section>
    }
}

fn error_view(error: String) -> AnyView {
    view! { <p class="error">{error}</p> }.into_any()
}

fn loading() -> AnyView {
    view! { <p class="muted">"Loading…"</p> }.into_any()
}

#[component]
fn Kpi(label: &'static str, value: Signal<String>) -> impl IntoView {
    view! {
        <div class="kpi">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
        </div>
    }
}

#[component]
fn Overview(recent: RwSignal<Vec<Share>>) -> impl IntoView {
    let window = RwSignal::new(3600_u64);
    let hashrate = polled::<Hashrate>(move || format!("/hashrate?window={}", window.get()));
    let chain = polled::<ChainInfo>(|| "/chain_info".into());
    let blocks = polled::<Vec<FoundBlock>>(|| "/found_blocks".into());

    let rate = move |pick: fn(&Hashrate) -> Option<f64>| {
        Signal::derive(move || match hashrate.get() {
            Some(Ok(h)) => pick(&h).map(format::hashrate).unwrap_or_else(|| "–".into()),
            Some(Err(_)) => "error".into(),
            None => "…".into(),
        })
    };
    // The live feed moves the height between polls.
    let height = Signal::derive(move || {
        let polled = match chain.get() {
            Some(Ok(info)) => info.chain_tip_height,
            _ => None,
        };
        let live = recent.with(|r| r.first().map(|s| s.height));
        polled.max(live).map_or("–".into(), |h| h.to_string())
    });
    let points = Signal::derive(move || match hashrate.get() {
        Some(Ok(h)) => h.history,
        _ => Vec::<HashratePoint>::new(),
    });

    view! {
        <section class="kpis">
            <Kpi label="Pool hashrate" value=rate(|h| h.pool_hashrate) />
            <Kpi label="Local hashrate" value=rate(|h| h.local_hashrate) />
            <Kpi label="Network hashrate" value=rate(|h| h.network_hashrate) />
            <Kpi label="Share chain height" value=height />
        </section>
        <section class="card">
            <div class="card-head">
                <h2>"Hashrate"</h2>
                <div class="tabs">
                    {WINDOWS
                        .iter()
                        .map(|&(secs, label)| {
                            view! {
                                <button
                                    class:active=move || window.get() == secs
                                    on:click=move |_| window.set(secs)
                                >
                                    {label}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
            {move || match hashrate.get() {
                Some(Err(error)) => error_view(error),
                _ => view! { <HashrateChart points=points /> }.into_any(),
            }}
        </section>
        <div class="columns">
            <section class="card">
                <h2>"Recent shares"</h2>
                <RecentShares recent=recent />
            </section>
            <section class="card">
                <h2>"Found blocks"</h2>
                {move || match blocks.get() {
                    None => loading(),
                    Some(Err(error)) => error_view(error),
                    Some(Ok(blocks)) => view! { <FoundBlocks blocks=blocks /> }.into_any(),
                }}
            </section>
        </div>
    }
}

fn share_link(hash: String) -> impl IntoView {
    let page = ctx().page;
    let label = format::short(&hash);
    view! {
        <a href="#" class="mono" on:click=move |event| {
            event.prevent_default();
            page.set(Page::Share(hash.clone()));
        }>{label}</a>
    }
}

fn miner_link(address: String) -> impl IntoView {
    let page = ctx().page;
    let label = format::short(&address);
    view! {
        <a href="#" class="mono" title=address.clone() on:click=move |event| {
            event.prevent_default();
            page.set(Page::Miner(address.clone()));
        }>{label}</a>
    }
}

#[component]
fn RecentShares(recent: RwSignal<Vec<Share>>) -> impl IntoView {
    let tick = ctx().tick;
    view! {
        <table>
            <thead>
                <tr><th>"Height"</th><th>"Share"</th><th>"Miner"</th><th>"Uncles"</th><th>"Age"</th></tr>
            </thead>
            <tbody>
                <For
                    each=move || recent.get()
                    key=|share| share.blockhash.clone()
                    children=move |share| {
                        let timestamp = share.timestamp;
                        view! {
                            <tr>
                                <td>{share.height}</td>
                                <td>{share_link(share.blockhash)}</td>
                                <td>{miner_link(share.miner_bitcoin_address)}</td>
                                <td>{share.uncles.len()}</td>
                                <td class="muted">
                                    {move || {
                                        tick.track();
                                        format::ago(now(), timestamp)
                                    }}
                                </td>
                            </tr>
                        }
                    }
                />
            </tbody>
        </table>
    }
}

#[component]
fn FoundBlocks(blocks: Vec<FoundBlock>) -> impl IntoView {
    if blocks.is_empty() {
        return view! { <p class="muted">"No blocks found yet."</p> }.into_any();
    }
    view! {
        <table>
            <thead>
                <tr><th>"Height"</th><th>"Block"</th><th>"Share"</th><th>"Miner"</th><th>"Time (UTC)"</th></tr>
            </thead>
            <tbody>
                {blocks
                    .into_iter()
                    .map(|block| {
                        view! {
                            <tr>
                                <td>{block.bitcoin_height}</td>
                                <td class="mono" title=block.bitcoin_blockhash.clone()>
                                    {format::short(&block.bitcoin_blockhash)}
                                </td>
                                <td>{share_link(block.share_blockhash)}</td>
                                <td>{miner_link(block.miner_bitcoin_address)}</td>
                                <td>{format::utc(block.bitcoin_time)}</td>
                            </tr>
                        }
                    })
                    .collect_view()}
            </tbody>
        </table>
    }
    .into_any()
}

#[component]
fn ShareView(hash: String) -> impl IntoView {
    let path = format!("/share?hash={}", api::url_encode(&hash));
    let Ctx { connection, .. } = ctx();
    let detail = LocalResource::new(move || {
        let connection = connection.get();
        let path = path.clone();
        async move { connection.get::<Vec<ShareDetail>>(&path).await }
    });
    view! {
        <section class="card">
            <h2>"Share"</h2>
            {move || match detail.get() {
                None => loading(),
                Some(Err(error)) => error_view(error),
                Some(Ok(details)) => details
                    .into_iter()
                    .map(|share| view! { <ShareFields share=share /> })
                    .collect_view()
                    .into_any(),
            }}
        </section>
    }
}

#[component]
fn ShareFields(share: ShareDetail) -> impl IntoView {
    let header = share.bitcoin_header;
    view! {
        <dl class="fields">
            <dt>"Hash"</dt><dd class="mono">{share.blockhash}</dd>
            <dt>"Height"</dt><dd>{share.height.map_or("–".into(), |h| h.to_string())}</dd>
            <dt>"Chain"</dt><dd>{share.chain}" · "{share.validation_status}</dd>
            <dt>"Parent"</dt><dd>{share_link(share.parent)}</dd>
            <dt>"Uncles"</dt>
            <dd>
                {if share.uncles.is_empty() { Some("none") } else { None }}
                {share.uncles.into_iter().map(|u| view! { {share_link(u)}" " }).collect_view()}
            </dd>
            <dt>"Payout address"</dt><dd>{miner_link(share.miner_bitcoin_address)}</dd>
            <dt>"Miner address"</dt><dd class="mono">{share.miner_address}</dd>
            <dt>"Share target"</dt><dd class="mono">{share.bits}</dd>
            <dt>"Time"</dt><dd>{share.time}</dd>
            <dt>"Block header hash"</dt><dd class="mono">{header.block_hash}</dd>
            <dt>"Block prev hash"</dt><dd class="mono">{header.prev_blockhash}</dd>
            <dt>"Merkle root"</dt><dd class="mono">{header.merkle_root}</dd>
            <dt>"Block bits / nonce"</dt><dd class="mono">{header.bits}" / "{header.nonce}</dd>
            <dt>"Block time"</dt><dd>{header.time}</dd>
        </dl>
    }
}

#[component]
fn MinerView(initial: String) -> impl IntoView {
    let Ctx {
        connection, page, ..
    } = ctx();
    let input = RwSignal::new(initial.clone());
    let query = RwSignal::new(initial);
    let miner = LocalResource::new(move || {
        let connection = connection.get();
        let address = query.get();
        async move {
            if address.is_empty() {
                return None;
            }
            let path = format!("/miner?address={}&limit=50", api::url_encode(&address));
            Some(connection.get::<Miner>(&path).await)
        }
    });
    let submit = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        let address = input.get_untracked().trim().to_string();
        page.set(Page::Miner(address.clone()));
        query.set(address);
    };
    view! {
        <section class="card">
            <h2>"Miner lookup"</h2>
            <form class="lookup" on:submit=submit>
                <input bind:value=input placeholder="Payout or share address" />
                <button type="submit">"Look up"</button>
            </form>
            {move || match miner.get().flatten() {
                None => None,
                Some(Err(error)) => Some(error_view(error)),
                Some(Ok(miner)) => Some(view! { <MinerFields miner=miner /> }.into_any()),
            }}
        </section>
    }
}

#[component]
fn MinerFields(miner: Miner) -> impl IntoView {
    view! {
        <section class="kpis">
            <Kpi label="Share of PPLNS window" value=Signal::stored(format::percent(miner.share_fraction)) />
            <Kpi label="Payout fraction" value=Signal::stored(format::percent(miner.payout_fraction)) />
            <Kpi label="Shares" value=Signal::stored(miner.share_count.to_string()) />
            <Kpi label="Uncles" value=Signal::stored(miner.uncle_count.to_string()) />
        </section>
        <p class="muted">
            {format!("{} ({}) · window anchored at height {}", miner.address, miner.address_type, miner.anchor_height)}
        </p>
        <table>
            <thead>
                <tr><th>"Height"</th><th>"Share"</th><th>"Kind"</th><th>"Difficulty"</th><th>"Weight"</th></tr>
            </thead>
            <tbody>
                {miner
                    .shares
                    .into_iter()
                    .map(|share| {
                        view! {
                            <tr>
                                <td>{share.height}</td>
                                <td>{share_link(share.blockhash)}</td>
                                <td>{if share.nephew.is_some() { "uncle" } else { "share" }}</td>
                                <td>{share.difficulty}</td>
                                <td>{share.weight}</td>
                            </tr>
                        }
                    })
                    .collect_view()}
            </tbody>
        </table>
    }
}
