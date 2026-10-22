// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dashboard's pages, rendered to HTML in Rust.
//!
//! Every value is escaped by maud; only the fixed stylesheet is inlined raw.
//! Pages carry no script: the overview refreshes itself with a meta
//! refresh, tooltips are SVG titles, and the miner lookup is a plain form.

use super::chart::{Series, line_chart};
use super::history::Sample;
use super::style::STYLE;
use crate::api::endpoints::miner::MinerResponse;
use crate::api::endpoints::share::ShareLookupOutput;
use bitcoin::BlockHash;
use maud::{DOCTYPE, Markup, PreEscaped, html};

/// Seconds between refreshes of the overview page.
pub(crate) const OVERVIEW_REFRESH_SECONDS: u32 = 30;

/// A confirmed share as the overview lists it.
pub(crate) struct RecentShare {
    pub(crate) height: u32,
    pub(crate) blockhash: String,
    pub(crate) time: u32,
    pub(crate) payout_address: String,
    pub(crate) is_block: bool,
}

/// A block the pool found, as the overview lists it.
pub(crate) struct FoundBlockRow {
    /// Bitcoin Cash height.
    pub(crate) height: u64,
    pub(crate) block_hash: BlockHash,
    /// The share whose header carries the block.
    pub(crate) share_hash: BlockHash,
    /// Unix seconds of the block header.
    pub(crate) time: u32,
    /// Payout address of the miner that found it.
    pub(crate) payout_address: String,
}

/// Everything the overview shows.
pub(crate) struct Overview {
    pub(crate) network: String,
    pub(crate) now: u64,
    pub(crate) tip_height: Option<u32>,
    pub(crate) pool_hashrate: Option<f64>,
    pub(crate) local_hashrate: Option<f64>,
    pub(crate) network_hashrate: Option<f64>,
    pub(crate) network_difficulty: Option<f64>,
    pub(crate) miners_online: usize,
    pub(crate) workers_online: usize,
    pub(crate) samples: Vec<Sample>,
    /// Blocks the pool found in all.
    pub(crate) blocks_found: usize,
    /// The newest of them, newest first.
    pub(crate) blocks: Vec<FoundBlockRow>,
    pub(crate) recent_shares: Vec<RecentShare>,
}

/// Everything a miner's page shows.
pub(crate) struct MinerView {
    pub(crate) network: String,
    pub(crate) report: MinerResponse,
    /// The miner's hashrate over the recent shares, if it has any there.
    pub(crate) hashrate: Option<f64>,
    /// How many recent shares, and over how many seconds, it was taken from.
    pub(crate) recent_window: Option<(usize, u32)>,
}

/// Everything a share's page shows.
pub(crate) struct ShareView {
    pub(crate) network: String,
    pub(crate) share: ShareLookupOutput,
    pub(crate) is_block: bool,
}

const UNITS: [&str; 7] = ["", "k", "M", "G", "T", "P", "E"];

/// `value` scaled to a unit prefix, three significant digits.
fn with_prefix(value: f64) -> (f64, &'static str) {
    let mut scaled = value;
    let mut unit = 0;
    while scaled.abs() >= 1000.0 && unit + 1 < UNITS.len() {
        scaled /= 1000.0;
        unit += 1;
    }
    (scaled, UNITS[unit])
}

fn three_digits(value: f64) -> String {
    if value.abs() >= 100.0 {
        format!("{value:.0}")
    } else if value.abs() >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    }
}

pub(crate) fn fmt_hashrate(hashes_per_second: f64) -> String {
    let (value, unit) = with_prefix(hashes_per_second);
    format!("{} {unit}H/s", three_digits(value))
}

pub(crate) fn fmt_difficulty(difficulty: f64) -> String {
    let (value, unit) = with_prefix(difficulty);
    format!("{}{unit}", three_digits(value))
        .trim_end()
        .to_string()
}

pub(crate) fn fmt_utc(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map(|time| time.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| unix.to_string())
}

/// Day and time, short enough for a chart axis that spans a day.
pub(crate) fn fmt_day_time(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map(|time| time.format("%b %-d %H:%M UTC").to_string())
        .unwrap_or_else(|| unix.to_string())
}

pub(crate) fn fmt_ago(now: u64, then: u64) -> String {
    let seconds = now.saturating_sub(then);
    match seconds {
        0..=59 => format!("{seconds} s ago"),
        60..=3_599 => format!("{} min ago", seconds / 60),
        3_600..=86_399 => format!("{} h ago", seconds / 3_600),
        _ => format!("{} d ago", seconds / 86_400),
    }
}

/// A long hash cut to its ends.
pub(crate) fn short(hash: &str) -> String {
    if hash.len() <= 20 {
        return hash.to_string();
    }
    format!("{}…{}", &hash[..10], &hash[hash.len() - 6..])
}

fn optional(value: Option<f64>, format: fn(f64) -> String) -> String {
    value.map(format).unwrap_or_else(|| "—".to_string())
}

fn percent(fraction: f64) -> String {
    format!("{:.2}%", fraction * 100.0)
}

fn miner_link(address: &str) -> Markup {
    html! {
        a.mono href=(format!("/dashboard/miner?address={}", url_component(address))) { (address) }
    }
}

fn share_link(blockhash: &str, text: &str) -> Markup {
    html! { a.mono href=(format!("/dashboard/share/{}", url_component(blockhash))) { (text) } }
}

/// Percent-encode anything outside the unreserved set, for a query or path
/// component. Addresses and hashes are ASCII, but the escape keeps a
/// strange value from changing the URL's structure.
fn url_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b':') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn kpi(label: &str, value: String, note: Option<String>) -> Markup {
    html! {
        div.kpi {
            div.label { (label) }
            div.value { (value) }
            @if let Some(note) = note { div.note { (note) } }
        }
    }
}

/// The page frame: header, styles and footer around `body`.
pub(crate) fn layout(title: &str, network: &str, refresh: Option<u32>, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                @if let Some(seconds) = refresh {
                    meta http-equiv="refresh" content=(seconds);
                }
                title { (title) " · P2Pool v2" }
                style { (PreEscaped(STYLE)) }
            }
            body {
                header {
                    h1 { a href="/dashboard" { "P2Pool" span { "v2" } } }
                    span.network { (network) }
                    nav { a href="/dashboard" { "Overview" } }
                }
                main { (body) }
                footer { "Served by this P2Pool node. No scripts, no tracking." }
            }
        }
    }
}

fn lookup_form(value: &str) -> Markup {
    html! {
        form.lookup action="/dashboard/miner" method="get" {
            input type="text" name="address" value=(value)
                placeholder="Payout or share chain address" required aria-label="Miner address";
            button type="submit" { "Look up miner" }
        }
    }
}

fn series(samples: &[Sample], pick: fn(&Sample) -> Option<f64>) -> Vec<(u64, f64)> {
    samples
        .iter()
        .filter_map(|sample| pick(sample).map(|value| (sample.time, value)))
        .collect()
}

pub(crate) fn overview(view: &Overview) -> Markup {
    let chart = line_chart(
        "Hashrate over the last day",
        &[
            Series {
                label: "Pool",
                class: "pool",
                points: series(&view.samples, |sample| sample.pool),
            },
            Series {
                label: "This node",
                class: "local",
                points: series(&view.samples, |sample| sample.local),
            },
        ],
        fmt_hashrate,
        fmt_day_time,
    );
    let body = html! {
        section.kpis {
            (kpi("Pool hashrate", optional(view.pool_hashrate, fmt_hashrate),
                Some("from the newest shares".to_string())))
            (kpi("This node", optional(view.local_hashrate, fmt_hashrate),
                Some(format!("{} miners, {} workers online", view.miners_online, view.workers_online))))
            (kpi("Network hashrate", optional(view.network_hashrate, fmt_hashrate),
                view.network_difficulty.map(|difficulty| format!("difficulty {}", fmt_difficulty(difficulty)))))
            (kpi("Share chain height",
                view.tip_height.map(|height| height.to_string()).unwrap_or_else(|| "—".to_string()),
                None))
            (kpi("Blocks found", view.blocks_found.to_string(),
                Some("by the pool, from its share chain".to_string())))
        }
        h2 { "Hashrate" }
        div.panel { (chart) }
        h2 { "Find a miner" }
        div.panel { (lookup_form("")) }
        h2 { "Blocks found" }
        div.panel {
            @if view.blocks.is_empty() {
                p.empty { "The pool has not found a block yet." }
            } @else {
                table {
                    thead { tr { th { "Height" } th { "Bitcoin Cash block" } th { "Share" } th { "When" } th { "Found by" } } }
                    tbody {
                        @for block in &view.blocks {
                            tr {
                                td { (block.height) }
                                td.mono { (short(&block.block_hash.to_string())) }
                                td { (share_link(&block.share_hash.to_string(), &short(&block.share_hash.to_string()))) }
                                td title=(fmt_utc(u64::from(block.time))) { (fmt_ago(view.now, u64::from(block.time))) }
                                td { (miner_link(&block.payout_address)) }
                            }
                        }
                    }
                }
            }
        }
        h2 { "Recent shares" }
        div.panel {
            @if view.recent_shares.is_empty() {
                p.empty { "No confirmed shares yet." }
            } @else {
                table {
                    thead { tr { th { "Height" } th { "Share" } th { "When" } th { "Payout address" } th {} } }
                    tbody {
                        @for share in &view.recent_shares {
                            tr {
                                td { (share.height) }
                                td { (share_link(&share.blockhash, &short(&share.blockhash))) }
                                td title=(fmt_utc(u64::from(share.time))) { (fmt_ago(view.now, u64::from(share.time))) }
                                td { (miner_link(&share.payout_address)) }
                                td { @if share.is_block { span.badge { "block" } } }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(
        "Overview",
        &view.network,
        Some(OVERVIEW_REFRESH_SECONDS),
        body,
    )
}

pub(crate) fn miner(view: &MinerView) -> Markup {
    let report = &view.report;
    let body = html! {
        div.panel { (lookup_form(&report.address)) }
        h2 { "Miner" }
        div.panel {
            dl.fields {
                dt { "Address" } dd.mono { (report.address) }
                dt { "Kind" } dd { (if report.address_type == "share" { "share chain address" } else { "payout address" }) }
                dt { "Window" } dd {
                    (report.window.share_count) " shares"
                    @if let (Some(newest), Some(oldest)) = (report.window.newest_height, report.window.oldest_height) {
                        ", heights " (oldest) " to " (newest)
                    }
                }
                dt { "Mining on" } dd { (share_link(&report.anchor, &format!("height {}", report.anchor_height))) }
            }
        }
        section.kpis {
            (kpi("Share of the next block's payout", percent(report.payout_fraction),
                Some("after the donation and any operator fee".to_string())))
            (kpi("Shares in the window", report.share_count.to_string(),
                Some(format!("{} of all shares", percent(report.share_fraction)))))
            (kpi("Uncles credited", report.uncle_count.to_string(), None))
            (kpi("Hashrate", optional(view.hashrate, fmt_hashrate),
                view.recent_window.map(|(shares, seconds)| format!("over the last {shares} shares, {} min", seconds / 60))))
        }
        h2 { "Shares credited in the window" }
        div.panel {
            @if report.shares.is_empty() {
                p.empty { "This address has no shares in the current window." }
            } @else {
                table {
                    thead { tr { th { "Height" } th { "Share" } th { "Difficulty" } th { "Weight" } th { "Kind" } } }
                    tbody {
                        @for share in &report.shares {
                            tr {
                                td { (share.height) }
                                td { (share_link(&share.blockhash, &short(&share.blockhash))) }
                                td.mono { (share.difficulty) }
                                td.mono { (share.weight) }
                                td { @if share.nephew.is_some() { "uncle" } @else { "share" } }
                            }
                        }
                    }
                }
            }
        }
    };
    layout(
        &format!("Miner {}", short(&report.address)),
        &view.network,
        None,
        body,
    )
}

pub(crate) fn share(view: &ShareView) -> Markup {
    let share = &view.share;
    let header = &share.bitcoin_header;
    let body = html! {
        h2 { "Share" }
        div.panel {
            @if view.is_block {
                p { span.badge { "block" } " This share met its Bitcoin Cash block target." }
            }
            dl.fields {
                dt { "Hash" } dd.mono { (share.blockhash) }
                dt { "Height" } dd { (share.height.map(|height| height.to_string()).unwrap_or_else(|| "—".to_string())) }
                dt { "Chain" } dd { (share.chain) }
                dt { "Validation" } dd { (share.validation_status) }
                dt { "Parent" } dd { (share_link(&share.parent, &share.parent)) }
                dt { "Payout address" } dd { (miner_link(&share.miner_bitcoin_address)) }
                dt { "Share chain address" } dd { (miner_link(&share.miner_address)) }
                dt { "Share bits" } dd.mono { (share.bits) }
                dt { "Time" } dd { (share.time) }
                dt { "Uncles" } dd {
                    @if share.uncles.is_empty() { "none" }
                    @for uncle in &share.uncles { (share_link(uncle, &short(uncle))) " " }
                }
            }
        }
        h2 { "Bitcoin Cash header" }
        div.panel {
            dl.fields {
                dt { "Block hash" } dd.mono { (header.block_hash) }
                dt { "Previous block" } dd.mono { (header.prev_blockhash) }
                dt { "Merkle root" } dd.mono { (header.merkle_root) }
                dt { "Time" } dd { (header.time) }
                dt { "Bits" } dd.mono { (header.bits) }
                dt { "Nonce" } dd.mono { (header.nonce) }
                dt { "Version" } dd.mono { (format!("{:#x}", header.version)) }
            }
        }
    };
    layout(
        &format!("Share {}", short(&share.blockhash)),
        &view.network,
        None,
        body,
    )
}

/// A page for a request the dashboard could not answer.
pub(crate) fn error(network: &str, message: &str) -> Markup {
    let body = html! {
        div.panel.error { p { (message) } }
        h2 { "Find a miner" }
        div.panel { (lookup_form("")) }
    };
    layout("Not available", network, None, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrates_use_unit_prefixes() {
        assert_eq!(fmt_hashrate(0.0), "0.00 H/s");
        assert_eq!(fmt_hashrate(2_400_000_000_000.0), "2.40 TH/s");
        assert_eq!(fmt_hashrate(38_790_000_000_000.0), "38.8 TH/s");
        assert_eq!(fmt_hashrate(665_000.0), "665 kH/s");
    }

    #[test]
    fn difficulties_use_unit_prefixes() {
        assert_eq!(fmt_difficulty(665_151.95), "665k");
        assert_eq!(fmt_difficulty(4.5), "4.50");
    }

    #[test]
    fn chart_times_carry_the_day() {
        assert_eq!(fmt_day_time(1_792_000_000), "Oct 14 17:46 UTC");
    }

    #[test]
    fn ages_pick_a_readable_unit() {
        assert_eq!(fmt_ago(100, 58), "42 s ago");
        assert_eq!(fmt_ago(1_000, 100), "15 min ago");
        assert_eq!(fmt_ago(20_000, 0), "5 h ago");
        assert_eq!(fmt_ago(200_000, 0), "2 d ago");
        assert_eq!(fmt_ago(0, 100), "0 s ago");
    }

    #[test]
    fn long_hashes_are_shortened() {
        assert_eq!(short("abc"), "abc");
        let hash = "00000000000cb752459c2b08e1955e5f33252b0207b1c7b5b2f069d5254b9025";
        assert_eq!(short(hash), "0000000000…4b9025");
    }

    #[test]
    fn url_components_escape_structure() {
        assert_eq!(url_component("bchtest:qr3rryn6"), "bchtest:qr3rryn6");
        assert_eq!(url_component("a&b=c d"), "a%26b%3Dc%20d");
    }

    #[test]
    fn the_layout_has_no_script_and_escapes_its_title() {
        let page = layout(
            "<b>x</b>",
            "Bitcoin Cash chipnet",
            Some(30),
            html! { p { "hi" } },
        )
        .into_string();
        assert!(!page.contains("<script"));
        assert!(page.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(page.contains("http-equiv=\"refresh\""));
        assert!(page.contains("Bitcoin Cash chipnet"));
    }

    #[test]
    fn an_empty_overview_renders() {
        let page = overview(&Overview {
            network: "Bitcoin Cash chipnet".to_string(),
            now: 1_000,
            tip_height: None,
            pool_hashrate: None,
            local_hashrate: None,
            network_hashrate: None,
            network_difficulty: None,
            miners_online: 0,
            workers_online: 0,
            samples: Vec::new(),
            blocks_found: 0,
            blocks: Vec::new(),
            recent_shares: Vec::new(),
        })
        .into_string();
        assert!(page.contains("No confirmed shares yet."));
        assert!(page.contains("Collecting data"));
        assert!(!page.contains("<script"));
    }

    #[test]
    fn a_hostile_payout_address_is_escaped_in_the_overview() {
        let page = overview(&Overview {
            network: "Bitcoin Cash chipnet".to_string(),
            now: 1_000,
            tip_height: Some(1),
            pool_hashrate: Some(1.0),
            local_hashrate: None,
            network_hashrate: None,
            network_difficulty: None,
            miners_online: 0,
            workers_online: 0,
            samples: Vec::new(),
            blocks_found: 0,
            blocks: Vec::new(),
            recent_shares: vec![RecentShare {
                height: 1,
                blockhash: "ab".to_string(),
                time: 900,
                payout_address: "<img src=x onerror=alert(1)>".to_string(),
                is_block: true,
            }],
        })
        .into_string();
        assert!(!page.contains("<img"));
        assert!(page.contains("&lt;img"));
        assert!(page.contains("class=\"badge\""));
    }
}
