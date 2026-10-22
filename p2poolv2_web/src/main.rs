// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interactive P2Poolv2 dashboard, written in Rust with Leptos and compiled to
//! WebAssembly. It reads the node's JSON API and `/ws` feed; see README.md.

mod api;
mod app;
mod chart;
mod format;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
