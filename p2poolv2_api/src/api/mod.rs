// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod auth;
mod bitcoin_rpc;
pub mod endpoints;
pub mod error;
pub mod server;
pub(crate) mod websocket;

pub use bitcoin_rpc::start_bitcoin_rpc_server;
