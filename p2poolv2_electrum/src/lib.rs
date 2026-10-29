// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum JSON-RPC server over plain TCP, serving share chain
//! queries to the operator's own wallet.

mod connection;
pub mod error;
mod methods;
mod protocol;
mod server;
#[cfg(test)]
mod test_utils;

pub use error::ElectrumServerError;
pub use server::run_server;
