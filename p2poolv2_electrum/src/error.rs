// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use p2poolv2_lib::store::writer::StoreError;
use std::io;
use thiserror::Error;
use tokio::task::JoinError;

/// Errors that stop one Electrum server instance. The caller decides
/// whether to restart; none of these are fatal to the node.
#[derive(Debug, Error)]
pub enum ElectrumServerError {
    /// The listener could not bind, or its bound address could not be read.
    #[error("failed to bind Electrum server to {address}: {source}")]
    Bind { address: String, source: io::Error },
    /// Accepting connections failed too many times in a row.
    #[error("Electrum server stopped accepting connections: {0}")]
    Accept(io::Error),
    /// Reading the share chain tip failed.
    #[error("Electrum server could not read the share chain tip: {0}")]
    TipRead(StoreError),
    /// The blocking task reading the share chain tip failed.
    #[error("Electrum server tip read task failed: {0}")]
    TipReadTask(JoinError),
}
