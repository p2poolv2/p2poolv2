// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use crate::api::error::ApiError;
use p2poolv2_lib::{
    config::{self, StratumConfig},
    shares::chain::chain_store::ChainStore,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::info;
pub mod api;
pub use api::server::ApiServer;

/// Starts the API server asynchronously and returns shutdown handle.
pub fn api_start(
    chain_store: Arc<ChainStore>,
    config: StratumConfig<config::Parsed>,
    port: u16,
) -> Result<oneshot::Sender<()>, ApiError> {
    let server = ApiServer::new(chain_store, config, port);
    let shutdown_tx = server.start()?;
    info!("API server started on port {}", port);
    Ok(shutdown_tx)
}

/// Gracefully shuts down the API server.
pub async fn api_shutdown(shutdown_tx: oneshot::Sender<()>) {
    info!("Shutting down API server...");
    let _ = shutdown_tx.send(());
    info!("API server stopped.");
}
