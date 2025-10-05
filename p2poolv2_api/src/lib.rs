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

use p2poolv2_lib::{
    config::{self, StratumConfig},
    shares::chain::chain_store::ChainStore,
};
use std::sync::Arc;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::info;

pub mod api;
pub use api::server::ApiServer;

/// Starts the API server asynchronously and returns shutdown handle + JoinHandle.
pub fn api_start(
    chain_store: Arc<ChainStore>,
    config: StratumConfig<config::Parsed>,
    port: u16,
) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let server = ApiServer::new(chain_store, config, port);
    let (shutdown_tx, handle) = server.start();
    info!("API server started on port {}", port);
    (shutdown_tx, handle)
}

/// Gracefully shuts down the API server.
pub async fn api_shutdown(shutdown_tx: oneshot::Sender<()>, handle: JoinHandle<()>) {
    info!("Shutting down API server...");
    let _ = shutdown_tx.send(());
    let _ = handle.await;
    info!("API server stopped.");
}
