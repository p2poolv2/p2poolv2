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

use axum::{Router, routing::get};
use p2poolv2_lib::{
    config::{self, StratumConfig},
    shares::chain::chain_store::ChainStore,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::info;

pub struct ApiServer {
    chain_store: Arc<ChainStore>,
    config: StratumConfig<config::Parsed>,
    port: u16,
}

impl ApiServer {
    pub fn new(
        chain_store: Arc<ChainStore>,
        config: StratumConfig<config::Parsed>,
        port: u16,
    ) -> Self {
        Self {
            chain_store,
            config,
            port,
        }
    }

    pub fn start(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));

        let app = Router::new().route("/health", get(Self::health_check));

        let handle = tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            info!("API server listening on {}", addr);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                    info!("API shutdown signal received.");
                })
                .await
                .unwrap();
        });

        (shutdown_tx, handle)
    }

    async fn health_check() -> &'static str {
        "ok"
    }
}
