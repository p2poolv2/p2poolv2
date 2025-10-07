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
use axum::{Router, routing::get};
use p2poolv2_lib::{config::ApiConfig, shares::chain::chain_store::ChainStore};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::oneshot;
use tracing::info;

pub struct ApiServer {
    _chain_store: Arc<ChainStore>,
    config: ApiConfig,
}

impl ApiServer {
    pub fn new(chain_store: Arc<ChainStore>, config: ApiConfig) -> Self {
        Self {
            _chain_store: chain_store,
            config,
        }
    }

    /// Start the API server and return a shutdown channel
    ///
    /// Send a signal through the returned channel to gracefully shutdown the server.
    pub async fn start(self) -> Result<oneshot::Sender<()>, std::io::Error> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(self.config.hostname.parse().unwrap()),
            self.config.port,
        );
        let app = Router::new().route("/health", get(health_check));

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) => return Err(e),
        };

        info!("API server listening on {}", addr);

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                    info!("API server shutdown signal received");
                })
                .await
                .map_err(|e| ApiError::ServerError(e.to_string()))?;

            info!("API server stopped");
            Ok::<(), ApiError>(())
        });
        Ok(shutdown_tx)
    }
}

async fn health_check() -> String {
    "ok".into()
}
