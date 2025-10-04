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

use super::handlers::{get_block_template, get_pplns_distribution, get_shares, health_check};
use super::models::ApiState;
use crate::config::StratumConfig;
use crate::shares::chain::chain_store::ChainStore;
use crate::stratum::work::block_template::BlockTemplate;
use axum::{
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

/// API Server for P2Pool v2
pub struct ApiServer {
    chain_store: Arc<ChainStore>,
    current_template: Arc<RwLock<Option<BlockTemplate>>>,
    config: StratumConfig<crate::config::Parsed>,
    port: u16,
}

impl ApiServer {
    /// Create a new API server instance
    pub fn new(
        chain_store: Arc<ChainStore>,
        config: StratumConfig<crate::config::Parsed>,
        port: u16,
    ) -> Self {
        Self {
            chain_store,
            current_template: Arc::new(RwLock::new(None)),
            config,
            port,
        }
    }

    /// Update the current block template
    pub async fn update_template(&self, template: BlockTemplate) {
        let mut current = self.current_template.write().await;
        *current = Some(template);
        info!("Updated block template in API server");
    }

    /// Start the API server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.create_app().await?;
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        
        info!("Starting API server on {}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }

    /// Create the Axum application with routes and middleware
    async fn create_app(&self) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
        let state = ApiState {
            chain_store: self.chain_store.clone(),
            current_template: self.current_template.clone(),
            config: self.config.clone(),
        };

        let app = Router::new()
            .route("/health", get(health_check))
            .route("/api/shares", get(get_shares))
            .route("/api/block-template", get(get_block_template))
            .route("/api/pplns-distribution", get(get_pplns_distribution))
            .with_state(state)
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(
                        CorsLayer::new()
                            .allow_origin(Any)
                            .allow_methods(Any)
                            .allow_headers(Any),
                    ),
            );

        Ok(app)
    }
}