// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

pub mod p2p_service;

use crate::config::NetworkConfig;
use crate::node::layers::rate_limit_layer::RateLimitLayer;
use crate::node::rate_limiter::RateLimiter;
use crate::node::SwarmSend;
use crate::service::p2p_service::{P2PService, RequestContext};
use crate::utils::time_provider::TimeProvider;

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tower::{Service, ServiceBuilder};

pub fn build_service<C, T>(
    config: NetworkConfig,
    swarm_tx: Sender<SwarmSend<C>>,
    limiter: Arc<RateLimiter>,
) -> impl Service<RequestContext<C, T>, Response = (), Error = Box<dyn Error + Send + Sync>> + Clone
where
    C: Send + Sync + Clone + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    // Build the base service with swarm_tx
    let base_service = P2PService::new(swarm_tx.clone());

    // Build layered service stack
    ServiceBuilder::new()
        .layer(RateLimitLayer::new(limiter, config.clone()))
        .service(base_service)
}
