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
use crate::node::SwarmSend;
use crate::service::p2p_service::{P2PService, RequestContext};
use crate::utils::time_provider::TimeProvider;

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tower::limit::RateLimitLayer;
use tower::{Service, ServiceBuilder};

pub fn build_service<C, T>(
    config: NetworkConfig,
    swarm_tx: Sender<SwarmSend<C>>,
) -> impl Service<RequestContext<C, T>, Response = (), Error = Box<dyn Error + Send + Sync>>
where
    C: Send + Sync + Clone + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    // Base P2P service
    let base_service = P2PService::new(swarm_tx.clone());

    // Apply Tower's built-in RateLimit middleware
    ServiceBuilder::new()
        .layer(RateLimitLayer::new(
            config.max_requests_per_second,
            Duration::from_secs(1),
        ))
        .service(base_service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use crate::service::p2p_service::{P2PService, RequestContext};
    use crate::shares::chain::actor::ChainHandle;
    use crate::utils::time_provider::TestTimeProvider;

    use libp2p::PeerId;
    use std::time::{Duration, SystemTime};
    use tokio::sync::{mpsc, oneshot};
    use tower::limit::RateLimitLayer;
    use tower::{Service, ServiceBuilder};

    #[tokio::test]
    async fn test_rate_limit_blocks_excess_requests() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let (response_channel_tx, _response_channel_rx) = oneshot::channel::<Message>();

        let peer_id = PeerId::random();
        let time_provider = TestTimeProvider(SystemTime::now());

        let ctx = RequestContext {
            peer: peer_id,
            request: Message::Ping,
            chain_handle,
            response_channel: response_channel_tx,
            swarm_tx: swarm_tx.clone(),
            time_provider,
        };

        // Build the base service
        let base_service = P2PService::new(swarm_tx.clone());

        // Apply the rate limiting layer
        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(1, Duration::from_secs(1)))
            .service(base_service);

        // First call should succeed
        let result1 = service.ready().await.unwrap().call(ctx.clone()).await;
        assert!(result1.is_ok(), "First request should succeed");

        // Second call immediately should be blocked by the rate limiter
        let result2 = service.ready().await.unwrap().call(ctx.clone()).await;
        assert!(result2.is_err(), "Second request should be rate limited");
    }
}
