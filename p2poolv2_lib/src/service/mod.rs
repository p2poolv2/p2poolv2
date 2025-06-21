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
    use crate::utils::time_provider::TimeProvider;
    use libp2p::PeerId;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tower::limit::RateLimitLayer;
    use tower::{Service, ServiceBuilder, ServiceExt};

    // Dummy TimeProvider
    #[derive(Clone)]
    struct DummyTimeProvider;
    impl TimeProvider for DummyTimeProvider {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }

        fn set_time(&self, _time: std::time::SystemTime) {
            // No-op for dummy
        }

        fn seconds_since_epoch(&self) -> u64 {
            0
        }
    }

    // Dummy ChainHandle
    #[derive(Clone, Default)]
    struct DummyChainHandle;
    impl ChainHandle for DummyChainHandle {}

    // dummy RequestContext
    fn dummy_request_context<C>() -> RequestContext<C, DummyTimeProvider> {
        RequestContext {
            peer: PeerId::random(),
            request: Message::Ping,
            chain_handle: Arc::new(DummyChainHandle),
            response_channel: None::<C>.unwrap_or_else(|| panic!("Response channel unused")),
            swarm_tx: mpsc::channel(10).0,
            time_provider: DummyTimeProvider,
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_excess_requests() {
        // We hardcode rate limit for this unit test
        let (swarm_tx, _rx) = mpsc::channel(10);
        let base_service = P2PService::new(swarm_tx.clone());

        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(1, Duration::from_secs(1)))
            .service(base_service);

        let req_context = dummy_request_context();

        // First call should succeed
        let result1 = service
            .ready()
            .await
            .unwrap()
            .call(req_context.clone())
            .await;
        assert!(result1.is_ok(), "First request should succeed");

        // Second call immediately should be blocked by rate limiter
        let result2 = service
            .ready()
            .await
            .unwrap()
            .call(req_context.clone())
            .await;
        assert!(result2.is_err(), "Second request should be rate limited");
    }
}
