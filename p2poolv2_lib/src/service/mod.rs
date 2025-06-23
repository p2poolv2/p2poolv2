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
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tower::{limit::RateLimitLayer, util::BoxService,ServiceBuilder, ServiceExt};

// Build the full service stack
pub fn build_service<C, T>(
    config: NetworkConfig,
    swarm_tx: Sender<SwarmSend<C>>,
) -> BoxService<RequestContext<C, T>, (), Box<dyn Error + Send + Sync>>
where
    C: Send + Sync + 'static,
    T: TimeProvider + Send + Sync + 'static,
{
    let base_service = P2PService::new(swarm_tx);

    let builder = ServiceBuilder::new().layer(RateLimitLayer::new(
        config.max_requests_per_second,
        Duration::from_secs(1),
    ));

    let service = builder.service(base_service);

    BoxService::new(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use crate::service::p2p_service::{P2PService, RequestContext};
    #[mockall_double::double]
    use crate::shares::chain::actor::ChainHandle;
    use crate::shares::miner_message::{UserWorkbase, UserWorkbaseParams};
    use crate::utils::time_provider::TestTimeProvider;
    use libp2p::PeerId;
    use std::error::Error;
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::time::{advance, timeout, Duration};
    use tower::{limit::RateLimitLayer, Service, ServiceBuilder};
    use tower::{Service, ServiceBuilder};

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_blocks_excess_requests() {
        //! Verifies that Tower's RateLimitLayer enforces backpressure by making the service
        //! not ready after the allowed rate is exceeded, and that readiness resumes after the interval.

        const RATE: u64 = 1;
        const INTERVAL: Duration = Duration::from_secs(1);
        const TIMEOUT_MS: u64 = 100;

        let svc = tower::service_fn(|_req| async {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let mut service = ServiceBuilder::new()
            .layer(RateLimitLayer::new(RATE, INTERVAL))
            .service(svc);

        // First request should succeed
        let result1 = service.ready().await.unwrap().call(()).await;
        assert!(result1.is_ok(), "First request should succeed");

        // All further requests within the interval should be rate limited (not ready)
        for i in 1..=3 {
            let not_ready = timeout(Duration::from_millis(TIMEOUT_MS), service.ready()).await;
            assert!(
                not_ready.is_err(),
                "Request {i} should be rate limited (not ready yet), got: {not_ready:?}"
            );
        }

        // Advance time and verify service becomes ready again
        for i in 1..=3 {
            advance(INTERVAL).await;
            let ready = timeout(Duration::from_millis(TIMEOUT_MS), service.ready()).await;
            assert!(ready.is_ok(), "Service should be ready after interval {i}");
            let result = service.call(()).await;
            assert!(result.is_ok(), "Request {i} after interval should succeed");
        }
    }
}
