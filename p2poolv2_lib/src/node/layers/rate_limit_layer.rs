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

use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tower::{Layer, Service};

use crate::config::NetworkConfig;
use crate::node::messages::Message;
use crate::node::rate_limiter::RateLimiter;
use crate::node::SwarmSend;
use crate::service::p2p_service::RequestContext;
use crate::shares::chain::actor::ChainHandle;
use crate::utils::time_provider::TimeProvider;

// This layer itself is not generic
#[derive(Clone)]
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter>,
    config: NetworkConfig,
}

impl RateLimitLayer {
    pub fn new(limiter: Arc<RateLimiter>, config: NetworkConfig) -> Self {
        Self { limiter, config }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitMiddleware {
            inner,
            limiter: self.limiter.clone(),
            config: self.config.clone(),
        }
    }
}

// Middleware is generic over inner service S
#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    limiter: Arc<RateLimiter>,
    config: NetworkConfig,
}

impl<S, C, T> Service<RequestContext<C, T>> for RateLimitMiddleware<S>
where
    S: Service<RequestContext<C, T>, Response = (), Error = Box<dyn StdError + Send + Sync>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    C: Send + Sync + Clone + 'static,
    T: Send + Sync + 'static,
{
    type Response = ();
    type Error = Box<dyn StdError + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestContext<C, T>) -> Self::Future {
        let mut inner = self.inner.clone();
        let limiter = self.limiter.clone();
        let config = self.config.clone();
        let peer_id = req.peer;
        let message = req.request.clone();

        Box::pin(async move {
            let allowed = limiter.check_rate_limit(&peer_id, message, &config).await;
            if !allowed {
                tracing::warn!("Dropping request from peer {} due to rate limit", peer_id);
                return Ok(());
            }
            inner.call(req).await
        })
    }
}
