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

use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Future;
use tokio::sync::mpsc;
use tower::Service;

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::handle_request;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::utils::time_provider::TimeProvider;
use std::sync::Arc;

/// Request context wrapping all inputs for the service call.
pub struct RequestContext<C, T> {
    pub peer: libp2p::PeerId,
    pub request: Message,
    pub store: Arc<ChainStore>,
    pub response_channel: C,
    pub swarm_tx: mpsc::Sender<SwarmSend<C>>,
    pub time_provider: T,
}

/// The Tower service that processes inbound P2P requests.
#[derive(Clone)]
pub struct P2PService<C> {
    pub swarm_tx: mpsc::Sender<SwarmSend<C>>,
}

impl<C> P2PService<C> {
    pub fn new(swarm_tx: mpsc::Sender<SwarmSend<C>>) -> Self {
        Self { swarm_tx }
    }
}

impl<C: 'static + Send + Sync, T: TimeProvider + Send + Sync + 'static>
    Service<RequestContext<C, T>> for P2PService<C>
{
    type Response = ();
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Always ready
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestContext<C, T>) -> Self::Future {
        Box::pin(async move {
            handle_request(req).await.map_err(|e| {
                tracing::error!("Service failed to process request: {}", e);
                e
            })
        })
    }
}
