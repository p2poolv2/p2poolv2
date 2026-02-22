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

use crate::config::NetworkConfig;
use crate::node::SwarmSend;
use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::handle_response;
use crate::service::build_service;
use crate::service::p2p_service::RequestContext;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::utils::time_provider::SystemTimeProvider;
use libp2p::request_response::ResponseChannel;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tower::util::BoxService;
use tower::{Service, ServiceExt};
use tracing::{debug, error};

/// Handles request-response events from the libp2p network.
///
/// Owns the Tower service stack (rate limiting, inactivity tracking) and
/// dispatches inbound requests through it. Responses are handled directly
/// without the service layers since they are solicited by us and do not
/// need peer-protection middleware.
pub struct RequestResponseHandler {
    request_service: BoxService<
        RequestContext<ResponseChannel<Message>, SystemTimeProvider>,
        (),
        Box<dyn Error + Send + Sync>,
    >,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
}

impl RequestResponseHandler {
    /// Create a new RequestResponseHandler with the Tower service stack.
    pub fn new(
        network_config: NetworkConfig,
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    ) -> Self {
        let service =
            build_service::<ResponseChannel<Message>, _>(network_config, swarm_tx.clone());
        Self {
            request_service: service,
            chain_store_handle,
            swarm_tx,
        }
    }

    /// Handle a request-response event from the libp2p network.
    ///
    /// Inbound requests are dispatched through the Tower service stack
    /// (rate limiting, inactivity tracking). If the service is not ready
    /// within 1 second, the peer is disconnected.
    ///
    /// Inbound responses are dispatched directly to handle_response
    /// without the service layers.
    pub async fn handle_event(
        &mut self,
        event: RequestResponseEvent,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            RequestResponseEvent::Message {
                peer,
                message:
                    libp2p::request_response::Message::Request {
                        request_id: _,
                        request,
                        channel,
                    },
            } => {
                let ctx = RequestContext::<ResponseChannel<Message>, _> {
                    peer,
                    request: request.clone(),
                    chain_store_handle: self.chain_store_handle.clone(),
                    response_channel: channel,
                    swarm_tx: self.swarm_tx.clone(),
                    time_provider: SystemTimeProvider,
                };

                match tokio::time::timeout(Duration::from_secs(1), self.request_service.ready())
                    .await
                {
                    Ok(Ok(_)) => {
                        if let Err(err) = self.request_service.call(ctx).await {
                            error!("Service call failed for peer {}: {}", peer, err);
                        }
                    }
                    Ok(Err(err)) => {
                        error!("Service not ready for peer {}: {}", peer, err);
                        if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await
                        {
                            error!(
                                "Failed to send disconnect command for peer {}: {:?}",
                                peer, send_err
                            );
                        }
                    }
                    Err(_) => {
                        error!("Service readiness timed out for peer {}", peer);
                        if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await
                        {
                            error!(
                                "Failed to send disconnect command for peer {}: {:?}",
                                peer, send_err
                            );
                        }
                    }
                }
            }
            RequestResponseEvent::Message {
                peer,
                message:
                    libp2p::request_response::Message::Response {
                        request_id,
                        response,
                    },
            } => {
                debug!(
                    "Received response for request {} from peer {}",
                    request_id, peer
                );
                let time_provider = SystemTimeProvider;
                if let Err(err) = handle_response(
                    peer,
                    response,
                    self.chain_store_handle.clone(),
                    &time_provider,
                )
                .await
                {
                    error!(
                        "Error handling response for request {} from peer {}: {}",
                        request_id, peer, err
                    );
                }
            }
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error: failure_error,
            } => {
                debug!(
                    "Outbound failure from peer {}, request_id: {}, error: {:?}",
                    peer, request_id, failure_error
                );
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error: failure_error,
            } => {
                debug!(
                    "Inbound failure from peer {}, request_id: {}, error: {:?}",
                    peer, request_id, failure_error
                );
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                debug!("Response sent to peer {}, request_id: {}", peer, request_id);
            }
        }
        Ok(())
    }
}
