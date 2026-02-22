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
/// Generic over the channel type `C` to allow testing with substitute
/// types.  In production, `C` is `ResponseChannel<Message>` from
/// libp2p. In tests, `C` can be any `Send + Sync + 'static` type such
/// as `oneshot::Sender<Message>`.
///
/// We need to do this as ResponseChannel is an opaque type and we
/// can't write tests for modules that directly use these types.
///
/// Service: The struct owns a tower service stack (rate limiting,
/// inactivity tracking) and dispatches inbound requests through
/// it. Responses are handled directly without the service layers
/// since they are solicited by us and do not need peer-protection
/// middleware.
pub struct RequestResponseHandler<C: Send + Sync + 'static> {
    request_service:
        BoxService<RequestContext<C, SystemTimeProvider>, (), Box<dyn Error + Send + Sync>>,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
}

/// Implementation of ResponseChannel<Message>, used in production.
/// The only part left out of tests is the type based dispatching. The
/// dispatch.* functions are tested for the generic implementation.
impl RequestResponseHandler<ResponseChannel<Message>> {
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
    /// Inbound requests are dispatched through the Tower service
    /// stack (rate limiting, inactivity tracking). If the service is
    /// not ready within 1 second, the peer is disconnected.
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
            } => self.dispatch_request(peer, request, channel).await,
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
                self.dispatch_response(peer, response).await
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
                Ok(())
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
                Ok(())
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => {
                debug!("Response sent to peer {}, request_id: {}", peer, request_id);
                Ok(())
            }
        }
    }
}

/// Generic implementation. The dispatch.* functions can be tested as
/// here we don't depend on the the tokio opaque types.
impl<C: Send + Sync + 'static> RequestResponseHandler<C> {
    /// Dispatch an inbound request through the Tower service stack.
    ///
    /// Creates a `RequestContext` and attempts to call the service within a
    /// 1-second timeout. If the service is not ready in time or returns an
    /// error, the peer is disconnected.
    async fn dispatch_request(
        &mut self,
        peer: libp2p::PeerId,
        request: Message,
        channel: C,
    ) -> Result<(), Box<dyn Error>> {
        let ctx = RequestContext::<C, _> {
            peer,
            request: request.clone(),
            chain_store_handle: self.chain_store_handle.clone(),
            response_channel: channel,
            swarm_tx: self.swarm_tx.clone(),
            time_provider: SystemTimeProvider,
        };

        match tokio::time::timeout(Duration::from_secs(1), self.request_service.ready()).await {
            Ok(Ok(_)) => {
                if let Err(err) = self.request_service.call(ctx).await {
                    error!("Service call failed for peer {}: {}", peer, err);
                }
            }
            Ok(Err(err)) => {
                error!("Service not ready for peer {}: {}", peer, err);
                if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await {
                    error!(
                        "Failed to send disconnect command for peer {}: {:?}",
                        peer, send_err
                    );
                }
            }
            Err(_) => {
                error!("Service readiness timed out for peer {}", peer);
                if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await {
                    error!(
                        "Failed to send disconnect command for peer {}: {:?}",
                        peer, send_err
                    );
                }
            }
        }
        Ok(())
    }

    /// Dispatch a response by calling handle_response directly.
    ///
    /// Responses bypass the Tower service layers (rate limiting, inactivity
    /// tracking) because they are solicited by us and libp2p only delivers
    /// them for matching outstanding requests.
    async fn dispatch_response(
        &mut self,
        peer: libp2p::PeerId,
        response: Message,
    ) -> Result<(), Box<dyn Error>> {
        let time_provider = SystemTimeProvider;
        if let Err(err) = handle_response(
            peer,
            response,
            self.chain_store_handle.clone(),
            &time_provider,
            self.swarm_tx.clone(),
        )
        .await
        {
            error!("Error handling response from peer {}: {}", peer, err);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;
    use crate::node::SwarmSend;
    use crate::node::messages::{InventoryMessage, Message};
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash as _;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;

    type TestChannel = oneshot::Sender<Message>;

    fn test_network_config() -> NetworkConfig {
        NetworkConfig {
            max_requests_per_second: 10,
            peer_inactivity_timeout_secs: 60,
            ..NetworkConfig::default()
        }
    }

    fn build_test_handler(
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<TestChannel>>,
    ) -> RequestResponseHandler<TestChannel> {
        let service = build_service::<TestChannel, _>(test_network_config(), swarm_tx.clone());
        RequestResponseHandler {
            request_service: service,
            chain_store_handle,
            swarm_tx,
        }
    }

    /// A service that never becomes ready, causing poll_ready to return
    /// Pending indefinitely. Used to test the timeout path in dispatch_request.
    struct NeverReadyService;

    impl<C, T> tower::Service<RequestContext<C, T>> for NeverReadyService {
        type Response = ();
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _request: RequestContext<C, T>) -> Self::Future {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn test_dispatch_response_share_headers() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();
        let share_headers = vec![block1.header.clone(), block2.header.clone()];

        let result = handler
            .dispatch_response(peer_id, Message::ShareHeaders(share_headers))
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_not_found() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();

        let result = handler
            .dispatch_response(peer_id, Message::NotFound(()))
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_inventory() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let block_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<BlockHash>()
                .unwrap(),
        ];
        let inventory = InventoryMessage::BlockHashes(block_hashes);

        let result = handler
            .dispatch_response(peer_id, Message::Inventory(inventory))
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_response_unexpected_message() {
        let (swarm_tx, _swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let result = handler
            .dispatch_response(
                peer_id,
                Message::GetData(crate::node::messages::GetData::Block(BlockHash::all_zeros())),
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatch_request_calls_service() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();

        let block1 = TestShareBlockBuilder::new().build();
        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash()];
        let stop_block_hash = block2.block_hash();

        chain_store_handle.expect_clone().returning(|| {
            let mut mock = ChainStoreHandle::default();
            let headers = vec![
                TestShareBlockBuilder::new().build().header,
                TestShareBlockBuilder::new().build().header,
            ];
            mock.expect_get_headers_for_locator()
                .returning(move |_, _, _| Ok(headers.clone()));
            mock
        });

        let mut handler = build_test_handler(chain_store_handle, swarm_tx);

        let peer_id = libp2p::PeerId::random();
        let (response_tx, _response_rx) = oneshot::channel::<Message>();

        let result = handler
            .dispatch_request(
                peer_id,
                Message::GetShareHeaders(block_hashes, stop_block_hash),
                response_tx,
            )
            .await;

        assert!(result.is_ok());

        // Verify the service produced a response on swarm_tx
        if let Some(SwarmSend::Response(_, Message::ShareHeaders(headers))) = swarm_rx.recv().await
        {
            assert_eq!(headers.len(), 2);
        } else {
            panic!("Expected SwarmSend::Response with ShareHeaders message");
        }
    }

    #[tokio::test]
    async fn test_dispatch_request_service_timeout_disconnects_peer() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel(32);
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        // Use a service that never becomes ready, guaranteeing the 1-second
        // timeout in dispatch_request fires and triggers a disconnect.
        let mut handler = RequestResponseHandler {
            request_service: BoxService::new(NeverReadyService),
            chain_store_handle,
            swarm_tx,
        };

        let peer_id = libp2p::PeerId::random();
        let (channel_tx, _channel_rx) = oneshot::channel::<Message>();

        let result = handler
            .dispatch_request(peer_id, Message::NotFound(()), channel_tx)
            .await;
        assert!(result.is_ok());

        // Verify that a Disconnect was sent for the peer
        let received = swarm_rx
            .try_recv()
            .expect("Expected a SwarmSend message after timeout");
        if let SwarmSend::Disconnect(disconnected_peer) = received {
            assert_eq!(
                disconnected_peer, peer_id,
                "Expected Disconnect for the correct peer"
            );
        } else {
            panic!("Expected SwarmSend::Disconnect, got {received:?}");
        }
    }
}
