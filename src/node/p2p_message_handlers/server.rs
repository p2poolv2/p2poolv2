use std::pin::Pin;
use std::task::{Context, Poll};

use tower::Service;
use futures::Future;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;

use crate::node::messages::Message;
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::utils::time_provider::SystemTimeProvider;

use tokio::sync::mpsc;
use std::error::Error;
use std::sync::Arc;

/// The request type passed to the Tower service.
pub struct RequestContext {
    pub peer: PeerId,
    pub message: Message,
    pub channel: ResponseChannel<Message>,
    pub chain_handle: ChainHandle,
    pub swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
}

/// The Tower service for processing inbound P2P requests.
#[derive(Clone)]
pub struct P2PoolService {
    time_provider: Arc<SystemTimeProvider>,
}

impl P2PoolService {
    pub fn new() -> Self {
        Self {
            time_provider: Arc::new(SystemTimeProvider {}),
        }
    }
}

impl Service<RequestContext> for P2PoolService {
    type Response = ();
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Always ready to accept requests
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestContext) -> Self::Future {
        let time_provider = self.time_provider.clone();
        let RequestContext {
            peer,
            message,
            channel,
            chain_handle,
            swarm_tx,
        } = req;

        Box::pin(async move {
            crate::node::p2p_message_handlers::handle_request_with_service(
                peer,
                message,
                chain_handle,
                channel,
                swarm_tx,
                &*time_provider,
            )
            .await
            .map_err(|e| {
                tracing::error!("Service failed to process request: {}", e);
                e
            })
        })
    }
}
