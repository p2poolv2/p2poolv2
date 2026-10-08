// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Off-driver worker that processes inbound P2P responses.
//!
//! Inbound responses can be heavy to process -- a `ShareHeaders` batch runs up
//! to `MAX_HEADERS_IN_RESPONSE` `organise_header` calls -- so the
//! request-response handler hands them here over a bounded channel rather than
//! running `handle_response` on the node's swarm-driver task. A single task
//! processing one response at a time preserves per-peer response order, which
//! matters because each `ShareHeaders` batch depends on the previous one.

use crate::node::SwarmSend;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::handle_response;
use crate::node::p2p_message_handlers::receivers::block_receiver::BlockReceiverHandle;
use crate::node::request_response_handler::block_fetcher::BlockFetcherHandle;
use crate::node::validation_worker::ValidationSender;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::validation::ShareValidator;
use libp2p::PeerId;
use libp2p::request_response::ResponseChannel;
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::error;

/// Channel capacity for inbound responses awaiting processing.
const RESPONSE_WORKER_CHANNEL_CAPACITY: usize = 1024;

/// An inbound response handed to the worker for processing.
pub struct ResponseWorkerEvent {
    pub peer: PeerId,
    pub response: Message,
}

/// Sender half of the response worker channel.
pub type ResponseWorkerSender = mpsc::Sender<ResponseWorkerEvent>;
/// Receiver half of the response worker channel.
pub type ResponseWorkerReceiver = mpsc::Receiver<ResponseWorkerEvent>;

/// Create a response worker channel with bounded capacity.
pub fn create_response_worker_channel() -> (ResponseWorkerSender, ResponseWorkerReceiver) {
    mpsc::channel(RESPONSE_WORKER_CHANNEL_CAPACITY)
}

/// Fatal error raised by the response worker.
#[derive(Debug)]
pub struct ResponseWorkerError {
    message: String,
}

impl fmt::Display for ResponseWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ResponseWorkerError: {}", self.message)
    }
}

impl std::error::Error for ResponseWorkerError {}

/// Processes inbound P2P responses off the swarm-driver task.
pub struct ResponseWorker {
    receiver: ResponseWorkerReceiver,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    block_fetcher_handle: BlockFetcherHandle,
    validation_tx: ValidationSender,
    block_receiver_handle: BlockReceiverHandle,
    share_validator: Arc<dyn ShareValidator + Send + Sync>,
}

impl ResponseWorker {
    #[allow(clippy::too_many_arguments)] // wiring constructor: each parameter is a distinct collaborator, a params struct would only move the list
    pub fn new(
        receiver: ResponseWorkerReceiver,
        chain_store_handle: ChainStoreHandle,
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
        block_receiver_handle: BlockReceiverHandle,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> Self {
        Self {
            receiver,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle,
            share_validator,
        }
    }

    /// Process responses until the channel closes.
    pub async fn run(mut self) -> Result<(), ResponseWorkerError> {
        while let Some(event) = self.receiver.recv().await {
            if let Err(error) = handle_response(
                event.peer,
                event.response,
                self.chain_store_handle.clone(),
                self.swarm_tx.clone(),
                self.block_fetcher_handle.clone(),
                self.validation_tx.clone(),
                self.block_receiver_handle.clone(),
                self.share_validator.clone(),
            )
            .await
            {
                error!("Error handling response from peer {}: {error}", event.peer);
            }
        }
        Ok(())
    }
}
