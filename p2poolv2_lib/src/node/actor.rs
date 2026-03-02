// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::accounting::stats::metrics::MetricsHandle;
use crate::command::Command;
use crate::config::Config;
use crate::node::Node;
use crate::node::SwarmSend;
use crate::node::emission_worker::EmissionWorker;
use crate::node::messages::Message;
use crate::node::organise_worker::{OrganiseError, OrganiseSender};
use crate::node::organise_worker::{OrganiseWorker, create_organise_channel};
use crate::node::p2p_message_handlers::senders::send_block_inventory;
use crate::node::request_response_handler::block_fetcher::{
    BlockFetcher, BlockFetcherError, create_block_fetcher_channel,
};
use crate::node::validation_worker::{
    ValidationWorker, ValidationWorkerError, create_validation_channel,
};
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::stratum::emission::EmissionReceiver;
use libp2p::futures::StreamExt;
use std::error::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

/// NodeHandle provides an interface to interact with a Node running in a separate task
#[derive(Clone)]
#[allow(dead_code)]
pub struct NodeHandle {
    // The channel to send commands to the Node Actor
    command_tx: mpsc::Sender<Command>,
}

#[allow(dead_code)]
impl NodeHandle {
    /// Create a new Node and return a handle to interact with it
    pub async fn new(
        config: Config,
        chain_store_handle: ChainStoreHandle,
        emissions_rx: EmissionReceiver,
        metrics: MetricsHandle,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error + Send + Sync>> {
        let (command_tx, command_rx) = mpsc::channel::<Command>(32);
        let (node_actor, stopping_rx) = NodeActor::new(
            config,
            chain_store_handle,
            command_rx,
            emissions_rx,
            metrics,
        )
        .unwrap();

        tokio::spawn(async move {
            node_actor.run().await;
        });

        Ok((Self { command_tx }, stopping_rx))
    }

    /// Get a list of connected peers
    pub async fn get_peers(&self) -> Result<Vec<libp2p::PeerId>, Box<dyn Error + Send + Sync>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx.send(Command::GetPeers(tx)).await?;
        match rx.await {
            Ok(peers) => Ok(peers),
            Err(e) => Err(e.into()),
        }
    }

    /// Shutdown the node
    pub async fn shutdown(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx.send(Command::Shutdown(tx)).await?;
        match rx.await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Get PPLNS shares with filtering
    pub async fn get_pplns_shares(
        &self,
        query: crate::command::GetPplnsShareQuery,
    ) -> Vec<SimplePplnsShare> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .command_tx
            .send(Command::GetPplnsShares(query, tx))
            .await;
        rx.await.unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl NodeHandle {
    /// Create a stub NodeHandle for tests that responds to commands with defaults.
    pub fn new_for_test() -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<Command>(32);
        tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    Command::GetPeers(reply) => {
                        let _ = reply.send(Vec::new());
                    }
                    Command::Shutdown(reply) => {
                        let _ = reply.send(());
                        return;
                    }
                    Command::GetPplnsShares(_, reply) => {
                        let _ = reply.send(Vec::new());
                    }
                    Command::SendToPeer(_, _, reply) => {
                        let _ = reply.send(Ok(()));
                    }
                }
            }
        });
        Self { command_tx }
    }

    /// Create a stub NodeHandle for tests pre-loaded with a set of generated peers.
    ///
    /// Returns the handle and the string representations of the generated peer IDs
    /// so callers can assert on expected values without depending on libp2p directly.
    pub fn new_for_test_with_peer_count(count: usize) -> (Self, Vec<String>) {
        let peer_ids: Vec<libp2p::PeerId> = (0..count)
            .map(|_| {
                libp2p::identity::Keypair::generate_ed25519()
                    .public()
                    .to_peer_id()
            })
            .collect();
        let peer_id_strings: Vec<String> = peer_ids.iter().map(|id| id.to_string()).collect();
        let (command_tx, mut command_rx) = mpsc::channel::<Command>(32);
        tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    Command::GetPeers(reply) => {
                        let _ = reply.send(peer_ids.clone());
                    }
                    Command::Shutdown(reply) => {
                        let _ = reply.send(());
                        return;
                    }
                    Command::GetPplnsShares(_, reply) => {
                        let _ = reply.send(Vec::new());
                    }
                    Command::SendToPeer(_, _, reply) => {
                        let _ = reply.send(Ok(()));
                    }
                }
            }
        });
        (Self { command_tx }, peer_id_strings)
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub NodeHandle {
        pub async fn new(config: Config, chain_store_handle: ChainStoreHandle) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>>;
        pub async fn get_peers(&self) -> Result<Vec<libp2p::PeerId>, Box<dyn Error>>;
        pub async fn shutdown(&self) -> Result<(), Box<dyn Error>>;
        pub async fn send_to_peer(&self, peer_id: libp2p::PeerId, message: Message) -> Result<(), Box<dyn Error>>;
    }

    // Provide a clone implementation for NodeHandle mock double
    impl Clone for NodeHandle {
        fn clone(&self) -> Self {
            Self { command_tx: self.command_tx.clone() }
        }
    }
}

/// NodeActor runs the Node in a separate task and handles all its events
struct NodeActor {
    node: Node,
    command_rx: mpsc::Receiver<Command>,
    stopping_tx: oneshot::Sender<()>,
    emissions_rx: EmissionReceiver,
    chain_store_handle: ChainStoreHandle,
    #[allow(dead_code)]
    metrics: MetricsHandle,
    organise_tx: OrganiseSender,
    organise_handle: tokio::task::JoinHandle<Result<(), OrganiseError>>,
    block_fetcher_handle: tokio::task::JoinHandle<Result<(), BlockFetcherError>>,
    validation_handle: tokio::task::JoinHandle<Result<(), ValidationWorkerError>>,
}

impl NodeActor {
    fn new(
        config: Config,
        chain_store_handle: ChainStoreHandle,
        command_rx: mpsc::Receiver<Command>,
        emissions_rx: EmissionReceiver,
        metrics: MetricsHandle,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>> {
        // Create organise channel
        let (organise_tx, organise_rx) = create_organise_channel();

        // Create validation channel
        let (validation_tx, validation_rx) = create_validation_channel();

        // Create block fetcher channel
        let (block_fetcher_tx, block_fetcher_rx) = create_block_fetcher_channel();

        let node = Node::new(
            config,
            chain_store_handle.clone(),
            block_fetcher_tx,
            validation_tx,
        )?;

        // Spawn organise worker
        let organise_worker = OrganiseWorker::new(organise_rx, chain_store_handle.clone());
        let organise_handle = tokio::spawn(organise_worker.run());

        // Spawn validation worker
        let validation_worker = ValidationWorker::new(
            validation_rx,
            chain_store_handle.clone(),
            organise_tx.clone(),
            node.swarm_tx.clone(),
        );
        let validation_handle = tokio::spawn(validation_worker.run());

        // Spawn block fetcher
        let block_fetcher = BlockFetcher::new(block_fetcher_rx, node.swarm_tx.clone());
        let block_fetcher_handle = tokio::spawn(block_fetcher.run());

        let (stopping_tx, stopping_rx) = oneshot::channel();
        Ok((
            Self {
                node,
                command_rx,
                stopping_tx,
                emissions_rx,
                chain_store_handle,
                metrics,
                organise_tx,
                organise_handle,
                block_fetcher_handle,
                validation_handle,
            },
            stopping_rx,
        ))
    }

    async fn run(mut self) {
        // Spawn emission worker - processes shares in separate task and enqueues SwarmSend::Broadcast
        let emission_worker = EmissionWorker::new(
            self.emissions_rx,
            self.node.swarm_tx.clone(),
            self.chain_store_handle.clone(),
            self.node.config.stratum.network,
            self.organise_tx,
        );
        tokio::spawn(emission_worker.run());

        loop {
            tokio::select! {
                buf = self.node.swarm_rx.recv() => {
                    match buf {
                        Some(SwarmSend::Request(peer_id, msg)) => {
                            let request_id = self
                                .node
                                .swarm
                                .behaviour_mut()
                                .request_response
                                .send_request(&peer_id, msg);
                            debug!("Sent message to peer: {peer_id}, request_id: {request_id}");
                        }
                        Some(SwarmSend::Response(response_channel, msg)) => {
                            let request_id = self
                                .node
                                .swarm
                                .behaviour_mut()
                                .request_response
                                .send_response(response_channel, msg);
                            debug!("Sent message to response channel: {:?}", request_id);
                        }
                        Some(SwarmSend::Inv(block_hash)) => {
                            let connected_peers = self.node.connected_peers();
                            let peer_knowledge = self.node
                                .request_response_handler
                                .peer_block_knowledge();
                            if let Err(relay_error) = send_block_inventory(
                                block_hash,
                                None,
                                &connected_peers,
                                peer_knowledge,
                                self.node.swarm_tx.clone(),
                            )
                            .await
                            {
                                error!("Failed to relay inv for block {block_hash}: {relay_error}");
                            }
                        }
                        Some(SwarmSend::Disconnect(peer_id)) => {
                            if let Err(_e) = self.node.swarm.disconnect_peer_id(peer_id) {
                                error!("Error disconnecting peer {peer_id}");
                            } else {
                                debug!("Disconnected peer: {peer_id}");
                            }
                        }
                        Some(SwarmSend::Broadcast(share_block)) => {
                            // Broadcast share to all peers (from emission worker)
                            debug!("Broadcasting share to peers");
                            if let Err(e) = self
                                .node
                                .send_to_all_peers(Message::ShareBlock(share_block))
                            {
                                error!("Error sending share to all peers {e}");
                            }
                        }
                        None => {
                            info!("Stopping node actor on swarm channel close");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                    }
                },
                event = self.node.swarm.select_next_some() => {
                    if let Err(e) = self.node.handle_swarm_event(event).await {
                        error!("Error handling swarm event: {}", e);
                    }
                },
                command = self.command_rx.recv() => {
                    match command {
                        Some(Command::GetPeers(tx)) => {
                            let peers =
                                self.node.swarm.connected_peers().cloned().collect::<Vec<_>>();
                            if tx.send(peers).is_err() {
                                error!("Failed to send GetPeers response - receiver dropped");
                            }
                        },
                        Some(Command::SendToPeer(peer_id, message, tx)) => {
                            match self.node.send_to_peer(&peer_id, message) {
                                Ok(_) => {
                                    if tx.send(Ok(())).is_err() {
                                        error!(
                                            "Failed to send SendToPeer response - receiver dropped"
                                        );
                                    }
                                },
                                Err(e) => {
                                    error!("Error sending message to peer: {}", e);
                                    if tx.send(Err("Error sending message to peer".into())).is_err()
                                    {
                                        error!(
                                            "Failed to send SendToPeer error response - receiver dropped"
                                        );
                                    }
                                },
                            };
                        },
                        Some(Command::Shutdown(tx)) => {
                            self.node.shutdown().unwrap();
                            if tx.send(()).is_err() {
                                error!("Failed to send Shutdown response - receiver dropped");
                            }
                            return;
                        },
                        Some(Command::GetPplnsShares(query, tx)) => {
                            info!(
                                "Received GetPplnsShares command with limit: {}",
                                query.limit
                            );
                            let result = self.node.handle_get_pplns_shares(query);
                            if tx.send(result).is_err() {
                                error!("Failed to send GetPplnsShares response - receiver dropped");
                            }
                        },
                        None => {
                            info!("Stopping node actor on channel close");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                    }
                },
                organise_result = &mut self.organise_handle => {
                    match organise_result {
                        Ok(Err(e)) => {
                            error!("Organise worker fatal error: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                        Ok(Ok(())) => {
                            info!("Organise worker stopped cleanly");
                        }
                        Err(e) => {
                            error!("Organise worker panicked: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                    }
                }
                block_fetcher_result = &mut self.block_fetcher_handle => {
                    match block_fetcher_result {
                        Ok(Err(e)) => {
                            error!("Block fetcher fatal error: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                        Ok(Ok(())) => {
                            info!("Block fetcher stopped cleanly");
                        }
                        Err(e) => {
                            error!("Block fetcher panicked: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                    }
                }
                validation_result = &mut self.validation_handle => {
                    match validation_result {
                        Ok(Err(e)) => {
                            error!("Validation worker fatal error: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                        Ok(Ok(())) => {
                            info!("Validation worker stopped cleanly");
                        }
                        Err(e) => {
                            error!("Validation worker panicked: {e}");
                            if self.stopping_tx.send(()).is_err() {
                                error!("Failed to send stopping signal - receiver dropped");
                            }
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::command::GetPplnsShareQuery;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_node_handle_get_pplns_shares_sends_correct_command() {
        let (command_tx, mut command_rx) = mpsc::channel(32);
        let node_handle = NodeHandle { command_tx };

        let query = GetPplnsShareQuery {
            limit: 42,
            start_time: Some(1000),
            end_time: Some(2000),
        };

        // Spawn the get_pplns_shares call in a separate task
        let query_clone = query.clone();
        let handle = tokio::spawn(async move { node_handle.get_pplns_shares(query_clone).await });

        // Verify the correct command was sent
        if let Some(Command::GetPplnsShares(received_query, tx)) = command_rx.recv().await {
            assert_eq!(received_query.limit, query.limit);
            assert_eq!(received_query.start_time, query.start_time);
            assert_eq!(received_query.end_time, query.end_time);

            // Send back a test response
            let test_shares = vec![SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1500,
                "job1".to_string(),
                "extra1".to_string(),
                "nonce1".to_string(),
            )];
            let _ = tx.send(test_shares);
        } else {
            panic!("Expected GetPplnsShares command");
        }

        // Verify the result is returned correctly
        let shares = handle.await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].n_time, 1500);
    }

    #[tokio::test]
    async fn test_node_handle_get_pplns_shares_channel_send_error() {
        // Create a channel with buffer size 0 and close the receiver
        let (command_tx, command_rx) = mpsc::channel(1);
        drop(command_rx); // Close the receiver to cause send error

        let node_handle = NodeHandle { command_tx };

        let query = GetPplnsShareQuery {
            limit: 10,
            start_time: None,
            end_time: None,
        };

        let result = node_handle.get_pplns_shares(query).await;
        assert_eq!(result.len(), 0);
    }
}
