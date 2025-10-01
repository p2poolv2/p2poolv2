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

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::accounting::stats::metrics::MetricsHandle;
use crate::command::Command;
use crate::config::Config;
use crate::node::Node;
use crate::node::SwarmSend;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::handle_stratum_shares::handle_stratum_shares;
use libp2p::futures::StreamExt;
use std::error::Error;
use std::sync::Arc;
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
        store: Arc<ChainStore>,
        shares_rx: tokio::sync::mpsc::Receiver<SimplePplnsShare>,
        metrics: MetricsHandle,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error + Send + Sync>> {
        let (command_tx, command_rx) = mpsc::channel::<Command>(32);
        let (node_actor, stopping_rx) = NodeActor::new(config, store.clone(), command_rx).unwrap();

        tokio::spawn(async move {
            node_actor.run().await;
        });

        tokio::spawn(async move {
            handle_stratum_shares(shares_rx, store, metrics).await;
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

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
use crate::node::messages::Message;

#[cfg(test)]
mock! {
    pub NodeHandle {
        pub async fn new(config: Config, store: std::sync::Arc<ChainStore>) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>>;
        pub async fn get_peers(&self) -> Result<Vec<libp2p::PeerId>, Box<dyn Error>>;
        pub async fn shutdown(&self) -> Result<(), Box<dyn Error>>;
        pub async fn send_gossip(&self, message: Message) -> Result<(), Box<dyn Error>>;
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
}

impl NodeActor {
    fn new(
        config: Config,
        store: Arc<ChainStore>,
        command_rx: mpsc::Receiver<Command>,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>> {
        let node = Node::new(&config, store)?;
        let (stopping_tx, stopping_rx) = oneshot::channel();
        Ok((
            Self {
                node,
                command_rx,
                stopping_tx,
            },
            stopping_rx,
        ))
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                buf = self.node.swarm_rx.recv() => {
                    match buf {
                        Some(SwarmSend::Request(peer_id, msg)) => {
                            let request_id =    self.node.swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
                            debug!("Sent message to peer: {peer_id}, request_id: {request_id}");
                        }
                        Some(SwarmSend::Response(response_channel, msg)) => {
                            let request_id = self.node.swarm.behaviour_mut().request_response.send_response(response_channel, msg);
                            debug!("Sent message to response channel: {:?}", request_id);
                        }
                        Some(SwarmSend::Inv(_share_block)) => {
                            // Handle inventory message (optional logging or processing)
                            tracing::info!("Received SwarmSend::Inv message");
                        }
                        Some(SwarmSend::Disconnect(peer_id)) => {
                            if let Err(_e) = self.node.swarm.disconnect_peer_id(peer_id) {
                                error!("Error disconnecting peer {peer_id}");
                            } else {
                                debug!("Disconnected peer: {peer_id}");
                            }
                        }
                        None => {
                            info!("Stopping node actor on channel close");
                            self.stopping_tx.send(()).unwrap();
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
                            let peers = self.node.swarm.connected_peers().cloned().collect::<Vec<_>>();
                            tx.send(peers).unwrap();
                        },
                        Some(Command::SendToPeer(peer_id, message, tx)) => {
                            match self.node.send_to_peer(peer_id, message) {
                                Ok(_) => tx.send(Ok(())).unwrap(),
                                Err(e) => {
                                    error!("Error sending message to peer: {}", e);
                                    tx.send(Err("Error sending message to peer".into())).unwrap()
                                },
                            };
                        },
                        Some(Command::Shutdown(tx)) => {
                            self.node.shutdown().unwrap();
                            tx.send(()).unwrap();
                            return;
                        },
                        Some(Command::GetPplnsShares(query, tx)) => {
                            info!("Received GetPplnsShares command with limit: {}", query.limit);
                            let result = self.node.handle_get_pplns_shares(query);
                            let _ = tx.send(result);
                        },
                        None => {
                            info!("Stopping node actor on channel close");
                            self.stopping_tx.send(()).unwrap();
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
