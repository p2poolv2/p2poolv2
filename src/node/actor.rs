// Copyright (C) 2024 [Kulpreet Singh]
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

use crate::command::Command;
use crate::config::Config;
use crate::node::Node;
use crate::node::SwarmSend;
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::miner_message::MinerWorkbase;
use crate::shares::ShareBlock;
use libp2p::futures::StreamExt;
use std::error::Error;
use tokio::{
    sync::{mpsc, oneshot},
    time::{interval, Duration},
};
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
        chain_handle: ChainHandle,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error + Send + Sync>> {
        let (command_tx, command_rx) = mpsc::channel::<Command>(32);
        let (node_actor, stopping_rx) = NodeActor::new(config, chain_handle, command_rx).unwrap();

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

    /// Add share to the chain
    pub async fn add_share(&self, share: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx.send(Command::AddShare(share, tx)).await?;
        match rx.await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Store workbase in the node's database
    pub async fn add_workbase(
        &self,
        workbase: MinerWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(Command::StoreWorkbase(workbase, tx))
            .await?;
        match rx.await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
use crate::node::messages::Message;

#[cfg(test)]
mock! {
    pub NodeHandle {
        pub async fn new(config: Config, chain_handle: ChainHandle) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>>;
        pub async fn get_peers(&self) -> Result<Vec<libp2p::PeerId>, Box<dyn Error>>;
        pub async fn shutdown(&self) -> Result<(), Box<dyn Error>>;
        pub async fn send_gossip(&self, message: Message) -> Result<(), Box<dyn Error>>;
        pub async fn send_to_peer(&self, peer_id: libp2p::PeerId, message: Message) -> Result<(), Box<dyn Error>>;
        pub async fn add_share(&self, share: ShareBlock) -> Result<(), Box<dyn Error>>;
        pub async fn add_workbase(&self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error>>;
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
        chain_handle: ChainHandle,
        command_rx: mpsc::Receiver<Command>,
    ) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>> {
        let node = Node::new(&config, chain_handle)?;
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
        let mut interval = interval(Duration::from_secs(
            self.node.config.network.rate_limit_window_secs,
        ));
        loop {
            tokio::select! {
                buf = self.node.swarm_rx.recv() => {
                    match buf {
                        Some(SwarmSend::Gossip(message)) => {
                            let buf = message.cbor_serialize().unwrap();
                            if let Err(e) = self.node.swarm.behaviour_mut().gossipsub.publish(self.node.share_topic.clone(), buf) {
                                error!("Error publishing share: {}", e);
                            }
                        }
                        Some(SwarmSend::Request(peer_id, msg)) => {
                            let request_id =    self.node.swarm.behaviour_mut().request_response.send_request(&peer_id, msg);
                            debug!("Sent message to peer: {peer_id}, request_id: {request_id}");
                        }
                        Some(SwarmSend::Response(response_channel, msg)) => {
                            let request_id = self.node.swarm.behaviour_mut().request_response.send_response(response_channel, msg);
                            debug!("Sent message to response channel: {:?}", request_id);
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
                        Some(Command::SendGossip(buf, tx)) => {
                            match self.node.swarm.behaviour_mut().gossipsub.publish(self.node.share_topic.clone(), buf) {
                                Err(e) => error!("Error publishing share: {}", e),
                                Ok(_) => tx.send(Ok(())).unwrap(),
                            }
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
                        Some(Command::AddShare(share, tx)) => {
                            match self.node.chain_handle.add_share(share).await {
                                Ok(_) => tx.send(Ok(())).unwrap(),
                                Err(e) => {
                                    error!("Error adding share to chain: {}", e);
                                    tx.send(Err("Error adding share to chain".into())).unwrap()
                                },
                            };
                        },
                        Some(Command::StoreWorkbase(workbase, tx)) => {
                            match self.node.chain_handle.add_workbase(workbase).await {
                                Ok(_) => tx.send(Ok(())).unwrap(),
                                Err(e) => {
                                    error!("Error storing workbase: {}", e);
                                    tx.send(Err("Error storing workbase".into())).unwrap()
                                },
                            };
                        },
                        None => {
                            info!("Stopping node actor on channel close");
                            self.stopping_tx.send(()).unwrap();
                            return;
                        }
                    }
                }
                _ = interval.tick() => {
                    self.node.rate_limiter.decay();
                }
            }
        }
    }
}
