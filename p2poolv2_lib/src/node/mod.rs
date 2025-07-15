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

pub mod behaviour;
pub mod request_response_handler;
pub use crate::config::Config;
pub mod actor;
pub mod messages;
pub mod p2p_message_handlers;

use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::senders::{send_blocks_inventory, send_getheaders};
use crate::service::build_service;
use crate::service::p2p_service::RequestContext;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
#[cfg(not(test))]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::receive_mining_message::start_receiving_mining_messages;
use crate::shares::ShareBlock;
use crate::utils::time_provider::SystemTimeProvider;
use behaviour::{P2PoolBehaviour, P2PoolBehaviourEvent};
use libp2p::identify;
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use libp2p::{
    kad::{Event as KademliaEvent, QueryResult},
    swarm::SwarmEvent,
    Multiaddr, Swarm,
};
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tower::{util::BoxService, Service, ServiceExt};
use tracing::{debug, error, info, warn};

pub struct SwarmResponseChannel<T> {
    channel: ResponseChannel<T>,
}

#[allow(dead_code)]
pub trait SwarmResponseChannelTrait<T> {
    fn new(channel: ResponseChannel<T>) -> Self;
    fn channel(&self) -> &ResponseChannel<T>;
}

impl<T> SwarmResponseChannelTrait<T> for SwarmResponseChannel<T> {
    fn new(channel: ResponseChannel<T>) -> Self {
        Self { channel }
    }
    fn channel(&self) -> &ResponseChannel<T> {
        &self.channel
    }
}

/// Capture send type for swarm p2p messages that can be sent to the swarm
#[allow(dead_code)]
#[derive(Debug)]
pub enum SwarmSend<C> {
    Request(PeerId, Message),
    Response(C, Message),
    Inv(ShareBlock),
    Disconnect(PeerId),
}

/// Node is the main struct that represents the node
struct Node {
    swarm: Swarm<P2PoolBehaviour>,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    swarm_rx: mpsc::Receiver<SwarmSend<ResponseChannel<Message>>>,
    chain_handle: ChainHandle,
    config: Config,
    service: BoxService<
        RequestContext<ResponseChannel<Message>, SystemTimeProvider>,
        (),
        Box<dyn Error + Send + Sync>,
    >,
}

impl Node {
    pub fn new(
        config: &Config,
        chain_handle: ChainHandle,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let id_keys = libp2p::identity::Keypair::generate_ed25519();

        let behavior = match P2PoolBehaviour::new(&id_keys, config) {
            Ok(behavior) => behavior,
            Err(err) => {
                error!("Failed to create P2PoolBehaviour: {}", err);
                std::process::exit(1);
            }
        };

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|_| behavior)?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
            })
            .build();

        match config.network.listen_address.parse() {
            Ok(addr) => match swarm.listen_on(addr) {
                Ok(_) => {
                    info!("Node listening on {}", config.network.listen_address);
                }
                Err(e) => {
                    error!(
                        "Failed to listen on {}: {}",
                        config.network.listen_address, e
                    );
                    return Err(format!(
                        "Failed to listen on {}: {}",
                        config.network.listen_address, e
                    )
                    .into());
                }
            },
            Err(e) => {
                error!(
                    "Invalid listen address {}: {}",
                    config.network.listen_address, e
                );
                return Err(format!(
                    "Invalid listen address {}: {}",
                    config.network.listen_address, e
                )
                .into());
            }
        }

        for peer_addr in &config.network.dial_peers {
            match peer_addr.parse::<Multiaddr>() {
                Ok(remote) => {
                    if let Err(e) = swarm.dial(remote) {
                        debug!("Failed to dial {}: {}", peer_addr, e);
                    } else {
                        info!("Dialed {}", peer_addr);
                    }
                }
                Err(e) => debug!("Invalid multiaddr {}: {}", peer_addr, e),
            }
        }

        let (swarm_tx, swarm_rx) = mpsc::channel(100);

        if let Err(e) =
            start_receiving_mining_messages(config, chain_handle.clone(), swarm_tx.clone())
        {
            error!("Failed to start receiving shares: {}", e);
            return Err(e);
        }

        // Initialize the service field before constructing the Node
        let service =
            build_service::<ResponseChannel<Message>, _>(config.network.clone(), swarm_tx.clone());

        Ok(Self {
            swarm,
            swarm_tx,
            swarm_rx,
            chain_handle,
            config: config.clone(),
            service,
        })
    }

    /// Returns a Vec of peer IDs that are currently connected to this node
    #[allow(dead_code)]
    pub fn connected_peers(&self) -> Vec<libp2p::PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        for peer_id in self.swarm.connected_peers().cloned().collect::<Vec<_>>() {
            self.swarm.disconnect_peer_id(peer_id).unwrap_or_default();
        }
        Ok(())
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(
        &mut self,
        peer_id: libp2p::PeerId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        info!("Sending message to peer: {peer_id}, message: {message:?}");
        self.swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, message);
        Ok(())
    }

    /// Handle swarm events, these are events that are generated by the libp2p library
    pub async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<P2PoolBehaviourEvent>,
    ) -> Result<(), Box<dyn Error>> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address:?}");
                Ok(())
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                match endpoint {
                    libp2p::core::ConnectedPoint::Dialer { .. } => {
                        if let Err(e) = send_getheaders(
                            peer_id,
                            self.chain_handle.clone(),
                            self.swarm_tx.clone(),
                        )
                        .await
                        {
                            error!(
                                "Failed to handle outbound connection to peer {}: {}",
                                peer_id, e
                            );
                        } else {
                            info!("Outbound connection established to peer: {}", peer_id);
                        }
                    }
                    libp2p::core::ConnectedPoint::Listener { .. } => {
                        info!("Inbound connection established from peer: {peer_id}");
                    }
                }
                Ok(())
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {peer_id}");
                self.swarm.behaviour_mut().remove_peer(&peer_id);
                Ok(())
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id,
                error,
                connection_id,
            } => {
                error!("Failed to connect to peer: {peer_id:?}, error: {error}, connection_id: {connection_id}");
                Ok(())
            }
            SwarmEvent::Behaviour(event) => match event {
                P2PoolBehaviourEvent::Identify(identify_event) => {
                    self.handle_identify_event(identify_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::Kademlia(kad_event) => {
                    self.handle_kademlia_event(kad_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::RequestResponse(request_response_event) => {
                    self.handle_request_response_event(request_response_event)
                        .await
                }
            },
            _ => Ok(()),
        }
    }

    /// Handle identify events, these are events that are generated by the identify protocol
    fn handle_identify_event(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info } => {
                info!(
                    "Identified Peer {} with protocol version {}",
                    peer_id, info.protocol_version
                );
                // Add the peer's advertised addresses to Kademlia
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                // Also add our observed address to Kademlia so other peers can reach us
                info!("Peer {} observed us as {}", peer_id, info.observed_addr);
                self.swarm.add_external_address(info.observed_addr);
                if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                    warn!("Failed to bootstrap Kademlia: {}", e);
                } else {
                    info!("Successfully started Kademlia bootstrap");
                }
            }
            _ => {
                debug!("Other identify event: {:?}", event);
            }
        }
    }

    /// Handle kademlia events, these are events that are generated by the kademlia protocol
    fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        match event {
            KademliaEvent::RoutingUpdated {
                peer,
                is_new_peer,
                addresses,
                bucket_range,
                old_peer,
            } => {
                info!("Routing updated for peer: {peer}, is_new_peer: {is_new_peer}, addresses: {addresses:?}, bucket_range: {bucket_range:?}, old_peer: {old_peer:?}");
            }
            KademliaEvent::OutboundQueryProgressed { result, .. } => match result {
                QueryResult::GetClosestPeers(Ok(ok)) => {
                    debug!("Got closest peers: {:?}", ok.peers);
                }
                QueryResult::GetClosestPeers(Err(err)) => {
                    error!("Failed to get closest peers: {err}");
                }
                _ => debug!("Other query result: {:?}", result),
            },
            _ => debug!("Other Kademlia event: {:?}", event),
        }
    }

    /// Handle connection established events, these are events that are generated when a connection is established
    async fn handle_connection_established(&mut self, peer_id: libp2p::PeerId) {
        info!("Connection established with peer: {peer_id}");
        let _ = send_blocks_inventory::<ResponseChannel<Message>>(
            peer_id,
            self.chain_handle.clone(),
            self.swarm_tx.clone(),
        )
        .await;
    }

    /// Handle request-response events from the libp2p network
    async fn handle_request_response_event(
        &mut self,
        request_response_event: RequestResponseEvent<Message, Message>,
    ) -> Result<(), Box<dyn Error>> {
        if let RequestResponseEvent::Message {
            peer,
            message:
                libp2p::request_response::Message::Request {
                    request_id: _,
                    request,
                    channel,
                },
        } = request_response_event
        {
            // Create the RequestContext
            let ctx = RequestContext::<ResponseChannel<Message>, _> {
                peer,
                request: request.clone(),
                chain_handle: self.chain_handle.clone(),
                response_channel: channel,
                swarm_tx: self.swarm_tx.clone(),
                time_provider: SystemTimeProvider,
            };

            // Check readiness with a timeout
            match tokio::time::timeout(Duration::from_secs(1), self.service.ready()).await {
                Ok(Ok(_)) => {
                    // Service is ready, call it
                    if let Err(err) = self.service.call(ctx).await {
                        error!("Service call failed for peer {}: {}", peer, err);
                    }
                }
                Ok(Err(err)) => {
                    // Service failed permanently
                    error!("Service not ready for peer {}: {}", peer, err);
                    if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await {
                        error!(
                            "Failed to send disconnect command for peer {}: {:?}",
                            peer, send_err
                        );
                    }
                }

                Err(_) => {
                    // Timeout due to rate limit or other delay
                    error!("Service readiness timed out for peer {}", peer);
                    if let Err(send_err) = self.swarm_tx.send(SwarmSend::Disconnect(peer)).await {
                        error!(
                            "Failed to send disconnect command for peer {}: {:?}",
                            peer, send_err
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
