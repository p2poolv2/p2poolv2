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
pub mod gossip_handler;
pub mod messages;
pub mod p2p_message_handlers;
pub mod rate_limiter;

use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::senders::{send_blocks_inventory, send_getheaders};
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::receive_mining_message::start_receiving_mining_messages;
use behaviour::{P2PoolBehaviour, P2PoolBehaviourEvent};
use gossip_handler::handle_gossipsub_event;
use libp2p::identify;
use libp2p::mdns::Event as MdnsEvent;
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;
use libp2p::{
    gossipsub,
    kad::{Event as KademliaEvent, QueryResult},
    swarm::SwarmEvent,
    Multiaddr, Swarm,
};
use rate_limiter::RateLimiter;
use request_response_handler::handle_request_response_event;
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use std::sync::{Arc, Mutex};

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
pub enum SwarmSend<C> {
    Gossip(Message),
    Request(PeerId, Message),
    Response(C, Message),
    Disconnect(PeerId),
}

/// Node is the main struct that represents the node
struct Node {
    swarm: Swarm<P2PoolBehaviour>,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    swarm_rx: mpsc::Receiver<SwarmSend<ResponseChannel<Message>>>,
    share_topic: gossipsub::IdentTopic,
    chain_handle: ChainHandle,
    rate_limiter: RateLimiter,
    config: Config,
    last_share_time: Arc<Mutex<HashMap<PeerId, Instant>>>,
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

        let share_topic = gossipsub::IdentTopic::new("share");
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&share_topic) {
            error!("Failed to subscribe to share topic: {}", e);
        }

        let (swarm_tx, swarm_rx) = mpsc::channel(100);

        if let Err(e) =
            start_receiving_mining_messages(config, chain_handle.clone(), swarm_tx.clone())
        {
            error!("Failed to start receiving shares: {}", e);
            return Err(e);
        }

        let rate_limiter =
            RateLimiter::new(Duration::from_secs(config.network.rate_limit_window_secs));

        let last_share_clone = last_share_time.clone();
        let swarm_tx_clone = swarm_tx.clone();
        let inactivity_timeout = config.network.inactive_peer_timeout;
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(86400)).await; // Daily check
                let mut times = last_share_clone.lock().unwrap();
                let now = Instant::now();
                
                let mut to_disconnect = Vec::new();
                times.retain(|peer_id, last_seen| {
                    if now.duration_since(*last_seen) > inactivity_timeout {
                        to_disconnect.push(*peer_id);
                        false
                    } else {
                        true
                    }
                });
                
                for peer_id in to_disconnect {
                    if let Err(e) = swarm_tx_clone.send(SwarmSend::Disconnect(peer_id)).await {
                        error!("Failed to queue disconnect for {}: {}", peer_id, e);
                    }
                }
            }
        });    

        Ok(Self {
            swarm,
            swarm_tx,
            swarm_rx,
            share_topic,
            chain_handle,
            rate_limiter,
            config: config.clone(),
            last_share_time: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }
                cmd = self.swarm_rx.recv() => {
                    match cmd {
                        Some(SwarmSend::Disconnect(peer_id)) => {
                            self.swarm.disconnect_peer_id(peer_id)?;
                            info!("Disconnected inactive peer: {}", peer_id);
                        }
                        Some(SwarmSend::Gossip(message)) => {
                            let data = message.cbor_serialize()?;
                            self.swarm.behaviour_mut().gossipsub.publish(
                                self.share_topic.clone(),
                                data
                            )?;
                        }
                        Some(SwarmSend::Request(peer_id, message)) => {
                            self.send_to_peer(peer_id, message)?;
                        }
                        Some(SwarmSend::Response(channel, message)) => {
                            self.swarm.behaviour_mut().request_response.send_response(
                                channel,
                                message.cbor_serialize()?
                            )?;
                        }
                        None => break,
                    }
                }
            }
        }
        Ok(())
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
                P2PoolBehaviourEvent::Mdns(mdns_event) => {
                    self.handle_mdns_event(mdns_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::Identify(identify_event) => {
                    self.handle_identify_event(identify_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::Kademlia(kad_event) => {
                    self.handle_kademlia_event(kad_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::Gossipsub(gossip_event) => {
                    self.handle_gossipsub_event(gossip_event).await
                }
                P2PoolBehaviourEvent::RequestResponse(request_response_event) => {
                    self.handle_request_response_event(request_response_event)
                        .await
                }
            },
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {peer_id}");
                self.swarm.behaviour_mut().remove_peer(&peer_id);
                let mut times = self.last_share_time.lock().unwrap();
                times.remove(&peer_id);
                Ok(())
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
                        .add_address(peer_id, addr.clone());
                }
            }
            _ => {
                debug!("Other identify event: {:?}", event);
            }
        }
    }

    /// Handle mdns events, these are events that are generated by the mdns protocol
    fn handle_mdns_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(discovered) => {
                info!("Discovered peer: {:?}", discovered);
                for (peer_id, addr) in discovered {
                    // Check if we're not already connected to this peer
                    if !self.swarm.is_connected(&peer_id) {
                        // Try to dial the discovered peer
                        match self.swarm.dial(addr.clone()) {
                            Ok(_) => {
                                // Add the peer's address to Kademlia
                                self.swarm.behaviour_mut().add_address(peer_id, addr);
                            }
                            Err(e) => debug!("Failed to dial discovered peer {}: {}", peer_id, e),
                        }
                    }
                }
            }
            _ => debug!("Other Mdns event: {:?}", event),
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
                    debug!("Failed to get closest peers: {err}");
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

    /// Handle gossipsub events from the libp2p network
    async fn handle_gossipsub_event(
        &mut self,
        gossip_event: gossipsub::Event,
    ) -> Result<(), Box<dyn Error>> {
        if let gossipsub::Event::Message {
            propagation_source,
            message_id: _,
            message,
        } = &gossip_event
        {
            match Message::cbor_deserialize(&message.data) {
                Ok(deserialized_msg) => {
                    if let Message::MiningShare(_) = deserialized_msg {
                        let mut times = self.last_share_times.lock().unwrap();
                        times.insert(*propagation_source, Instant::now());
                    }
                    let message_type = Message::from(deserialized_msg);
                    if !self
                        .rate_limiter
                        .check_rate_limit(
                            &propagation_source,
                            message_type.clone(),
                            &self.config.network,
                        )
                        .await
                    {
                        warn!(
                        "Rate limit exceeded for peer {} with message type {:?}. Disconnecting.",
                        propagation_source, message_type
                    );
                        self.swarm
                            .disconnect_peer_id(*propagation_source)
                            .unwrap_or_else(|e| {
                                error!("Failed to disconnect rate-limited peer: {:?}", e);
                            });
                        return Ok(());
                    }

                    let chain_handle = self.chain_handle.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_gossipsub_event(gossip_event, chain_handle).await {
                            error!("Failed to handle gossipsub event: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!(
                        "Failed to deserialize gossip message from {}: {}",
                        propagation_source, e
                    );
                    return Err("Failed to deserialize message".into());
                }
            }
        }
        Ok(())
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
                    channel: _,
                },
        } = &request_response_event
        {
            let message = Message::from(request.clone());
            if !self
                .rate_limiter
                .check_rate_limit(&peer, message.clone(), &self.config.network)
                .await
            {
                warn!(
                    "Rate limit exceeded for peer {} with message type {:?}. Disconnecting.",
                    peer, message
                );
                self.swarm.disconnect_peer_id(*peer).unwrap_or_else(|e| {
                    error!("Failed to disconnect rate-limited peer: {:?}", e);
                });
                return Ok(());
            }

            let chain_handle = self.chain_handle.clone();
            let swarm_tx = self.swarm_tx.clone();
            let event_clone = request_response_event;
            tokio::spawn(async move {
                if let Err(e) =
                    handle_request_response_event(event_clone, chain_handle, swarm_tx).await
                {
                    error!("Failed to handle request-response event: {}", e);
                }
            });
        }
        Ok(())
    }
}
