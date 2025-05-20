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

pub mod request_response;
use crate::config::Config;
use crate::node::messages::Message;
use libp2p::connection_limits;
use libp2p::request_response::ProtocolSupport;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    gossipsub, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    mdns::{tokio::Behaviour as MdnsTokio, Config as MdnsConfig, Event as MdnsEvent},
    swarm::NetworkBehaviour,
    Multiaddr, PeerId,
};
use request_response::P2PoolRequestResponseProtocol;
use request_response::{RequestResponseBehaviour, RequestResponseEvent};
use std::error::Error;
use void;

// Combine the behaviors we want to use
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PoolBehaviourEvent")]
pub struct P2PoolBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub mdns: Toggle<MdnsTokio>,
    pub request_response: RequestResponseBehaviour<Message, Message>,
    pub limits: connection_limits::Behaviour,
}

/// The interval at which the node will send heartbeat messages to peers
#[allow(dead_code)]
const HEARTBEAT_INTERVAL: u64 = 15;

// Define the events that can be emitted by our behavior
#[derive(Debug)]
#[allow(dead_code)]

pub enum P2PoolBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
    Mdns(MdnsEvent),
    RequestResponse(RequestResponseEvent<Message, Message>),
}

#[allow(dead_code)]

impl P2PoolBehaviour {
    pub fn new(local_key: &Keypair, config: &Config) -> Result<Self, Box<dyn Error>> {
        // Initialize gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(HEARTBEAT_INTERVAL))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .expect("Valid config");

        let gossipsub_behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;

        // Initialize Kademlia
        let store = MemoryStore::new(local_key.public().to_peer_id());
        let mut kad_config = kad::Config::default();
        kad_config.set_query_timeout(tokio::time::Duration::from_secs(60));

        let kademlia_behaviour =
            kad::Behaviour::with_config(local_key.public().to_peer_id(), store, kad_config);

        let identify_behaviour = identify::Behaviour::new(identify::Config::new(
            "/p2pool/1.0.0".to_string(),
            local_key.public(),
        ));

        // Initialize MDNS only if enabled in config
        let mdns_behaviour = if config.network.enable_mdns {
            Toggle::from(Some(MdnsTokio::new(
                MdnsConfig::default(),
                local_key.public().to_peer_id(),
            )?))
        } else {
            Toggle::from(None)
        };

        let limits_config = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(config.network.max_pending_incoming))
            .with_max_pending_outgoing(Some(config.network.max_pending_outgoing))
            .with_max_established_incoming(Some(config.network.max_established_incoming))
            .with_max_established_outgoing(Some(config.network.max_established_outgoing))
            .with_max_established_per_peer(Some(config.network.max_established_per_peer));
        let limits = connection_limits::Behaviour::new(limits_config);

        let behaviour = P2PoolBehaviour {
            gossipsub: gossipsub_behaviour,
            kademlia: kademlia_behaviour,
            identify: identify_behaviour,
            mdns: mdns_behaviour,
            request_response: RequestResponseBehaviour::new(
                [(P2PoolRequestResponseProtocol::new(), ProtocolSupport::Full)],
                libp2p::request_response::Config::default(),
            ),
            limits,
        };

        Ok(behaviour)
    }

    /// Add a peer's address to Kademlia's routing table and get the closest peers so the peer availablility propagates across the network
    pub fn add_address(&mut self, peer_id: PeerId, addr: Multiaddr) {
        // Add the peer's address to Kademlia's routing table
        self.kademlia.add_address(&peer_id, addr);
        // Get the closest peers so the peer availablility propagates across the network
        self.kademlia.get_closest_peers(peer_id);
        self.gossipsub.add_explicit_peer(&peer_id);
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        // Remove the peer from Kademlia's routing table
        self.kademlia.remove_peer(peer_id);
    }
}

impl From<gossipsub::Event> for P2PoolBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        P2PoolBehaviourEvent::Gossipsub(event)
    }
}

impl From<kad::Event> for P2PoolBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        P2PoolBehaviourEvent::Kademlia(event)
    }
}

impl From<identify::Event> for P2PoolBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        P2PoolBehaviourEvent::Identify(event)
    }
}

impl From<MdnsEvent> for P2PoolBehaviourEvent {
    fn from(event: MdnsEvent) -> Self {
        P2PoolBehaviourEvent::Mdns(event)
    }
}

impl From<RequestResponseEvent<Message, Message>> for P2PoolBehaviourEvent {
    fn from(event: RequestResponseEvent<Message, Message>) -> Self {
        P2PoolBehaviourEvent::RequestResponse(event)
    }
}

// Provide From for the void (unreachable) type for connection_limits behaviour
impl From<void::Void> for P2PoolBehaviourEvent {
    fn from(void: void::Void) -> Self {
        // Since void::Void is uninhabited (can never be constructed),
        // we can safely make this unreachable
        match void {}
    }
}
