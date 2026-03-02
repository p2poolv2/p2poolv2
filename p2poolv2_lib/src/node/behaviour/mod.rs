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

pub mod request_response;
use crate::config::Config;
use crate::node::messages::network_magic;
use libp2p::connection_limits;
use libp2p::request_response::ProtocolSupport;
use libp2p::{
    Multiaddr, PeerId, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
};
use request_response::{ConsensusCodec, P2PoolRequestResponseProtocol};
use request_response::{RequestResponseBehaviour, RequestResponseEvent};
use std::error::Error;
use void;

// Combine the behaviors we want to use
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PoolBehaviourEvent")]
pub struct P2PoolBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub request_response: RequestResponseBehaviour,
    pub limits: connection_limits::Behaviour,
}

/// The interval at which the node will send heartbeat messages to peers
#[allow(dead_code)]
const HEARTBEAT_INTERVAL: u64 = 15;

// Define the events that can be emitted by our behavior
#[derive(Debug)]
#[allow(dead_code)]
pub enum P2PoolBehaviourEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
    RequestResponse(RequestResponseEvent),
}

#[allow(dead_code)]
impl P2PoolBehaviour {
    pub fn new(local_key: &Keypair, config: &Config) -> Result<Self, Box<dyn Error>> {
        // Initialize Kademlia
        let store = MemoryStore::new(local_key.public().to_peer_id());
        let mut kad_config = kad::Config::default();
        kad_config.set_query_timeout(tokio::time::Duration::from_secs(60));
        kad_config.set_protocol_names(vec![libp2p::StreamProtocol::new("/p2pool/kad/1.0.0")]);

        let kademlia_behaviour =
            kad::Behaviour::with_config(local_key.public().to_peer_id(), store, kad_config);

        let identify_behaviour = identify::Behaviour::new(identify::Config::new(
            "/p2pool/1.0.0".to_string(),
            local_key.public(),
        ));

        let limits_config = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(config.network.max_pending_incoming))
            .with_max_pending_outgoing(Some(config.network.max_pending_outgoing))
            .with_max_established_incoming(Some(config.network.max_established_incoming))
            .with_max_established_outgoing(Some(config.network.max_established_outgoing))
            .with_max_established_per_peer(Some(config.network.max_established_per_peer));
        let limits = connection_limits::Behaviour::new(limits_config);

        // Select the appropriate network magic based on the bitcoin network
        let magic = match config.stratum.network {
            bitcoin::Network::Bitcoin => network_magic::MAINNET,
            bitcoin::Network::Testnet => network_magic::TESTNET,
            bitcoin::Network::Signet => network_magic::SIGNET,
            bitcoin::Network::Regtest => network_magic::REGTEST,
            _ => network_magic::REGTEST, // Default to regtest for unknown networks
        };

        let codec = ConsensusCodec::new(magic);

        let behaviour = P2PoolBehaviour {
            kademlia: kademlia_behaviour,
            identify: identify_behaviour,
            request_response: RequestResponseBehaviour::with_codec(
                codec,
                std::iter::once((P2PoolRequestResponseProtocol::new(), ProtocolSupport::Full)),
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
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        // Remove the peer from Kademlia's routing table
        self.kademlia.remove_peer(peer_id);
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

impl From<RequestResponseEvent> for P2PoolBehaviourEvent {
    fn from(event: RequestResponseEvent) -> Self {
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
