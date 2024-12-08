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

use futures::StreamExt;
use libp2p::{
    swarm::SwarmEvent,
    Multiaddr,
    Swarm,
};
use tracing::{debug, info, error};
use std::time::Duration;
use crate::config::Config;
use crate::behaviour::{P2PoolBehaviour, P2PoolBehaviourEvent};

pub struct Node {
    swarm: Swarm<P2PoolBehaviour>,
}

impl Node {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let id_keys = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = id_keys.public().to_peer_id();

        let behavior = match P2PoolBehaviour::new(&id_keys) {
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
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
            .build();

        swarm.listen_on(config.network.listen_address.parse()?)?;

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

        Ok(Self { swarm })
    }

    pub async fn run(&mut self) {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {address:?}"),
                SwarmEvent::Behaviour(event) => {
                    match event {
                        P2PoolBehaviourEvent::Gossipsub(gossip_event) => {
                            debug!("Gossipsub event: {:?}", gossip_event);
                        },
                        P2PoolBehaviourEvent::Kademlia(kad_event) => {
                            debug!("Kademlia event: {:?}", kad_event);
                        },
                        P2PoolBehaviourEvent::Ping(ping_event) => {
                            debug!("Ping event: {:?}", ping_event);
                        },
                    }
                },
                _ => {}
            }
        }
    }
} 