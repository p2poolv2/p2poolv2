use libp2p::futures::StreamExt;
use libp2p::{
    ping,
    swarm::SwarmEvent,
    Multiaddr,
    Swarm,
};
use tracing::{debug, info};
use std::time::Duration;
use crate::config::Config;

pub struct Node {
    swarm: Swarm<ping::Behaviour>,
}

impl Node {
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|_| ping::Behaviour::default())?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
            .build();

        // Listen on the configured address
        swarm.listen_on(config.network.listen_address.parse()?)?;

        // Dial configured peers
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
                SwarmEvent::Behaviour(event) => info!("{event:?}"),
                _ => {}
            }
        }
    }
} 