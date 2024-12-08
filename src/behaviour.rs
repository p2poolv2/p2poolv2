use libp2p::{
    gossipsub,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    swarm::NetworkBehaviour,
    ping,
};
use std::error::Error;

// Combine the behaviors we want to use
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "P2PoolBehaviourEvent")]
pub struct P2PoolBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub ping: ping::Behaviour,
}

// Define the events that can be emitted by our behavior
#[derive(Debug)]
pub enum P2PoolBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Ping(ping::Event),
}

impl P2PoolBehaviour {
    pub fn new(
        local_key: &Keypair,
    ) -> Result<Self, Box<dyn Error>> {
        // Initialize gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .expect("Valid config");

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )?;

        // Initialize Kademlia
        let store = MemoryStore::new(local_key.public().to_peer_id());
        let kademlia = kad::Behaviour::new(
            local_key.public().to_peer_id(),
            store,
        );

        Ok(P2PoolBehaviour {
            gossipsub,
            kademlia,
            ping: libp2p::ping::Behaviour::default(),
        })
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

impl From<ping::Event> for P2PoolBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        P2PoolBehaviourEvent::Ping(event)
    }
}