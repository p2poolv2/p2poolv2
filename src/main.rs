use clap::Parser;
use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::{ping, Multiaddr};
use serde::Deserialize;
use std::error::Error;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use tracing::{debug, info};

#[derive(Debug, Deserialize)]
struct NetworkConfig {
    listen_address: String,
    dial_peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Config {
    network: NetworkConfig,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

impl Config {
    fn load(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()?
            .try_deserialize()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse command line arguments
    let args = Args::parse();
    debug!("Parsed args: {:?}", args);

    // Load configuration
    let config = Config::load(&args.config)?;

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new, // Use the XX pattern as we don't need know the peer's identity
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

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {address:?}"),
            SwarmEvent::Behaviour(event) => info!("{event:?}"),
            _ => {}
        }
    }
}
