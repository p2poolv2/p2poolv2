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

pub mod behaviour;
pub mod request_response_handler;
pub use crate::config::Config;
pub mod actor;
pub mod messages;
pub mod p2p_message_handlers;

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::node::behaviour::request_response::RequestResponseEvent;
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::senders::{send_blocks_inventory, send_getheaders};
use crate::service::build_service;
use crate::service::p2p_service::RequestContext;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::share_block::ShareBlock;
use crate::utils::time_provider::SystemTimeProvider;
use behaviour::{P2PoolBehaviour, P2PoolBehaviourEvent};
use libp2p::PeerId;
use libp2p::SwarmBuilder;
use libp2p::core::transport::Transport;
use libp2p::identify;
use libp2p::request_response::ResponseChannel;
use libp2p::tcp::Config as TcpConfig;
use libp2p::{
    Multiaddr, Swarm,
    kad::{Event as KademliaEvent, QueryResult},
    swarm::SwarmEvent,
};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tower::{Service, ServiceExt, util::BoxService};
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
    chain_store: Arc<ChainStore>,
    service: BoxService<
        RequestContext<ResponseChannel<Message>, SystemTimeProvider>,
        (),
        Box<dyn Error + Send + Sync>,
    >,
}

impl Node {
    pub fn new(
        config: &Config,
        chain_store: Arc<ChainStore>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let id_keys = libp2p::identity::Keypair::generate_ed25519();

        let behavior = match P2PoolBehaviour::new(&id_keys, config) {
            Ok(behavior) => behavior,
            Err(err) => {
                error!("Failed to create P2PoolBehaviour: {}", err);
                std::process::exit(1);
            }
        };

        let dial_timeout_secs = config.network.dial_timeout_secs;

        let tcp_config = TcpConfig::default().nodelay(true);
        let noise_config = match libp2p::noise::Config::new(&id_keys) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!("Failed to create Noise config: {}", err);
                return Err(Box::new(err));
            }
        };

        let transport = libp2p::tcp::Transport::<libp2p::tcp::tokio::Tcp>::new(tcp_config.clone())
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise_config)
            .multiplex(libp2p::yamux::Config::default())
            .timeout(Duration::from_secs(dial_timeout_secs))
            .boxed();

        let mut swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_other_transport(|_| transport)?
            .with_behaviour(|_| behavior)?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
            })
            .build();

        if !config.network.listen_address.is_empty() {
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
        }

        let (swarm_tx, swarm_rx) = mpsc::channel(100);

        // Initialize the service field before constructing the Node
        let service =
            build_service::<ResponseChannel<Message>, _>(config.network.clone(), swarm_tx.clone());

        Ok(Self {
            swarm,
            swarm_tx,
            swarm_rx,
            chain_store,
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

    /// Send Message to all peers
    pub fn send_to_all_peers(&mut self, message: Message) -> Result<(), Box<dyn Error>> {
        debug!("Sending message to all peers");
        let peer_ids: Vec<_> = self.swarm.connected_peers().cloned().collect();
        for peer_id in peer_ids {
            self.send_to_peer(&peer_id, message.clone())?;
        }
        Ok(())
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(
        &mut self,
        peer_id: &libp2p::PeerId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        info!("Sending message to peer: {peer_id}, message: {message:?}");
        self.swarm
            .behaviour_mut()
            .request_response
            .send_request(peer_id, message);
        Ok(())
    }

    /// Handle the command to get pplns shares from store
    pub fn handle_get_pplns_shares(
        &self,
        query: crate::command::GetPplnsShareQuery,
    ) -> Vec<SimplePplnsShare> {
        self.chain_store.get_pplns_shares_filtered(
            Some(query.limit),
            query.start_time,
            query.end_time,
        )
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
                            self.chain_store.clone(),
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
                error!(
                    "Failed to connect to peer: {peer_id:?}, error: {error}, connection_id: {connection_id}"
                );
                error!(
                    "Failed to connect to peer: {peer_id:?}, error: {error}, connection_id: {connection_id}"
                );
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
                info!(
                    "Routing updated for peer: {peer}, is_new_peer: {is_new_peer}, addresses: {addresses:?}, bucket_range: {bucket_range:?}, old_peer: {old_peer:?}"
                );
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
            self.chain_store.clone(),
            self.swarm_tx.clone(),
        )
        .await;
    }

    /// Handle request-response events from the libp2p network
    async fn handle_request_response_event(
        &mut self,
        request_response_event: RequestResponseEvent,
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
                store: self.chain_store.clone(),
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

/// This test verifies that dialing an unreachable peer does not hang indefinitely,
/// and that the libp2p Swarm emits a connection error within a reasonable timeout.
///
/// How it works:
/// - We configure the node to dial a local address on an unused TCP port (`127.0.0.1:65535`).
///   This port is almost certainly closed, so the TCP connection will either be refused immediately,
///   or will time out during the transport handshake phase.
/// - The Swarm is polled for events. We expect to receive a `SwarmEvent::OutgoingConnectionError`
///   within a few seconds.
/// - The test asserts that the error string contains either "timeout", "connection refused",
///   or "failed to negotiate transport protocol" (to cover all error variants libp2p might emit
///   for failed or timed-out dials).
/// - If no such event is received within the timeout window (e.g., 5 or 10 seconds), the test fails.
///
/// Why this is important:
/// - It ensures that the node’s dial logic and libp2p’s handshake timeout are working as intended,
///   and that attempts to connect to unreachable peers do not block or hang the node.
/// - This is critical for network robustness, as hanging dials can lead to resource exhaustion
///   or degraded peer connectivity in real-world deployments.
///
/// Note:
/// - The test does not require the error to be specifically a "timeout"; it accepts any connection
///   failure, since the exact error string may vary by OS and libp2p version.
/// - The test must not set connection limits (like `max_pending_outgoing`) to zero, or the dial
///   will be denied before it is attempted.
#[cfg(test)]
mod tests {
    use crate::config::{
        ApiConfig, Config, LoggingConfig, MinerConfig, NetworkConfig, StoreConfig, StratumConfig,
    };
    use crate::node::Node;
    #[mockall_double::double]
    use crate::shares::chain::chain_store::ChainStore;
    use bitcoindrpc::BitcoinRpcConfig;
    use futures::StreamExt;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_node_dial_timeout_does_not_hang() {
        use libp2p::swarm::SwarmEvent;

        // Use a local address that will refuse connections immediately
        let unreachable_peer = "/ip4/127.0.0.1/tcp/65535".to_string(); // Fast fail

        let mut network_config = NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/0".to_string(),
            dial_peers: vec![],
            max_pending_incoming: 10,
            max_pending_outgoing: 10,
            max_established_incoming: 10,
            max_established_outgoing: 10,
            max_established_per_peer: 10,
            max_workbase_per_second: 10,
            max_userworkbase_per_second: 10,
            max_miningshare_per_second: 10,
            max_inventory_per_second: 10,
            max_transaction_per_second: 10,
            rate_limit_window_secs: 1,
            max_requests_per_second: 1,
            peer_inactivity_timeout_secs: 30,
            dial_timeout_secs: 2,
        };
        network_config.dial_peers = vec![unreachable_peer];
        network_config.dial_timeout_secs = 2;

        let mut config = Config {
            network: network_config.clone(),
            bitcoinrpc: BitcoinRpcConfig {
                url: "http://localhost:8332".to_string(),
                username: "testuser".to_string(),
                password: "testpass".to_string(),
            },
            store: StoreConfig {
                path: "test_chain.db".to_string(),
                background_task_frequency_hours: 1,
                pplns_ttl_days: 3,
            },

            stratum: StratumConfig::new_for_test_default(),
            miner: Some(MinerConfig {
                pubkey: "020202020202020202020202020202020202020202020202020202020202020202"
                    .parse()
                    .unwrap(),
            }),
            logging: LoggingConfig {
                level: "info".to_string(),
                file: Some("./p2pool.log".to_string()),
                stats_dir: "./logs/stats".to_string(),
            },
            api: ApiConfig {
                hostname: "127.0.0.1".to_string(),
                port: 3000,
                auth_user: None,
                auth_token: None,
            },
        };
        config.network = network_config;

        let mock_store = ChainStore::default();
        let store = std::sync::Arc::new(mock_store);

        let mut node = Node::new(&config, store).expect("Node initialization failed");

        //  Initiate the dial manually!
        let unreachable_peer_multiaddr: libp2p::Multiaddr =
            config.network.dial_peers[0].parse().unwrap();
        node.swarm
            .dial(unreachable_peer_multiaddr.clone())
            .expect("Dial failed to start");

        let start = Instant::now();
        let timeout = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                event = node.swarm.next() => {
                                            match event {
                                                Some(SwarmEvent::OutgoingConnectionError { error, .. }) => {
                                                    let elapsed = start.elapsed();
                                                   let err_str = error.to_string();
            let err_str_lower = err_str.to_lowercase();
            assert!(
                err_str_lower.contains("timeout") ||
                err_str_lower.contains("connection refused") ||
                err_str_lower.contains("failed to negotiate transport protocol"),
                "Expected timeout or connection refused error, got: {}",
                err_str
            );


                                                    assert!(
                                                        elapsed.as_secs_f32() <= 10.0,
                                                        "Dialing took too long: {:?}, expected ~10s",
                                                        elapsed
                                                    );
                                                    break;
                                                }
                                                Some(_) => continue,
                                                None => panic!("Swarm event stream ended unexpectedly"),
                                            }
                                        }
                                        _ = &mut timeout => {
                                            panic!("Test timed out after 5 seconds, dial timeout not triggered");
                                        }
                                    }
        }
    }
}
