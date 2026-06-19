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

mod address_filter;
pub mod behaviour;
pub mod connection_tracker;
pub mod emission_worker;
pub mod organise_worker;
pub mod peer_reconnector;
pub mod request_response_handler;
pub mod validation_worker;
pub use crate::config::Config;
pub mod actor;
pub mod messages;
pub mod p2p_message_handlers;

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::monitoring_events::{MonitoringEvent, MonitoringEventSender, PeerResponse, PeerStatus};
use crate::node::messages::Message;
use crate::node::p2p_message_handlers::receivers::block_receiver::BlockReceiverHandle;
use crate::node::p2p_message_handlers::senders::send_handshake;
use crate::node::request_response_handler::RequestResponseHandler;
use crate::node::request_response_handler::block_fetcher::BlockFetcherHandle;
use crate::node::validation_worker::ValidationSender;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::validation::ShareValidator;
use behaviour::{P2PoolBehaviour, P2PoolBehaviourEvent};
use bitcoin::BlockHash;
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
use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
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
    /// Relay a block inventory announcement to connected peers.
    /// Sent after a ShareBlock is successfully validated and stored, so
    /// that other peers learn about the block and can request it via GetData.
    Inv(BlockHash),
    Disconnect(PeerId),
}

use connection_tracker::{ConnectionAction, ConnectionTracker};

/// Node is the main struct that represents the node
struct Node {
    swarm: Swarm<P2PoolBehaviour>,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    swarm_rx: mpsc::Receiver<SwarmSend<ResponseChannel<Message>>>,
    chain_store_handle: ChainStoreHandle,
    request_response_handler: RequestResponseHandler<ResponseChannel<Message>>,
    config: Config,
    monitoring_event_sender: MonitoringEventSender,
    peer_reconnector: peer_reconnector::PeerReconnector,
    connection_tracker: ConnectionTracker,
    /// Whether an external address has been confirmed and advertised
    external_address_confirmed: bool,
    /// Cached TCP listen port extracted from config
    listen_port: Option<u16>,
    /// Whether kademlia bootstrap has been triggered at least once
    has_bootstrapped_kad: bool,
}

impl Node {
    pub fn new(
        config: Config,
        chain_store_handle: ChainStoreHandle,
        block_fetcher_handle: BlockFetcherHandle,
        validation_tx: ValidationSender,
        block_receiver_handle: BlockReceiverHandle,
        monitoring_event_sender: MonitoringEventSender,
        share_validator: Arc<dyn ShareValidator + Send + Sync>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let id_keys = libp2p::identity::Keypair::generate_ed25519();

        let behavior = match P2PoolBehaviour::new(&id_keys, &config) {
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

        info!("Local peer id: {}", swarm.local_peer_id());

        let listen_port = address_filter::extract_listen_port(&config.network.listen_address);

        let external_address_confirmed =
            if let Some(ref external_addr_str) = config.network.external_address {
                match external_addr_str.parse::<Multiaddr>() {
                    Ok(external_addr) => {
                        info!("Using configured external address: {}", external_addr);
                        swarm.add_external_address(external_addr);
                        true
                    }
                    Err(error) => {
                        warn!(
                            "Invalid external_address '{}' in config: {}",
                            external_addr_str, error
                        );
                        false
                    }
                }
            } else {
                false
            };

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

        let request_response_handler = RequestResponseHandler::new(
            config.network.clone(),
            chain_store_handle.clone(),
            swarm_tx.clone(),
            block_fetcher_handle,
            validation_tx,
            block_receiver_handle,
            share_validator,
        );

        let peer_reconnector = peer_reconnector::PeerReconnector::new(&config.network.dial_peers);

        let blocked_ips: HashSet<IpAddr> = config
            .network
            .blocked_ips
            .iter()
            .filter_map(|ip_str| {
                ip_str
                    .parse::<IpAddr>()
                    .map_err(|error| {
                        warn!("Invalid blocked IP '{}' in config: {}", ip_str, error);
                    })
                    .ok()
            })
            .collect();

        if !blocked_ips.is_empty() {
            info!("Loaded {} blocked IPs from config", blocked_ips.len());
        }

        Ok(Self {
            swarm,
            swarm_tx,
            swarm_rx,
            chain_store_handle,
            request_response_handler,
            config,
            monitoring_event_sender,
            peer_reconnector,
            connection_tracker: ConnectionTracker::new(blocked_ips),
            external_address_confirmed,
            listen_port,
            has_bootstrapped_kad: false,
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

    /// Attempt to reconnect to any configured dial_peers that are not currently connected.
    fn attempt_reconnections(&mut self) {
        let addresses = self
            .peer_reconnector
            .addresses_to_reconnect(&self.connection_tracker.connected_dial_addresses);
        for address in addresses {
            match self.swarm.dial(address.clone()) {
                Ok(_) => {
                    debug!("Reconnecting to {address}");
                }
                Err(error) => {
                    error!("Failed to redial {address}: {error}");
                    self.peer_reconnector.record_dial_failure(&address);
                }
            }
        }
    }

    /// Send a message to a specific peer
    pub fn send_to_peer(
        &mut self,
        peer_id: &libp2p::PeerId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        debug!("Sending message to peer: {peer_id}, message: {message:?}");
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
        self.chain_store_handle.get_pplns_shares_filtered(
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
                if self.listen_port.is_none() {
                    if let Some(port) = address_filter::extract_tcp_port(&address) {
                        info!("Resolved actual listen port: {port}");
                        self.listen_port = Some(port);
                    }
                }
                if !self.external_address_confirmed
                    && address_filter::is_routable_multiaddr(&address)
                {
                    self.swarm.add_external_address(address.clone());
                    self.external_address_confirmed = true;
                    info!("Added routable listen address as external: {address}");
                }
                Ok(())
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if let libp2p::core::ConnectedPoint::Dialer { ref address, .. } = endpoint {
                    self.peer_reconnector.record_dial_success(address);
                }

                match self
                    .connection_tracker
                    .handle_established(peer_id, &endpoint)
                {
                    ConnectionAction::Block => {
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        return Ok(());
                    }
                    ConnectionAction::Accept(ref peer_info) => {
                        if let Err(error) = send_handshake(
                            peer_id,
                            self.chain_store_handle.clone(),
                            self.swarm_tx.clone(),
                        )
                        .await
                        {
                            error!("Failed to send handshake to peer {}: {}", peer_id, error);
                        } else {
                            debug!(
                                "{:?} connection established, handshake sent to peer: {}",
                                peer_info.direction, peer_id
                            );
                        }
                    }
                }

                self.request_response_handler.add_peer(peer_id);
                let _ = self
                    .monitoring_event_sender
                    .send(MonitoringEvent::Peer(PeerResponse {
                        peer_id: peer_id.to_string(),
                        status: PeerStatus::Connected,
                    }));
                Ok(())
            }
            SwarmEvent::ConnectionClosed {
                peer_id, endpoint, ..
            } => {
                info!("Disconnected from peer: {peer_id}");
                self.connection_tracker.handle_closed(&peer_id, &endpoint);
                self.swarm.behaviour_mut().remove_peer(&peer_id);
                self.request_response_handler.remove_peer(&peer_id).await;
                let _ = self
                    .monitoring_event_sender
                    .send(MonitoringEvent::Peer(PeerResponse {
                        peer_id: peer_id.to_string(),
                        status: PeerStatus::Disconnected,
                    }));
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
                P2PoolBehaviourEvent::Ping(ping_event) => {
                    self.handle_ping_event(ping_event);
                    Ok(())
                }
                P2PoolBehaviourEvent::RequestResponse(request_response_event) => {
                    self.request_response_handler
                        .handle_event(request_response_event)
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
                // Add the peer's routable advertised addresses to Kademlia
                for addr in info.listen_addrs {
                    if address_filter::is_routable_multiaddr(&addr) {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                    } else {
                        debug!(
                            "Skipping non-routable address {} from peer {}",
                            addr, peer_id
                        );
                    }
                }
                self.try_confirm_external_address(&info.observed_addr);
                if !self.has_bootstrapped_kad {
                    self.attempt_kademlia_bootstrap();
                }
            }
            _ => {
                debug!("Other identify event: {:?}", event);
            }
        }
    }

    /// Triggers a kademlia bootstrap query to discover peers in the DHT.
    /// Called once on first identify event and periodically thereafter.
    fn attempt_kademlia_bootstrap(&mut self) {
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => {
                debug!("Started Kademlia bootstrap");
                self.has_bootstrapped_kad = true;
            }
            Err(error) => {
                warn!("Failed to bootstrap Kademlia: {error}");
            }
        }
    }

    /// Attempts to derive and confirm an external address from an identify
    /// observation. Uses the observed IP combined with our listen port.
    fn try_confirm_external_address(&mut self, observed_addr: &Multiaddr) {
        if self.external_address_confirmed {
            return;
        }
        let listen_port = match self.listen_port {
            Some(port) => port,
            None => {
                debug!("No listen port configured, skipping external address detection");
                return;
            }
        };
        if let Some(external_addr) =
            address_filter::build_external_address(observed_addr, listen_port)
        {
            info!("Detected external address from peer observation: {external_addr}");
            self.swarm.add_external_address(external_addr);
            self.external_address_confirmed = true;
        } else {
            debug!("Peer observed us as {observed_addr}, not usable as external address");
        }
    }

    /// Handle ping events from the libp2p ping protocol.
    /// Ping failures are logged; libp2p handles connection closure automatically.
    fn handle_ping_event(&mut self, event: libp2p::ping::Event) {
        match event.result {
            Ok(rtt) => {
                debug!("Ping to {} succeeded, rtt: {:?}", event.peer, rtt);
            }
            Err(ref error) => {
                warn!("Ping to {} failed: {}", event.peer, error);
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
                debug!(
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
    use super::ChainStoreHandle;
    use crate::config::{
        ApiConfig, Config, LoggingConfig, NetworkConfig, StoreConfig, StratumConfig,
    };
    use crate::monitoring_events::create_monitoring_event_channel;
    use crate::node::Node;
    use crate::node::p2p_message_handlers::receivers::block_receiver::create_block_receiver_channel;
    use crate::node::request_response_handler::block_fetcher::create_block_fetcher_channel;
    use crate::node::validation_worker::create_validation_channel;
    use bitcoindrpc::BitcoinRpcConfig;
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_node_dial_timeout_does_not_hang() {
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
            max_requests_per_second: 1,
            dial_timeout_secs: 2,
            blocked_ips: vec![],
            external_address: None,
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
            logging: LoggingConfig {
                console: Some(true),
                level: "info".to_string(),
                file: Some("./p2pool.log".to_string()),
                stats_dir: "./logs/stats".to_string(),
            },
            api: ApiConfig {
                hostname: "127.0.0.1".to_string(),
                port: 3000,
                auth_user: None,
                auth_token: None,
                auth_password: None,
                cors_allowed: false,
            },
        };
        config.network = network_config;

        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);

        let (block_fetcher_tx, _block_fetcher_rx) = create_block_fetcher_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let (block_receiver_handle, _block_receiver_rx) = create_block_receiver_channel();
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        let mut node = Node::new(
            config.clone(),
            chain_store_handle,
            block_fetcher_tx,
            validation_tx,
            block_receiver_handle,
            monitoring_tx,
            Arc::new(crate::shares::validation::MockDefaultShareValidator::default()),
        )
        .expect("Node initialization failed");

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
                                err_str_lower.contains("timeout")
                                    || err_str_lower.contains("connection refused")
                                    || err_str_lower
                                        .contains("failed to negotiate transport protocol"),
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

    fn build_test_config(listen_address: &str, external_address: Option<String>) -> Config {
        Config {
            network: NetworkConfig {
                listen_address: listen_address.to_string(),
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
                max_requests_per_second: 1,
                dial_timeout_secs: 2,
                blocked_ips: vec![],
                external_address,
            },
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
            logging: LoggingConfig {
                console: Some(true),
                level: "info".to_string(),
                file: Some("./p2pool.log".to_string()),
                stats_dir: "./logs/stats".to_string(),
            },
            api: ApiConfig {
                hostname: "127.0.0.1".to_string(),
                port: 3000,
                auth_user: None,
                auth_token: None,
                auth_password: None,
                cors_allowed: false,
            },
        }
    }

    fn build_test_node(config: Config) -> Node {
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_clone()
            .returning(ChainStoreHandle::default);
        let (block_fetcher_tx, _block_fetcher_rx) = create_block_fetcher_channel();
        let (validation_tx, _validation_rx) = create_validation_channel();
        let (block_receiver_handle, _block_receiver_rx) = create_block_receiver_channel();
        let (monitoring_tx, _monitoring_rx) = create_monitoring_event_channel();
        Node::new(
            config,
            chain_store_handle,
            block_fetcher_tx,
            validation_tx,
            block_receiver_handle,
            monitoring_tx,
            Arc::new(crate::shares::validation::MockDefaultShareValidator::default()),
        )
        .expect("Node initialization failed")
    }

    #[tokio::test]
    async fn test_config_external_address_is_added_to_swarm() {
        let config = build_test_config(
            "/ip4/127.0.0.1/tcp/0",
            Some("/ip4/203.0.113.5/tcp/6884".to_string()),
        );
        let node = build_test_node(config);

        let external_addrs: Vec<_> = node.swarm.external_addresses().cloned().collect();
        let expected: libp2p::Multiaddr = "/ip4/203.0.113.5/tcp/6884".parse().unwrap();
        assert!(
            external_addrs.contains(&expected),
            "Expected external address {expected} not found in {external_addrs:?}"
        );
        assert!(node.external_address_confirmed);
    }

    #[tokio::test]
    async fn test_no_config_external_address_leaves_unconfirmed() {
        let config = build_test_config("/ip4/127.0.0.1/tcp/0", None);
        let node = build_test_node(config);

        let external_addrs: Vec<_> = node.swarm.external_addresses().cloned().collect();
        assert!(
            external_addrs.is_empty(),
            "Expected no external addresses, got {external_addrs:?}"
        );
        assert!(!node.external_address_confirmed);
    }

    #[tokio::test]
    async fn test_try_confirm_from_routable_observation() {
        let config = build_test_config("/ip4/127.0.0.1/tcp/0", None);
        let mut node = build_test_node(config);
        node.listen_port = Some(7001);

        assert!(!node.external_address_confirmed);

        let observed: libp2p::Multiaddr = "/ip4/93.184.216.34/tcp/54321".parse().unwrap();
        node.try_confirm_external_address(&observed);

        assert!(node.external_address_confirmed);
        let external_addrs: Vec<_> = node.swarm.external_addresses().cloned().collect();
        let expected: libp2p::Multiaddr = "/ip4/93.184.216.34/tcp/7001".parse().unwrap();
        assert!(
            external_addrs.contains(&expected),
            "Expected external address {expected} not found in {external_addrs:?}"
        );
    }

    #[tokio::test]
    async fn test_try_confirm_ignores_private_observation() {
        let config = build_test_config("/ip4/127.0.0.1/tcp/0", None);
        let mut node = build_test_node(config);
        node.listen_port = Some(7002);

        let observed: libp2p::Multiaddr = "/ip4/192.168.1.1/tcp/54321".parse().unwrap();
        node.try_confirm_external_address(&observed);

        assert!(!node.external_address_confirmed);
        let external_addrs: Vec<_> = node.swarm.external_addresses().cloned().collect();
        assert!(
            external_addrs.is_empty(),
            "Expected no external addresses, got {external_addrs:?}"
        );
    }

    #[tokio::test]
    async fn test_try_confirm_noop_when_already_confirmed() {
        let config = build_test_config(
            "/ip4/127.0.0.1/tcp/0",
            Some("/ip4/203.0.113.5/tcp/7003".to_string()),
        );
        let mut node = build_test_node(config);
        node.listen_port = Some(7003);
        assert!(node.external_address_confirmed);

        let observed: libp2p::Multiaddr = "/ip4/198.51.100.99/tcp/54321".parse().unwrap();
        node.try_confirm_external_address(&observed);

        let external_addrs: Vec<_> = node.swarm.external_addresses().cloned().collect();
        let should_not_exist: libp2p::Multiaddr = "/ip4/198.51.100.99/tcp/7003".parse().unwrap();
        assert!(
            !external_addrs.contains(&should_not_exist),
            "Second observation should not override confirmed address"
        );
    }

    #[tokio::test]
    async fn test_try_confirm_noop_when_no_listen_port() {
        let config = build_test_config("/ip4/127.0.0.1/tcp/0", None);
        let mut node = build_test_node(config);
        assert!(node.listen_port.is_none());

        let observed: libp2p::Multiaddr = "/ip4/198.51.100.7/tcp/54321".parse().unwrap();
        node.try_confirm_external_address(&observed);

        assert!(!node.external_address_confirmed);
    }

    #[tokio::test]
    async fn test_new_listen_addr_resolves_ephemeral_port() {
        let config = build_test_config("/ip4/127.0.0.1/tcp/0", None);
        let mut node = build_test_node(config);
        assert!(node.listen_port.is_none());

        let resolved_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/45678".parse().unwrap();
        let event = SwarmEvent::NewListenAddr {
            listener_id: libp2p::core::transport::ListenerId::next(),
            address: resolved_addr,
        };
        node.handle_swarm_event(event).await.unwrap();

        assert_eq!(node.listen_port, Some(45678));
    }
}
