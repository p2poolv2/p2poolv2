// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::tor;
use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::error::Error;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll};

/// Kademlia behaviour whose dial candidates stay inside the configured
/// transport boundary. Addresses returned by an active Kademlia query are
/// temporary dial candidates and do not necessarily enter the routing table
/// before libp2p schedules the dial.
pub struct FilteredKademlia {
    inner: kad::Behaviour<MemoryStore>,
    onion_only: bool,
}

#[derive(Debug)]
pub(crate) struct DialOutsideTransportBoundary;

impl fmt::Display for DialOutsideTransportBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("dial address is outside the configured transport boundary")
    }
}

impl Error for DialOutsideTransportBoundary {}

impl FilteredKademlia {
    pub(super) fn new(inner: kad::Behaviour<MemoryStore>, onion_only: bool) -> Self {
        Self { inner, onion_only }
    }
}

impl Deref for FilteredKademlia {
    type Target = kad::Behaviour<MemoryStore>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for FilteredKademlia {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl NetworkBehaviour for FilteredKademlia {
    type ConnectionHandler = <kad::Behaviour<MemoryStore> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = kad::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_address: &Multiaddr,
        remote_address: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_address, remote_address)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_address: &Multiaddr,
        remote_address: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_address,
            remote_address,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if self.onion_only
            && addresses
                .iter()
                .any(|address| tor::onion_target(address).is_none())
        {
            return Err(ConnectionDenied::new(DialOutsideTransportBoundary));
        }

        let mut discovered_addresses = self.inner.handle_pending_outbound_connection(
            connection_id,
            peer,
            addresses,
            effective_role,
        )?;
        discovered_addresses
            .retain(|address| !self.onion_only || tor::onion_target(address).is_some());
        Ok(discovered_addresses)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            address,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer, connection_id, event);
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multiaddr::Protocol;

    #[test]
    fn onion_only_kademlia_returns_only_onion_dial_candidates() {
        let local_peer = PeerId::random();
        let store = MemoryStore::new(local_peer);
        let config = kad::Config::new(libp2p::StreamProtocol::new("/p2poolv2/test/kad/1.0.0"));
        let inner = kad::Behaviour::with_config(local_peer, store, config);
        let mut kademlia = FilteredKademlia::new(inner, true);
        let remote_peer = PeerId::random();
        let onion: Multiaddr =
            "/onion3/2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd:56886"
                .parse()
                .unwrap();
        let clearnet: Multiaddr = "/ip4/93.184.216.34/tcp/56886".parse().unwrap();
        kademlia.add_address(&remote_peer, clearnet);
        kademlia.add_address(&remote_peer, onion.clone());

        let addresses = kademlia
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(remote_peer),
                &[],
                Endpoint::Dialer,
            )
            .unwrap();

        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], onion.with(Protocol::P2p(remote_peer)));
    }

    #[test]
    fn onion_only_kademlia_returns_no_clearnet_dial_candidate() {
        let local_peer = PeerId::random();
        let store = MemoryStore::new(local_peer);
        let config = kad::Config::new(libp2p::StreamProtocol::new("/p2poolv2/test/kad/1.0.0"));
        let inner = kad::Behaviour::with_config(local_peer, store, config);
        let mut kademlia = FilteredKademlia::new(inner, true);
        let remote_peer = PeerId::random();
        let clearnet: Multiaddr = "/ip4/93.184.216.34/tcp/56886".parse().unwrap();
        kademlia.add_address(&remote_peer, clearnet);

        let addresses = kademlia
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(remote_peer),
                &[],
                Endpoint::Dialer,
            )
            .unwrap();

        assert!(addresses.is_empty());
    }

    #[test]
    fn onion_only_kademlia_denies_explicit_clearnet_dial_candidates() {
        let local_peer = PeerId::random();
        let store = MemoryStore::new(local_peer);
        let config = kad::Config::new(libp2p::StreamProtocol::new("/p2poolv2/test/kad/1.0.0"));
        let inner = kad::Behaviour::with_config(local_peer, store, config);
        let mut kademlia = FilteredKademlia::new(inner, true);
        let remote_peer = PeerId::random();
        let clearnet: Multiaddr = "/ip4/93.184.216.34/tcp/56886".parse().unwrap();

        let error = kademlia
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(remote_peer),
                &[clearnet],
                Endpoint::Dialer,
            )
            .unwrap_err();

        assert!(
            error
                .downcast_ref::<DialOutsideTransportBoundary>()
                .is_some()
        );
    }

    #[test]
    fn tcp_kademlia_keeps_existing_dial_candidate_behavior() {
        let local_peer = PeerId::random();
        let store = MemoryStore::new(local_peer);
        let config = kad::Config::new(libp2p::StreamProtocol::new("/p2poolv2/test/kad/1.0.0"));
        let inner = kad::Behaviour::with_config(local_peer, store, config);
        let mut kademlia = FilteredKademlia::new(inner, false);
        let remote_peer = PeerId::random();
        let onion: Multiaddr =
            "/onion3/2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd:56886"
                .parse()
                .unwrap();
        let clearnet: Multiaddr = "/ip4/93.184.216.34/tcp/56886".parse().unwrap();
        kademlia.add_address(&remote_peer, onion.clone());
        kademlia.add_address(&remote_peer, clearnet.clone());

        let addresses = kademlia
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(1),
                Some(remote_peer),
                &[],
                Endpoint::Dialer,
            )
            .unwrap();
        let onion_with_peer = onion.with(Protocol::P2p(remote_peer));
        let clearnet_with_peer = clearnet.with(Protocol::P2p(remote_peer));

        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&onion_with_peer));
        assert!(addresses.contains(&clearnet_with_peer));
    }
}
