// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A transport wrapper that refuses to dial addresses a predicate rejects,
//! and the dial policies the node stacks with it.
//!
//! Kademlia dials whatever addresses peers hand it: FIND_NODE responses may
//! carry any multiaddr, `/dns` included, and a node inserts each address it
//! dialed into its routing table, so it relays the hostnames of its own
//! dial_peers as well. Without a policy, any peer could make the node resolve
//! and dial a hostname pointing at a private or loopback host. The node
//! therefore only dials `/dns` addresses its operator configured.
//!
//! A second filter checks each address after DNS has resolved it and before
//! TCP connects, and refuses dials to IPs on the blocklist. Before resolution
//! the IP behind a hostname is not known, so the check cannot go earlier.
//! See base_transport in node/mod.rs for the order of the layers.

use super::connection_tracker::{BlockedIps, extract_ip_from_multiaddr};
use libp2p::Multiaddr;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;

/// Wraps a transport and refuses, with `MultiaddrNotSupported`, every dial
/// whose address `is_allowed` rejects. Listening is passed through unchanged.
pub(crate) struct DialFilter<T, P> {
    inner: T,
    is_allowed: P,
}

impl<T, P> DialFilter<T, P> {
    pub(crate) fn new(inner: T, is_allowed: P) -> Self {
        Self { inner, is_allowed }
    }
}

impl<T, P> Transport for DialFilter<T, P>
where
    T: Transport + Unpin,
    P: Fn(&Multiaddr) -> bool + Unpin,
{
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, address)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if (self.is_allowed)(&address) {
            self.inner.dial(address, opts)
        } else {
            debug!("Dial policy refused {address}");
            Err(TransportError::MultiaddrNotSupported(address))
        }
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// The DNS addresses among the configured dial_peers, without any trailing
/// `/p2p` component. Unparsable entries are skipped; PeerReconnector::new
/// already warns about them.
pub(crate) fn configured_dns_addresses(dial_peers: &[String]) -> HashSet<Multiaddr> {
    let mut configured = HashSet::with_capacity(dial_peers.len());
    for dial_peer in dial_peers {
        if let Ok(address) = dial_peer.parse::<Multiaddr>()
            && has_dns_component(&address)
        {
            configured.insert(without_p2p_suffix(address));
        }
    }
    configured
}

/// Dial policy: addresses without a DNS component are allowed; a DNS address
/// is allowed only if, ignoring a trailing `/p2p`, it is a configured
/// dial_peer. Kademlia appends `/p2p/<peer id>` to the addresses it dials.
pub(crate) fn is_configured_or_not_dns(
    address: &Multiaddr,
    configured_dns: &HashSet<Multiaddr>,
) -> bool {
    !has_dns_component(address) || configured_dns.contains(&without_p2p_suffix(address.clone()))
}

/// Dial policy: refuse an address whose IP is on the blocklist. Placed below
/// DNS, so `/dns` addresses arrive here already resolved. Addresses without
/// an IP are allowed; the transport below decides whether it supports them.
pub(crate) fn is_not_blocked(address: &Multiaddr, blocked_ips: &BlockedIps) -> bool {
    match extract_ip_from_multiaddr(address) {
        Some(ip) => !blocked_ips.contains(&ip),
        None => true,
    }
}

fn has_dns_component(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| {
        matches!(
            protocol,
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_)
        )
    })
}

fn without_p2p_suffix(mut address: Multiaddr) -> Multiaddr {
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.pop();
    }
    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use libp2p::core::Endpoint;
    use libp2p::core::transport::{MemoryTransport, PortUse};

    fn dial_opts() -> DialOpts {
        DialOpts {
            role: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    }

    #[test]
    fn ip4_address_is_allowed() {
        let configured = configured_dns_addresses(&[]);
        let address: Multiaddr = "/ip4/10.0.0.1/tcp/6884".parse().unwrap();
        assert!(is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn configured_dns_address_is_allowed() {
        let configured = configured_dns_addresses(&["/dns4/peer.example.com/tcp/6884".to_string()]);
        let address: Multiaddr = "/dns4/peer.example.com/tcp/6884".parse().unwrap();
        assert!(is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn configured_dns_address_with_p2p_suffix_is_allowed() {
        let configured = configured_dns_addresses(&["/dns4/peer.example.com/tcp/6884".to_string()]);
        let address: Multiaddr = "/dns4/peer.example.com/tcp/6884"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(PeerId::random()));
        assert!(is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn configured_dial_peer_with_p2p_suffix_matches_bare_address() {
        let dial_peer = "/dns4/peer.example.com/tcp/6884"
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(PeerId::random()));
        let configured = configured_dns_addresses(&[dial_peer.to_string()]);
        let address: Multiaddr = "/dns4/peer.example.com/tcp/6884".parse().unwrap();
        assert!(is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn unconfigured_dns_address_is_refused() {
        let configured = configured_dns_addresses(&["/dns4/peer.example.com/tcp/6884".to_string()]);
        let address: Multiaddr = "/dns4/internal.example.com/tcp/6884".parse().unwrap();
        assert!(!is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn unconfigured_dnsaddr_address_is_refused() {
        let configured = configured_dns_addresses(&[]);
        let address: Multiaddr = "/dnsaddr/internal.example.com".parse().unwrap();
        assert!(!is_configured_or_not_dns(&address, &configured));
    }

    #[test]
    fn configured_dns_addresses_skips_ip_and_invalid_dial_peers() {
        let configured = configured_dns_addresses(&[
            "/ip4/127.0.0.1/tcp/6884".to_string(),
            "not-a-multiaddr".to_string(),
        ]);
        assert!(configured.is_empty());
    }

    #[test]
    fn blocked_ip_address_is_refused() {
        let blocked_ips = BlockedIps::default();
        blocked_ips.insert("203.0.113.5".parse().unwrap());
        let address: Multiaddr = "/ip4/203.0.113.5/tcp/6884".parse().unwrap();
        assert!(!is_not_blocked(&address, &blocked_ips));
    }

    #[test]
    fn unblocked_ip_address_is_allowed() {
        let blocked_ips = BlockedIps::default();
        blocked_ips.insert("203.0.113.5".parse().unwrap());
        let address: Multiaddr = "/ip4/203.0.113.6/tcp/6884".parse().unwrap();
        assert!(is_not_blocked(&address, &blocked_ips));
    }

    #[test]
    fn dial_filter_refuses_rejected_address_and_dials_allowed_one() {
        let allowed: Multiaddr = "/memory/41771".parse().unwrap();
        let refused: Multiaddr = "/memory/41772".parse().unwrap();
        let allowed_for_predicate = allowed.clone();
        let mut transport =
            DialFilter::new(MemoryTransport::default(), move |address: &Multiaddr| {
                *address == allowed_for_predicate
            });
        transport
            .listen_on(ListenerId::next(), allowed.clone())
            .unwrap();
        transport
            .listen_on(ListenerId::next(), refused.clone())
            .unwrap();

        assert!(transport.dial(allowed, dial_opts()).is_ok());
        assert!(matches!(
            transport.dial(refused, dial_opts()),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }
}
