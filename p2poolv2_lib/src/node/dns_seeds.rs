// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in DNS seeds used to find the first peers on startup.
//!
//! Like Bitcoin's chainparams, each network compiles in a list of seed
//! hostnames and the P2P port their nodes listen on. A seed's A/AAAA records
//! list the IPs of long-running nodes. Seeds only supply addresses to dial;
//! the noise handshake with the network protocol prologue still decides
//! whether a peer is on our network.

use super::{SwarmSend, address_filter};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Timeout for a single seed hostname lookup.
const DNS_SEED_LOOKUP_TIMEOUT_SECS: u64 = 10;

/// Time configured dial_peers get to connect before falling back to DNS
/// seeds.
const DNS_SEED_FALLBACK_DELAY_SECS: u64 = 10;

/// Maximum number of addresses taken from one seed, so a single seed
/// operator cannot fill every outbound connection slot.
const MAX_ADDRESSES_PER_SEED: usize = 16;

/// P2P port testnet4 nodes listen on.
const TESTNET4_P2P_PORT: u16 = 46884;

/// Seed hostnames for testnet4.
const TESTNET4_SEED_HOSTNAMES: &[&str] = &["seed.testnet4.p2poolv2.org"];

/// The DNS seeds for one network and the port their nodes listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DnsSeeds {
    pub(crate) hostnames: &'static [&'static str],
    pub(crate) port: u16,
}

/// Returns the built-in DNS seeds for a bitcoin network, or None when the
/// network has no seeds.
///
/// For use cases where people run multiple p2poolv2 networks for a
/// single bitcoin network, they should use dial_peers and set
/// dns_seed to false in their configs.
pub(crate) fn dns_seeds_for_network(network: bitcoin::Network) -> Option<DnsSeeds> {
    match network {
        bitcoin::Network::Testnet4 => Some(DnsSeeds {
            hostnames: TESTNET4_SEED_HOSTNAMES,
            port: TESTNET4_P2P_PORT,
        }),
        _ => None,
    }
}

/// How long to wait before querying DNS seeds. Without dial_peers the seeds
/// are the only way to find the network, so they are queried at once.
/// Otherwise dial_peers get DNS_SEED_FALLBACK_DELAY_SECS to connect and the
/// seeds are only a fallback, as in Bitcoin Core.
pub(crate) fn dns_seed_delay(dial_peers_configured: bool) -> Duration {
    if dial_peers_configured {
        Duration::from_secs(DNS_SEED_FALLBACK_DELAY_SECS)
    } else {
        Duration::ZERO
    }
}

/// Spawns a short-lived task that resolves the seeds and asks the node actor
/// to dial each returned address once. DNS lookups never run on the actor
/// loop; if the actor has stopped, the remaining sends fail and are dropped.
pub(crate) fn spawn_dns_seed_dials<C: Send + 'static>(
    seeds: DnsSeeds,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) {
    tokio::spawn(async move {
        let dial_addresses = resolve_dns_seeds(seeds).await;
        info!("Dialing {} addresses from DNS seeds", dial_addresses.len());
        for address in dial_addresses {
            if let Err(error) = swarm_tx.send(SwarmSend::Dial(address)).await {
                debug!("Node actor stopped before DNS seed dial: {error}");
            }
        }
    });
}

/// Resolves every seed hostname and returns the deduplicated, routable
/// addresses to dial. A failed or timed out lookup is logged and skipped so
/// one bad seed does not stop the others.
pub(crate) async fn resolve_dns_seeds(seeds: DnsSeeds) -> HashSet<Multiaddr> {
    let mut dial_addresses = HashSet::with_capacity(seeds.hostnames.len() * MAX_ADDRESSES_PER_SEED);
    for hostname in seeds.hostnames {
        dial_addresses.extend(resolve_dns_seed(hostname, seeds.port).await);
    }
    dial_addresses
}

/// Resolves one seed hostname through the system resolver and returns at
/// most MAX_ADDRESSES_PER_SEED routable addresses on `port`. Duplicates are
/// left to the caller, which merges every seed's addresses into one set.
async fn resolve_dns_seed(hostname: &str, port: u16) -> Vec<Multiaddr> {
    let lookup = timeout(
        Duration::from_secs(DNS_SEED_LOOKUP_TIMEOUT_SECS),
        lookup_host((hostname, port)),
    );
    match lookup.await {
        Ok(Ok(resolved)) => {
            let dial_addresses = seed_dial_addresses(resolved, MAX_ADDRESSES_PER_SEED);
            info!(
                "DNS seed {hostname} returned {} dialable addresses",
                dial_addresses.len()
            );
            dial_addresses
        }
        Ok(Err(error)) => {
            warn!("DNS seed {hostname} lookup failed: {error}");
            Vec::new()
        }
        Err(_) => {
            warn!("DNS seed {hostname} lookup timed out after {DNS_SEED_LOOKUP_TIMEOUT_SECS}s");
            Vec::new()
        }
    }
}

/// Converts resolved socket addresses to TCP multiaddrs, dropping
/// non-routable IPs and keeping at most `limit`.
fn seed_dial_addresses(resolved: impl Iterator<Item = SocketAddr>, limit: usize) -> Vec<Multiaddr> {
    resolved
        .map(socket_addr_to_multiaddr)
        .filter(address_filter::is_routable_multiaddr)
        .take(limit)
        .collect()
}

/// Maps a socket address to `/ip4/<ip>/tcp/<port>` or `/ip6/<ip>/tcp/<port>`.
fn socket_addr_to_multiaddr(address: SocketAddr) -> Multiaddr {
    Multiaddr::from(address.ip()).with(Protocol::Tcp(address.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addr_to_multiaddr_ipv4() {
        let address: SocketAddr = "23.227.187.89:46884".parse().unwrap();
        let expected: Multiaddr = "/ip4/23.227.187.89/tcp/46884".parse().unwrap();
        assert_eq!(socket_addr_to_multiaddr(address), expected);
    }

    #[test]
    fn socket_addr_to_multiaddr_ipv6() {
        let address: SocketAddr = "[2606:4700::1111]:46884".parse().unwrap();
        let expected: Multiaddr = "/ip6/2606:4700::1111/tcp/46884".parse().unwrap();
        assert_eq!(socket_addr_to_multiaddr(address), expected);
    }

    #[test]
    fn seed_dial_addresses_drops_private_and_loopback() {
        let resolved: Vec<SocketAddr> = vec![
            "127.0.0.1:46884".parse().unwrap(),
            "192.168.1.10:46884".parse().unwrap(),
            "23.227.187.89:46884".parse().unwrap(),
        ];
        let expected: Multiaddr = "/ip4/23.227.187.89/tcp/46884".parse().unwrap();
        assert_eq!(
            seed_dial_addresses(resolved.into_iter(), MAX_ADDRESSES_PER_SEED),
            vec![expected]
        );
    }

    /// Non-routable addresses do not use up the limit.
    #[test]
    fn seed_dial_addresses_caps_routable_addresses_at_limit() {
        let resolved: Vec<SocketAddr> = vec![
            "127.0.0.1:46884".parse().unwrap(),
            "23.227.187.89:46884".parse().unwrap(),
            "23.227.187.90:46884".parse().unwrap(),
            "23.227.187.91:46884".parse().unwrap(),
        ];
        let first: Multiaddr = "/ip4/23.227.187.89/tcp/46884".parse().unwrap();
        let second: Multiaddr = "/ip4/23.227.187.90/tcp/46884".parse().unwrap();
        assert_eq!(
            seed_dial_addresses(resolved.into_iter(), 2),
            vec![first, second]
        );
    }

    #[test]
    fn dns_seed_delay_is_zero_without_dial_peers() {
        assert_eq!(dns_seed_delay(false), Duration::ZERO);
    }

    #[test]
    fn dns_seed_delay_waits_for_dial_peers() {
        assert_eq!(
            dns_seed_delay(true),
            Duration::from_secs(DNS_SEED_FALLBACK_DELAY_SECS)
        );
    }

    #[test]
    fn dns_seeds_for_network_testnet4_has_seeds() {
        let seeds = dns_seeds_for_network(bitcoin::Network::Testnet4).unwrap();
        assert!(!seeds.hostnames.is_empty());
        assert_eq!(seeds.port, TESTNET4_P2P_PORT);
    }

    #[test]
    fn dns_seeds_for_network_signet_is_none() {
        assert_eq!(dns_seeds_for_network(bitcoin::Network::Signet), None);
    }
}
