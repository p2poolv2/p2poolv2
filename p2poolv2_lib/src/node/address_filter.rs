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

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;

/// Returns true if an IPv4 address is globally routable.
/// Rejects loopback, private (RFC 1918), link-local, unspecified,
/// broadcast, documentation, and shared address space ranges.
fn is_ipv4_global(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    let first = octets[0];
    let second = octets[1];
    // Unspecified (0.0.0.0/8)
    if first == 0 {
        return false;
    }
    // Loopback (127.0.0.0/8)
    if ip.is_loopback() {
        return false;
    }
    // Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ip.is_private() {
        return false;
    }
    // Link-local (169.254.0.0/16)
    if ip.is_link_local() {
        return false;
    }
    // Broadcast (255.255.255.255)
    if ip.is_broadcast() {
        return false;
    }
    // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (first == 192 && second == 0 && octets[2] == 2)
        || (first == 198 && second == 51 && octets[2] == 100)
        || (first == 203 && second == 0 && octets[2] == 113)
    {
        return false;
    }
    // Shared address space (100.64.0.0/10)
    if first == 100 && (second & 0xC0) == 64 {
        return false;
    }
    true
}

/// Returns true if an IPv6 address is globally routable.
/// Rejects loopback, unspecified, link-local, and unique local addresses.
fn is_ipv6_global(ip: &std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    let segments = ip.segments();
    // Link-local (fe80::/10)
    if (segments[0] & 0xFFC0) == 0xFE80 {
        return false;
    }
    // Unique local (fc00::/7)
    if (segments[0] & 0xFE00) == 0xFC00 {
        return false;
    }
    true
}

/// Returns true if the multiaddr contains a globally routable IP address.
/// Rejects loopback, private, link-local, and unspecified addresses.
pub fn is_routable_multiaddr(address: &Multiaddr) -> bool {
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(ip) => return is_ipv4_global(&ip),
            Protocol::Ip6(ip) => return is_ipv6_global(&ip),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_loopback() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_private_10() {
        let addr: Multiaddr = "/ip4/10.0.0.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_private_172() {
        let addr: Multiaddr = "/ip4/172.16.0.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_private_192() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_unspecified() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_ipv6_loopback() {
        let addr: Multiaddr = "/ip6/::1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_ipv6_link_local() {
        let addr: Multiaddr = "/ip6/fe80::1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_ipv6_unique_local() {
        let addr: Multiaddr = "/ip6/fd00::1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_accepts_public_ipv4() {
        let addr: Multiaddr = "/ip4/8.8.8.8/tcp/6884".parse().unwrap();
        assert!(is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_accepts_public_ipv6() {
        let addr: Multiaddr = "/ip6/2001:4860:4860::8888/tcp/6884".parse().unwrap();
        assert!(is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_no_ip() {
        let addr: Multiaddr = "/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_shared_address_space() {
        let addr: Multiaddr = "/ip4/100.64.0.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }

    #[test]
    fn test_rejects_documentation_range() {
        let addr: Multiaddr = "/ip4/192.0.2.1/tcp/6884".parse().unwrap();
        assert!(!is_routable_multiaddr(&addr));
    }
}
