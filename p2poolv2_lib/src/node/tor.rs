// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tor-only peer networking.
//!
//! Configured like Bitcoin Core: `network.onlynet = ["onion"]` with
//! `network.proxy` set to the tor daemon's SOCKS5 port. The node then uses
//! [`TorTransport`] instead of the TCP and DNS transport. It dials only
//! `/onion3` addresses, and only through the proxy, always sending the onion
//! hostname so that nothing is resolved locally. Every other address is
//! refused with `MultiaddrNotSupported`. There is no direct TCP dialer in this
//! mode, so a tor outage makes dials fail rather than fall back to clearnet.
//!
//! Each outbound dial offers Tor format-zero SOCKS5 credentials: the fixed
//! username `<torS0X>0` and a distinct per-dial password nonce. Stream
//! isolation depends on the proxy selecting authentication and honoring
//! `IsolateSOCKSAuth`.
//!
//! Inbound peers reach the node through an onion service run by tor, which
//! forwards to the loopback `listen_address`. Listening on anything other
//! than loopback is refused. The onion address to advertise is
//! `network.external_address`, as with Bitcoin Core's `-externalip`.
//!
//! The Bitcoin RPC and ZMQ clients cannot use a proxy, so in Tor mode both
//! must point at a loopback IP literal (or a local `ipc://` socket for ZMQ).
//! Reaching a remote bitcoind is left to the operator, for example through a
//! client-authorized onion service and a local forwarder. The node refuses to
//! start otherwise; see [`validate_tor_config`], which runs before anything
//! connects.

use crate::config::{Config, NetworkConfig};
use bitcoin::secp256k1::rand;
use bitcoindrpc::loopback_rpc_url;
use futures::future::BoxFuture;
use libp2p::Multiaddr;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::multiaddr::Protocol;
use libp2p::tcp::Config as TcpConfig;
use libp2p::tcp::tokio::{TcpStream, Transport as TcpTransport};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tracing::{debug, warn};

/// The setting that turns Tor-only mode on, as error messages spell it.
const ONION_ONLY_SETTING: &str = "network.onlynet = [\"onion\"]";
/// SOCKS protocol version 5 (RFC 1928).
const SOCKS_VERSION: u8 = 0x05;
/// Authentication method "no authentication required".
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
/// Authentication method "username/password" (RFC 1929). Tor uses the
/// credentials only to keep streams with different credentials on different
/// circuits, never to authenticate.
const SOCKS_METHOD_USERNAME_PASSWORD: u8 = 0x02;
/// Server reply meaning none of the offered methods is acceptable.
const SOCKS_METHOD_NONE_ACCEPTABLE: u8 = 0xff;
/// Version of the username/password subnegotiation (RFC 1929).
const SOCKS_USERNAME_PASSWORD_VERSION: u8 = 0x01;
/// Username/password subnegotiation status for success.
const SOCKS_USERNAME_PASSWORD_ACCEPTED: u8 = 0x00;
/// Tor format-zero username marker; the per-dial isolation nonce is the password.
const SOCKS_ISOLATION_USERNAME: &str = "<torS0X>0";
/// CONNECT command.
const SOCKS_COMMAND_CONNECT: u8 = 0x01;
/// Address type: IPv4 address.
const SOCKS_ADDRESS_IPV4: u8 = 0x01;
/// Address type: fully qualified domain name, resolved by the proxy.
const SOCKS_ADDRESS_DOMAIN: u8 = 0x03;
/// Address type: IPv6 address.
const SOCKS_ADDRESS_IPV6: u8 = 0x04;
/// Reply code for a successful request.
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
/// Length in bytes of a v3 onion address before base32 encoding.
const ONION3_ADDRESS_BYTES: usize = 35;
/// RFC 4648 base32 alphabet in lower case, as used in onion hostnames.
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Validated Tor settings used to build the transport and advertise the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TorSettings {
    pub(crate) proxy: SocketAddr,
    pub(crate) onion_address: Option<Multiaddr>,
}

/// An onion destination for a SOCKS5 CONNECT: `<56 chars>.onion` and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OnionTarget {
    pub(crate) hostname: String,
    pub(crate) port: u16,
}

/// Checks a whole config for Tor-only operation. Does nothing for plain TCP
/// networking (neither `network.onlynet` nor `network.proxy` set). Call it
/// before starting anything that connects out, because it also covers the
/// Bitcoin RPC and ZMQ endpoints, which are used before the peer-to-peer node
/// exists.
pub fn validate_tor_config(config: &Config) -> Result<(), String> {
    if tor_settings(&config.network)?.is_some() {
        validate_tor_bitcoin_rpc_url(&config.bitcoinrpc.url)?;
        validate_tor_zmq_endpoint(&config.stratum.zmqpubhashblock)?;
    }
    Ok(())
}

/// The Tor settings of a network config. None for plain TCP networking, the
/// validated settings for `onlynet = ["onion"]`. A proxy without `onlynet`,
/// or any other `onlynet`, is an error: sending clearnet peers through the
/// proxy is not supported, and nothing is downgraded silently.
pub(crate) fn tor_settings(network: &NetworkConfig) -> Result<Option<TorSettings>, String> {
    match (network.onlynet.is_empty(), &network.proxy) {
        (true, None) => Ok(None),
        (true, Some(_)) => Err(format!(
            "network.proxy requires {ONION_ONLY_SETTING}: sending clearnet peers through the proxy is not supported"
        )),
        (false, _) => validate_onion_only_network(network).map(Some),
    }
}

/// The Bitcoin RPC client connects directly and resolves hostnames itself,
/// so with Tor the URL must name a loopback IP literal.
fn validate_tor_bitcoin_rpc_url(url: &str) -> Result<(), String> {
    loopback_rpc_url(url)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// The ZMQ subscriber connects directly, so with Tor the endpoint must be a
/// loopback IP literal over tcp, or a local ipc socket. An empty endpoint
/// makes no connection and is left to the ZMQ listener to report.
fn validate_tor_zmq_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty()
        || endpoint
            .strip_prefix("ipc://")
            .is_some_and(|path| !path.is_empty())
    {
        return Ok(());
    }
    if endpoint
        .strip_prefix("tcp://")
        .and_then(|socket| socket.parse::<SocketAddr>().ok())
        .is_some_and(|socket| socket.ip().is_loopback() && socket.port() != 0)
    {
        return Ok(());
    }
    Err(format!(
        "stratum.zmqpubhashblock must use a loopback TCP socket address or a local IPC endpoint with {ONION_ONLY_SETTING}"
    ))
}

/// Checks a network config that sets `onlynet` for Tor-only operation and
/// returns the parsed settings. Every option that would reach the clearnet,
/// resolve names locally, or advertise an IP address is an error.
fn validate_onion_only_network(network: &NetworkConfig) -> Result<TorSettings, String> {
    if !network.is_onion_only() {
        return Err(format!(
            "network.onlynet {:?} is not supported: only {ONION_ONLY_SETTING} (Tor-only) is",
            network.onlynet
        ));
    }
    let proxy = match &network.proxy {
        Some(proxy) => parse_proxy(proxy)?,
        None => {
            return Err(format!(
                "{ONION_ONLY_SETTING} requires network.proxy, the tor SOCKS5 port, for example 127.0.0.1:9050"
            ));
        }
    };
    if network.dns_seed {
        return Err(format!(
            "{ONION_ONLY_SETTING} requires network.dns_seed = false: DNS seeds are clearnet lookups"
        ));
    }
    if !network.blocked_ips.is_empty() {
        return Err(format!(
            "network.blocked_ips cannot be used with {ONION_ONLY_SETTING}: every inbound onion peer arrives through the loopback forwarder"
        ));
    }
    validate_tor_listen_address(&network.listen_address)?;
    validate_tor_dial_peers(&network.dial_peers)?;
    let onion_address = match &network.external_address {
        Some(external_address) => Some(parse_onion_external_address(
            external_address,
            &network.listen_address,
        )?),
        None => None,
    };
    Ok(TorSettings {
        proxy,
        onion_address,
    })
}

/// Parses the SOCKS5 proxy as an IP literal and port. A non-loopback proxy
/// is allowed (for a tor gateway on a trusted network) but warned about,
/// because the hop to it is outside Tor.
fn parse_proxy(proxy: &str) -> Result<SocketAddr, String> {
    let address = proxy.parse::<SocketAddr>().map_err(|error| {
        format!("network.proxy must be an IP address and port such as 127.0.0.1:9050: {error}")
    })?;
    if address.port() == 0 {
        return Err("network.proxy port must not be zero".to_string());
    }
    if !address.ip().is_loopback() {
        warn!(
            "network.proxy {address} is not on loopback; the clear SOCKS hop, including destination onion names, is exposed to the intervening network"
        );
    }
    Ok(address)
}

/// The listen address must be empty (outbound only) or loopback TCP, which
/// the onion service forwards to.
fn validate_tor_listen_address(listen_address: &str) -> Result<(), String> {
    if listen_address.is_empty() {
        return Ok(());
    }
    let address = listen_address.parse::<Multiaddr>().map_err(|error| {
        format!("network.listen_address '{listen_address}' is not a valid multiaddr: {error}")
    })?;
    if loopback_tcp_port(&address).is_some_and(|port| port != 0) {
        Ok(())
    } else {
        Err(format!(
            "network.listen_address '{listen_address}' must be loopback TCP with {ONION_ONLY_SETTING}, for example /ip4/127.0.0.1/tcp/56886"
        ))
    }
}

/// Every configured dial peer must be an onion address.
fn validate_tor_dial_peers(dial_peers: &[String]) -> Result<(), String> {
    for dial_peer in dial_peers {
        let address = dial_peer.parse::<Multiaddr>().map_err(|error| {
            format!("network.dial_peers entry '{dial_peer}' is not a valid multiaddr: {error}")
        })?;
        if onion_target(&address).is_none() {
            return Err(format!(
                "network.dial_peers entry '{dial_peer}' is not an /onion3 address; only onion peers are allowed with {ONION_ONLY_SETTING}"
            ));
        }
    }
    Ok(())
}

/// Parses the external address to advertise in Tor-only mode. It must be a
/// bare `/onion3` address, and advertising it needs a listener for the onion
/// service.
fn parse_onion_external_address(
    external_address: &str,
    listen_address: &str,
) -> Result<Multiaddr, String> {
    let address = external_address.parse::<Multiaddr>().map_err(|error| {
        format!("network.external_address '{external_address}' is not a valid multiaddr: {error}")
    })?;
    let mut protocols = address.iter();
    let is_bare_onion = matches!(
        protocols.next(),
        Some(Protocol::Onion3(onion)) if onion.port() != 0
    ) && protocols.next().is_none();
    if !is_bare_onion {
        return Err(format!(
            "network.external_address '{external_address}' must be the node's own /onion3/<address>:<port> with {ONION_ONLY_SETTING}"
        ));
    }
    if listen_address.is_empty() {
        return Err(
            "network.external_address requires a loopback network.listen_address for the onion service to forward to"
                .to_string(),
        );
    }
    Ok(address)
}

/// True for `/ip4/127.x.x.x/tcp/<port>` and `/ip6/::1/tcp/<port>`.
fn is_loopback_tcp(address: &Multiaddr) -> bool {
    loopback_tcp_port(address).is_some()
}

/// Returns the port for a loopback TCP multiaddr.
fn loopback_tcp_port(address: &Multiaddr) -> Option<u16> {
    let mut protocols = address.iter();
    let is_loopback_ip = match protocols.next() {
        Some(Protocol::Ip4(ip)) => ip.is_loopback(),
        Some(Protocol::Ip6(ip)) => ip.is_loopback(),
        _ => false,
    };
    let port = match protocols.next() {
        Some(Protocol::Tcp(port)) => port,
        _ => return None,
    };
    if is_loopback_ip && protocols.next().is_none() {
        Some(port)
    } else {
        None
    }
}

/// The onion destination of an `/onion3/<address>:<port>` multiaddr,
/// optionally followed by `/p2p/<peer id>`. Any other address gives None.
pub(crate) fn onion_target(address: &Multiaddr) -> Option<OnionTarget> {
    let mut protocols = address.iter();
    let target = match protocols.next() {
        Some(Protocol::Onion3(onion)) if onion.port() != 0 => OnionTarget {
            hostname: format!("{}.onion", base32_lower(onion.hash())),
            port: onion.port(),
        },
        _ => return None,
    };
    match (protocols.next(), protocols.next()) {
        (None, None) | (Some(Protocol::P2p(_)), None) => Some(target),
        _ => None,
    }
}

/// RFC 4648 base32 without padding, lower case. 35 bytes encode to exactly
/// 56 characters, the length of a v3 onion hostname label.
fn base32_lower(bytes: &[u8; ONION3_ADDRESS_BYTES]) -> String {
    let mut encoded = String::with_capacity(ONION3_ADDRESS_BYTES * 8 / 5);
    let mut buffer: u16 = 0;
    let mut buffered_bits: u32 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        buffered_bits += 8;
        while buffered_bits >= 5 {
            buffered_bits -= 5;
            let index = usize::from((buffer >> buffered_bits) & 0x1f);
            encoded.push(char::from(BASE32_LOWER[index]));
        }
        buffer &= (1 << buffered_bits) - 1;
    }
    encoded
}

/// Opens a TCP connection to `hostname:port` through the SOCKS5 proxy, with
/// the hostname sent to the proxy for resolution (address type DOMAINNAME).
/// No local DNS lookup happens and no IP is ever placed in the request.
///
/// `isolation_nonce` is the distinct password in Tor's format-zero credentials.
/// A Tor proxy with SOCKS authentication isolation can use it to separate
/// streams. A proxy that does not want credentials may choose "no
/// authentication" instead.
pub(crate) async fn socks5_connect(
    proxy: SocketAddr,
    hostname: &str,
    port: u16,
    isolation_nonce: &str,
) -> io::Result<TokioTcpStream> {
    let hostname_length = socks5_field_length(hostname, "hostname")?;
    let username_length = socks5_field_length(SOCKS_ISOLATION_USERNAME, "username")?;
    let password_length = socks5_field_length(isolation_nonce, "password")?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 destination port must not be zero",
        ));
    }
    let mut stream = TokioTcpStream::connect(proxy).await?;
    stream.set_nodelay(true)?;

    stream
        .write_all(&[
            SOCKS_VERSION,
            2,
            SOCKS_METHOD_NO_AUTH,
            SOCKS_METHOD_USERNAME_PASSWORD,
        ])
        .await?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if check_method_reply(method_reply)? == SOCKS_METHOD_USERNAME_PASSWORD {
        send_isolation_credentials(
            &mut stream,
            isolation_nonce,
            username_length,
            password_length,
        )
        .await?;
    }

    let mut request = Vec::with_capacity(7 + hostname.len());
    request.extend_from_slice(&[
        SOCKS_VERSION,
        SOCKS_COMMAND_CONNECT,
        0x00,
        SOCKS_ADDRESS_DOMAIN,
        hostname_length,
    ]);
    request.extend_from_slice(hostname.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply_header = [0u8; 4];
    stream.read_exact(&mut reply_header).await?;
    check_connect_reply(reply_header)?;
    discard_bound_address(&mut stream, reply_header[3]).await?;
    Ok(stream)
}

/// The length of a SOCKS5 string field, which must be 1 to 255 bytes.
fn socks5_field_length(field: &str, name: &str) -> io::Result<u8> {
    u8::try_from(field.len())
        .ok()
        .filter(|length| *length > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("SOCKS5 {name} must be 1 to 255 bytes"),
            )
        })
}

/// The proxy must answer SOCKS5 and choose one of the offered methods.
/// Returns the chosen method.
fn check_method_reply(method_reply: [u8; 2]) -> io::Result<u8> {
    match method_reply {
        [SOCKS_VERSION, SOCKS_METHOD_NO_AUTH] => Ok(SOCKS_METHOD_NO_AUTH),
        [SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD] => Ok(SOCKS_METHOD_USERNAME_PASSWORD),
        [SOCKS_VERSION, SOCKS_METHOD_NONE_ACCEPTABLE] => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy accepts none of the offered authentication methods",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 proxy sent an invalid method reply",
        )),
    }
}

/// Sends the RFC 1929 request with the format-zero username marker and the
/// isolation nonce as password, then checks that the proxy accepted it.
async fn send_isolation_credentials(
    stream: &mut TokioTcpStream,
    isolation_nonce: &str,
    username_length: u8,
    password_length: u8,
) -> io::Result<()> {
    let mut request =
        Vec::with_capacity(3 + SOCKS_ISOLATION_USERNAME.len() + isolation_nonce.len());
    request.extend_from_slice(&[SOCKS_USERNAME_PASSWORD_VERSION, username_length]);
    request.extend_from_slice(SOCKS_ISOLATION_USERNAME.as_bytes());
    request.push(password_length);
    request.extend_from_slice(isolation_nonce.as_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply
        == [
            SOCKS_USERNAME_PASSWORD_VERSION,
            SOCKS_USERNAME_PASSWORD_ACCEPTED,
        ]
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy rejected the circuit isolation credentials",
        ))
    }
}

/// The CONNECT reply must be SOCKS5 with reply code "succeeded".
fn check_connect_reply(reply_header: [u8; 4]) -> io::Result<()> {
    if reply_header[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 proxy sent an invalid connect reply",
        ));
    }
    if reply_header[1] == SOCKS_REPLY_SUCCEEDED {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "SOCKS5 connect failed: {}",
                socks_reply_message(reply_header[1])
            ),
        ))
    }
}

/// Human readable text for a SOCKS5 reply code (RFC 1928 section 6).
fn socks_reply_message(reply_code: u8) -> &'static str {
    match reply_code {
        0x01 => "general failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

/// Reads and drops the bound address that follows a successful reply, so
/// the stream is positioned at the first byte from the destination.
async fn discard_bound_address(stream: &mut TokioTcpStream, address_type: u8) -> io::Result<()> {
    let address_length = match address_type {
        SOCKS_ADDRESS_IPV4 => 4,
        SOCKS_ADDRESS_IPV6 => 16,
        SOCKS_ADDRESS_DOMAIN => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 proxy sent an unknown bound address type",
            ));
        }
    };
    let mut bound_address_and_port = vec![0u8; address_length + 2];
    stream.read_exact(&mut bound_address_and_port).await?;
    Ok(())
}

/// Transport for Tor-only mode: dials onion addresses through SOCKS5 and
/// listens on loopback TCP only. See the module documentation.
pub(crate) struct TorTransport {
    proxy: SocketAddr,
    listener: TcpTransport,
}

impl TorTransport {
    pub(crate) fn new(proxy: SocketAddr, tcp_config: TcpConfig) -> Self {
        Self {
            proxy,
            listener: TcpTransport::new(tcp_config),
        }
    }
}

impl Transport for TorTransport {
    type Output = TcpStream;
    type Error = io::Error;
    type ListenerUpgrade = <TcpTransport as Transport>::ListenerUpgrade;
    type Dial = BoxFuture<'static, Result<TcpStream, io::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        address: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        if is_loopback_tcp(&address) {
            self.listener.listen_on(id, address)
        } else {
            debug!("Tor transport refused non-loopback listen address {address}");
            Err(TransportError::MultiaddrNotSupported(address))
        }
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.listener.remove_listener(id)
    }

    fn dial(
        &mut self,
        address: Multiaddr,
        _opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        let Some(target) = onion_target(&address) else {
            debug!("Tor transport refused non-onion dial {address}");
            return Err(TransportError::MultiaddrNotSupported(address));
        };
        let proxy = self.proxy;
        let isolation_nonce = format!("p2poolv2-{:032x}", rand::random::<u128>());
        Ok(Box::pin(async move {
            let stream =
                socks5_connect(proxy, &target.hostname, target.port, &isolation_nonce).await?;
            Ok(TcpStream(stream))
        }))
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.listener).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        FAKE_SOCKS_METHOD_NO_AUTH, FAKE_SOCKS_METHOD_USERNAME_PASSWORD, ObservedSocksConnect,
        spawn_fake_socks5_proxy, unused_local_address,
    };
    use libp2p::PeerId;
    use libp2p::core::Endpoint;
    use libp2p::core::transport::PortUse;
    use std::future::poll_fn;
    use std::time::Duration;
    use tokio::net::TcpListener;

    /// A v3 onion address used across tests (the Tor Project's own).
    const ONION_HOSTNAME: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd.onion";
    const ONION_MULTIADDR: &str =
        "/onion3/2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd:56886";

    #[test]
    fn onion_target_maps_onion3_to_hostname_and_port() {
        let address: Multiaddr = ONION_MULTIADDR.parse().unwrap();
        let target = onion_target(&address).unwrap();
        assert_eq!(target.hostname, ONION_HOSTNAME);
        assert_eq!(target.port, 56886);
    }

    #[test]
    fn onion_target_hostname_matches_multiaddr_text_form() {
        let address: Multiaddr = ONION_MULTIADDR.parse().unwrap();
        let target = onion_target(&address).unwrap();
        let expected = format!(
            "/onion3/{}:56886",
            target.hostname.trim_end_matches(".onion")
        );
        assert_eq!(address.to_string(), expected);
    }

    #[test]
    fn onion_target_accepts_trailing_peer_id() {
        let address = ONION_MULTIADDR
            .parse::<Multiaddr>()
            .unwrap()
            .with(Protocol::P2p(PeerId::random()));
        assert_eq!(onion_target(&address).unwrap().hostname, ONION_HOSTNAME);
    }

    #[test]
    fn onion_target_rejects_ip4() {
        let address: Multiaddr = "/ip4/203.0.113.5/tcp/56886".parse().unwrap();
        assert_eq!(onion_target(&address), None);
    }

    #[test]
    fn onion_target_rejects_ip6() {
        let address: Multiaddr = "/ip6/2001:db8::1/tcp/56886".parse().unwrap();
        assert_eq!(onion_target(&address), None);
    }

    #[test]
    fn onion_target_rejects_dns() {
        let address: Multiaddr = "/dns4/seed.example.com/tcp/56886".parse().unwrap();
        assert_eq!(onion_target(&address), None);
    }

    #[test]
    fn onion_target_rejects_extra_transport_components() {
        let address: Multiaddr = format!("{ONION_MULTIADDR}/tcp/1").parse().unwrap();
        assert_eq!(onion_target(&address), None);
    }

    #[test]
    fn tor_settings_accepts_onion_only_config() {
        let network = NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/56886".to_string(),
            dns_seed: false,
            dial_peers: vec![ONION_MULTIADDR.to_string()],
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            external_address: Some(ONION_MULTIADDR.to_string()),
            ..NetworkConfig::default()
        };
        let settings = tor_settings(&network).unwrap().unwrap();
        assert_eq!(settings.proxy, "127.0.0.1:9050".parse().unwrap());
        assert_eq!(
            settings.onion_address,
            Some(ONION_MULTIADDR.parse().unwrap())
        );
    }

    #[test]
    fn tor_settings_is_none_for_plain_tcp_networking() {
        assert_eq!(tor_settings(&NetworkConfig::default()), Ok(None));
    }

    #[test]
    fn tor_settings_accepts_outbound_only_without_listener_or_external_address() {
        let network = NetworkConfig {
            listen_address: String::new(),
            dns_seed: false,
            dial_peers: vec![ONION_MULTIADDR.to_string()],
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let settings = tor_settings(&network).unwrap().unwrap();
        assert_eq!(settings.onion_address, None);
    }

    #[test]
    fn tor_settings_rejects_proxy_without_onlynet() {
        let network = NetworkConfig {
            proxy: Some("127.0.0.1:9050".to_string()),
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("network.proxy requires network.onlynet"));
    }

    #[test]
    fn tor_settings_rejects_onlynet_other_than_onion() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["ipv4".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("network.onlynet [\"ipv4\"] is not supported"));
    }

    #[test]
    fn tor_settings_rejects_onlynet_mixing_onion_and_ipv4() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string(), "ipv4".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("is not supported"));
    }

    #[test]
    fn tor_settings_rejects_onlynet_onion_without_proxy() {
        let network = NetworkConfig {
            dns_seed: false,
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("requires network.proxy"));
    }

    #[test]
    fn tor_settings_rejects_dns_seed() {
        let network = NetworkConfig {
            dns_seed: true,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("dns_seed"));
    }

    #[test]
    fn tor_settings_rejects_clearnet_dial_peer() {
        let network = NetworkConfig {
            dns_seed: false,
            dial_peers: vec!["/ip4/203.0.113.5/tcp/56886".to_string()],
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("dial_peers"));
    }

    #[test]
    fn tor_settings_rejects_dns_dial_peer() {
        let network = NetworkConfig {
            dns_seed: false,
            dial_peers: vec!["/dns4/peer.example.com/tcp/56886".to_string()],
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("dial_peers"));
    }

    #[test]
    fn tor_settings_rejects_public_listen_address() {
        let network = NetworkConfig {
            listen_address: "/ip4/0.0.0.0/tcp/56886".to_string(),
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("listen_address"));
    }

    #[test]
    fn tor_settings_rejects_ip_external_address() {
        let network = NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/56886".to_string(),
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            external_address: Some("/ip4/203.0.113.5/tcp/56886".to_string()),
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("external_address"));
    }

    #[test]
    fn tor_settings_rejects_external_address_without_listener() {
        let network = NetworkConfig {
            listen_address: String::new(),
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            external_address: Some(ONION_MULTIADDR.to_string()),
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("listen_address"));
    }

    #[test]
    fn tor_settings_rejects_blocked_ips() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            blocked_ips: vec!["203.0.113.5".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("blocked_ips"));
    }

    #[test]
    fn tor_settings_rejects_hostname_proxy() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("localhost:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("network.proxy"));
    }

    #[test]
    fn tor_settings_does_not_echo_malformed_proxy_credentials() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("socks5://private-user:private-password@127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(!error.contains("private-user"));
        assert!(!error.contains("private-password"));
    }

    #[test]
    fn tor_settings_rejects_zero_proxy_port() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("127.0.0.1:0".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("port must not be zero"));
    }

    #[test]
    fn tor_settings_rejects_zero_listen_port() {
        let network = NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/0".to_string(),
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("listen_address"));
    }

    #[test]
    fn tor_settings_rejects_zero_external_port() {
        let network = NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/56886".to_string(),
            dns_seed: false,
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            external_address: Some(ONION_MULTIADDR.replace(":56886", ":0")),
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("external_address"));
    }

    #[test]
    fn tor_settings_rejects_zero_dial_peer_port() {
        let network = NetworkConfig {
            dns_seed: false,
            dial_peers: vec![ONION_MULTIADDR.replace(":56886", ":0")],
            proxy: Some("127.0.0.1:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let error = tor_settings(&network).unwrap_err();
        assert!(error.contains("dial_peers"));
    }

    #[test]
    fn bitcoin_rpc_url_accepts_ipv4_loopback() {
        assert!(validate_tor_bitcoin_rpc_url("http://127.0.0.1:18352").is_ok());
    }

    #[test]
    fn bitcoin_rpc_url_accepts_ipv6_loopback() {
        assert!(validate_tor_bitcoin_rpc_url("http://[::1]:18352").is_ok());
    }

    #[test]
    fn bitcoin_rpc_url_accepts_userinfo_and_path() {
        assert!(
            validate_tor_bitcoin_rpc_url("https://user:secret@127.0.0.1:18352/wallet/a").is_ok()
        );
    }

    #[test]
    fn bitcoin_rpc_url_rejects_clearnet_ip() {
        let error = validate_tor_bitcoin_rpc_url("http://203.0.113.5:18352").unwrap_err();
        assert!(error.contains("bitcoinrpc.url"));
    }

    #[test]
    fn bitcoin_rpc_url_rejects_localhost_hostname() {
        assert!(validate_tor_bitcoin_rpc_url("http://localhost:18352").is_err());
    }

    #[test]
    fn bitcoin_rpc_url_rejects_onion_hostname() {
        assert!(validate_tor_bitcoin_rpc_url(&format!("http://{ONION_HOSTNAME}:18352")).is_err());
    }

    #[test]
    fn bitcoin_rpc_url_rejects_other_scheme() {
        assert!(validate_tor_bitcoin_rpc_url("ftp://127.0.0.1:18352").is_err());
    }

    #[test]
    fn bitcoin_rpc_url_error_does_not_echo_password() {
        let error =
            validate_tor_bitcoin_rpc_url("http://user:secret@203.0.113.5:18352").unwrap_err();
        assert!(!error.contains("secret"));
    }

    #[test]
    fn zmq_endpoint_accepts_tcp_loopback() {
        assert!(validate_tor_zmq_endpoint("tcp://127.0.0.1:28335").is_ok());
    }

    #[test]
    fn zmq_endpoint_accepts_ipc_socket() {
        assert!(validate_tor_zmq_endpoint("ipc:///run/bitcoind/hashblock").is_ok());
    }

    #[test]
    fn zmq_endpoint_accepts_ipv6_loopback() {
        assert!(validate_tor_zmq_endpoint("tcp://[::1]:28335").is_ok());
    }

    #[test]
    fn zmq_endpoint_rejects_invalid_port() {
        assert!(validate_tor_zmq_endpoint("tcp://127.0.0.1:invalid").is_err());
    }

    #[test]
    fn zmq_endpoint_rejects_trailing_content_without_echoing_it() {
        let error =
            validate_tor_zmq_endpoint("tcp://127.0.0.1:28335/private-test-value").unwrap_err();
        assert!(!error.contains("private-test-value"));
    }

    #[test]
    fn zmq_endpoint_rejects_clearnet_ip() {
        let error = validate_tor_zmq_endpoint("tcp://203.0.113.5:28335").unwrap_err();
        assert!(error.contains("zmqpubhashblock"));
    }

    #[test]
    fn zmq_endpoint_rejects_hostname() {
        assert!(validate_tor_zmq_endpoint("tcp://bitcoind.lan:28335").is_err());
    }

    #[tokio::test]
    async fn socks5_connect_sends_onion_hostname_for_remote_resolution() {
        let (proxy, proxy_handle) = spawn_fake_socks5_proxy(
            FAKE_SOCKS_METHOD_NO_AUTH,
            SOCKS_REPLY_SUCCEEDED,
            b"hello",
            1,
        )
        .await;
        let mut stream = socks5_connect(proxy, ONION_HOSTNAME, 56886, "circuit-a")
            .await
            .unwrap();
        let mut payload = [0u8; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        assert_eq!(
            proxy_handle.await.unwrap(),
            vec![ObservedSocksConnect {
                offered_methods: vec![SOCKS_METHOD_NO_AUTH, SOCKS_METHOD_USERNAME_PASSWORD],
                username: None,
                password: None,
                address_type: SOCKS_ADDRESS_DOMAIN,
                hostname: ONION_HOSTNAME.to_string(),
                port: 56886,
            }]
        );
    }

    #[tokio::test]
    async fn socks5_connect_sends_format_zero_isolation_credentials() {
        let (proxy, proxy_handle) = spawn_fake_socks5_proxy(
            FAKE_SOCKS_METHOD_USERNAME_PASSWORD,
            SOCKS_REPLY_SUCCEEDED,
            b"",
            1,
        )
        .await;
        socks5_connect(proxy, ONION_HOSTNAME, 56886, "circuit-a")
            .await
            .unwrap();
        let observed = proxy_handle.await.unwrap();
        assert_eq!(observed[0].username, Some("<torS0X>0".to_string()));
        assert_eq!(observed[0].password, Some("circuit-a".to_string()));
        assert_eq!(observed[0].hostname, ONION_HOSTNAME);
    }

    #[tokio::test]
    async fn socks5_connect_reports_proxy_failure_reply() {
        let (proxy, _proxy_handle) =
            spawn_fake_socks5_proxy(FAKE_SOCKS_METHOD_NO_AUTH, 0x04, b"", 1).await;
        let error = socks5_connect(proxy, ONION_HOSTNAME, 56886, "circuit-a")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(error.to_string().contains("host unreachable"));
    }

    #[tokio::test]
    async fn socks5_connect_fails_when_proxy_is_down() {
        let proxy = unused_local_address().await;
        assert!(
            socks5_connect(proxy, ONION_HOSTNAME, 56886, "circuit-a")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn socks5_connect_rejects_empty_hostname() {
        let proxy = unused_local_address().await;
        let error = socks5_connect(proxy, "", 56886, "circuit-a")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn socks5_connect_rejects_empty_isolation_nonce() {
        let proxy = unused_local_address().await;
        let error = socks5_connect(proxy, ONION_HOSTNAME, 56886, "")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn socks5_connect_rejects_zero_destination_port() {
        let proxy = unused_local_address().await;
        let error = socks5_connect(proxy, ONION_HOSTNAME, 0, "circuit-a")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn transport_dials_onion_through_socks_proxy() {
        let (proxy, proxy_handle) =
            spawn_fake_socks5_proxy(FAKE_SOCKS_METHOD_NO_AUTH, SOCKS_REPLY_SUCCEEDED, b"", 1).await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let dial = transport
            .dial(
                ONION_MULTIADDR.parse().unwrap(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        assert!(dial.await.is_ok());
        assert_eq!(proxy_handle.await.unwrap()[0].hostname, ONION_HOSTNAME);
    }

    #[tokio::test]
    async fn transport_offers_different_isolation_nonces_for_successive_dials() {
        let (proxy, proxy_handle) = spawn_fake_socks5_proxy(
            FAKE_SOCKS_METHOD_USERNAME_PASSWORD,
            SOCKS_REPLY_SUCCEEDED,
            b"",
            2,
        )
        .await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let first_dial = transport
            .dial(
                ONION_MULTIADDR.parse().unwrap(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        assert!(first_dial.await.is_ok());
        let second_dial = transport
            .dial(
                ONION_MULTIADDR.parse().unwrap(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        assert!(second_dial.await.is_ok());
        let observed = proxy_handle.await.unwrap();
        let first_username = observed[0].username.clone().unwrap();
        let second_username = observed[1].username.clone().unwrap();
        let first_password = observed[0].password.clone().unwrap();
        let second_password = observed[1].password.clone().unwrap();
        assert_eq!(first_username, SOCKS_ISOLATION_USERNAME);
        assert_eq!(second_username, SOCKS_ISOLATION_USERNAME);
        assert!(first_password.starts_with("p2poolv2-"));
        assert_eq!(first_password.len(), 41);
        assert_ne!(first_password, second_password);
    }

    #[tokio::test]
    async fn transport_refuses_ip4_dial_without_connecting() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/{target_port}").parse().unwrap();
        assert!(matches!(
            transport.dial(
                address,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            ),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
        let accept = tokio::time::timeout(Duration::from_millis(200), target.accept());
        assert!(
            accept.await.is_err(),
            "a direct connection reached the target"
        );
    }

    #[tokio::test]
    async fn transport_refuses_dns_dial() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let address: Multiaddr = "/dns4/peer.example.com/tcp/56886".parse().unwrap();
        assert!(matches!(
            transport.dial(
                address,
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            ),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn transport_onion_dial_fails_closed_when_proxy_is_down() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let dial = transport
            .dial(
                ONION_MULTIADDR.parse().unwrap(),
                DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                },
            )
            .unwrap();
        assert!(dial.await.is_err());
    }

    #[tokio::test]
    async fn transport_refuses_non_loopback_listen() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let address: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
        assert!(matches!(
            transport.listen_on(ListenerId::next(), address),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn transport_listens_on_loopback() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        assert!(transport.listen_on(ListenerId::next(), address).is_ok());
    }

    #[test]
    fn tor_settings_accepts_proxy_off_loopback() {
        let network = NetworkConfig {
            dns_seed: false,
            proxy: Some("192.0.2.10:9050".to_string()),
            onlynet: vec!["onion".to_string()],
            ..NetworkConfig::default()
        };
        let settings = tor_settings(&network).unwrap().unwrap();
        assert_eq!(settings.proxy, "192.0.2.10:9050".parse().unwrap());
    }

    #[test]
    fn is_loopback_tcp_accepts_ipv6_loopback() {
        let address: Multiaddr = "/ip6/::1/tcp/56886".parse().unwrap();
        assert!(is_loopback_tcp(&address));
    }

    #[test]
    fn is_loopback_tcp_rejects_dns() {
        let address: Multiaddr = "/dns4/localhost/tcp/56886".parse().unwrap();
        assert!(!is_loopback_tcp(&address));
    }

    #[test]
    fn method_reply_without_acceptable_method_is_refused() {
        let error = check_method_reply([SOCKS_VERSION, SOCKS_METHOD_NONE_ACCEPTABLE]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn method_reply_with_wrong_version_is_invalid() {
        let error = check_method_reply([0x04, SOCKS_METHOD_NO_AUTH]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn connect_reply_with_wrong_version_is_invalid() {
        let error = check_connect_reply([0x04, SOCKS_REPLY_SUCCEEDED, 0x00, SOCKS_ADDRESS_IPV4])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn socks_reply_messages_follow_rfc_1928() {
        assert_eq!(socks_reply_message(0x01), "general failure");
        assert_eq!(
            socks_reply_message(0x02),
            "connection not allowed by ruleset"
        );
        assert_eq!(socks_reply_message(0x03), "network unreachable");
        assert_eq!(socks_reply_message(0x04), "host unreachable");
        assert_eq!(socks_reply_message(0x05), "connection refused");
        assert_eq!(socks_reply_message(0x06), "TTL expired");
        assert_eq!(socks_reply_message(0x07), "command not supported");
        assert_eq!(socks_reply_message(0x08), "address type not supported");
        assert_eq!(socks_reply_message(0x09), "unknown reply code");
    }

    #[tokio::test]
    async fn socks5_connect_fails_when_proxy_rejects_isolation_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD])
                .await
                .unwrap();
            let mut credentials = vec![0u8; 3 + SOCKS_ISOLATION_USERNAME.len() + "circuit-a".len()];
            stream.read_exact(&mut credentials).await.unwrap();
            stream
                .write_all(&[SOCKS_USERNAME_PASSWORD_VERSION, 0x01])
                .await
                .unwrap();
        });
        let error = socks5_connect(proxy, ONION_HOSTNAME, 56886, "circuit-a")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn discard_bound_address_skips_ipv6_address_and_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TokioTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        server.write_all(&[0u8; 18]).await.unwrap();
        server.write_all(b"x").await.unwrap();
        discard_bound_address(&mut client, SOCKS_ADDRESS_IPV6)
            .await
            .unwrap();
        let mut next = [0u8; 1];
        client.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"x");
    }

    #[tokio::test]
    async fn discard_bound_address_skips_hostname_and_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TokioTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        server.write_all(&[3]).await.unwrap();
        server.write_all(b"abc").await.unwrap();
        server.write_all(&[0, 80]).await.unwrap();
        server.write_all(b"x").await.unwrap();
        discard_bound_address(&mut client, SOCKS_ADDRESS_DOMAIN)
            .await
            .unwrap();
        let mut next = [0u8; 1];
        client.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"x");
    }

    #[tokio::test]
    async fn discard_bound_address_rejects_unknown_address_type() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TokioTcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let error = discard_bound_address(&mut client, 0x02).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn transport_removes_its_listener() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let listener_id = ListenerId::next();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        transport.listen_on(listener_id, address).unwrap();
        assert!(transport.remove_listener(listener_id));
    }

    #[tokio::test]
    async fn transport_reports_its_loopback_listen_address() {
        let proxy = unused_local_address().await;
        let mut transport = TorTransport::new(proxy, TcpConfig::default());
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        transport.listen_on(ListenerId::next(), address).unwrap();
        let event = poll_fn(|context| Pin::new(&mut transport).poll(context)).await;
        assert!(matches!(event, TransportEvent::NewAddress { .. }));
    }
}
