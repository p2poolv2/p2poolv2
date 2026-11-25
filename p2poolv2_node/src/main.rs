// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use p2poolv2_lib::config::{Config, NetworkConfig, ONLYNET_ONION};
use p2poolv2_lib::logging::setup_logging;
use std::net::SocketAddr;
use std::process::ExitCode;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env("P2POOL_CONFIG"))]
    config: String,

    /// Restrict peer connections to onion services (requires a SOCKS5 proxy and DNS seeds disabled).
    #[arg(long = "no-clearnet-p2p")]
    no_clearnet_p2p: bool,

    /// Tor SOCKS5 endpoint for onion-only peering. Overrides network.proxy.
    #[arg(long, value_name = "IP:PORT")]
    socks5: Option<SocketAddr>,

    /// Disable DNS seeds in onion-only mode; peer names are sent to the Tor proxy.
    #[arg(long)]
    no_dns: bool,

    /// Append onion peers (HOST.onion:PORT or /onion3/...); separate multiple peers with commas.
    #[arg(
        long = "addpeers",
        value_name = "PEER[,PEER...]",
        value_delimiter = ','
    )]
    add_peers: Vec<String>,
}

impl Args {
    fn apply_network_options(&self, network: &mut NetworkConfig) -> Result<(), &'static str> {
        if self.no_clearnet_p2p {
            if !network.onlynet.is_empty() && !network.is_onion_only() {
                return Err("--no-clearnet-p2p conflicts with network.onlynet; use only onion");
            }
            network.onlynet = vec![ONLYNET_ONION.to_owned()];
        }
        if let Some(proxy) = self.socks5 {
            if !network.is_onion_only() {
                return Err("--socks5 requires --no-clearnet-p2p or network.onlynet = [\"onion\"]");
            }
            network.proxy = Some(proxy.to_string());
        }
        if self.no_dns {
            if !network.is_onion_only() {
                return Err(
                    "--no-dns requires onion-only mode; use network.dns_seed = false to disable only seeds in TCP mode",
                );
            }
            network.dns_seed = false;
        }
        for peer in &self.add_peers {
            if !network.is_onion_only() {
                return Err(
                    "--addpeers in this version requires onion-only mode; use network.dial_peers for other transports",
                );
            }
            let address = if peer.starts_with("/onion3/") {
                peer.clone()
            } else {
                let (name, port) = peer.split_once(".onion:").ok_or(
                    "--addpeers expects a v3 onion hostname and port or an /onion3 multiaddr",
                )?;
                if name.len() != 56
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
                {
                    return Err("--addpeers expects a 56-character lowercase v3 onion hostname");
                }
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or("--addpeers requires a port between 1 and 65535")?;
                format!("/onion3/{name}:{port}")
            };
            if !network.dial_peers.contains(&address) {
                network.dial_peers.push(address);
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let mut config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(message) = args.apply_network_options(&mut config.network) {
        eprintln!("Invalid network options: {message}");
        return ExitCode::FAILURE;
    }

    // Hold guards to keep non-blocking writers alive
    let _guards = match setup_logging(&config.logging) {
        Ok(guards) => guards,
        Err(err) => {
            // no logger yet
            eprintln!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        "Running on {} network (git: {})",
        config.stratum.chain,
        env!("GIT_VERSION")
    );

    let (_handles, runner) = match p2poolv2_node::build_node(config).await {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };

    runner.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_addpeers_appends_only_new_onion_peers() {
        let name = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd";
        let existing = format!("/onion3/{name}:1234");
        let additional = format!("/onion3/{name}:5678");
        let peers = format!("{name}.onion:1234,{additional}");
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--addpeers",
            &peers,
        ])
        .unwrap();
        let mut network = NetworkConfig {
            dial_peers: vec![existing.clone()],
            ..NetworkConfig::default()
        };
        args.apply_network_options(&mut network).unwrap();
        assert_eq!(network.dial_peers, vec![existing, additional]);
    }

    #[test]
    fn cli_addpeers_refuses_plain_dns_in_onion_mode() {
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--addpeers",
            "peer.example:56886",
        ])
        .unwrap();
        assert!(
            args.apply_network_options(&mut NetworkConfig::default())
                .is_err()
        );
    }

    #[test]
    fn cli_no_dns_refuses_dns_capable_tcp_transport() {
        let args = Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--no-dns"]).unwrap();
        assert!(
            args.apply_network_options(&mut NetworkConfig::default())
                .is_err()
        );
    }

    #[test]
    fn cli_no_dns_disables_seeds_with_onion_peer_flags() {
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--socks5",
            "127.0.0.1:9050",
            "--no-dns",
        ])
        .unwrap();
        let mut network = NetworkConfig::default();
        args.apply_network_options(&mut network).unwrap();
        assert!(!network.dns_seed);
        assert!(network.is_onion_only());
        assert_eq!(network.proxy.as_deref(), Some("127.0.0.1:9050"));
    }

    #[test]
    fn cli_socks5_overrides_configured_proxy_in_onion_mode() {
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--socks5",
            "127.0.0.1:9150",
        ])
        .unwrap();
        let mut network = NetworkConfig {
            proxy: Some("127.0.0.1:9050".into()),
            ..NetworkConfig::default()
        };
        args.apply_network_options(&mut network).unwrap();
        assert!(network.is_onion_only());
        assert_eq!(network.proxy.as_deref(), Some("127.0.0.1:9150"));
    }

    #[test]
    fn cli_socks5_alone_does_not_enable_proxying_clearnet_peers() {
        let args = Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--socks5", "[::1]:9050"])
            .unwrap();
        assert!(
            args.apply_network_options(&mut NetworkConfig::default())
                .is_err()
        );
    }

    #[test]
    fn cli_socks5_rejects_proxy_hostnames() {
        assert!(
            Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--socks5", "localhost:9050"])
                .is_err()
        );
    }

    #[test]
    fn cli_no_clearnet_p2p_enables_onion_only_without_inventing_a_proxy() {
        let args =
            Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--no-clearnet-p2p"]).unwrap();
        let mut network = NetworkConfig::default();
        args.apply_network_options(&mut network).unwrap();
        assert!(network.is_onion_only());
        assert!(network.proxy.is_none());
    }

    #[test]
    fn cli_no_clearnet_p2p_rejects_conflicting_networks() {
        let args =
            Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--no-clearnet-p2p"]).unwrap();
        let mut network = NetworkConfig {
            onlynet: vec!["ipv4".to_owned()],
            ..NetworkConfig::default()
        };
        assert!(args.apply_network_options(&mut network).is_err());
    }

    #[test]
    fn cli_without_flag_preserves_the_configured_transport() {
        let args = Args::try_parse_from(["p2poolv2", "-c", "node.toml"]).unwrap();
        let mut network = NetworkConfig::default();
        args.apply_network_options(&mut network).unwrap();
        assert!(!network.is_onion_only());
        network.onlynet = vec![ONLYNET_ONION.to_owned()];
        args.apply_network_options(&mut network).unwrap();
        assert!(network.is_onion_only());
    }

    #[test]
    fn cli_addpeers_requires_onion_only_mode() {
        let peer = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wyd.onion:56886";
        let args =
            Args::try_parse_from(["p2poolv2", "-c", "node.toml", "--addpeers", peer]).unwrap();
        assert_eq!(
            args.apply_network_options(&mut NetworkConfig::default()),
            Err(
                "--addpeers in this version requires onion-only mode; use network.dial_peers for other transports"
            )
        );
    }

    #[test]
    fn cli_addpeers_rejects_short_onion_name() {
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--addpeers",
            "shortname.onion:56886",
        ])
        .unwrap();
        assert_eq!(
            args.apply_network_options(&mut NetworkConfig::default()),
            Err("--addpeers expects a 56-character lowercase v3 onion hostname")
        );
    }

    #[test]
    fn cli_addpeers_rejects_uppercase_onion_name() {
        let args = Args::try_parse_from([
            "p2poolv2",
            "-c",
            "node.toml",
            "--no-clearnet-p2p",
            "--addpeers",
            "2GZYXA5IHM7NSGGFXNU52RCK2VV4RVMDLKIU3ZZUI5DU4XYCLEN53WYD.onion:56886",
        ])
        .unwrap();
        assert_eq!(
            args.apply_network_options(&mut NetworkConfig::default()),
            Err("--addpeers expects a 56-character lowercase v3 onion hostname")
        );
    }
}
