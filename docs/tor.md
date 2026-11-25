# Onion-only peering over Tor

A node can keep its IP address private by connecting to share chain
peers only through Tor. This mode is opt-in, and the default TCP
transport is unchanged. See the `[network]` section of
`config.sample.toml` for the settings and the matching CLI flags.

## What it protects

- Peers see an onion address instead of your IP address. The node
  advertises only its onion address, if one is configured.
- Every outbound peer dial goes through the Tor SOCKS5 proxy. Inbound
  peers arrive through the onion service's loopback forwarder. If Tor
  is down, dials fail; the node never falls back to a direct connection.
- No local DNS lookups are made for peers: DNS seeds must be off, and
  onion names are resolved by Tor.

## What it does not hide

- Share chain addresses. Shares carry your payout addresses, so a peer
  that receives a share first from your onion address can link the
  two. Use a fresh onion service for mining, not one you use for
  anything else.
- Your Bitcoin node. Onion-only mode covers share chain peering only.
  bitcoind makes its own connections; configure it for Tor separately
  if you need that.
- Your miners. Stratum connections to your node are not affected.

## Privacy benefits and propagation trade-offs

Tor routes share chain peer traffic through encrypted circuits. Onion
service connections stay inside the Tor network and do not use an exit
relay. Onion-only peering keeps your public IP address hidden from share
chain peers and lets them connect to your node without a public TCP port
or router port forwarding, including when you are behind NAT or CGNAT.
This can make running a node more private and accessible. It does not
make mining anonymous; the limitations above still apply.

Every connection to a peer goes through a Tor circuit, which adds
latency. How much depends on the circuit, and it changes over time.
Often the delay is small compared with the time between shares, but
on a slow circuit your shares can reach the rest of the network later
than they would over a direct connection.

A share that arrives late is more likely to lose the race for its
height to a competing share. When that happens, your share can at best
be included as an uncle:

- an uncle is credited with 90% of its work instead of 100%;
- an uncle can be referenced only by a nephew at most 3 share heights
  above it, and each nephew can reference at most 3 uncles. If a losing
  share neither enters the selected chain nor is referenced before that
  eligibility window closes, it earns nothing.

If Tor delays your shares often enough to raise your uncle rate, you
earn less cumulative share value in the PPLNS window, and so a smaller
part of each block reward. Weigh this against the privacy before
enabling onion-only peering.

This cost applies when you peer with other operators' nodes, whose
shares race yours. Your own miners submit shares to your node over
stratum, which Tor does not touch.

## What stays local

The Bitcoin RPC and ZMQ clients cannot use a proxy. In onion-only mode
both must point at loopback, or ZMQ at a local IPC socket, and the node
refuses to start otherwise. For a remote Bitcoin node, provide a local
forwarder.

Configured IP blocklists must be empty. Inbound onion peers all arrive
through the loopback forwarder, so their source IP cannot distinguish
them and the node refuses to start with `blocked_ips` configured. Runtime
commands to add an IP to the blocklist are refused in onion-only mode for
the same reason.

The SOCKS proxy should normally be on loopback. A proxy on another host
may be useful as a trusted Tor gateway, but the hop to it is outside Tor:
the intervening network can see Tor use and the destination onion names.
