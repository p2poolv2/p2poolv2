
**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Stratum Password Field

This document specifies the options a miner can carry in the password
field of `mining.authorize`: what each option means, how the string is
parsed, and how a miner gets a ready made setup from the CLI.

The parsing lives in `p2poolv2_lib/src/stratum/parse_password.rs`. That
module only extracts values. Policy lives with the caller: difficulty
clamping happens in `stratum/message_handlers/authorize_response.rs`
through the session difficulty adjuster, and the share address network
check happens at authorize as well.

## Options

| Option | Value | Meaning |
|---|---|---|
| `d=<integer>` | difficulty | Sets the session start difficulty directly |
| `th=<integer>` | terahash/s | States the miner hashrate, converted to a difficulty |
| `p2p=<address>` | share chain address | Names the owner of the miner's share coinbase outputs |

If both `d=` and `th=` are present, `d=` takes priority. A zero value
is treated as absent, so `d=0` behaves like no difficulty hint at all.

### Difficulty hints

`th=` converts to difficulty with:

```
difficulty = th * 10^12 / (TARGET_DRR * 2^32)
```

`TARGET_DRR` is the target share rate, defined in
`stratum/difficulty_adjuster/mod.rs`. At the current value of 0.3 shares
per second, one terahash per second converts to a difficulty of about
776. The conversion is integer, so small hashrates round down toward
the pool minimum.

A requested difficulty is a hint, not an order. At authorize the value
is clamped by the session difficulty adjuster against the configured
`minimum_difficulty` and `maximum_difficulty` (`[stratum]` config
section), so a miner cannot opt out of the pool minimum by sending
`d=1`. With no hint, the configured `start_difficulty` applies.

## Syntax

The password is scanned for recognized options anywhere in the string,
separated by comma, space, tab or semicolon, or bounded by the start
and end of the string. Unknown text is ignored, so options can be mixed
with miner firmware extras:

```
d=500,p2p=sp2pool1p...
th=100; p2p=sp2pool1p...
D=500 p2p=sp2pool1p...
```

Parsing rules a conforming parser must match:

- Keys `d=`, `th=` and `p2p=` are matched case insensitively.
- Integer values are the digits immediately following the key; non-digit
  text before the next delimiter is ignored and does not start another
  option.
- The `p2p=` value keeps the case it was given. Lowercasing first would
  silently repair a mixed case bech32 address, which BIP173 requires
  be rejected because mixed case defeats the checksum, and would
  desynchronise byte offsets on non ASCII input.
- An option that appears with no value contributes nothing.

## The p2p option

`p2p=` names the owner of the share coinbase outputs on the share
chain. The value must be a share chain address as specified in
`address-format.md`: bech32m over a witness v1 taproot output key under
a P2Poolv2 HRP. It is not a bitcoin address and must never be derived
from one.

The full `p2p=<address>` option is 71 characters. Some miner firmware caps the
password field, and a truncated address fails its checksum rather than
silently redirecting shares elsewhere, which is exactly what the
checksum is for. A fleet that cannot carry 71 characters should use the
operator route in `address-format.md` instead.

Dumb client mode: a miner that cannot add anything meaningful to the
username or password (firmware that takes no pool credentials beyond
host, port and a fixed username) needs no `p2p=` at all. Set the share
chain address on the operator side with `[stratum] miner_address` in
the node config, and every share the pool mines is owned by that
address. The miner keeps its bitcoin PPLNS payouts through the stratum
username as usual. Because a configured address is authoritative, a
miner that does send a different `p2p=<address>` is rejected as a
conflict rather than reassigned; see "From the operator:
`[stratum] miner_address`" in `address-format.md`.

The stratum **username** remains the bitcoin payout address. These are
two different addresses on two different chains, and swapping them is
rejected rather than silently accepted.

Who wins when both the operator config and the miner password carry an
address is the resolution table in `address-format.md` under
"Supplying an address". In short: the operator's
`[stratum] miner_address` wins, a disagreement is rejected with stratum
error `UnauthorizedWorker` (code 24), and a second failure on the same
connection disconnects instead of erroring again.

## Getting a ready made setup: `new-address`

`p2poolv2_cli new-address` produces everything a miner needs from a
running bitcoind. It reads the config file (`--config`), talks to
bitcoind over JSON RPC using the `[bitcoinrpc]` section, and expects a
wallet named `miner` (override with `--wallet-name`) to exist there;
it loads it if needed but never creates one. It derives one bech32m
(P2TR) address from the wallet and prints:

```
Bitcoin Address: ...
ShareChain Address: sp2pool1p...
Taproot Output Key (hex): ac493f...
```

The bitcoin address is the stratum username and receives the PPLNS
payouts. The share chain address goes into the stratum password as
`p2p=<share chain address>` and owns the mined shares. The output key
is the taproot key the share chain address encodes. The identity lives
in the bitcoind wallet and is meant to be kept: back the wallet up
there.

Notes:

- The private key is generated inside bitcoind and never leaves it. No
  P2Poolv2 crate generates or handles private keys; see the
  "No P2Poolv2 crate generates private keys" section of
  `address-format.md`.
- The network comes from `network` in `[stratum]`; `--network` overrides
  it for the printed HRP.
- Re-running the command reuses the same wallet and mints another
  address from it. Each run is one new identity.
