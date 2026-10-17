# Running P2Poolv2 on Bitcoin Cash

A short operator guide. Design details are in [bch-design.md](bch-design.md)
and status in [bch-plan.md](bch-plan.md). Bitcoin Cash support has passed
a two-node check on chipnet (2026-10-15) but is not yet a proven production
pool. Try it on regtest or chipnet first.

## 1. Run Bitcoin Cash Node

P2Poolv2 asks BCHN for templates over JSON-RPC and listens for new blocks
over ZMQ. In `bitcoin.conf`:

```ini
server=1
rpcuser=p2pool
rpcpassword=<your password>
zmqpubhashblock=tcp://127.0.0.1:28332
```

BCHN answers `getblocktemplate` with "Bitcoin is not connected!" until it has
at least one peer, on regtest as well. On regtest, run a second BCHN node and
connect the two.

BCHN fills templates only to `-percentblockmaxsize` of the block size limit
(50% on mainnet by default). Leave it below 100%: the pool adds a coinbase
with one output per miner in the PPLNS window, and a full template plus that
coinbase could exceed the limit.

## 2. Get your share address

A share is owned by a P2PKH key from your own wallet. Take a regular
receiving address (`q...`) for the key that should own your shares, ideally
not your payout address, and re-encode it:

```sh
p2poolv2_cli bch-share-address --network mainnet bitcoincash:q...
# p2pool:q...
```

Use `--network chipnet` (`bchtest:` to `tp2pool:`) or `--network regtest`
(`bchreg:` to `rp2pool:`) on the test networks. The command takes no private
key.

## 3. Configure the node

Start from `config.sample.toml` and set, under `[stratum]`:

```toml
chain = "bitcoin-cash"
bitcoin_cash_network = "mainnet"   # or "chipnet", "regtest"
bch_share_chain = "mini"           # "main" for large miners
miner_address = "p2pool:q..."      # from step 2
bootstrap_address = "bitcoincash:q..."
```

`network` is ignored on Bitcoin Cash; the node uses the network
`bitcoin_cash_network` implies, so all nodes on one network agree.

Point `[bitcoinrpc]` at BCHN's RPC port and `zmqpubhashblock` at its ZMQ
endpoint.

### Donation and pool fee

By default each block this node finds donates 1.5% (150 basis points) to the
P2Poolv2 Bitcoin Cash address
`bitcoincash:qze95tc2dqrnltvxfa5yhunwx5952f34fvw4g6365k`. Change it with
`donation` (basis points; 0 turns it off). A public pool operator adds their
own cut with `fee_address` and `fee`. Donation plus fee may not exceed 1,000
basis points (10%): other nodes reject shares above that. The node logs the
donation in effect at startup.

### Stratum V2

Set `sv2_port` to serve Stratum V2 beside Stratum V1. Mining connections open
standard or extended channels with `user_identity = "<payout address>.<worker>"`;
their shares belong to `miner_address`. When `miner_address` is unset, each
miner names its own share address after the username, as the Stratum V1
password does: `user_identity = "<payout address>.<worker>,p2p=<share address>"`.
A `p2p=` that differs from a configured `miner_address` is refused with
`invalid-share-address`. Job Declaration connections are served too.

Without keys, Stratum V2 frames are unencrypted, which the specification
allows only between local roles; keep the port on localhost or a trusted LAN.
To require Noise encryption, set an authority key pair made with an external
tool (for example the Stratum V2 reference implementation's key utility):

```toml
sv2_authority_public_key = "9b..."
# secret via env: P2POOL__STRATUM__SV2_AUTHORITY_SECRET_KEY=...
sv2_cert_validity_secs = 3600
```

Miners then pin the public key.

## 4. Point miners at the node

Stratum V1:

```
url:      stratum+tcp://<node>:3333
user:     <payout CashAddr>.<worker>      (the bitcoincash: prefix is optional)
password: x                                (or p2p=<share address> if miner_address is unset)
```

Stratum V2: `<node>:<sv2_port>`, user identity `<payout CashAddr>.<worker>`
(add `,p2p=<share address>` if `miner_address` is unset), and the authority
public key when Noise is enabled.

Pool-issued standard and extended jobs are supported. BCH extended channels
also support work selection with both Job Declaration modes. A BCH-aware
declarator must follow the direct PPLNS coinbase contract in
[bch-job-declaration.md](bch-job-declaration.md). Full-Template work requires
local BCHN proposal validation; a Coinbase-Only declarator validates and
broadcasts its own private block. Both modes have passed the encrypted
two-node BCHN regtest, including proof verification and an experimental
SAFA token withdrawal. Independent declarator/ASIC interoperability, final
SAFA policy, chipnet issuance and remote CI remain open in
[bch-plan.md](bch-plan.md).

Payouts appear in the miners' wallets in the coinbase of each block the pool
finds and become spendable after 100 blocks, as for any Bitcoin Cash
coinbase.

## 5. Check two nodes on chipnet

This check passed on 2026-10-15 (see [bch-design.md](bch-design.md#chipnet-run-2026-10-15)).
It needs a machine that can reach BCH peers on port 48333.

1. Run BCHN with `chipnet=1`, `server=1` and `zmqpubhashblock`, and let it
   sync (`bitcoin-cli -chipnet getblockchaininfo`).
2. Start two P2Poolv2 nodes with `bitcoin_cash_network = "chipnet"`, the
   same `bch_share_chain`, their own `store` paths and ports, and
   `dial_peers` on the second pointing at the first's `listen_address`.
   Both logs should show `Identified Peer ... /p2pool/test/<genesis>/1.0.0`
   with the same genesis id. On a new share chain the genesis share is old,
   so the first node never counts its chain as current: set
   `wait_for_chain_sync = false` there or its Stratum port never opens.
3. Point a miner at the first node's Stratum port with a `bchtest:` username.
   A share needs about 2e10 hashes on the mini chain (stratum difficulty
   about 4.7), so a CPU miner needs `start_difficulty` and
   `minimum_difficulty` near 1; at the sample's 100000 it would almost never
   submit. 24 CPU threads (about 150 MH/s) found a share every minute or
   two; a small ASIC finds them in seconds.
4. Pass: `curl http://<api>/chain_info` on both nodes shows the same
   `chain_tip_height` above 0, and neither log has `Chain-context validation
   failed`. A block found on chipnet appears in BCHN with the 1.5% donation
   output first.
