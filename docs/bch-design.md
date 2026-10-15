# Bitcoin Cash design checks

Written 2026-10-13, before the startup-selection change, and updated
2026-10-14 for genesis, local Stratum V2, the AuxPoW output, the donation
and pool fee, network derivation, Stratum usernames, share transactions, and
the first live BCHN regtest run. Open questions stay open: this file does not
invent a PPLNS window length or a license change.

## Startup selection, decided in this change

`stratum.chain` chooses the template source and the payout script family.

| `chain` | Template request | Payout address |
|---|---|---|
| `bitcoin` (default) | Existing SegWit rules, plus Signet when that share-chain network is selected | `bitcoin::Address` |
| `bitcoin-cash` | BCHN request with no Bitcoin-only rules, then `BlockTemplate::validate_bch` | CashAddr for `bitcoin_cash_network` |

`bitcoin_cash_network` is `mainnet`, `chipnet`, or `regtest`. It is required
for `bitcoin-cash` and rejected for `bitcoin`. Chipnet's CashAddr prefix is
`bchtest`, which BCHN also uses for its other test networks, so the prefix
cannot tell chipnet from testnet3 or testnet4. The Bitcoin Cash RPC URL is
what points the node at chipnet.

`stratum.network` stays the share-chain network (`main`, `testnet4`,
`signet`, `regtest`) for a Bitcoin node, and that is still what selects the
Bitcoin genesis. On a Bitcoin Cash node `Config::load` and
`StratumConfig::parse` replace it with the network `bitcoin_cash_network`
implies (`BitcoinCashNetwork::legacy_network`: mainnet as `main`, chipnet as
`test`, regtest as `regtest`, whose proof-of-work limits match BCHN's). The
P2P protocol id and every difficulty calculation read that field, so two
Bitcoin Cash nodes on one network can no longer split because one left
`signet` in its file. A Bitcoin Cash node ignores it for genesis. It builds a
P2PKH share from the published BCHN genesis block for `bitcoin_cash_network`
and from `bch_share_chain` (`main` or `mini`). Mini's anchor target is
`0x1c384bd7`, 256 times easier than the main ceiling `0x1b384bd7`. Main
keeps the existing anchor `0x1b4188f5` and that same ceiling, so a Bitcoin
config that omits `chain` still starts on the taproot genesis.

A Bitcoin Cash startup that would encode a witness payout is rejected at
config parse. CashAddr decoding accepts only 20-byte P2PKH and P2SH. The
decoded script is what the existing coinbase builder pays. Token addresses
and longer hashes are rejected.

An invalid BCHN template is not forwarded to job construction. The poll and
ZMQ paths both use this check.

Stratum usernames on a Bitcoin Cash node are `<cashaddr>.<worker>`. The
CashAddr must be a 20-byte P2PKH or P2SH payout address for
`bitcoin_cash_network`; its prefix may be left out, as BCH miners commonly
do, and the checksum must still match that network's prefix. Before
2026-10-14 the username parser only read Bitcoin addresses, so no Bitcoin
Cash miner could authorize.

## Donation and pool fee, decided 2026-10-14

Decided by the maintainer: P2Poolv2 for Bitcoin Cash donates 1.5% of each
block a node finds to the project address
`bitcoincash:qze95tc2dqrnltvxfa5yhunwx5952f34fvw4g6365k`, the operator can
raise or lower it, and a public pool operator can add a fee of their own.

| Setting | Bitcoin | Bitcoin Cash |
|---|---|---|
| `donation_address` | Any payout address; required with `donation` | May be omitted. If set, must be the project address under this network's prefix |
| `donation` (basis points) | Default none | Default 150 (1.5%). Any value raises or lowers it; 0 turns it off |
| `fee_address`, `fee` | Operator's cut, both or neither | Same |
| Limits | Each at most 10,000 | Each at most 10,000, and donation plus fee at most 1,000 (10%) |

The donation key is the same on every Bitcoin Cash network: hash160
`b25a2f0a68073fad864f684bf26e350b4526354b`, shown as
`bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2` on chipnet and
`bchreg:qze95tc2dqrnltvxfa5yhunwx5952f34fvsm6us7sv` on regtest. The node logs
the donation in effect at startup.

Each share header already carries the donation and fee its node chose, and
peers rebuild the block coinbase from those fields, donation first, then the
fee on what is left, then PPLNS. Two consensus rules now bound them on
Bitcoin Cash:

- Donation plus fee at most `MAX_BITCOIN_CASH_POOL_CUT` (1,000 basis
  points). Without it a node could set a 100% fee to itself, keep every block
  it finds, and still earn from everyone else's blocks through its shares in
  the window. The 10% figure is this change's choice, not a published
  standard; lowering it later is a share-chain consensus change.
- A donation output must pay the built-in key. Otherwise the donation field
  would be a second, uncapped fee under another name.

On every chain a cut above 10,000 basis points is rejected, at config parse
and in share validation. Before this, a peer could send a header with
`donation = 65535` and the payout split would underflow and panic the
validating node; `include_address_and_cut` now also refuses such a cut
without panicking.

Bitcoin behavior is unchanged: no default donation, any donation address, and
a full donation (10,000) still skips miner address validation.

## Checklist

- **Segwit removal.** On the Bitcoin Cash paths: a template that still
  carries SegWit fields is refused, the block coinbase carries no BIP141
  witness commitment, the share coinbase is a single P2PKH output whose
  witness-commitment check is skipped, and share transactions, which would
  need Bitcoin Cash script rules, are refused. The Bitcoin code paths are
  unchanged and still the shared implementation underneath.
- **Share chain addresses.** A header stores `ShareOwner`. Bitcoin stays a
  taproot witness program. Bitcoin Cash stores a 20-byte P2PKH hash under
  tag `0x20`, addressed as CashAddr `p2pool`, `tp2pool`, or `rp2pool`. That
  string is not the payout CashAddr (`miner_bitcoin_address`). A Bitcoin Cash
  genesis share uses the same P2PKH form.
  `p2poolv2_cli bch-share-address` re-encodes a P2PKH CashAddr from the
  miner's wallet under the share prefix; it takes no private key.
- **Share trading.** Waits. The mini share chain is the stand-in named in the
  plan, and the atomic-swap scripts are not ported. No v1 code is copied.
  Share transactions are verified by `bitcoinconsensus` with Bitcoin rules,
  which would reject a Bitcoin Cash wallet's `SIGHASH_FORKID` signature and
  accept a Bitcoin legacy one, so a Bitcoin Cash share with any non-coinbase
  transaction is rejected until a Bitcoin Cash interpreter checks them. No
  node builds such shares today (`handle_stratum_share` adds none).
- **Block rules.** CTOR, compact-target agreement, witness exclusion, and the
  node size limit are checked on the template before use. The constructed
  coinbase starts with the BIP34 height push, and BCHN 29.2.0 accepted blocks
  built this way on regtest (see below). ABLA is tracked by BCHN, which
  reports the current limit as the template's `sizelimit`; this node does not
  keep ABLA state of its own. The template check counts template
  transactions, not the coinbase this node adds. BCHN fills templates only to
  `-percentblockmaxsize` of the limit (default 50% on mainnet, 100% on
  chipnet), which leaves room for a long PPLNS coinbase; an operator who sets
  100% on a full mempool risks a found block over the limit. Coinbase
  maturity (100 blocks) is BCHN's rule on the payout outputs; the share chain
  keeps its own `COINBASE_MATURITY` for share outputs.
- **Node RPC.** BCHN `getblocktemplate` is selected at startup when
  `chain = "bitcoin-cash"`. `getblocktemplatelight` stays optional and is
  not called. ZMQ `hashblock` still wakes the same template task.
- **Networks.** One code path. `bitcoin_cash_network` selects mainnet,
  chipnet, or regtest for the CashAddr prefix. New Bitcoin Cash tests use
  the regtest fixture captured from BCHN and the chipnet prefix; they do
  not require a live node.
- **Share window and difficulty.** PPLNS window length and the 10 second
  share interval are unchanged. Bitcoin Cash main and mini now have separate
  genesis shares. Mini is easier by the compact exponent above; it is not a
  retune of the PPLNS window. The window is sized in work, not in blocks:
  `bitcoin_difficulty * difficulty_multiplier`, about one block's expected
  work per unit of multiplier. The only 10 and 600 second constants
  (`IDEAL_BLOCK_TIME`, `HALFLIFE` in `sim_overrides.rs`) are the share
  chain's own ASERT, not the Bitcoin Cash block interval.
- **Faster blocks (CHIP-2025-03).** A proposal to move Bitcoin Cash to
  1-minute blocks, gathering statements for the 2027 upgrade (lock-in
  2026-11-15, activation 2027-05-15 per the research forum thread). It is
  not activated. If it activates, block difficulty falls about tenfold and
  the PPLNS window shrinks with it to about one block's expected work, which
  is the intended PPLNS behavior; the 10 second share interval stays below
  the block interval; templates change about ten times as often, which the
  ZMQ `hashblock` path already handles. The CHIP's tick-based heights and any
  change to coinbase maturity are BCHN's to enforce. Re-check its final spec
  before tuning the window for it.
- **Coinbase size.** An RFC on the research forum (2025-06, not a CHIP)
  suggests limiting the coinbase transaction to about 2 kB, roughly 60
  P2PKH outputs, and was opposed by a BCHN maintainer for the reason that it
  blocks direct coinbase payouts. Nothing limits the coinbase today beyond
  block size. If such a limit is adopted, the covenant payout tree in the
  plan becomes necessary rather than optional.
- **Stratum V2.** A local listener starts when `stratum.sv2_port` is set.
  SV1 stays. Without authority keys, frames are the unencrypted framing the
  Stratum V2 specification allows between local roles; with them, the Noise
  handshake described below is required.
  `SetupConnection` flag bit 0 (`DECLARE_TX_DATA`) selects the Job Declaration
  mode. Set, the client uses Full-Template: `DeclareMiningJob`, then
  `ProvideMissingTransactions` for every transaction, because this node has
  no mempool. Clear, `DeclareMiningJob` is rejected and `SetCustomMiningJob`
  mines the pool template. Both paths store the non-coinbase transactions in
  CTOR. Bitcoin Cash puts the AuxPoW output in
  `AllocateMiningJobTokenSuccess.coinbase_outputs`, encoded as the
  specification defines `coinbase_tx_outputs`: a CompactSize-prefixed array
  of consensus-serialized outputs (one output, count first). Bitcoin sends
  the empty array, the single byte zero. A Full-Template declaration is
  matched to its `ProvideMissingTransactionsSuccess` by request id within
  its own connection, so two clients that both start at request id 1 no
  longer collide, and a second declaration reusing a pending id is refused.
  The listener binds `hostname:port` the way SV1 does, so `localhost` and
  other host names work; a bind failure stops the node instead of leaving it
  running without the socket, and a failed accept is logged without closing
  the listener. Omitting `sv2_port` does not open the socket.

  Mining Protocol channels (2026-10-14). The listener now runs inside the
  stratum server and shares its job tracker, templates, share pipeline, and
  shutdown. A Mining connection opens standard or extended channels:
  - The SV1 coinbase is `coinbase1 | enonce1 (4) | enonce2 (8) | coinbase2`.
    An extended channel gets enonce1 as `extranonce_prefix`, rolls the 8
    enonce2 bytes, and receives `NewExtendedMiningJob` with coinbase1 and
    coinbase2 as prefix and suffix. A standard channel gets all 12 bytes and
    a `NewMiningJob` merkle root computed from them.
  - A new block tip sends the job as a future job followed by
    `SetNewPrevHash`; a refreshed template on the same tip sends an active
    job with `min_ntime`.
  - `SubmitShares*` rebuilds the header, submits it to the node when it
    meets the network target, emits it to the share chain when it meets the
    pool target, and answers success or `difficulty-too-low` against the
    channel target, the order SV1 uses. Vardiff is the SV1 adjuster, sent as
    `SetTarget` and capped at the device's `max_target`.
  - `user_identity` is `<payout address>.<worker>`, parsed as an SV1
    username (CashAddr on Bitcoin Cash). Stratum V2 has no password to carry
    `p2p=`, so shares belong to the configured `miner_address`, and a
    P2Poolv2 node without one refuses the channel
    (`share-address-required`). Binding a per-miner share address over SV2
    stays an open question.
  - Frames for channel messages carry the channel bit the specification
    requires; `SetCustomMiningJob` replies were sent without it before.
  - One connection may open 32 channels (`max-channels-reached` after
    that), because every template builds a job per channel.
  - Live check: a Python SV2 client on an extended channel mined BCHN regtest
    blocks 117 to 457 through this listener; block 300's coinbase carries the
    channel's extranonce prefix, the 1.5% donation, the 1% fee, the AuxPoW
    output, and the share commitment. A stricter run is under "Live regtest
    run" below: every block the node built from a client share had the
    client's own hash.
  - Not done: group channels, `UpdateChannel`, `CloseChannel`, and
    `SetExtranoncePrefix`.

  Noise encryption (2026-10-14). With `sv2_authority_public_key` and
  `sv2_authority_secret_key` set, every SV2 connection must complete the
  Noise NX handshake (`noise_sv2` through `codec_sv2`'s `noise_sv2`
  feature) before any message, and every frame after it is encrypted. The
  certificate carries version 0, as the specification requires, and is
  valid for `sv2_cert_validity_secs` (default 3600). Keys use the reference
  implementation's text form, checked against its published key-utils
  vectors: the secret is Base58Check of its 32 bytes, the public key Base58Check
  of version `[1, 0]` and the 32-byte x-only key. Both keys or neither, they
  need `sv2_port`, and the public key must be the one the secret derives.
  The keys come from an external tool; the node never generates one, and
  the secret is redacted from `Debug` output. The session's ephemeral and
  static keys are generated by `noise_sv2` per handshake, as Noise requires.
  A client that sends nothing within 10 seconds is disconnected. Without
  the keys frames stay unencrypted, which the specification allows only
  between local roles. Tested with a `noise_sv2` initiator: one pinning the
  authority key receives an encrypted `SetupConnection.Success`, and one
  pinning another key rejects the handshake.
- **Merge mining.** One zero-value `OP_RETURN` on the Bitcoin Cash block
  coinbase, after the payouts and before the share-commitment padding. The
  payload is the published AuxPoW commitment: magic `fa be 6d 6d`, a 32-byte
  merkle root, a little-endian tree size, and a little-endian nonce (44
  bytes). With no aux chain declared, the root, size, and nonce are zero.
  The share coinbase stays one P2PKH output. Bitcoin block coinbases omit
  the output. A per-share aux choice is not stored in the share header.

## Live regtest run, 2026-10-14

Setup: BCHN 29.2.0 (`bitcoin-cash-node-29.2.0-x86_64-linux-gnu`) on regtest
with ZMQ `hashblock`, plus a second BCHN regtest node as its only peer,
because BCHN answers `getblocktemplate` with "Bitcoin is not connected!"
when it has no peers, even on regtest. P2Poolv2 ran with `chain =
"bitcoin-cash"`, `bitcoin_cash_network = "regtest"`, `bch_share_chain =
"mini"`, `network = "signet"` left in on purpose, a configured `rp2pool:`
share address, `fee = 100`, and `sv2_port` bound through `hostname =
"localhost"`. A test CPU miner spoke Stratum V1 with a `bchreg:` username.

Observed:

- The node derived `regtest` from `bitcoin_cash_network` (P2P protocol
  `/p2pool/regtest/<genesis>/1.0.0`), logged the 1.5% donation to
  `bchreg:qze95tc2dqrnltvxfa5yhunwx5952f34fvsm6us7sv`, and opened Stratum V2
  on 127.0.0.1.
- BCHN accepted the blocks mined through the pool (height 110 to 116). The
  coinbase of block 116, decoded by BCHN: scriptSig starting with the BIP34
  push of 116; 0.75 BCH (1.5% of 50) to the donation address; 0.4925 BCH
  (1% of the remainder) to the fee address; the remainder to the PPLNS
  window; a zero-value AuxPoW `OP_RETURN` (`fabe6d6d`, zero root, size and
  nonce); the coinbase-aux and share-commitment `OP_RETURN`s. Version 2,
  303 bytes.
- The PPLNS remainder went to the genesis share's P2PKH, the NUMS key,
  because the genesis share was the only share in the window and regtest
  block difficulty is far below the mini share target. Upstream Bitcoin
  genesis pays a NUMS key the same way. On a real network the window holds
  about one block's work of real shares before a block is likely, so the
  genesis share's weight is negligible, but it is not zero until it leaves
  the window.

Header check. On regtest about half of all hashes meet the block target, so
a block BCHN accepts does not by itself show that the node rebuilt the
header the miner hashed. Both Python test miners had such a bug, found
while chasing a share that node1 did not take: the SV1 miner put the
previous block hash in the header in display order, and the SV2 miner
sometimes mined a future job before its `SetNewPrevHash`. The node's
headers were right in both cases; the blocks above were accepted because
the node's own header met the regtest target. With both miners fixed and
every share ground to a 1-in-65,536 target, so that a header mismatch would
show:

- Stratum V1, a node on commit `f97ffb7`: eight shares, eight blocks
  submitted, each with the hash the miner computed; BCHN height 692 to 700.
  The same check against the node's earlier build also matched eight of
  eight.
- Stratum V2 extended channel, the same node: 441 shares, 441 blocks
  submitted, all 441 with the client's hash; BCHN height 471 to 692 (the
  remaining blocks lost races at the same height).

First share at the mini share-chain target (2026-10-14, three nodes on
`f97ffb7`). The CPU miner found share `b39a8c24...` on node1, whose block
`0000000023dc6b8e...` BCHN accepted at height 701. Node1 relayed the share
and node2 and node3 received it, but all three rejected it: "Coinbase and
template merkle root don't match merkle root". Rebuilding the coinbase from
the stored share showed one differing byte. BCHN's template carries
`"coinbaseaux": {"flags": ""}`; the coinbase builder pushes one zero byte
for an empty or missing flags entry, but the share header recorded the
empty string as empty flags, so validators rebuilt an empty push (and a
padding output one byte longer). Bitcoin Core omits the entry, which is why
Bitcoin shares were not affected. The header now records no flags for an
empty entry (`BlockTemplate::share_coinbaseaux_flags`), and a test builds
the coinbase the builder's way from the BCHN fixture and validates it on a
Bitcoin Cash validator; that test fails without the fix with the error the
nodes logged. A share accepted into the share chain after the fix has not
been mined yet.

Not covered by this run: a share accepted into the share chain (see above),
chipnet, Stratum V2 job declaration from a real Job Declarator client, and
real ASIC firmware.

## Still unfinished

A share accepted into the share chain from live mining, two-node share
propagation on chipnet, a Bitcoin Cash script interpreter for share
transfers, a retuned PPLNS window (after CHIP-2025-03 is decided), and
per-miner share addresses over Stratum V2. A node started with `chain =
"bitcoin-cash"` validates BCHN templates, pays CashAddr scripts including
the donation and fee, records a P2PKH share owner, starts from a main or
mini P2PKH genesis, speaks both local Job Declaration modes, and commits a
reserved AuxPoW output, and BCHN has accepted blocks it built. It should not
be called a working Bitcoin Cash pool until shares have propagated between
nodes on chipnet.
