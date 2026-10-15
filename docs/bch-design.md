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
- **Share trading.** The atomic-swap scripts are not ported, and the mini
  share chain stays the stand-in named in the plan. No v1 code is copied.
  Share transfers are checked by a Bitcoin Cash interpreter
  (`shares/bch_script.rs`, 2026-10-15) instead of `bitcoinconsensus`, whose
  Bitcoin rules reject a Bitcoin Cash wallet's `SIGHASH_FORKID` signature and
  accept a Bitcoin legacy one. It accepts one spend: a P2PKH output and a
  `<signature> <public key>` input of two direct pushes, signed with
  `SIGHASH_FORKID` (`ALL`, `NONE` or `SINGLE`, optionally `ANYONECANPAY`) by
  ECDSA (strict DER, low S) or Bitcoin Cash Schnorr (64 bytes, not BIP340),
  with a compressed or uncompressed key and no witness. Spending P2SH,
  multisig, token-prefixed outputs or the atomic-swap scripts, and
  `SIGHASH_UTXOS`, are rejected, which is stricter than Bitcoin Cash. The
  outputs a transfer creates are not restricted, so a share sent to any
  other script cannot be spent on the share chain. The digest and both
  signature checks are tested against transactions BCHN 29.2.0's
  `bitcoin-tx` signed (Schnorr and ECDSA; `ALL`, `NONE`, `SINGLE` and
  `ANYONECANPAY`). No node builds shares with transfers today
  (`handle_stratum_share` adds none), the same as on Bitcoin.
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
  no mempool. Clear, `DeclareMiningJob` is rejected and the client keeps its
  transaction list private. BCH extended channels can negotiate work
  selection and install either mode. Full templates are stored in CTOR and
  require local BCHN proposal acceptance. Private templates retain the
  miner's Merkle path; the pool cannot validate hidden transactions or
  broadcast their block. Bitcoin Cash allocation returns the required PPLNS
  payout scripts with zero amounts in a CompactSize-prefixed output list;
  the final amounts follow the frozen share weights and chosen template
  revenue. Bitcoin sends an empty list. The BCH-specific coinbase and token
  contract is documented in [bch-job-declaration.md](bch-job-declaration.md).
  A Full-Template declaration is
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
    username (CashAddr on Bitcoin Cash), optionally followed by a comma,
    space, tab or semicolon and options in the SV1 password format.
    `p2p=<share address>` there binds the channel's shares to the miner's
    own share address (2026-10-15), with the SV1 authorize rules: a
    configured `miner_address` owns every share and a different `p2p=` is
    refused (`invalid-share-address`), and a P2Poolv2 node with neither
    refuses the channel (`share-address-required`).
  - Frames for channel messages carry the channel bit the specification
    requires; `SetCustomMiningJob` replies were sent without it before.
  - One connection may open 32 channels (`max-channels-reached` after
    that), because every template builds a job per channel.
  - Review fixes (2026-10-15): reading the current template for a new
    channel no longer marks it seen, which had let a template that arrived
    during a share submission skip every open channel, so they kept mining
    the old one. SV2 connections take permits from the SV1 server's
    connection limit, and a Noise handshake must finish within 10 seconds.
    `UpdateChannel` (sent by proxies such as the reference translator) caps
    the channel target and answers with `SetTarget`, and `CloseChannel`
    frees the channel; both used to close the connection.
    `sv2_cert_validity_secs` must fit the certificate's 32-bit field.
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
  nonce); the padding `OP_RETURN` that aligns the share commitment to a
  SHA256 block, and the share-commitment `OP_RETURN`. Version 2, 303 bytes.
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
nodes logged.

After the fix (2026-10-15, three nodes on `2b4ba97`): the CPU miner found
share `5d5ed9792d427e09...` on node1. Its block `000000000ff7c699...` was
accepted by BCHN at height 702, and the share is `BlockValid` on the
confirmed share chain at height 1 on all three nodes: node1 built it, node2
and node3 received it over P2P and validated it, with no validation errors
on any node. Block 702's coinbase pays 0.046875 BCH (1.5%) to the donation
address, 0.03078125 BCH (1%) to the fee address and the remainder to the
PPLNS window, then the AuxPoW, padding and share-commitment outputs.

Not covered by this run: chipnet, Stratum V2 job declaration from a real
Job Declarator client, real ASIC firmware, and a PPLNS window holding more
than the genesis share.

## Chipnet run (2026-10-15)

Setup: one BCHN 29.2.0 node synced to chipnet height 327,984 on a Windows
machine, and two P2Poolv2 nodes on it (`bitcoin_cash_network = "chipnet"`,
`bch_share_chain = "mini"`, no `miner_address`), the second dialing the
first. Both identified each other on `/p2pool/test/7b99261e/1.0.0`. A CPU
miner (cpuminer `minerd`, sha256d, 24 threads, about 150 to 240 MH/s)
mined through the first node's Stratum V1 port with a `bchtest:` username
and `p2p=<tp2pool share address>` in the password.

- The first chipnet template failed to parse: "Invalid BCH template JSON:
  missing field `depends`". BCHN lists no `depends` for template
  transactions (its templates are in canonical order), and the regtest
  fixture had no transactions, so the parser had never seen one. `depends`
  now defaults to empty; the chipnet template (height 327,985, 65
  transactions) is a new fixture, `bitcoindrpc/test_data/bchn-chipnet-template.json`.
- After the fix: shares at heights 1, 2 and 3 (tip `1d67686c...`) were built
  by the first node, relayed to the second, and `BlockValid` on both, with
  the same tip and total work on both and no validation errors in either
  log. All 7 submissions were accepted. Each share is owned by the miner's
  `tp2pool:` address from `p2p=`.
- No chipnet block was found: network difficulty was about 619,000.
- Found while checking: the API shows a Bitcoin Cash payout address
  (`miner_bitcoin_address`) in Bitcoin's Base58 form instead of CashAddr.
  It is the same key hash; only the display is wrong.

## Still unfinished

The completion audit (2026-10-15) found an unusable custom-job success id.
Both modes now install tracker/channel jobs and reach share submission in
server-handler tests, including mined regtest headers and peer-verifiable
coinbase proofs. Full templates require BCHN proposal acceptance; private
templates never substitute the pool's transactions. Independent Job Declarator
interoperability and live BCHN validation of this new path remain required.
Miners can choose a bounded aux root per declared job; auxiliary-token and
covenant proof verification remains unfinished.
Final job size now includes the full PPLNS coinbase and transaction count.
API payouts now use CashAddr text. Hydrapool CashAddr payout parsing and
SV2 worker cleanup are fixed in the completion follow-up in `bch-plan.md`.
BCH template proofs permit 25 Merkle-branch levels through storage and P2P,
with smaller header batches to keep the 1 MiB message cap. Bitcoin proofs
retain their 16-level limit. Boundary and codec tests cover these changes;
there is no live large-block result.

A retuned PPLNS window (after CHIP-2025-03 is decided). Two-node share
propagation on chipnet passed on 2026-10-15 (above). The Bitcoin Cash
script interpreter for share transfers and per-miner share addresses over
Stratum V2 were added on 2026-10-15. A node started
with `chain = "bitcoin-cash"` validates BCHN templates, pays CashAddr
scripts including the donation and fee, records a P2PKH share owner, starts
from a main or mini P2PKH genesis, handles both local declaration exchanges,
commits a reserved AuxPoW output, and on regtest builds blocks BCHN accepts
and shares that three nodes accept and relay, and on chipnet shares two
nodes accept and relay. It is still not a proven production pool: no
chipnet block has been found through it, and no real ASIC firmware or
Job Declarator client has mined against it.
