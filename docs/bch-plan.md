# P2Poolv2 for Bitcoin Cash: implementation plan

Status: implementation in progress. Written 2026-10-08 from design discussions
with the maintainer of [Pickaxe](https://github.com/CyberAshven/pickaxe-miner).
Audience: contributors and AI agents starting the BCH port. Read
[AGENTS.md](../AGENTS.md) and `docs/architecture/` before changing code.

## Current requirement checks (2026-10-16)

| Requirement | Status and evidence |
|---|---|
| BCHN templates and CashAddr payouts | Implemented; RPC/transaction fixtures and address tests. Final job size includes the actual coinbase and CompactSize transaction count. |
| Donation, operator fee and bootstrap accounting | Implemented; exact-amount tests and recorded BCHN regtest coinbases. Hydrapool accepts prefixed and prefixless CashAddr usernames. |
| P2PKH share ownership and transfers | Implemented; BCHN-signed ECDSA/FORKID and BCH Schnorr vectors, plus rejection tests. |
| Main/mini share chains and P2P propagation | Implemented; recorded three-node regtest and two-node chipnet share validation. |
| Large BCH template proofs | Implemented; 25-level BCH branches round-trip through share blocks, storage and compressed header batches. Bitcoin proof validation keeps its 16-level limit. |
| Pool-issued SV1/SV2 jobs and worker cleanup | Implemented; recorded CPU mining plus channel and socket tests. Independent ASIC firmware remains unverified. |
| CashAddr text in the API | Implemented; P2PKH/P2SH vectors and a chipnet share lookup test. |
| Declared BCH coinbase peer validation | Implemented; bounded header extension, prefix/aux proof tampering, payout diversion, storage and compressed-header tests. |
| Mineable Job Declaration in both modes | Encrypted loopback regression covers both modes with mocked BCHN. Separately, two real BCHN regtest nodes accepted Full-Template and private Coinbase-Only blocks, with verifiable emitted coinbase proofs. Independent client interoperability remains pending. |
| Miner-selected auxiliary commitments | Bounded shared trees and full coinbase/header proofs are implemented. An experimental SAFA variant verifies the proof inside the BCH VM and paid tokens in a real two-node regtest. Final SAFA policy, independent covenant review and chipnet issuance remain open. See [bch-auxpow.md](bch-auxpow.md). |
| PPLNS tuning and independent ASIC/JD interoperability | Pending; retain the existing settings until a justified tuning decision. |
| Remote CI and chipnet block | No GitHub Actions runs on this fork; no chipnet block found. Local checks and recorded propagation do not replace these. |

## Implementation checkpoint (2026-10-13)

The first checkpoint adds BCHN template fetching without Bitcoin SegWit or
Signet rules, parses BCH templates without Bitcoin-only fields, and validates
transaction bytes, IDs, CTOR, targets and basic block limits before use.
Malformed node data now returns errors through merkle and block construction
instead of panicking. Bitcoin template requests retain their existing rules.

A fixture captured from BCHN 29.2.0 on disposable regtest backs the parser and
RPC tests. The Windows workspace passed 1,491 tests (one skipped), formatting,
and Clippy with all targets and features and warnings denied. Native Windows
builds used `SECP256K1_STATIC` and `ENABLE_MODULE_ELLSWIFT` compiler defines;
no dependency source or consensus checks were disabled.

Startup now selects the template source. `chain = "bitcoin-cash"` with
`bitcoin_cash_network` set to mainnet, chipnet, or regtest asks BCHN for a template
and accepts CashAddr P2PKH and P2SH payouts for that prefix. Bitcoin
configuration is unchanged when `chain` is omitted.

A share header stores either a Bitcoin taproot witness program or a Bitcoin
Cash 20-byte P2PKH hash. Taproot bytes are unchanged: version, length, then
the program. The cash form starts with tag `0x20`, which is not a witness
version, so a Bitcoin decoder rejects it. Cash share addresses are CashAddr
P2PKH under `p2pool`, `tp2pool`, and `rp2pool`. The coinbase pays that P2PKH
script and does not add a BIP141 witness commitment. Stratum `p2p=` on a
Bitcoin Cash node parses that CashAddr form. Payout CashAddr and Bitcoin
bech32m share addresses are rejected there.

Still unfinished: live regtest or chipnet mining. Local Stratum V2 now
serves both Job Declaration modes when `sv2_port` is set, and a Bitcoin
Cash block coinbase carries one reserved AuxPoW output. The upstream
Bitcoin test suite passing does not validate live BCH mining.

## Implementation checkpoint (2026-10-14)

A live BCHN 29.2.0 regtest node accepted blocks built by this node from its
own templates and mined through its Stratum V1 port: BIP34 height, CashAddr
P2PKH payouts, the 1.5% donation, an operator fee, the AuxPoW output, and the
share commitment were all in a coinbase BCHN took. Details and what that run
did not cover are in [bch-design.md](bch-design.md#live-regtest-run-2026-10-14).

Operators: see [bch-quickstart.md](bch-quickstart.md) for BCHN settings,
the node config, share addresses, the donation and fee, and miner settings.

Also in this checkpoint:

- Bitcoin Cash donates 1.5% by default to the project address, adjustable
  by the operator, with an optional operator fee and a 10% consensus cap on
  the two together (decision 9 below).
- Stratum usernames accept CashAddr payouts. Before this no Bitcoin Cash
  miner could authorize.
- `stratum.network` on a Bitcoin Cash node is derived from
  `bitcoin_cash_network`, so nodes on one network cannot split on it.
- Bitcoin Cash shares carry no transfers until a Bitcoin Cash script
  interpreter checks them.
- `p2poolv2_cli bch-share-address` gives a miner their share address.
- The three open Stratum V2 review findings are fixed (request ids per
  connection, host-name bind that stops the node on failure, counted
  `coinbase_outputs`).
- Stratum V2 Mining Protocol channels, standard and extended, share the SV1
  job tracker and share pipeline (decisions 2 and 7). A Python SV2 client
  mined BCHN regtest blocks through them. Shares belong to the configured
  `miner_address`; per-miner share addresses over SV2 stay open.
- Stratum V2 Noise encryption with the operator's authority key
  (`sv2_authority_public_key`, `sv2_authority_secret_key`), decision 2.

On 2026-10-15 a share mined on BCHN regtest was accepted into the share
chain by three nodes, after a fix for BCHN's empty coinbase flags entry,
which had made every node reject the first such share (details in
[bch-design.md](bch-design.md#live-regtest-run-2026-10-14)).

Still unfinished: two-node share propagation on chipnet, a retuned PPLNS
window, a Bitcoin Cash script interpreter for share transfers, and
per-miner share addresses over Stratum V2.

## Implementation checkpoint (2026-10-15)

- A Bitcoin Cash script interpreter checks share transactions
  (`shares/bch_script.rs`, `shares/bch_sighash.rs`), so a Bitcoin Cash share
  may carry transfers again. It accepts P2PKH spends signed with
  `SIGHASH_FORKID` by ECDSA or Bitcoin Cash Schnorr and rejects every other
  script. Transactions signed by BCHN 29.2.0's `bitcoin-tx` back its tests.
  Details in [bch-design.md](bch-design.md).
- A Stratum V2 miner names its own share address with `p2p=` after the
  username in `user_identity`, under the SV1 password rules.
- An independent review of the 2026-10-14 Stratum V2 commits found that a
  template arriving during a share submission could skip a connection's
  channels, that the SV2 port had no connection limit, and that
  `UpdateChannel`/`CloseChannel` closed the connection. All three are
  fixed (details in [bch-design.md](bch-design.md)). The review found no
  consensus or payout bug in the donation, fee and coinbase flags commits.

- Two-node share propagation on chipnet passed: two P2Poolv2 nodes on one
  synced BCHN chipnet node accepted and relayed shares at heights 1 to 3
  mined by a CPU miner, with no validation errors. The first chipnet
  template exposed a parser bug (BCHN omits `depends`), now fixed. Details
  in [bch-design.md](bch-design.md#chipnet-run-2026-10-15).

## Completion follow-up (2026-10-15)

Hydrapool payout calculation now reads stored Bitcoin Cash usernames with
the same CashAddr parser as authorization, including prefixless usernames.
Equivalent names combine into one payout script. A wrong-network address
fails the distribution. With no shares, Bitcoin Cash keeps its donation and
fee outputs and pays only the remainder to the bootstrap address. Bitcoin's
existing bootstrap policy is unchanged.

Stratum V2 closes its authorized workers on `CloseChannel`, disconnect,
protocol errors and shutdown. Shared SV1/SV2 worker identities stay active
until their last connection or channel closes. Tests cover CashAddr P2PKH
and P2SH payouts, exact donation/fee amounts, wrong networks, shared worker
identities, and a real socket disconnect releasing its worker and permit.

Local validation: 1,651 workspace tests passed (1 skipped); 1,659 tests
passed with all features (1 skipped). Clippy passed for all targets and
features with warnings denied, and formatting passed. The all-features
build also fixes the simulator's share-owner conversion and checks its
existing block-submission suppression policy.

The follow-up also checks final BCH job size with the actual PPLNS
coinbase, including padding/commitments and the CompactSize transaction
count. Exact-limit and one-byte-over tests cover the transaction-count
encoding boundary. Share lookup returns network-correct CashAddr payout
text; existing Bitcoin text is unchanged.

After these changes: 1,659 default workspace tests and 1,667 all-features
tests passed (1 skipped in each suite), with all-target/all-feature Clippy
warnings denied and formatting clean.

At this checkpoint, the audit found that
`Sv2Connection::on_custom_job` returned a success id without installing a
job in `MiningChannels`. It now refuses work-selection negotiation with
`unsupported-feature-flags` and rejects a custom-job request with
`job-not-yet-validated` (or `invalid-mining-job-token` for an invalid token).
These errors mean the node has not committed to rewarding declared work.
Both ready declaration modes have rejection coverage. Declaration-message
tests and pool-issued SV2 mining tests do not prove mineable declarations.

The subsequent coinbase and mining changes below add bounded declarations,
token validation and channel/tracker installation. The current requirement
table records the remaining independent validation and auxiliary-proof work.

Other pending work is in the requirement table above. This port is not complete.

The completion audit also found a Bitcoin-sized 16-level coinbase branch
cap in proof verification, share decoding and stored/header-batch branches.
BCH now permits 25 levels, covering BCHN 29.2.0's 2 GB context-free maximum
and 65-byte minimum transactions ([source](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/v29.2.0/src/consensus/consensus.h)).
Bitcoin proof validation and share-block decoding keep their existing
16-level cap. Header responses carry at most 700 headers before completing
the final height, so even distinct maximum-size branches fit the existing
1 MiB message cap; the worst-case message-size regression still passes.
Proof tests accept the exact limits and reject the next level. No large
block was mined for this check.

Final local checks after the proof change: 1,663 default workspace tests
and 1,671 all-features tests passed (1 skipped each). Clippy passed with all
targets/features and warnings denied; formatting passed.

## Declared BCH coinbase validation (2026-10-15)

Declared jobs need a different scriptSig layout: SV2 appends the extranonce
after the miner's raw prefix. `BchCoinbase` records that prefix and the single
aux-tree commitment. The share commitment hashes both, and peer payout
validation reconstructs the exact PPLNS outputs, padding and commitment tail.
Changing a payee, prefix or aux choice invalidates the share. Declared jobs
retain transaction version 2, sequence `0xfffffffe` and locktime `height - 1`.
The prefix is at most 88 bytes, leaving 12 bytes for the extranonce under
BCH's 100-byte coinbase scriptSig limit.

The new header uses marker `0x21` before its normal cash owner encoding and
appends the bounded descriptor after its coinbase proof. Existing Bitcoin
headers, BCH headers without a declaration, and genesis encodings stay
unchanged. Older binaries reject the new marker: peers must upgrade before
mining declared jobs. Existing stored headers require no rewrite. Header
responses now stop at 650 entries before completing the last height, keeping
the worst case with the descriptor and 25-level branches under 1 MiB.

This checkpoint supplied peer validation and storage support. Custom-job
installation was completed in the subsequent change below.

Local validation after this change: 1,669 default workspace tests and 1,677
all-features tests passed, with one skipped in each suite. Clippy passed for
all targets/features with warnings denied; formatting passed. The descriptor
was checked through serialization, storage and payout validation, not through
a live declared-job miner.

## Declared BCH mining channels (2026-10-15)

Both Job Declaration modes now install real extended-channel jobs. Allocation
freezes the PPLNS weight snapshot and exposes bounded job terms in an
unpredictable, expiring, single-use token. A changed transaction fee total
recomputes every payment from the same weights and cuts used by peer
validation. A custom job must match its frozen template anchor, header rules,
coinbase layout and exact payouts before receiving a mineable job id.

Full-Template work preserves the declared coinbase, verifies its transaction
Merkle path and requires local BCHN proposal acceptance before installation.
Coinbase-Only work keeps the miner's private Merkle path; its transaction list
is never replaced with the pool cache, and its declarator must validate and
broadcast the full block. Both modes can choose the bounded auxiliary-tree
commitment. See [bch-job-declaration.md](bch-job-declaration.md) for client rules
and limits.

Server-handler coverage performs both exchanges, mines actual regtest-target
headers and verifies their emitted coinbase proofs. The RPC is mocked in that
test; it is not evidence of live BCHN or independent client interoperability.

Local validation: 1,684 default workspace tests and 1,692 all-features tests
passed, with one skipped in each suite. Clippy passed for all targets and
features with warnings denied, and formatting passed. Additional cases cover
node proposal rejection, token expiry/reuse/limits, declaration and payment
tampering, and the 255-byte token budget with the maximum uncle count.

## Declared-job BCHN validation (2026-10-15)

The opt-in two-node test in `stratum/sv2/live_tests.rs` passed against BCHN
29.2.0. The pool installed and submitted a Full-Template block containing a
wallet transaction. For Coinbase-Only, neither node's mempool held the private
transaction: the pool accepted its header without submitting an incomplete
block, then both BCHN nodes accepted the full block broadcast by the client.
Both emitted coinbase proofs reconstruct their mined Merkle roots. BCHN
rejected a copy paying one extra satoshi with `bad-cb-amount`.

The repeated run found blocks at heights 205 and 206. Each paid 2,500,000,219 satoshis
across the PPLNS outputs, including 219 satoshis in transaction fees. Block
hashes and reproducible setup are in
[bch-job-declaration.md](bch-job-declaration.md#two-node-bchn-regtest-check).
This test drives mining handlers directly; independent client, encrypted
network Job Declaration and ASIC interoperability remain separate checks.

SV2 jobs now retain their assigned target and credited difficulty when vardiff
or `UpdateChannel` changes later work. A regression reproduced the old behavior:
a job assigned difficulty 5 was credited as 99 after an update. Standard and
custom jobs use the same corrected insertion path, including the device's
maximum target. Zero targets are refused at channel opening and update.

The combined workspace, including the CashAddr API follow-up, passed 1,705
default tests (two skipped) and 1,713 all-features tests (one skipped). The
opt-in BCHN check was run separately. All-target Clippy passed with default
and all features, with warnings denied, as did formatting.

## Auxiliary work proofs (2026-10-16)

The shared verifier now builds bounded sparse trees for up to 64 selected
work items and checks each inclusion proof through the full coinbase to the
parent header, against independently supplied work and target. The offline
`bch-auxpow build` and `verify` commands use that same implementation. Exact
hash ordering, collision handling and transport limits are documented in
[bch-auxpow.md](bch-auxpow.md).

Both BCHN regtest nodes accepted Full-Template block 207 with two selected
items and private Coinbase-Only block 208 with one. Their exported proofs
also passed the built CLI; a wrong chain id and a target of one were refused.
These synthetic work items do not prove token issuance. SAFA is the selected
covenant target, and its draft needs an AuxPoW variant and unsigned hash
comparison before that requirement can pass.

With the concurrent address-renderer cleanup included: 1,719 default
workspace tests passed (two skipped), and 1,727 all-features tests passed
(one skipped). All-target Clippy passed with default and all features, with
warnings denied. Formatting and whitespace checks passed. The two-node
opt-in test passed separately. Independent clients/ASICs, the SAFA covenant,
remote CI and a chipnet block remain unverified or incomplete.

## SAFA reference covenant (2026-10-16)

The first auxiliary-token adapter now has an executable covenant, pinned
Libauth BCH 2026 VM, offline work/unlock commands and 39 passing tests.
It binds category, covenant identity, previous baton and next baton to the
shared work leaf. The covenant checks both Merkle paths, full coinbase,
unsigned target, exact token reward, subsidy, recipient, CSV/CLTV and
disjoint output groups. Its unchanged-baton market path remains available.

The opt-in two-node JD test committed real SAFA-variant work in blocks 280
and 281. Both proofs passed Rust and covenant verification. BCHN then
accepted a withdrawal paying 1,000 tokens and continuing the mutable NFT
with 419,999,000 tokens in block 282. An altered Merkle sibling was refused.
The scriptSig was 1,266 bytes with a 839-byte redeem script; the standard
VM also accepts both maximum Merkle depths and the exact 10,000-byte budget.
Public genesis/withdrawal/proof vectors are replayed in the offline suite.

This is an experimental SAFA variant, with its full rules and reproduction
steps in [tools/safa-auxpow](../tools/safa-auxpow/README.md). The published
draft's conflicting virtual-reserve multipliers need agreement before any
real issuance. Independent covenant review, chipnet issuance, independent
ASIC/JD interoperability and remote CI remain open. The Rust CI definition
now includes the covenant tests; no remote run is claimed.

## Encrypted Job Declaration checkpoint (2026-10-16)

The existing both-mode declaration regression now runs through the actual
Noise listener, using separate authenticated TCP connections for mining,
Full-Template declaration and Coinbase-Only allocation. It checks token reuse
rejection, transaction requests, installed jobs, mined headers, emitted proofs,
Full-Template RPC policy, private transaction handling and connection cleanup.
The 5,000-byte declaration also exercises decoding across listener reads.
The BCHN RPC is mocked; independent client/ASIC and combined encrypted-network
with live-node interoperability remain unverified. See
[the network regression](bch-job-declaration.md#encrypted-network-regression).

Local Windows validation passed: 1,719 default workspace tests (two skipped),
1,727 all-features tests (one skipped), all-target Clippy in both configurations
with warnings denied, formatting and `git diff --check`.

## Startup selection (2026-10-13)

Design checks for every porting item are in [bch-design.md](bch-design.md).
Open questions there stay open.

`stratum.chain = "bitcoin-cash"` now selects the BCHN template request at
node startup, on both the poll and ZMQ paths, and drops a template that
fails BCH validation. `bitcoin_cash_network` is `mainnet`, `chipnet`, or
`regtest`. Payout, donation, fee, and solo addresses on that chain must be
CashAddr for the selected prefix (`bitcoincash`, `bchtest`, `bchreg`).
Chipnet uses `bchtest`. A Bitcoin witness payout is rejected so it cannot
be written into a Bitcoin Cash coinbase.

The share-chain `network` field still selects the Bitcoin genesis. On
`bitcoin-cash`, genesis is a P2PKH share anchored at the published BCHN
genesis block. `bch_share_chain` is `main` or `mini`. A configured
`miner_address` is a CashAddr share address (`p2pool`, `tp2pool`, or
`rp2pool`) and the header stores that P2PKH hash. `sv2_port`, when set,
opens a local unencrypted Stratum V2 listener beside SV1. Both Job
Declaration modes keep CTOR, and a Bitcoin Cash block coinbase carries one
reserved AuxPoW output. Noise, a retuned PPLNS window, and a per-share aux
choice are not part of this. Live regtest or chipnet mining is still
unfinished. This is still not a working Bitcoin Cash pool.

## Goal

A peer-to-peer Bitcoin Cash mining pool built from P2Poolv2: miners
coordinate without an operator, and every block's coinbase pays the miners
directly. Pickaxe will run it for its users the way Gupaxx runs P2Pool for
Monero: the user's own node plus a local share chain, behind one setup
screen. Pool operators may use the same software too, while the aim is to
move most BCH hashrate to the share chain.

## Decisions so far

1. **Base.** Fork P2Poolv2 (Rust, MIT/Apache-2.0) and port the Bitcoin
   specifics to BCH. Take what is needed from P2Pool v1 for BCH
   ([jtoomim/p2pool](https://github.com/jtoomim/p2pool), and
   [BitcoinCash1/p2poolBCH](https://github.com/BitcoinCash1/p2poolBCH), a fork
   of frstrtr's): both are GPL-3.0, so copying their code (not just their
   ideas) changes this fork's license; see open questions.
2. **Miner protocol: Stratum V2 first.** Encryption with an authenticated
   server key, binary framing, standard and extended channels, and Job
   Declaration, added the way ckpool added SV2 beside SV1. P2Poolv2's current
   stratum server is SV1; nothing about it needs to stay hardcoded. SV1
   remains only for firmware that cannot speak SV2 (Pickaxe already
   translates SV1 devices). Prior art:
   [average-gary/sv2-p2pool](https://github.com/average-gary/sv2-p2pool), an
   SV2 pool with P2Poolv2's share chain as its backend, "usable on testnet4".
3. **Job Declaration: both modes.** Full-Template and Coinbase-only, because
   miners and pools are in transition. On BCH, declared jobs must keep
   canonical transaction order (CTOR), or they declare invalid blocks.
4. **Payouts: direct in the coinbase, no ledger, no custody.**
   - PPLNS: a share enters a sliding window (the "conveyor belt"; Monero's
     P2Pool uses 2,160 share-chain blocks, about 6 hours). While the share is
     in the window, it earns a slice of every block found.
   - Payouts appear in the miners' wallets with the block and become
     spendable after 100 blocks (BCH consensus, about 17 hours).
   - A miner who stops keeps earning from blocks found while their shares
     are in the window; then the shares slide out. Nothing is held, kept or
     expired.
   - Dust: each share is worth a slice of a full block reward, far above
     BCH's dust limit, so nothing accumulates.
   - Small miners' variance: a main and a "mini" share chain with lower
     share difficulty, as Monero's P2Pool has (main, mini, nano), plus uncles
     (P2Poolv2 already has them).
   - Optional later: a keyless covenant payout tree in one coinbase output
     (BCH introspection can check the spending transaction's outputs), only
     if the number of coinbase outputs becomes a problem.
5. **Merge mining.** Reserve one coinbase commitment output whose hash covers
   every token the miner chose to merge-mine (AuxPoW-style); each token's
   covenant checks a short proof up to it. The share chain fixes the payouts;
   each share's token choice is free within a size budget. This is what lets
   Pickaxe users choose their tokens.
6. **Templates from the miner's own node.** BCHN over local JSON-RPC
   (`getblocktemplate`, or `getblocktemplatelight` with `submitblocklight`),
   or Knuth (its C API in-process, or its Stratum V2 Template Distribution
   once complete). Any local inter-process link works; Cap'n Proto is not
   required by the Stratum V2 specification.
7. **Interface with Pickaxe: Stratum V2 is the boundary.** The P2Pool node
   acts as an SV2 pool and job declarator; Pickaxe connects the devices (SV2
   directly, SV1 through its adapter) and the user's node, and can start the
   P2Pool node in the background. Pickaxe's default will be the most
   decentralized option: the local share chain plus the user's own node.
8. **Not adopted.** DATUM-style designs, where an operator sets the coinbase
   outputs and holds small balances, keep the central infrastructure this
   project wants to remove.
9. **Donation and pool fee (2026-10-14).** Every Bitcoin Cash node donates
   1.5% of each block it finds, from the coinbase, to the project address
   `bitcoincash:qze95tc2dqrnltvxfa5yhunwx5952f34fvw4g6365k` unless its
   operator changes it: `donation` raises or lowers the basis points and 0
   opts out. The address is fixed in the share chain's rules, so a donation
   cannot be redirected. Public pool operators set their own `fee_address`
   and `fee`. Donation plus fee is capped at 10% by share-chain consensus so
   no node can take a block's reward from the miners in its window.
10. **Rust stays the implementation.** Ideas from P2Pool v1, CashStratum and
    other BCH software are reimplemented in Rust here, never ported back as
    Python or C.

## BCH porting checklist

Found by reading P2Poolv2's code and docs; each item needs a short design
check before code.

- **Segwit removal.** Witness commitment, wtxid handling and witness data in
  compact blocks: `p2poolv2_lib/src/shares/` (`compact_block.rs`,
  `share_commitment.rs`, `transactions/coinbase.rs`, `handle_stratum_share.rs`,
  `share_block/`) and `p2poolv2_lib/src/node/` (`emission_worker.rs`,
  `messages.rs`).
- **Share chain addresses.** Today bech32m over a Taproot (P2TR) key
  (`docs/architecture/address-format.md`, `p2poolv2_wallet`). BCH has no
  Taproot: choose a BCH form (for example CashAddr over a Schnorr key).
- **Share trading.** The atomic-swap scripts for selling shares
  (`docs/atomic-swap/`) need BCH scripts, or the feature waits while the mini
  share chain covers small miners.
- **Block rules.** CTOR (lexicographic transaction order), no block weight
  (BCH's adaptive block size limit, ABLA), BIP34 height, ASERT on the main
  chain, 100-block coinbase maturity, CashAddr payout scripts.
- **Node RPC.** BCHN's `getblocktemplate` has no segwit fields; the light
  calls are optional; BCHN supports ZMQ `hashblock`.
- **Networks.** BCH mainnet, chipnet and regtest as one code path with a
  network switch; new work is tested on chipnet first.
- **Share window and difficulty.** Tune the PPLNS window and share interval
  for BCH's 10-minute blocks; keep every share above dust; define the main
  and mini share chains. Share difficulty already uses ASERT
  (`docs/difficulty_adjustment/`).
- **Stratum V2 server.** On the reference crates (`stratum-core`), beside or
  instead of SV1, with both Job Declaration modes.

## Open questions

- License: if v1 code is copied, relicense the fork as GPL-3.0 or AGPL-3.0
  (AGPL-3.0 matches Pickaxe).
- PPLNS window length, share interval and share difficulty for the main and
  mini share chains. Wait for the outcome of CHIP-2025-03 (1-minute blocks,
  lock-in 2026-11-15) before tuning; the window already scales with block
  difficulty.
- Whether 10% is the right consensus cap on donation plus fee.
- Which scripts beyond P2PKH the share-chain interpreter should accept
  (P2SH, the atomic-swap scripts, `SIGHASH_UTXOS`); P2PKH transfers with
  `SIGHASH_FORKID` ECDSA or Schnorr are checked since 2026-10-15.
- Keep P2Poolv2's share trading on BCH, or rely on the mini share chain.
- Merge-mining commitment format and size budget (Stratum V2's
  `CoinbaseOutputConstraints` already declares coinbase space).
- Binding each miner's payout address to their shares over SV2 (sv2-p2pool
  lists it as open, its ADR 0002). Since 2026-10-15 a `p2p=` option in
  `user_identity` names the share address, as the SV1 password does; a
  signed binding a miner could prove is still open.
- Whether the covenant payout tree is needed at all; prove it within BCH's VM
  limits first.
- Pool operators running this software beside the share chain.

## First steps

1. Read `AGENTS.md` and `docs/architecture/`; build and run the tests on
   Bitcoin signet unchanged.
2. Write a design check for each porting item.
3. Build a BCHN regtest and chipnet harness.
4. Implement in small pull requests, each verified on regtest and chipnet.

## Sources and how they were checked

Checked on 2026-10-05 and 2026-10-08 by web search, by reading the pages and
specifications below, and through the GitHub API (repository, code, pull
request, issue and branch searches). Re-check anything marked open or pending
before relying on it.

Stratum V2:

- Specification: [protocol overview](https://stratumprotocol.org/specification/03-protocol-overview/),
  [Mining Protocol](https://stratumprotocol.org/specification/05-mining-protocol/),
  [Job Declaration](https://stratumprotocol.org/specification/06-job-declaration-protocol/).
- Reference implementation: https://github.com/stratum-mining/stratum ,
  applications https://github.com/stratum-mining/sv2-apps , Umbrel UI
  https://github.com/stratum-mining/sv2-ui .
- Coinbase payouts extension (open, updated 2026-09-15):
  https://github.com/stratum-mining/sv2-spec/pull/203 ; closed alternatives
  https://github.com/stratum-mining/sv2-spec/pull/202 and
  https://github.com/stratum-mining/sv2-spec/pull/195 .
- Start9 packages: https://github.com/Start9Labs/stratum-v2-startos ,
  https://github.com/Start9Labs/stratum-v2-pool-startos .
- ckpool (pool, solo, proxy and Job Declaration server):
  https://github.com/ckolivas/ckpool .
- Adoption: large pools joining the Stratum V2 working group (May 2026)
  https://news.bitcoin.com/bitcoin-mining-pool-giants-foundry-antpool-and-f2pool-signal-stratum-v2-shift/ ;
  DEMAND's first Stratum V2 block
  https://cryptobriefing.com/demand-pool-first-stratum-v2-block/ ; pools in
  production https://www.spark.money/research/bitcoin-stratum-v2-mining-decentralization ;
  support matrix https://d-central.tech/data/stratum-protocol-matrix/ .

Stratum V2 on BCH:

- bchn-sv2-bridge: https://github.com/danhaus93-ops/bchn-sv2-bridge ;
  LoneStrike BCH apps: https://github.com/danhaus93-ops/umbrel-bch-apps ;
  LoneStrike ckpool image: https://github.com/danhaus93-ops/lonestrike-ckpool .
- Knuth: https://github.com/k-nuth/kth (Stratum V2 from
  https://github.com/k-nuth/kth/pull/534 ; JSON-RPC:
  https://github.com/k-nuth/kth/blob/master/docs/json-rpc.md); package:
  https://github.com/BitcoinCash1/knuth-bch-startos ; site: https://kth.cash .
- SoloFury: https://solofury.com/blog/stratum-v2-bitcoin-cash-solo-mining/ ,
  https://solofury.com/blog/stratum-v2-solo-mining-guide/ .
- CashStratum (GPL-3.0), skaisser's BCH ckpool fork under a new name, with its
  own C Stratum V2 code including Job Declaration (`src/sv2_*.c`); SoloFury's
  BCH pool builds on it: https://github.com/cashstratum/cashstratum . Its SV2
  certificate uses format version 1, which the spec forbids (checked
  2026-10-08): https://github.com/cashstratum/cashstratum/issues/3 .
- ViaBTC BCH (SV1 endpoints):
  https://support.viabtc.com/hc/en-us/articles/7207458561679-BCH-Mining .
- Bitaxe ESP-Miner: https://github.com/bitaxeorg/ESP-Miner .

P2Pool and decentralized pools:

- P2Poolv2: https://github.com/p2poolv2/p2poolv2 ; docs
  https://github.com/p2poolv2/docs (`compare_datum_sv2.adoc`, `stratum.adoc`).
- sv2-p2pool: https://github.com/average-gary/sv2-p2pool ; design notes
  https://github.com/average-gary/wiki/tree/main/topics/sv2-p2pool-integration .
- Braidpool: https://github.com/braidpool/braidpool .
- P2Pool v1: https://github.com/jtoomim/p2pool ; for BCH
  https://github.com/BitcoinCash1/p2poolBCH (from
  https://github.com/frstrtr/p2poolBCH).
- Monero P2Pool: https://github.com/SChernykh/p2pool ; Gupaxx:
  https://github.com/Cyrix126/gupaxx .
- https://p2pool.org/ ; Bitcoin Optech on pooled mining:
  https://bitcoinops.org/en/topics/pooled-mining/ .
- OCEAN DATUM: https://ocean.xyz/docs/datum ; explainers
  https://www.simplemining.io/insights/post/what-is-datum-bitcoin ,
  https://thebitcoinmanual.com/articles/datum/ .
- Pickaxe: https://github.com/CyberAshven/pickaxe-miner ; its architecture page with
  the decided mining destinations: https://github.com/CyberAshven/pickaxe-miner/pull/39 .

BCH pools, nodes and tokens:

- ASICseer pool: https://github.com/ASICseer/asicseer-pool ; BCHN
  `getblocktemplatelight`: https://gist.github.com/cculianu/89805c9cf525f314f46ea75e5b103d29 .
- BitcoinCash1: https://github.com/orgs/BitcoinCash1/repositories .
- SAFA: https://bitcoincashresearch.org/t/safas-a-sha256-asic-minable-automated-token-market/2123 ;
  BTOP: https://bitcoincashresearch.org/t/block-tops-btop-a-minable-cashtoken/1703 .
- Faster blocks, checked 2026-10-14: CHIP-2025-03
  https://bitcoincashresearch.org/t/chip-2025-03-faster-blocks-for-bitcoin-cash/1513 ;
  statements for the 2027 upgrade
  https://bitcoincashresearch.org/t/chip-2025-03-faster-blocks-gathering-statements-of-support-and-dissent/2095 .
- Coinbase size RFC (2025-06, not a CHIP), checked 2026-10-14:
  https://bitcoincashresearch.org/t/rfc-limit-coinbase-tx-size/1602 .
- BCHN 29.2.0 binaries used for the regtest run:
  https://download.bitcoincashnode.org/releases/29.2.0/ (SHA-256 checked
  against the release's signed sums file; the signature itself was not
  verified).
- Stratum V2 `coinbase_tx_outputs` encoding (CompactSize-prefixed output
  array), checked 2026-10-14:
  https://stratumprotocol.org/specification/06-job-declaration-protocol/ .

Searches used on 2026-10-08, to repeat or extend:

- Web: "P2Pool Stratum V2 decentralized pool 2026"; "Stratum V2 Job
  Declaration pool coinbase outputs miner template specification";
  "sv2-spec SetPayoutDistribution coinbase payouts extension pull request
  203"; "Bitcoin Cash BCH mining pool Stratum V2 support SoloFury ViaBTC
  2026"; "DEMAND pool Stratum V2 job declaration production Braiins pool SV2
  endpoint 2026"; "OCEAN DATUM protocol miner block templates coinbase
  payouts TIDES non-custodial".
- GitHub: code search `p2pool` + `sv2` (found sv2-p2pool); repository
  searches for `p2pool sv2`, `p2pool stratum v2` and `p2pool`; the p2poolv2
  organization's repositories, branches, commits, pull requests and issues
  for `sv2` and `stratum v2`; the sv2-spec pull requests for `payout`.
