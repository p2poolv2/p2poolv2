# P2Poolv2 for Bitcoin Cash: implementation plan

Status: implementation in progress. Written 2026-10-08 from design discussions
with the maintainer of [Pickaxe](https://github.com/CyberAshven/pickaxe-miner).
Audience: contributors and AI agents starting the BCH port. Read
[AGENTS.md](../AGENTS.md) and `docs/architecture/` before changing code.

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

This is a foundation checkpoint: the BCH fetch path is not yet selected by
node startup. The BCH share identities and consensus, CashAddr payouts,
main/mini genesis and difficulty settings, Stratum V2 and Job Declaration,
merge-mining commitments, and live regtest/chipnet mining validation remain
unfinished. The upstream Bitcoin test suite passing does not validate those
BCH requirements.

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
  mini share chains.
- Keep P2Poolv2's share trading on BCH, or rely on the mini share chain.
- Merge-mining commitment format and size budget (Stratum V2's
  `CoinbaseOutputConstraints` already declares coinbase space).
- Binding each miner's payout address to their shares over SV2 (sv2-p2pool
  lists it as open, its ADR 0002).
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
