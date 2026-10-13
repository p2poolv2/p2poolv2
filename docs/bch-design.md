# Bitcoin Cash design checks

Written 2026-10-13, before the startup-selection change. Each porting item
from [bch-plan.md](bch-plan.md) gets a decision here. Open questions stay
open: this file does not invent PPLNS lengths, a merge-mining commitment,
or a license change.

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
Bitcoin genesis. A Bitcoin Cash node ignores it for genesis. It builds a
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

## Checklist

- **Segwit removal.** Not done. Witness commitments and share-chain script
  validation are still the Bitcoin implementation. This change only refuses
  to turn a template that still carries those fields into a Bitcoin Cash job.
- **Share chain addresses.** A header stores `ShareOwner`. Bitcoin stays a
  taproot witness program. Bitcoin Cash stores a 20-byte P2PKH hash under
  tag `0x20`, addressed as CashAddr `p2pool`, `tp2pool`, or `rp2pool`. That
  string is not the payout CashAddr (`miner_bitcoin_address`). A Bitcoin Cash
  genesis share uses the same P2PKH form.
- **Share trading.** Waits. The mini share chain is the stand-in named in the
  plan, and the atomic-swap scripts are not ported. No v1 code is copied.
- **Block rules.** CTOR, compact-target agreement, witness exclusion, and the
  node size limit are checked on the template before use. ABLA state, BIP34
  height in a constructed coinbase, and 100-block maturity enforcement in
  the share chain are not done.
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
  retune of the PPLNS window.
- **Stratum V2.** Not started. SV1 remains the server. Both Job Declaration
  modes stay future work, and declared jobs will have to keep CTOR.

## Still unfinished

Stratum V2 with both Job Declaration modes, the merge-mining commitment, and
live regtest or chipnet mining. A node started with `chain = "bitcoin-cash"`
can validate BCHN templates, pay a CashAddr script, record a P2PKH share
owner, and start from a main or mini P2PKH genesis. It must not be treated
as a working Bitcoin Cash pool until those remaining items land.
