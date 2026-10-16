# Experimental SAFA AuxPoW covenant

This is a working AuxPoW variant of [2qx's SAFA draft](https://bitcoincashresearch.org/t/safas-a-sha256-asic-minable-automated-token-market/2123).
It is a reference covenant and adapter for this BCH port, not the author's
published token or a production deployment. The mining branch verifies the
shared P2Pool proof inside the BCH 2026 VM; the market branch retains the
unchanged-baton constant-product rule.

`safa.cash` compiles with pinned Libauth `3.1.0-next.8`. Its redeem script is
839 bytes, with raw SHA256d hash
`41487c18c5644504dd4c13015739131d21cac3b0961ffd05a5d1d7f02bc7e3da`.
The output is P2SH32. The existing Rust node and `AuxPowProof` representation
are unchanged; JavaScript supplies the BCH VM and token adapter.

```sh
npm ci --ignore-scripts
npm test
node cli.mjs work state.json
node cli.mjs unlock proof.json 71
```

The work input has `category` (display-order hex), `previous_baton` (80 bytes
of hex), recipient locking bytecode as `recipient` hex, integer `age`, Unix
`timestamp`, and `nonce`. The result includes the next baton, expected work,
target and covenant bytecode. Add its `work` object to a selection consumed
by `p2poolv2_cli bch-auxpow build`. Declare the resulting commitment under
the [BCH JD contract](../../docs/bch-job-declaration.md).
The unlock command takes the full Rust proof JSON and prints scriptSig hex.
Both commands read public data only, bounded to 1 MiB per input file.

## Variant rules

The baton keeps the draft's 80-byte layout: scalar (4), previous baton hash
(32), recipient locking-bytecode hash (32), timestamp (4), compact target
(4) and nonce (4). Integers are little endian; hashes here are raw digest
bytes. The covenant requires a mutable NFT and exact 80-byte commitments.
Every invocation returns the same category, mutable capability and covenant
at output `active_input_index`.

For mining, the payout is at output `input_count + active_input_index`.
These two output ranges are disjoint across all inputs, including batches.
The token reward is exactly `floor(input_tokens / 420000)`, must be positive,
and has the vault category. The continuation keeps exactly the remainder.
The vault can contribute at most 1,500 satoshis; additional fees may use a
sponsor input. The next baton binds that payout's locking bytecode. Its
timestamp cannot decrease, and CLTV enforces it. CSV enforces the claimed
block age (`0 <= age < 65535`) on a version-2 transaction.

The next target is the previous decoded target multiplied by
`(floor(age * 5000 / 71) + 5000) / 10000`, with integer division. Clamp to
`[1, 2^256 - 1]`, encode canonically as Bitcoin compact, then decode that
rounded target for the PoW comparison. Negative, zero, overflowing and
noncanonical compact encodings are rejected. Hash-to-integer conversion
appends a zero sign byte, fixing the draft's signed comparison issue.

The work leaf is:

```text
SHA256d("BCH-SAFA-AUXPOW-V1\0" || category_wire_bytes ||
        SHA256d(UTXO_locking_bytecode) || SHA256d(previous_baton) ||
        SHA256d(next_baton))
```

The ASCII domain is 19 bytes, including its NUL terminator. Category wire
bytes are the reverse of a displayed token category. The chain id is the
first four raw leaf bytes interpreted as unsigned little endian. This lets
several threads from the same token participate with distinct work ids.
Slot collisions use the shared tree builder's growth and rejection rules.

The covenant parses the complete version-2 coinbase, including its unique
null input, bounded scriptSig, canonical CompactSize fields and all outputs.
It requires exactly one canonical, zero-value auxiliary output. It derives
the slot and exact branch depth from that output, folds the auxiliary and
coinbase paths, and compares the parent hash to its state-derived target.
The parent header's own `nBits` cannot choose the token's target.

Market/oracle spends keep the baton identical and enforce
`(output_cash + virtual_cash) * output_tokens >=
(input_cash + virtual_cash) * input_tokens`.
This variant uses the linked executable template's `scalar * 10000000`
virtual reserve; the forum narrative's `1000000` multiplier differs. That
economic parameter needs agreement before any real SAFA issuance.

The complete scriptSig, including redeem script, must fit 10,000 bytes.
Both maximum-depth branches (30 auxiliary, 25 coinbase) pass the standard VM.
Large pool coinbases may exceed the remaining budget and are refused by the
adapter. This does not claim full parent-block validity or chain membership.
As in the draft, initially identical threads must have distinct randomized
batons; a mutable NFT category alone does not establish unique thread state.

## Regtest evidence and reproduction

On 2026-10-16 two BCHN 29.2.0 nodes accepted P2Pool JD blocks 280 and 281
committing this variant's real work. The Full-Template proof covered two
work items; Coinbase-Only selected just SAFA. Both passed the Rust verifier
and the covenant VM. A 71-block-old mutable baton then spent successfully
using the private proof, returning 419,999,000 tokens and paying 1,000 tokens.

The withdrawal is `6603a8f72a8d6dec0649039fcc2d84a3fd5d852f1b12f9c514b1911dcad213e4`,
in block `16f3f77f338747dedaa170eddaf023ad22c16f74e163450efd7086d87fcaa2bc`
at height 282. Its scriptSig is 1,266 bytes; the Full-Template proof uses
1,298 bytes. The transaction paid 5,000 satoshis in fees with a sponsor input.
BCHN's mempool check rejected a changed Merkle sibling. Public transaction
and proof bytes in `test_data/regtest-withdrawal.json` are replayed by the
offline VM tests, including the BCHN-signed sponsor input.

Use two disposable, connected regtest nodes and the funded `jd-regtest`
wallet from [the JD test setup](../../docs/bch-job-declaration.md#two-node-bchn-regtest-check).
The opt-in harness refuses other chains and non-loopback endpoints. It
creates test tokens and spends regtest wallet funds; it never reads keys.
In PowerShell from the repository root:

```powershell
$env:BCHN_JD_CLIENT_RPC = 'http://127.0.0.1:19453'
$env:BCHN_JD_POOL_RPC = 'http://127.0.0.1:19455'
$safaEvidence = Join-Path $env:TEMP ('safa-auxpow-' + (Get-Date -Format yyyyMMdd-HHmmss))
node tools/safa-auxpow/live-regtest.mjs prepare $safaEvidence
$env:BCHN_JD_AUXILIARY_WORK = Join-Path $safaEvidence 'work.json'
cargo nextest run -p p2poolv2_lib --run-ignored ignored-only -E 'test(bchn_declared_jobs_reach_both_real_nodes)' --nocapture *> "$safaEvidence/jd.log"
$records = Get-Content "$safaEvidence/jd.log" | Where-Object { $_.StartsWith('{"auxiliary_chains"') } | ConvertFrom-Json
$records[1].auxpow_proof | ConvertTo-Json -Depth 30 | Set-Content "$safaEvidence/proof.json"
node tools/safa-auxpow/live-regtest.mjs spend $safaEvidence "$safaEvidence/proof.json"
Remove-Item Env:BCHN_JD_AUXILIARY_WORK
```

The harness preserves state, genesis, candidate withdrawal and final evidence
in the new directory. Stop only the disposable nodes you started. This is
local regtest validation. Chipnet issuance, independent review of the new
covenant and compatibility with a final SAFA specification remain open.
