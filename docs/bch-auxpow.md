# BCH auxiliary work proofs

`shares::auxpow` builds the tree for a miner's selected work and verifies an
individual proof through the full BCH coinbase to the parent header. The
caller supplies the expected work hash, chain id and target independently.
The proof cannot choose its own authoritative target. Token issuance and
covenant state transitions still require a token-specific verifier.

## Commitment and proof

The existing zero-value coinbase output is exactly:

```text
6a 2c fabe6d6d <root:32> <tree_size:u32le> <nonce:u32le>
```

The tree follows the [merged-mining slot and hash convention](https://en.bitcoin.it/wiki/Merged_mining_specification).
Leaves are raw double-SHA256 hashes. Hash each pair as `SHA256d(left || right)`;
reverse the final root bytes for the output. Hash strings in the JSON API
use Bitcoin display order. This BCH format uses an output; existing Namecoin
proofs that look in the coinbase scriptSig are not interchangeable with it.

For a chain id, use wrapping 32-bit arithmetic:

```text
slot = nonce * 1103515245 + 12345
slot = slot + chain_id
slot = slot * 1103515245 + 12345
slot = slot % tree_size
```

The builder starts at one slot and doubles until all selected ids have
different slots. Changing the nonce cannot resolve a collision at a fixed
width. Unused leaves are 32 zero bytes; higher empty subtrees are hashes of
their children. Sparse construction stores only occupied paths. The same
selection in a different input order produces the same commitment.

The local selection limit is 64 work items, each with a distinct chain id.
The maximum tree width is `2^30`, so a branch has at most 30 siblings. Some
distinct ids collide at every supported width; the builder returns an error.
An empty selection produces the reserved zero root, zero size and zero nonce.
It cannot prove any work.

`AuxPowProof` carries the parent header, complete coinbase transaction,
coinbase Merkle siblings and one auxiliary work branch. Verification requires
one canonical, unpaid aux output, a coinbase scriptSig of 2 to 100 bytes, no
witness, at most 25 coinbase siblings, and at most 65,685 coinbase bytes. The
coinbase transaction id is computed from its bytes; no SHA256 midstate is
trusted. Both branches must reconstruct their committed roots. The parent's
hash must meet the caller's target, independently of its advertised `nBits`.
This checks auxiliary work; full parent-block validity requires a BCH node.

These Rust proof bounds are not an on-chain script-size guarantee. A token
adapter must enforce its own standard transaction and VM resource budgets.
The [2026 P2S rules](https://github.com/bitjson/bch-p2s#unlocking-bytecode-length)
allow 10,000 bytes of standard unlocking bytecode, including the redeem
script. The 65,685-byte Rust coinbase limit cannot fit that budget in full;
the covenant adapter must reject proofs that exceed its own complete spend
budget rather than relying on the shared verifier's larger transport bound.

## Offline CLI

No node configuration or wallet is required. Given `work.json`:

```json
{
  "nonce": 0,
  "work": [
    {"chain_id": 1, "hash": "609a190c7afc006d9f9b2a0850dc9f9ac283e8da1ee87bf75ac6ce2cdea5ced8"},
    {"chain_id": 2, "hash": "c26264a2eb4829c73215adf97ae22cf8fb9bf322508bf7f61dbdd9b81abbbf4d"}
  ]
}
```

```sh
p2poolv2_cli bch-auxpow build work.json
p2poolv2_cli bch-auxpow verify proof.json --chain-id 2 --work-hash c26264a2eb4829c73215adf97ae22cf8fb9bf322508bf7f61dbdd9b81abbbf4d --target 7fffff0000000000000000000000000000000000000000000000000000000000
```

The build output includes the commitment and individual work proofs. The
verify input is a serialized `AuxPowProof`, including the actual parent and
coinbase. Each input JSON file is limited to 1 MiB. The hashes in this example
are synthetic work; the example target is for regtest, not a token policy.

## SAFA integration target

SAFA is the first requested token target. Its
[author's draft and linked Bitauth template](https://bitcoincashresearch.org/t/safas-a-sha256-asic-minable-automated-token-market/2123)
check `SHA256d(next NFT baton)` against a difficulty target. The template has
no parent header, coinbase or inclusion branch arguments. Committing its baton
hash in BCH does not satisfy that mining rule. SAFA AuxPoW therefore needs a
new covenant variant before issuance or end-to-end compatibility can be claimed.

The proposed variant retains the draft's state, market, reward and payout
binding, and replaces the mining hash check with a bounded AuxPoW check:

1. Validate the current mutable NFT category, continuing covenant, age and
   target adjustment. Derive the target from that state, with unsigned
   256-bit hash comparison and explicit compact-target range checks.
2. Validate the next baton and the recipient script under the SAFA rules.
   Bind the category, covenant identity, previous baton and next baton to a
   domain-separated work leaf. This must prevent cross-category, cross-thread
   and cross-contract replay, and reward redirection.
3. Derive the expected leaf and chain id inside the covenant, then verify its
   auxiliary branch, canonical coinbase output, coinbase transaction id,
   parent Merkle path and parent proof of work against the derived target.
4. Enforce the token and satoshi accounting in the same spend, including the
   matching reward category. A successful shared proof alone cannot authorize
   a withdrawal.

The exact leaf serialization and chain-id assignment are not frozen. The
implementation must first prove a standard spend with real BCH VM execution,
including its complete redeem script and proof bytes. Maximum-size Rust
proofs need not fit a standard SAFA spend. Test payout diversion, replay,
wrong targets/categories, malformed branches, market-path preservation and
resource limits before treating the variant as usable. No SAFA covenant is
deployed or claimed compatible at this checkpoint.

The linked draft's release and swap scenarios both pass in Libauth
`3.1.0-next.8`'s standard BCH 2026 VM. This is not a security endorsement:
the release scenario's hash exceeds its unsigned target but passes the
script's direct `OP_BIN2NUM` comparison. The variant must append a zero sign
byte before converting a 32-byte hash to an integer, and test the high-bit
case. A draft scenario passing alone is insufficient validation.

## Two-node regtest evidence (2026-10-16)

The opt-in JD test passed against two connected BCHN 29.2.0 nodes. Both nodes
accepted these blocks; each coinbase paid 2,500,000,219 satoshis, including
219 satoshis in fees:

| Declaration | Height | Selected work items | Block hash |
|---|---|---|---|
| Full-Template | 207 | 2 | `076b69a0f410cd892e12894c2a6788df9090863c26fe4e6ac53f904b66e7bb9e` |
| Coinbase-Only | 208 | 1 | `3f97953b75a2644d91ab3fffcf70e877de886ceeb54e88463fdb5e322e4d5bef` |

Both work proofs reconstruct the first block's aux root. The next job selects
only the second item and changes the root and nonce. Its private transaction
was absent from both mempools until the client broadcast the complete block.
Each emitted coinbase proof and full auxiliary proof verifies; BCHN still
rejects an extra satoshi of coinbase value. The test prints public proof JSON
for offline verification. These are synthetic auxiliary work hashes, not SAFA
withdrawals. See [the JD test setup](bch-job-declaration.md#two-node-bchn-regtest-check).

The built offline CLI verified both exported proofs, reproduced the independent
two-leaf root above, and rejected a wrong chain id and a target of one.
