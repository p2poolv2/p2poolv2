**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Pruning Architecture

This document describes how P2Poolv2 handles chain pruning. It covers
efficient syncing, validating blocks in two zones, enforcing output
spendability, and deleting old block bodies.

**Status.**
- Implemented: header sync, body fetch, two-zone validation, output
  spendability and the confirmation pipeline.
- Designed, not implemented: block body deletion ("Block Body
  Pruning") and the missing-input marker ("Missing Input at Write
  Time").

## Overview

P2Poolv2 retains a rolling window of chain data. Old block bodies are
pruned while headers are kept indefinitely. The system uses two depth
constants:

- **PAYOUT_DEPTH** (127,008 blocks, ~14.7 days): `COINBASE_MATURITY`
  (6,048) plus `PPLNS_WINDOW_SHARES` (120,960). Blocks within this depth
  get full transaction validation. It covers every share a coinbase near
  the tip can pay: the maturity skip and then the PPLNS window (see
  `payout-distribution.md`).
- **PRUNE_DEPTH** (254,016 blocks, ~29.4 days): `2 * PAYOUT_DEPTH`.
  Blocks within this depth have their bodies retained. Blocks between
  PRUNE_DEPTH and PAYOUT_DEPTH get PoW-only body validation.

The second `PAYOUT_DEPTH` exists for output availability. A block at the
bottom of the full-validation zone, `tip - PAYOUT_DEPTH`, may spend
outputs up to `PAYOUT_DEPTH` older than itself (see "Output
Spendability"), so their bodies must still be held.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| COINBASE_MATURITY | 6,048 | 70% of a day at 10s/block |
| PPLNS_WINDOW_SHARES | 120,960 | 14 days at 10s/block |
| PAYOUT_DEPTH | 127,008 | COINBASE_MATURITY + PPLNS_WINDOW_SHARES |
| PRUNE_DEPTH | 254,016 | 2 x PAYOUT_DEPTH |
| PRUNE_INTERVAL | 360 | 1 hour of blocks |
| Block height | u32 | Overflows in ~1,361 years |

Defined in `accounting/payout/sharechain_pplns/pplns_window.rs`.

## Model: Rules for Validity, Boundaries for Storage

**Validity rules are measured from the block, so every node agrees.**
These are:
- spend expiry, `coinbase_root_height >= h - PAYOUT_DEPTH`;
- coinbase maturity;
- the PPLNS anchor on the block's parent;
- uncle depth.

The spending block's height `h` fixes each of them, and none depends on
a node's tip.

**Storage boundaries are measured from each node's own tip, so they are
local.** These are:
- `prune_height = candidate_tip - PRUNE_DEPTH`;
- the body fetch range;
- the prune watermark.

They decide what a node stores, never whether a block is valid. Nodes
with different tips have different prune heights and still reach the
same verdict on every block.

Every output below `prune_height` has a root below `tip - 2 *
PAYOUT_DEPTH`, so no block this node fully validates can spend it. That
makes deletion safe. The reasoning only runs one way: an output is
unspendable by rule, so it is safe to delete. Validity is never
inferred from data being absent.

**Two effects of different tips remain, and both are accepted.**

1. **Short data availability gaps.** A lagging node has a lower prune
   height, so it may need bodies its peers have already deleted. The
   gap is short-lived:
   - Headers sync before bodies are fetched, so a node's tip matches its
     peers' before it asks for bodies.
   - Deletion lags the boundary by one `PRUNE_INTERVAL` (see "Watermark
     and Boundary"), which serves peers up to 360 blocks behind.
2. **The validation zone a block gets depends on the tip.**
   - A block is fully validated on a node whose tip is near it. It gets
     PoW-only checks on a node whose tip is far ahead, such as a fresh
     sync.
   - The two could only disagree about a block that breaks the full
     rules but is buried `PAYOUT_DEPTH` deep under the most-work chain.
   - Honest miners never build on such a block, because
     `get_mining_base` only extends BlockValid blocks. Burying one
     therefore takes a majority of the hashrate.
   - This is the same trust model as assumevalid. It is already
     accepted in `share-processing-pipeline.md`, and pruning does not
     change it.

## Header Sync

Headers are always synced from genesis. The full header chain is kept
permanently, together with each header's template merkle branch. That
comes to about 1.0 KB per share, or about 3.1 GB per year on mainnet
(see "Appendix: Growth of Data Kept Forever").

This provides:

- Full ASERT difficulty validation for every header
- Complete chain connectivity back to genesis
- No trust in peer-provided metadata
- Strongest possible security model

A pruned header sync approach was evaluated and rejected. It required
boundary windows, ASERT skip logic, synthetic parent metadata,
defense-in-depth against malicious starting_height, and weakened the
trust model by making chain fragments "float" with only cumulative
work as a security guarantee. The marginal benefit (~20 min sync
savings, ~4 GB storage) did not justify the complexity and attack
surface.

### Checkpoint-based sync (future)

For faster initial sync, hard-coded checkpoints in the source (like
genesis) can serve as sync start points. A new node uses the
checkpoint hash as a getheaders locator. The peer responds normally
and the first header's parent matches the checkpoint -- same trust as
genesis. Once checkpoints are in place, headers and template merkle
branches below the latest checkpoint can also be pruned, which bounds
the growth above. Not in the MVP.

## Block Body Fetch

After header sync completes, block bodies are fetched only for blocks
within PRUNE_DEPTH of the candidate tip.

The scan start height in `missing_data_scan_start` is clamped upward
to `candidate_tip - PRUNE_DEPTH` so blocks in the prune zone are
never fetched. Their PoW was already validated during header sync.

Relevant code: `store/organise/candidate.rs` (`missing_data_scan_start`).

## Two-Zone Block Validation

When block bodies arrive, validation depends on the block's zone
relative to the candidate tip:

### Prune zone (height <= tip - PAYOUT_DEPTH)

`validate_below_pplns_depth` runs:
- Pool difficulty (PoW)
- Uncle validity
- Block size
- Transaction count

Skips: coinbase structure, merkle root, witness commitment,
transaction structure, script verification, prevout validation, MTP,
bitcoin coinbase payout verification.

### PPLNS zone (height > tip - PAYOUT_DEPTH)

`validate_share_block` runs all checks. `validate_with_chain_context`
runs MTP, bitcoin coinbase payout, and prevout validation before
promotion to confirmed.

### Zone determination

`check_pplns_zone(blockhash, chain_store_handle)` looks up the
block's height and candidate tip from the store. Returns `Ok(true)`
for PPLNS zone, `Ok(false)` for prune zone.

When metadata is not yet available (locally mined blocks, async store
write race), defaults to PPLNS zone (full validation). Only real store
errors (Database, ChannelClosed) are propagated.

Relevant code:
- `shares/validation/mod.rs` (`is_in_pplns_zone`, `check_pplns_zone`,
  `validate_below_pplns_depth`)
- `node/validation_worker.rs` (`validate_and_emit`)
- `node/organise_worker.rs` (`validate_and_promote_block`)

## Output Spendability (coinbase_root_height)

Each `StoredTxOut` carries a `coinbase_root_height` field: the block
height of the oldest coinbase ancestor in the output's spending chain.

### Computation (store-at-write)

- Coinbase outputs: `coinbase_root_height = block_height`
- Spending tx outputs: `coinbase_root_height = min(coinbase_root_height
  of all inputs)`

Computed at write time in `add_sharechain_txs`. In-block spending
chains (output created and spent within the same block) use a
batch-local `HashMap` cache since uncommitted batch data is not
readable from RocksDB.

### Validation

`validate_prevouts` computes `min_coinbase_root_height = block_height -
PAYOUT_DEPTH` from the spending block's own height and passes it to
`check_prevouts`. Outputs with `coinbase_root_height <
min_coinbase_root_height` are rejected in the same batch read that checks
output existence and coinbase maturity -- one pass covers all three.

A coinbase output cannot be spent before depth `COINBASE_MATURITY`, so
expiring at `PAYOUT_DEPTH` keeps a full `PPLNS_WINDOW_SHARES` of spendable
life after it matures: depths `COINBASE_MATURITY` to `PAYOUT_DEPTH - 1`.

### Why store-at-write, not walk-at-validation

A walk-at-validation approach was evaluated: walk the spending chain
back to the coinbase during `validate_prevouts`. Rejected because an
attacker can build spending chains up to ~12 million hops deep
(127,008 blocks x 99 txs/block), creating a DoS of ~24 seconds per
input validation. Store-at-write is O(1) at validation time and
O(inputs) at write time, bounded by block size (~5000 inputs max).

### Error handling

- `min_coinbase_root_height_for_inputs` returns `StoreError` if any
  input output is missing or undecodable (prevents persisting height 0
  which would make outputs permanently unspendable). A missing input
  currently leaves the block unstored and not marked invalid. The
  planned fix records an explicit unknown root instead of an error
  (see "Missing Input at Write Time").
- `compute_block_height_from_parent` returns `StoreError` if parent
  metadata is missing (genesis is special-cased to height 0).
- The parent's `expected_height` is required in `validate_prevouts`; its
  absence is propagated as `StoreAccess` rather than defaulted to 0,
  which would disable the spend rule.

Relevant code:
- `store/transaction_store.rs` (`StoredTxOut`,
  `min_coinbase_root_height_for_inputs`,
  `check_prevouts`)
- `store/share_store.rs` (`compute_block_height_from_parent`)
- `shares/validation/mod.rs` (`validate_prevouts`)

## Confirmation Pipeline (prune-zone promotion)

The confirmation pipeline (`organise_block`) promotes candidate blocks
to confirmed status. Blocks below the prune boundary are promoted
without requiring block body data.

### Flow

`organise_block` computes `prune_height = candidate_tip - PRUNE_DEPTH`
once from a single candidate tip snapshot, then passes it to all
downstream functions to avoid inconsistency from concurrent updates.

### Gates modified for pruning

1. **`contiguous_candidates_with_block_data`**: blocks with
   `height < prune_height` pass without `share_block_exists` check.
   Blocks at or above require full body data.

2. **`all_block_and_uncle_data_available`**: both blocks and their
   uncles are checked against prune_height using
   `get_block_height_from_metadata`. Blocks or uncles below
   prune_height skip the body check. Returns `Result<bool, StoreError>`
   -- propagates errors when metadata or expected_height is missing
   (these indicate store corruption for candidates that went through
   organise_header). Missing headers also error rather than silently
   assuming no uncles.

3. **`put_confirmed_entry`**: only calls `add_spends_for_block` when
   `share_block_exists` returns true. Prune-zone blocks without body
   data get the confirmed height index entry but no SpendsIndex
   population.

### Consistency

`organise_block` reads candidate_tip_height once and derives
prune_height from it. This single snapshot is passed to
`find_promotable_candidates`, `should_extend_confirmed`,
`reorg_confirmed`, and `try_fallback_confirmation` to avoid divergence
from concurrent header arrivals advancing the candidate tip.

### Safety

Prune-zone blocks without SpendsIndex entries cannot cause
double-spend acceptance:
- Their outputs have `coinbase_root_height` below `tip - PAYOUT_DEPTH`
- `check_prevouts` rejects spending those outputs
- SpendsIndex is only needed for outputs that CAN be spent

Relevant code:
- `store/organise/organise_block.rs` (`organise_block`,
  `find_promotable_candidates`, `contiguous_candidates_with_block_data`)
- `store/organise/confirmed.rs` (`put_confirmed_entry`,
  `all_block_and_uncle_data_available`, `should_extend_confirmed`,
  `reorg_confirmed`)

## Block Body Pruning (designed, not implemented)

### What is kept and what is deleted

| Data | Fate | Why |
|---|---|---|
| `Header`, `BlockMetadata` (incl. `chain_work`), `BlockIndex`, confirmed `BlockHeight` entries | kept forever | Header sync starts from genesis; the hashrate metric reads `chain_work` |
| `TemplateMerkleBranches` | kept forever | `getheaders` sends each header with its branch (`receivers/getheaders.rs`) |
| `FoundBlocks` | kept forever | Never pruned (`metrics.md`) |
| `Uncles` | kept | Small, and derived from headers |
| `BlockTxids`, `BitcoinTxids`, `BitcoinCoinbase` | deleted below the boundary | Body data |
| `Tx`, `Inputs`, `Outputs`, `TxidsBlocks`, `SpendsIndex` | deleted below the boundary, unless a kept block still references the txid | Body data that can be shared between blocks |
| candidate `BlockHeight` entries | deleted below the boundary, at confirmed heights only | Below the confirmed tip they duplicate the confirmed entries |

Out of scope:
- the Hydrapool `Share` CF, which has its own TTL pruning
  (`prune_shares`);
- the wallet API, whose window follows `PAYOUT_DEPTH`.

### Watermark and Boundary

A `Metadata` CF key, `meta:pruned_below_height` (u32), records that
every height below it has had its bodies deleted. It is written in the
same `WriteBatch` as those deletions, so after a crash either both are
on disk or neither is.

One function replaces the separate computations in `organise_block`,
`BlockReceiver::current_prune_height`, `missing_data_scan_start` and
`verify_chain`:

```
prune_height() = max(candidate_tip_height - PRUNE_DEPTH, pruned_below_height)
```

- **The boundary never moves down.** The tip height can drop after a
  reorg to a shorter chain with more work, or after `mark_invalid`.
  Without the `max`, the gates would then demand deleted bodies and
  confirmation would freeze.
- **A failed tip read falls back to the watermark,** not to 0.
- **`organise_block` still reads it once** and passes it down (see
  "Consistency").

Deletion lags the boundary by one interval:
`prune_target = candidate_tip - PRUNE_DEPTH - PRUNE_INTERVAL`. The gates
keep using `prune_height()`, so a node never needs bodies below its own
boundary. It keeps 360 to 720 extra heights that slightly lagging peers
may still fetch.

### Pruner

`store/prune_blocks.rs` is a functional module, following the
`prune_shares.rs` precedent. It runs on the writer thread through
`WriteCommand::PruneBlocks { target, reply }`.

It walks upward from the watermark to `target` in chunks of
`PRUNE_INTERVAL` heights. Each chunk is one batch and one writer
command, so normal writes run between chunks. For each chunk:

1. **Enumerate.** Use `BlockHeight` to find every block at each height,
   including forks and uncles.
2. **Find bodies.** Read `BlockTxids` with one `multi_get`. Blocks with
   no entry are header-only and have nothing to delete.
3. **Reference check.** Read `TxidsBlocks` for the txids, then the
   referencing blocks' heights from `BlockMetadata`, one `multi_get`
   each. The walk is upward, so a referencing block is kept exactly when
   its height is at or above the chunk end.
   - A txid with no kept referencer is deleted.
   - A txid with a kept referencer has its `TxidsBlocks` list rewritten
     without the pruned blocks.

   Share coinbase txids are unique, because the coinbase `script_sig`
   pushes the weak bitcoin block hash (`shares/transactions/coinbase.rs`).
   So sharing only happens for a non-coinbase transaction included in
   several blocks. That path is rare and gets its own test.
4. **Delete transactions.** Read the input and output counts from `Tx`
   metadata, then delete `Tx[txid]`, `Inputs[txid:i]`,
   `Outputs[txid:o]`, `SpendsIndex[txid:o]` and `TxidsBlocks[txid]`.
5. **Delete per-block data:** `BlockTxids`, `BitcoinTxids` and
   `BitcoinCoinbase`.
6. **Delete candidate index entries** (`height:c` in `BlockHeight`) at
   heights in the chunk that are at or below the confirmed tip.
   - Confirmed blocks carry `ChainMembership::Confirmed`, and reorgs
     that branch from the confirmed chain do not read the candidate
     index.
   - Promotion below the boundary is header-only, so the confirmed tip
     normally sits far above the chunk. The guard only matters during
     sync.
7. **Advance the watermark** to the chunk end in the same batch, then
   commit.

An interrupted chunk repeats cleanly: the deletes are idempotent, and
the watermark only moves when the batch commits.

`share_block_exists` keys off `BlockTxids`. The gates already accept a
missing body below `prune_height`, so they need no change beyond the
boundary function.

Reorg-out of a pruned block needs no new code.
`rewind_confirmed_entries` reads an empty transaction list, and step 4
already deleted the block's spends. This needs a test.

### Triggering

- **Steady state.** A background task in `background_tasks.rs`, like
  the existing `prune_shares` task, checks once a minute. It sends
  `PruneBlocks` when the node `is_current()` and `prune_target >=
  pruned_below_height + PRUNE_INTERVAL`.
- **Startup.** Before networking starts, prune against the stored
  candidate tip. This is not gated on `is_current`, because a stored tip
  can only give a lower, and therefore safe, boundary. If anything was
  pruned, compact the body CFs in `spawn_blocking`. In steady state,
  RocksDB's automatic compaction clears the tombstones.

### Ingress and serving

- **`BlockReceiver`.** If a block's header height is below
  `prune_height()`, mark the fetch complete and drop the block without
  storing it. The header and metadata already exist.
- **Writer guard.** `add_share_block` refuses a body below
  `pruned_below_height`.
  - The receiver check alone can race with a prune chunk: a block
    passes the check, the chunk commits, then the write brings the body
    back.
  - The writer runs both commands one after the other, so its check
    cannot race.
- **Parent-wait buffer.** Eviction (`mine-on-bitcoin-chain.md` change 2)
  uses `prune_height()`.
- **Block requests.** A pruned body goes through the existing
  `get_share -> None` path. Confirm that this path replies not-found and
  does not penalise the requester. The API share endpoint returns the
  header with a `pruned` marker.
- **`verify_chain`.** It uses `prune_height()`.
- **Candidate readers.** These need no change:
  - `build_locator` already falls back to the confirmed index.
  - `get_chain_range` iterates and skips missing keys, so
    `query_candidates` (the API `candidates` endpoint and CLI
    `db_query`) returns only heights above the deleted range. Document
    this on the function.
  - `organise_block`, `detach_candidate_branch` and
    `reorg_candidate_from_candidate` read only above the confirmed tip.

### CLI

`p2poolv2_cli prune --store <path>` runs with the node stopped, because
RocksDB holds a lock. It runs the same pruner against the stored
candidate tip, then compacts.
- There is no depth argument, because `PRUNE_DEPTH` is a safety bound,
  not a preference.
- There is no online trigger through the API. The background task
  covers a running node.

### Future: bitcoin header store (#652)

When the bitcoin header store lands, it keeps at least `PAYOUT_DEPTH +
PRUNE_DEPTH` plus one retarget period, about 8,400 headers (see
`mine-on-bitcoin-chain.md` "Retention"). Its pruning belongs in the
same background task.

### Documentation to update with the implementation

`store-schema.md` needs these changes:
- add the watermark key;
- remove `UnspentOutputs`, which no longer exists;
- add `TxidsBlocks`, `Uncles` and `SpendsIndex`.

## Missing Input at Write Time (decided, deferred)

**Problem.** `add_sharechain_txs` computes root heights at write time,
before validation, for every block. `min_coinbase_root_height_for_inputs`
returns `StoreError::NotFound` for a missing input, and
`store_and_emit_validation` returns `Err`. The block is then neither
stored nor marked Invalid. Two cases hit this:

- **(a) A block in the full-validation zone whose input does not
  exist.**
  - The block is invalid by rule, but it never reaches
    `validate_prevouts`.
  - This can happen today. It costs one share of PoW and earns nothing.
  - The body is re-fetched every 10s, confirmation stalls, and the
    block's descendants wait in the parent-wait buffer.
  - It heals on its own: honest miners fork around the block, and the
    candidate chain moves to their branch.
- **(b) A PoW-only-zone block spending a real output from below this
  node's `prune_height`.**
  - The block is valid. The input is within the block's own window,
    `>= h - PAYOUT_DEPTH`, but below `tip - PRUNE_DEPTH`, so this node
    never fetched it. Marking the block invalid would split nodes.
  - This cannot happen yet, because no non-coinbase share transactions
    exist (`handle_stratum_share.rs` TODO).
  - Once they exist, a valid block on the best chain becomes
    unstorable, and that stall does not heal.

**Fix.** `StoredTxOut` gets `enum CoinbaseRoot { Height(u32), Unknown }`.
- **Write.** Record `Unknown` only when an input is not found. Read and
  decode errors still propagate.
- **Propagate.** `Unknown` is the bottom value: a transaction with any
  `Unknown` input writes `Unknown` outputs.
- **Validate.** `check_prevouts` rejects it with
  `PrevoutRejection::UnknownCoinbaseRoot`.
- **Display.** The wallet API shows such outputs as unknown or expired.

What this gives each case:
- In (a), the block is stored, and `validate_prevouts` marks it Invalid.
- In (b), the true root is below `prune_height`. Any spender this node
  fully validates needs a root above that, so rejecting `Unknown`
  matches every node that holds the true value.
- The ancestry gate guarantees that every ancestor body at or above
  `prune_height` is present, so a missing input is always one of these
  two cases.

**Why a marker, not 0:**
- Genesis coinbase outputs really do have root height 0.
- The "never persist height 0" rule (see "Error handling") stays true.
- The enum makes every reader handle `Unknown`.

**Cost.** One byte per output. A chain reset is planned, so no
migration is needed.

**When.** The fix goes in before, or together with, share
transactions, and is not part of the pruning work. Its tests:
- an in-zone block spending a missing output is stored and marked
  Invalid;
- a PoW-only block spending an unfetched output is stored, gets
  `Unknown` outputs, and is confirmed;
- spending an `Unknown` output is rejected with `UnknownCoinbaseRoot`;
- `Height(0)` stays distinct from `Unknown`.

**Not taken:** keeping bodies down to `tip - 3 * PAYOUT_DEPTH` to
compute exact roots. That is 50% more body storage for values that can
never matter.

## Decisions (2026-10-15)

- **Template merkle branch growth (~1.4 GB/year on mainnet) is accepted
  until checkpoints land.** Deduplicating branches does not help: there
  is about one share per branch. Serving deep headers without branches
  is rejected, because it reopens free header fabrication.
- **Uncapped coinbase payout outputs are accepted.** Pruning holds
  `PRUNE_DEPTH` blocks of coinbases, about 8 GB at 1,000 miners. Capping
  outputs is a payout design change, tracked separately.
- **Candidate index entries below the boundary are deleted** (pruner
  step 6).
- **The CLI prune runs offline only,** with no API trigger.
- **A missing input at write time gets an unknown-root marker,** which
  is deferred until share transactions land.

## Alternatives Rejected

- **Height-prefixed transaction keys with `delete_range`.** Outpoint
  lookups need txid-keyed rows, so this would need a second index.
- **A RocksDB compaction filter.** It cannot do the cross-key reference
  check, and it cannot commit atomically with the watermark.
- **A column family per epoch, dropped whole.** Shared txids span
  epochs, and every reader would fan out across column families.

## Appendix: Growth of Data Kept Forever

At one share per 10s there are 3,153,600 shares per year. Sizes are raw
and include the 32-byte key. Hashes do not compress. The figures assume
candidate index entries are pruned.

| Item | Per share | Per year |
|---|---|---|
| `Header` (261 B value + P2TR address + ~0.5 uncles, + key) | ~321 B | 1.0 GB |
| `BlockMetadata` | ~71 B | 0.22 GB |
| `BlockIndex` | ~68 B | 0.21 GB |
| `BlockHeight` (height list + confirmed entry) | ~75 B | 0.24 GB |
| `TemplateMerkleBranches`, 12-13 levels on mainnet (0 for an empty template, 16 max) | 417-449 B | 1.3-1.4 GB |
| **Total on mainnet** | **~1.0 KB** | **~3.1 GB (15 GB after 5 years)** |

The bitcoin coinbase is body data and is pruned. It is about `235 + 31
* miners` bytes, or 43 bytes per payout for P2TR:

| Miners paid | Coinbase | Per year if it were kept | Held under pruning |
|---|---|---|---|
| 10 | ~0.5 KB | 1.7 GB | 0.14 GB |
| 100 | ~3.3 KB | 10.4 GB | 0.84 GB |
| 1,000 | ~31 KB | 98 GB | 7.9 GB |
