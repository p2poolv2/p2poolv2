**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Pruning Architecture

This document describes how P2Poolv2 handles chain pruning. It covers
efficient syncing, validating blocks in two zones, enforcing output
spendability, and deleting old block bodies.

**Status.**
- Implemented: header sync, body fetch, two-zone validation, output
  spendability, the confirmation pipeline, block body deletion and the
  reorg depth limit ("Block Body Pruning").
- Open: the reorg depth limit redoes its refusal on every announcement of a
  refused block (see "Reorg Depth Limit").
- Designed, not implemented: the missing-input marker ("Missing Input at
  Write Time").

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
- the prune target, where deletion stops.

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
   - Deletion lags the boundary by one `PRUNE_INTERVAL` (see
     "Boundaries"), which serves peers up to 360 blocks behind.
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
(`prune_height_for_tip`) once from a single candidate tip snapshot, then passes it to all
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

## Block Body Pruning

### What is kept and what is deleted

| Data | Fate | Why |
|---|---|---|
| `Header`, `BlockMetadata` (incl. `chain_work`), `BlockIndex`, `h:` height lists, confirmed `BlockHeight` entries | kept forever | Header sync starts from genesis; the hashrate metric reads `chain_work` |
| `TemplateMerkleBranches` | kept forever | `getheaders` sends each header with its branch (`receivers/getheaders.rs`) |
| `FoundBlocks` | kept forever | Never pruned (`metrics.md`) |
| `Uncles` | kept | Small, and derived from headers |
| `BlockTxids`, `BitcoinTxids`, `BitcoinCoinbase` | deleted below the prune target | Body data. Nothing writes `BitcoinTxids` yet; its key is deleted anyway so a future writer cannot leak data |
| `Tx`, `Inputs`, `Outputs`, `TxidsBlocks`, `SpendsIndex` | deleted below the prune target, unless a kept block still includes the txid | Body data that can be shared between blocks |
| candidate `BlockHeight` entries | deleted at every height below the prune target | Far below the confirmed tip they duplicate the confirmed entries |

Out of scope:
- the Hydrapool `Share` CF, which has its own TTL pruning
  (`prune_shares`, Hydrapool mode only);
- the wallet API, whose window follows `PAYOUT_DEPTH`.

### Boundaries

Nothing about pruning is persisted. Both boundaries are computed from the
candidate tip (`store/prune_blocks.rs`):

```
prune_height_for_tip(tip) = tip - PRUNE_DEPTH                   // the gates
prune_target_for_tip(tip) = tip - PRUNE_DEPTH - PRUNE_INTERVAL  // deletion
```

- **The gates use `prune_height`.** `organise_block`,
  `missing_data_scan_start`, `BlockReceiver` and `verify_chain` all call
  `prune_height_for_tip` (or `Store::prune_height`, which reads the
  candidate tip and returns 0 when there is none).
- **Deletion stops at `prune_target`,** one `PRUNE_INTERVAL` lower. The gap
  does two jobs:
  - A node keeps 360 or more heights below its own boundary, which peers
    slightly behind it may still fetch.
  - It replaces a "never move down" watermark. A tip drop smaller than
    `PRUNE_INTERVAL` can never make the gates demand a deleted body. A larger
    drop needs a reorg to a chain hundreds of blocks shorter with more work;
    even then the bodies are fetched again from peers that hold them. The gap
    absorbs honest reorgs only, not attacks (see "Reorg Depth Limit").
- **A failed tip read in `BlockReceiver`** falls back to the last prune
  height it computed, cached in memory, not to 0.

### Pruner

The work is split in two:
- `Store::prune_block_bodies_chunk(from, to, batch)` deletes the bodies at
  heights `[from, to)` into one `WriteBatch`. It runs on the writer thread
  through `WriteCommand::PruneBlockBodiesChunk { from, to, reply }`, which
  commits the batch.
- `ChainStoreHandle::prune_block_bodies(from, target)` sends one chunk command
  per `PRUNE_INTERVAL` heights, so normal writes run between chunks. It
  returns `PruneStats` (blocks and transactions deleted).

For each chunk:

1. **Enumerate.** Use the `h:` height lists to find every block at each
   height, including forks and uncles. Genesis (height 0) is never pruned.
2. **Find bodies.** Read `BlockTxids` with one `multi_get`. Blocks with no
   entry are header-only and have nothing to delete.
3. **Reference check.** Read `TxidsBlocks` for the txids, then the
   referencing blocks' heights from `BlockMetadata`. A referencer is kept
   when its height is at or above the chunk end, or when its metadata or
   height is missing (kept to be safe).
   - A txid with no kept referencer is deleted.
   - A txid with a kept referencer has its `TxidsBlocks` list rewritten
     without the pruned blocks.

   Share coinbase txids are unique, because the coinbase `script_sig`
   pushes the weak bitcoin block hash (`shares/transactions/coinbase.rs`).
   Sharing only happens for a non-coinbase transaction included in several
   blocks.
4. **Delete transactions.** Read the input and output counts from `Tx`
   metadata, then delete `Tx[txid]`, `Inputs[txid:i]`, `Outputs[txid:o]`,
   `SpendsIndex[txid:o]` and `TxidsBlocks[txid]`.
5. **Delete per-block data:** `BlockTxids`, `BitcoinTxids` and
   `BitcoinCoinbase`.
6. **Delete the candidate index entry** (`height:c` in `BlockHeight`) at
   every height in the chunk.
   - Promotion reads candidates above the confirmed tip, so this needs the
     confirmed tip above the chunk. Pruning only runs while the node is
     current, which keeps the confirmed tip far above the prune target.
   - Confirmed blocks carry `ChainMembership::Confirmed`, and reorgs that
     branch from the confirmed chain do not read the candidate index.

An interrupted chunk repeats cleanly: every delete is idempotent.

`share_block_exists` keys off `BlockTxids`. The gates already accept a
missing body below `prune_height`, so they need no other change.

Reorg-out of a pruned confirmed block needs no new code:
`rewind_confirmed_entries` reads an empty transaction list, and step 4
already deleted the block's spends.

### Start point

The pruner's start is derived, not stored.
`Store::find_prune_start(target)` binary-searches heights
`[1, min(target, top_confirmed + 1))` for the lowest confirmed block that
still has a body, and returns `target` when none does. The predicate is
monotone: heights are header-only below the original fetch floor or the
pruned range, and have bodies above it, because the gates require bodies
for confirmation at or above `prune_height`.

Correctness does not depend on the search. A start that is too low only
re-checks heights, and a start that is too high only leaks a few fork
bodies; neither deletes anything at or above the target.

After a run that prunes, the background task keeps its target in memory as
the next start, so the search only runs until the first such run after a
restart.

### Triggering

Pruning is fully automatic. There is no CLI command and no API trigger.

- **Task.** `start_background_tasks` (`p2poolv2_node/src/background_tasks.rs`)
  starts one task per pool mode. P2Poolv2 mode runs
  `start_block_body_pruning`; Hydrapool mode runs the PPLNS share pruning
  instead, since it has no share chain to prune.
- **Interval.** Every `BACKGROUND_TASK_INTERVAL`, fixed at 6 hours in code
  (the old `background_task_frequency_hours` config option is removed). The
  first tick fires at startup. A run that overruns the interval delays the
  next tick (`MissedTickBehavior::Delay`) rather than bursting.
- **Decision.** Each tick calls `ChainStoreHandle::prune_block_bodies_if_due`.
  The pure function `get_range_to_prune(is_current, candidate_tip_height,
  next_prune_start, find_prune_start)` returns the range `[start, target)`,
  or nothing when:
  - the node is not current (`is_current()`);
  - there is no candidate tip;
  - the start has reached the target.

  The start search only runs when both gates pass.
- **No startup prune.** An ungated prune could run while the confirmed
  chain lags the candidate chain, for example after a restart mid-sync, and
  step 6 would delete candidate entries promotion still needs. After a
  restart the backlog is pruned on the first tick once the node is current.
- **No manual compaction.** The body column families are keyed by hash, not
  height, so a manual compaction would rewrite each of them whole. It is
  exclusive by default, which blocks RocksDB's automatic compaction under
  write load, and it cannot be cancelled at shutdown. Automatic compaction
  reclaims the space and the tombstones.
- **Errors** shut the node down through `ShutdownReason::Error`.

Tombstones scale with the data deleted, not with how often the pruner runs.
At 6 hours a run deletes about 2,160 heights, and the node holds between
`PRUNE_DEPTH + 360` and about `PRUNE_DEPTH + 2,520` heights of bodies.

### Ingress and serving

- **`BlockReceiver`.** If a block's known height is below
  `current_prune_height()`, it drops the block without storing it. The
  header and metadata already exist.
- **Writer guard.** `add_share_block` refuses a body whose height is below
  `prune_target()` with `StoreError::BelowPruneHeight`. The receiver check
  alone can race with a prune chunk; the writer runs both commands in
  order, so its check cannot. `store_and_emit_validation` treats the error
  as success without queuing validation.
- **Block requests.** A pruned body goes through the existing
  `get_share -> None` path, which replies `NotFound` without penalising the
  requester.
- **Headers.** `getheaders` serves every header from genesis with its
  stored merkle branch, pruned heights included.
- **API.** `/share` with `full=true` returns the header with
  `"pruned": true` for a pruned body below `prune_height`, instead of
  `NotFound`.
- **Candidate readers.** These need no change:
  - `build_locator` falls back to the confirmed index.
  - `query_candidates` (the API `candidates` endpoint and CLI `db_query`)
    returns only heights above the deleted range; its doc says so.
  - `organise_block`, `detach_candidate_branch` and
    `reorg_candidate_from_candidate` read only above the confirmed tip.
- **Parent-wait buffer.** Eviction (`mine-on-bitcoin-chain.md` change 2) is
  still pending; when it lands it should use `prune_height`.

### Reorg Depth Limit

Pruning makes the prune target an implicit checkpoint. A heavier branch
forking below it needs the fork point's body, which every node has deleted,
so following it would stall confirmation for as long as the attacker keeps
the work lead.

`organise_header` therefore refuses to reorg the candidate chain onto a
branch whose fork point is below `prune_target_for_tip(candidate tip)`.
`reorg_branch_forks_below_prune_target` (`store/organise/candidate.rs`)
walks `get_branch_to_chain` to the branch point, the same walk
`reorg_candidate` does, and compares its height. On a refusal it logs
`Refusing candidate reorg to <hash>: branch forks below the prune target`
at info and returns `Ok(None)`, as the invalid-branch refusal does. The
walk stops on chain membership, not on the candidate index, so deleting
candidate entries does not affect it.

What different attacks achieve:

| Attack | Result |
|---|---|
| A lower tip by itself (a lighter fork, a withheld chain) | Harmless: lighter branches are never followed, and the 360-height gap absorbs honest tip drops |
| A heavier branch forking above the prune target | Followed normally; every body it needs is still held |
| A heavier branch forking below the prune target | Refused. Building one means out-working about 29.4 days of the whole pool. Honest nodes keep confirming and mining their own chain |
| Spending a pruned output | Needs share transactions, which do not exist yet. With them, the limit must tighten (below) |
| A fake tall tip to move the prune target up | Blocked: headers are PoW-bound, and pruning only runs while `is_current()` |

Fresh nodes syncing from genesis have no competing fork, so they are
unaffected. Two nodes could only diverge over a majority fork more than
29.4 days deep, depending on which branch each saw first. That is accepted.

**With share transactions** the limit must tighten to a fork depth of about
`PAYOUT_DEPTH + PRUNE_INTERVAL` (~14.7 days). Otherwise a valid in-zone
spend could need a deleted output after a deep, height-dropping reorg. See
"Missing Input at Write Time".

**Open issue: the refusal is not remembered.** The node redoes it on every
announcement of a block on the refused branch: it sends `getheaders`, gets
the branch's headers back from height 1, and refuses each one again with a
walk to the fork point. The sim `deep-fork-refused` run logged about 10,000
refusals in 90 seconds over 474 headers. At production depth that cost is
quadratic in the fork depth, and a peer holding such a branch can trigger it
with made-up announcements at no extra work. Reaching it needs a majority
attack first. The planned fix keeps refused fork points in memory so a
repeat refusal costs a lookup, and disconnects a peer whose chain is
refused.

### Tests

- Store level (`store/prune_blocks.rs`): one test per case of the
  boundaries, `get_range_to_prune`, `find_prune_start`, the chunk deletes,
  shared txids, forks, reruns and the writer guard.
- Serving (`p2poolv2_tests/src/pruned_serving_test.rs`): the real
  `getheaders` and `getdata` handlers against a pruned store, and the
  locator.
- Reorg depth limit: `candidate.rs` unit tests for
  `reorg_branch_forks_below_prune_target`.
- Sim (`load-tests/sim`, RUNBOOK Tests H and I). The sim build compiles
  short depths (prune depth 200, interval 20, background interval 30s; see
  `docs/simulation/overview.md`), so every scenario prunes:
  - `pruned-join`: a wiped node syncs from genesis off pruned peers;
  - `deep-fork-refused`: a minority group forked at genesis refuses the
    heavier majority once every node has pruned;
  - `shallow-fork-reorged`: the control, where the same minority reconnects
    above the prune target and follows the majority.

### Deferred

- **Conditional deletes.** The chunk deletes candidate entries for every
  height, `SpendsIndex` rows for every output (most are unspent) and the
  unused `BitcoinTxids` key without checking that they exist, and each
  delete writes a tombstone, again on every rerun. Checking each set with
  one `multi_get` first and deleting only present keys would avoid that.
- **Bitcoin header store (#652).** When it lands it keeps at least
  `PAYOUT_DEPTH + PRUNE_DEPTH` plus one retarget period, about 8,400
  headers (see `mine-on-bitcoin-chain.md` "Retention"). Its pruning belongs
  in the same background task.

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
- **A missing input at write time gets an unknown-root marker,** which
  is deferred until share transactions land.

## Decisions (2026-10-16 to 2026-10-18, implementation)

- **No persisted watermark.** Both boundaries are computed from the
  candidate tip, and the pruner's start is derived from the data. A stored
  watermark would have to be kept consistent with the store, and later
  cleanup would be harder.
- **Candidate index entries are deleted at every height below the prune
  target,** not only below the confirmed tip (pruner step 6).
- **Fully automatic.** No CLI command and no API trigger.
- **A fixed 6 hour interval,** in code. The
  `store.background_task_frequency_hours` option is removed.
- **`BitcoinTxids` keys are deleted** although nothing writes them yet.
- **A reorg depth limit at the prune target,** refusing forks below it.
- **No manual compaction and no startup prune** (see "Triggering").
- **Separate tasks per pool mode:** block body pruning in P2Poolv2 mode,
  PPLNS share pruning in Hydrapool mode.
- **Sim depths are compile-time constants** under `cfg(feature = "sim")`,
  not sim config, so every node built from one binary agrees on them.
- **Deferred:** the conditional-delete tombstone fix, and the fix for the
  repeated refusal (see "Reorg Depth Limit").

## Alternatives Rejected

- **Height-prefixed transaction keys with `delete_range`.** Outpoint
  lookups need txid-keyed rows, so this would need a second index.
- **A RocksDB compaction filter.** It cannot do the cross-key reference
  check.
- **A persisted watermark** (`meta:pruned_below_height`) written in the
  same batch as each chunk's deletes. Replaced by derived boundaries and a
  derived start point (see "Decisions (2026-10-16 to 2026-10-18)").
- **An offline CLI prune** (`p2poolv2_cli prune`). The background task
  covers every case.
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
