---
name: Share Processing Pipeline
description: Documents the data flow for processing shares from stratum submission through storage and organisation
---

# Share Processing Pipeline

This document describes the data flow for processing shares in p2pool-v2.

## Overview

The share processing pipeline is designed to:
1. Offload CPU-intensive work from the main swarm event loop
2. Serialize database writes via StoreWriter on a dedicated OS thread
3. Decouple candidate chain building from confirmed chain promotion
4. Validate blocks before organisation and relay
5. Cascade validation to dependents (children/nephews) when holes are filled

## Data Flow Diagram

```
+-------------------+          +---------------------+
|  Stratum Server   |          |  P2P Peer Network   |
|  (miner submit)   |          |  (share blocks)     |
+--------+----------+          +----------+----------+
         |                                |
         | Emission (mpsc)                | handle_share_block
         v                                v
+------------------------+     +---------------------------+
| EmissionWorker         |     | Share Block Handler       |
| (tokio task)           |     | (p2p message handler)     |
|                        |     |                           |
| - handle_stratum_share |     | - Stores share block      |
|   stores share,        |     | - Checks missing deps     |
|   organises header     |     |   (parent, uncles)        |
| - Sends ValidateShare  |     | - If deps missing:        |
|   Block to validation  |     |   sends FetchBlocks,      |
|                        |     |   defers validation       |
+---+----------+---------+     | - If deps present:        |
    |          |               |   sends ValidateBlock     |
    |          |               +----------+----------------+
    |          |                          |
    |          | validation_tx            | validation_tx
    |          | (mpsc, cap 8192)         | (mpsc, cap 8192)
    |          v                          v
    |   +------------------------------------------+
    |   | ValidationWorker (tokio task)            |
    |   |                                          |
    |   | - Receives ValidateBlock events          |
    |   | - Spawns capped concurrent tasks         |
    |   |   (semaphore = available CPUs)           |
    |   | - validate_share_block():                |
    |   |   returns Ok early if already BlockValid |
    |   |   validates uncles in store              |
    |   | - On success:                            |
    |   |   sends Block to organise                |
    |   |   sends Inv to swarm                     |
    |   | - On Consensus failure:                  |
    |   |   sends InvalidBlock to organise         |
    |   | - On Recoverable failure:                |
    |   |   nothing (see "Retrying a block that    |
    |   |   failed without a verdict" below)       |
    |   +----+-----------------+-------------------+
    |        |                 |
    |        | organise_tx     | swarm_tx
    v        v                 v
+-------------------+       +-----------------+
| OrganiseWorker    |       |   NodeActor     |
| (tokio task)      |       |                 |
|                   |       | - Receives      |
| Two event types:  |       |   SwarmSend::   |
|                   |       |   Inv/Broadcast |
| Header(ShareHdr): |       | - Relays inv to |
|   organise_header |       |   peers via     |
|   -> candidate    |       |   peer knowledge|
|   chain updates   |       +-----------------+
|                   |
| Block(ShareBlock):|
|   organise_block  |
|   -> confirmed    |
|   promotion       |
|                   |
| Fatal errors      |
| stop the node     |
+--------+----------+
         | WriteCommand::OrganiseHeader
         | WriteCommand::OrganiseBlock
         | (via StoreHandle oneshot pattern)
         v
+-------------------------------------+
| StoreWriter (dedicated OS thread)   |
|                                     |
| - Receives WriteCommands via        |
|   std::sync::mpsc (unbounded)       |
| - Processes sequentially            |
| - OrganiseHeader: calls             |
|   Store::organise_header() with     |
|   WriteBatch (atomic candidate      |
|   chain update)                     |
| - OrganiseBlock: calls              |
|   Store::organise_block() with      |
|   WriteBatch (atomic confirmed      |
|   chain promotion)                  |
+--------+----------------------------+
         |
         v
+--------------------------------------+
|      Store (RocksDB)                 |
|                                      |
| - organise_header()                  |
|   - extend candidates or reorg       |
|   - forward walk for children        |
| - organise_block()                   |
|   - extend confirmed or reorg        |
|   - reads committed candidate state  |
+--------------------------------------+
```

## Two-Event Model

The organisation pipeline processes two distinct event types:

### OrganiseEvent::Header(ShareHeader)
- **Purpose**: Update the candidate chain
- **Called by**: `Store::organise_header(header, batch)`
- **Behavior**: Extends or reorgs the candidate chain based on the new header.
  Only requires a `ShareHeader`, not a full `ShareBlock`.
- **Does NOT**: Touch the confirmed chain

### Retrying a block that failed without a verdict

A `Recoverable` or `StoreAccess` validation failure leaves the block at
`HeaderValid`, never `Invalid`. Only re-delivery revalidates it:
`handle_share_block` re-sends `ValidationEvent::ValidateBlockHash` for any block
already in the store that is not yet confirmed (`share_blocks.rs`), and that
handler serves both peer broadcasts and `GetData` responses. Nothing else does:
a candidate reorg never re-validates, and the block fetcher will not re-request
the body since `share_block_exists` is true. The retry is therefore
opportunistic -- it depends on a peer sending the block again, which this node
does not solicit.

The BlockReceiver's ancestry gate (below) makes the common causes unreachable,
but not all of them: `collect_recent_ancestors` walks `MAX_UNCLES_DEPTH` of
ancestry, and an uncle's `expected_height` may be absent. Until a re-delivery
arrives, such a block stalls, and in the PPLNS zone a stalled candidate stops
confirmation at its height.

### BlockReceiver ancestry gate

`process_share_block` holds a block in `pending` until its parent and every
uncle either has its **block body** stored or sits below `prune_height`
(`candidate tip - PRUNE_DEPTH`), checked by
`ChainStoreHandle::all_block_and_uncle_data_available`. `drive_descendants`
re-checks and releases buffered blocks each time one commits.

Gating on bodies rather than header status is what makes ancestry data an
induction: every ancestor down to the prune boundary has its body, so the
Outputs CF holds the transactions of every block a descendant may spend from.
Header status would not give this -- header sync marks a whole range
`HeaderValid` via `organise_header` before any body is fetched, so a child
could otherwise be validated while its parent's transactions are still missing,
and `collect_spent_outputs` would fail on a block that is perfectly valid.

Blocks below `prune_height` are exempt because their bodies are never fetched;
requiring one would stall the chain permanently at the boundary. Spends cannot
reach below it either: `min_coinbase_root_height` caps them one window back
(`MAX_PPLNS_WINDOW_SHARES`) while bodies are retained for two (`PRUNE_DEPTH`).

### OrganiseEvent::InvalidBlock(BlockHash)
- **Purpose**: Record that a block failed pre-context validation
- **Sent by**: the ValidationWorker, on a `Consensus` failure from
  `validate_share_block` / `validate_below_pplns_depth`
- **Behavior**: `mark_invalid` (which rebuilds the candidate chain from the
  invalid block's parent onto the best surviving branch), then `organise_block`
  to catch the confirmed chain up
- **Why**: the block's header may already be on the candidate chain. Left
  `HeaderValid`, it stops `contiguous_candidates_with_block_data` at its height
  and confirmation stalls there, with nothing to re-fetch or re-queue it.

### OrganiseEvent::Block(ShareBlock)
- **Purpose**: Promote candidates to confirmed
- **Called by**: `Store::organise_block(batch)`
- **Behavior**: Reads the committed candidate and confirmed chain state from
  RocksDB, then extends or reorgs the confirmed chain if conditions are met.
- **Does NOT**: Modify the candidate chain

This separation enables future use where header sync sends Header events
(building the candidate chain) and block fetch sends Block events (promoting
to confirmed), operating independently.

## Key Components

### EmissionWorker (`node/emission_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `Emission` from stratum server via `EmissionReceiver`
- Calls `handle_stratum_share()` which builds the share, stores it, and
  organises its header onto the candidate chain
- On success with `Some(ShareBlock)`: sends
  `ValidationEvent::ValidateShareBlock(share_block)` straight to the
  ValidationWorker (avoiding a redundant store read). The ValidationWorker
  emits `OrganiseEvent::Block` for confirmed promotion and broadcasts to peers
  after validation succeeds, and `OrganiseEvent::InvalidBlock` when validation
  fails with `FailureKind::Consensus`.
- On success with `None`: solo mode, no broadcast or organisation needed

### handle_stratum_share (`shares/handle_stratum_share.rs`)
- Async function that processes emissions
- P2P mode (share commitment present): builds `ShareBlock`, persists it and
  organises its header onto the candidate chain in one atomic write via
  `ChainStoreHandle::add_share_block_and_organise_header()`, and returns
  `Some(ShareBlock)`
- Solo mode (no commitment): stores PPLNS share via `ChainStoreHandle::add_pplns_share()`, returns `None`

Locally-mined blocks are not validated or marked `BlockValid` here. Like peer
blocks, they are enqueued for validation (see EmissionWorker), and the organise
worker's `validate_mark_promote` marks them `BlockValid` after chain-context
validation, just before confirmation.

### OrganiseWorker (`node/organise_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `OrganiseEvent` via bounded mpsc channel (capacity 8192)
- Matches on event type:
  - `Header(header)`: calls `ChainStoreHandle::organise_header(header)`
  - `Block(share_block)`: gated on its parent's validation state before any
    chain-context validation runs (see "Parent-gated block processing" under
    Organisation Logic)
  - `InvalidBlock(blockhash)`: marks the block `Invalid` and advances the
    confirmed chain; no validation or promotion runs for it
- Error handling reacts to the validation failure kind (`FailureKind`):
  - `Consensus` (a rule broken with all data present): mark the block `Invalid`
    and continue; confirmation can then advance onto a valid sibling.
  - `StoreAccess` (the store read itself failed, or data whose absence can only
    mean corruption is gone) and `StoreError::ChannelClosed`: both fatal --
    return `Err(OrganiseError)`, triggering node shutdown. No verdict a
    peer-supplied block can provoke may be classified this way, or any peer
    could shut the node down: a prevout that is missing or outside the payout
    window is `Consensus`, and an ancestor header or PPLNS anchor this node
    cannot resolve locally is `Recoverable`.
  - `Recoverable` (data the check needs is unavailable, so the block cannot be
    judged now -- a pre-context dependency that can still arrive, a missing
    ancestor header, or an unresolvable PPLNS anchor): leave the block for a
    later retry; never `Invalid`, never fatal.
  - Channel close (all senders dropped) is clean shutdown

### NodeActor (`node/actor.rs`)
- Creates organise channel and spawns OrganiseWorker
- Monitors OrganiseWorker's `JoinHandle` in `tokio::select!` loop
  - Fatal error or panic triggers node shutdown via `stopping_tx`
- Spawns EmissionWorker with `organise_tx`
- Handles `SwarmSend::Broadcast` to send shares to all peers

### StoreWriter (`store/writer/mod.rs`)
- Runs on dedicated OS thread via `tokio::task::spawn_blocking`
- Receives `WriteCommand` variants via `std::sync::mpsc` (unbounded)
- Processes commands sequentially with `WriteBatch` for atomicity
- `WriteCommand::OrganiseHeader` calls `Store::organise_header()` with a single batch for atomic candidate chain updates
- `WriteCommand::OrganiseBlock` calls `Store::organise_block()` with a single batch for atomic confirmed chain promotion

### ChainStoreHandle (`shares/chain/chain_store_handle.rs`)
- Wraps `StoreHandle` with chain-level logic (height calculation, chain work)
- Async writes (e.g. `add_share`, `organise_header`, `organise_block`) go through serialized write channel
- Synchronous reads go directly through `Arc<Store>`

## Channel Configuration

| Channel | Type | Capacity | Purpose |
|---------|------|----------|---------|
| emissions_rx | tokio mpsc | 100 | Stratum server -> EmissionWorker |
| validation_tx/rx | tokio mpsc | 8192 | Share handlers -> ValidationWorker |
| organise_tx/rx | tokio mpsc | 8192 | ValidationWorker/EmissionWorker -> OrganiseWorker |
| swarm_tx/rx | tokio mpsc | 100 | ValidationWorker/EmissionWorker -> NodeActor |
| block_fetcher_tx/rx | tokio mpsc | 8192 | Share handlers -> BlockFetcher |
| write_tx/rx | std::sync mpsc | unbounded | StoreHandle -> StoreWriter (serialized writes) |

## BlockHeight Column Family Key Schema

The `BlockHeight` CF (`"block_height"`) stores three distinct namespaces in a single column family, distinguished by key format:

| Key Format | Value | Purpose | Defined in |
|---|---|---|---|
| `h:` + `{height BE u32}` | `Vec<BlockHash>` (merge append) | All blocks at a given height | `share_store.rs` |
| `{height BE u32}` + `:c` | Single `BlockHash` | Candidate chain index | `organise/mod.rs` |
| `{height BE u32}` + `:f` | Single `BlockHash` | Confirmed chain index | `organise/mod.rs` |
| `meta:top_candidate_height` | `u32` | Top candidate height tracker | `organise/mod.rs` |
| `meta:top_confirmed_height` | `u32` | Top confirmed height tracker | `organise/mod.rs` |

All values use Bitcoin consensus serialization.

**Height-to-blocks index** (`h:{height}`): Written via RocksDB merge operator to atomically append blockhashes. Used by `get_blockhashes_for_height()` to find all blocks stored at a given height.

**Candidate/confirmed chain indexes** (`{height}:c`, `{height}:f`): Map a single height to its chain-selected blockhash. The `:c` and `:f` suffixes share the same 4-byte height prefix, so range queries filter by `key.ends_with(suffix)` to avoid cross-contamination.

**Metadata keys** (`meta:*`): Singleton keys that track the current top height of each chain. These are string keys that don't collide with the height-prefixed keys because `meta` is not a valid 4-byte BE height prefix.

Constants (`organise/mod.rs`):
```rust
const CANDIDATE_SUFFIX: &str = ":c";
const CONFIRMED_SUFFIX: &str = ":f";
const TOP_CANDIDATE_KEY: &str = "meta:top_candidate_height";
const TOP_CONFIRMED_KEY: &str = "meta:top_confirmed_height";
```

## Organisation Logic

### Store::organise_header (candidate chain)

`organise_header` processes a share header through three paths, checked in order:

1. **Extend candidate chain** (`extends_chain`): If the header's `prev_share_blockhash` matches the top candidate (or top confirmed as fallback), height is consecutive, and chain work is greater, it appends to the candidate index via `append_to_candidates`.

2. **Reorg candidate chain** (`should_reorg_candidate` / `reorg_candidate`): If the header has more cumulative work than the current top candidate but doesn't extend it, the candidate chain is replaced:
   - `get_branch_to_chain` walks backward from the new share to find the branch point (the first ancestor already on the candidate or confirmed chain)
   - `get_candidates_chain` fetches the old candidate entries from the branch point to the top
   - Old entries are deleted and reorged-out shares have their membership cleared to `ChainMembership::None` (so `is_candidate()` stays correct for future branch point lookups). Their `Status` is left untouched: status records validation only, so a reorged-out block stays `BlockValid`
   - New branch entries are written and their membership set to `ChainMembership::Candidate`
   - Top candidate height is set once at the end

3. **No-op**: Header doesn't extend or outwork the current candidate chain.

### Store::organise_block (confirmed promotion)

`organise_block` reads the committed candidate and confirmed chain state and checks:

1. **Extend confirmed chain** (`should_extend_confirmed`): If the candidate chain extends the confirmed chain at the next height with the same prefix, promote all candidates to confirmed.

2. **Reorg confirmed chain** (`should_reorg_confirmed`): If the candidate chain has more work than the confirmed chain, replace the confirmed chain with the candidate chain.

3. **No-op**: No promotion conditions met.

Confirmation only ever follows the candidate chain; there is no forward-by-height
fallback. A block that could not yet reorg the candidate chain (for example a
locally-mined block whose parent is not yet validated) is not chased by height --
it advances only once the candidate chain incorporates it and its parent is
`BlockValid` (see "Parent-gated block processing").

All writes go into a single `WriteBatch` for atomicity.

**Validated-only promotion**: inside the PPLNS zone, promotion accepts only
*validated* blocks. `contiguous_candidates_with_block_data` (the candidate-chain
scan) gates on `Store::is_candidate_and_block_valid`, which requires both
`Candidate` membership and `BlockValid` status -- rejecting `HeaderValid`
(PoW-valid but not chain-context validated), `Pending`, and `Invalid` blocks. So
an unvalidated or rejected block is never promoted, even when its body is stored.
The organise worker's `validate_mark_promote` marks a block `BlockValid` after
chain-context validation and *before* it calls `organise_block`, so the block is
already validated by the time this promotion path sees it.

**Prevout re-check at confirmation**: `BlockValid` is not sufficient on its own,
because prevout validity is relative to the confirmed chain and a block is
validated before it is confirmed. Two cases slip past ingest validation: a reorg
can move a spent output's source off the confirmed chain, and two blocks on one
candidate chain can each spend the same output (neither sees the other's spend,
since `SpendsIndex` is written only at confirmation). So `extend_confirmed` and
`reorg_confirmed` re-check each block's prevouts as they promote it, against the
confirmed state *the batch itself is building* -- a `WriteBatch` is opaque to
reads, so the deltas are carried in a `ConfirmationOverlay` (blocks leaving the
confirmed chain, the spends they release, and the spends applied so far in this
batch). Only the leading run that passes is confirmed; the first block that fails
is marked `Invalid`, which rebuilds the candidate chain from its parent. On a
reorg the re-check and the work comparison both run *before* the rewind, so a
fork whose surviving prefix no longer outweighs the confirmed chain leaves it
untouched rather than regressing the tip. Coinbase maturity needs no re-check: it
is measured at ingest against the block's own height (parent height + 1), which
is fixed by chain position and so is reorg-invariant.

### Parent-gated block processing

`OrganiseEvent::Block`s arrive in validation-completion order, not parent-child
order (the validation worker runs one task per block). To validate each block
exactly once with all its dependencies present, `process_share_block` gates a
block on its parent's state (`parent_state`) *before* any chain-context
validation:

- **Parent `Invalid`** -- the block is invalid by descent; drop it.
- **Parent metadata `Unknown`** -- drop it; it re-arrives when its parent does.
- **Parent `Pending`** (stored but not yet `BlockValid`) -- buffer the block in
  `pending_blocks`, keyed by the parent's height. This is the only wait-and-retry
  state, and the decision is a cheap metadata read, not a validation attempt.
- **Parent `Valid`** (`BlockValid` or `Confirmed`) -- run `validate_mark_promote`.
  Because the parent is validated, every dependency the checks need is present, so
  a failure is classified by `FailureKind` and handled as above (Consensus ->
  Invalid, StoreAccess -> fatal, Recoverable -> retry).

Deferral is driven purely by *parent validation state*, not by the block's height
relative to the confirmed tip. There is no forward-by-height scan chasing children
of the confirmed tip -- the removed `try_fallback_confirmation`.

When a block becomes `BlockValid` (or is promoted), `drain_pending_blocks`
re-attempts the blocks buffered under that height and walks contiguously upward,
stopping as soon as a height advances nothing. The parent height is only an index
for locating a validated parent's waiting children; a re-attempted block whose
parent is still `Pending` cheaply re-buffers. This keeps a full sync linear rather
than quadratic. Separately, the validation worker chases dependents by pointer
(`schedule_dependents` via `get_children_blockhashes` / `get_nephews`), not by
height (see "Hole-filling cascade").

### WriteBatch stale-read pattern

Within a single `WriteBatch`, reads from the DB return pre-batch (committed) state. The reorg logic avoids this by using direct batch helpers (`set_top_candidate_height`, `put_candidate_entry`, `delete_candidate_entry`) that write without validating against DB state, and setting the final top height once rather than incrementing/decrementing per entry.

## Validation Worker

### ValidationWorker (`node/validation_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `ValidationEvent::ValidateBlock(BlockHash)` via bounded mpsc channel (capacity 8192)
- Spawns capped concurrent validation tasks (semaphore sized to available CPUs)
- Each task:
  1. Reads the share block from the chain store
  2. Calls `validate_share_block()` which returns Ok early if the block
     already has `BlockValid` status (avoids redundant work for re-scheduled blocks)
  3. On success: sends `OrganiseEvent::Block` always; sends
     `SwarmSend::BroadcastBlock` only when `is_current()` is true
     (suppresses relay of historic blocks during initial sync)
  4. Calls `schedule_dependents()` which looks up children (via
     `get_children_blockhashes`) and nephews (via `get_nephews`) and sends
     `ValidateBlock` events back through the validation channel
- The worker holds a `ValidationSender` clone so `schedule_dependents` can
  send events. The worker is shut down by cancelling its task.

### Hole-filling cascade
When a missing block arrives and validates, `schedule_dependents` enqueues
its children and nephews for validation. Each of those, on success, enqueues
their own dependents. This cascades from the filled hole all the way to the
tip without explicit forward-walk logic.

Blocks that were already validated (status `BlockValid`) but could not be
promoted because their parent was not yet confirmed will be re-scheduled.
`validate_share_block` returns Ok immediately for these, and `organise_block`
gets another chance to promote them.

### Dependency fetching
When a share block arrives from a peer (`handle_share_block`), its parent
and uncle references are checked against the store. If any dependency is
missing, a `FetchBlocks` event is sent to the block fetcher and validation
is deferred. Once the dependency arrives and validates, `schedule_dependents`
picks up the waiting block.

### Payout (coinbase) validation
Chain-context validation (`validate_bitcoin_payout` in
`shares/validation/mod.rs`) reconstructs the expected coinbase from the PPLNS
window and checks it against the share's bitcoin merkle root. Success is what
transitions a block from `HeaderValid` to `BlockValid`.

The window is anchored on the share's declared `prev_share_blockhash`, not the
live confirmed tip, via `PplnsWindow::get_distribution_from_start_hash`. The
work-building path (notify) anchors the coinbase it hands to miners on the same
`prev`, so producer and validator compute the identical distribution for the
same parent -- closing a race where a confirmation advancing between reads made
a mined share's coinbase inconsistent with its declared parent.

Resolving the window walks parent pointers back to a confirmed ancestor and:
- follows `prev_share_blockhash` with no status or membership filter, stopping at
  the first ancestor already inside the cached confirmed window. The blocks it
  steps through are validated in practice because chain-context validation is
  parent-gated, not because the walk itself checks;
- returns an `Err` -- rather than a bootstrap or empty distribution -- on a
  store failure or an unresolvable anchor, so a transient read error cannot
  silently misdirect the reward. The producer pays the bootstrap address only
  for the explicit empty/genesis case (`PplnsWindow::is_empty`).

### Uncle selection vs uncle acceptance

These are deliberately different rules, and the asymmetry is intentional.

**Acceptance** (`validate_uncles`, `validate_uncle_positions`) is a pure
function of chain shape: count, no duplicates, body present, and the structural
position rules (an uncle is below the nephew, within `MAX_UNCLES_DEPTH`, and not
on the nephew's own ancestry). It deliberately does **not** consult mutable
per-node state. An earlier rule -- "an uncle must not be on the confirmed
chain" -- was removed for exactly this reason after it deadlocked nodes in the
sim (SYNC_ISSUES, August 15th): two nodes at different confirmation heights
disagreed about the same block, and the nephew that would have healed the split
was the one being rejected.

For the same reason, acceptance does not reject a nephew whose uncle this node
holds as `Invalid`. `Invalid` is a consensus verdict, but *when* a node reaches
it depends on validation progress, which differs across nodes and lags far
behind header sync during catchup. A node that had not yet validated the uncle
would accept the nephew while a node that had would reject it, and since
`Invalid` is terminal, that split is permanent. The rule would also make payouts
*less* consistent, not more: the distribution is derived from chain shape, so
nodes agree as long as they agree on which blocks are in the chain.

**Selection** (`Store::find_uncles`) is node-local policy and carries none of
that risk, so it is stricter: candidates must be at least header-validated,
skipping `Invalid` and `Pending`. Every node validates our produced share the
same way regardless of what we chose, so declining to reference a block we
judged invalid cannot diverge anything.

The cost of the gap this leaves is bounded, because an uncle contributes
**nothing to chain state**. `put_confirmed_entry` applies `add_spends_for_block`
only for the block being confirmed, never for its uncles, and an uncle's outputs
are unspendable anyway since `validate_prevouts` requires the source txid to be
confirmed. Referencing an uncle only pays PPLNS weight
(`UNCLE_SCALED_WEIGHT`, plus the nephew's `NEPHEW_SCALED_BONUS`). So the worst
case is that a peer's nephew credits a block we consider invalid -- for work
that was really done, since the block passed PoW at pool difficulty and was
rejected over its contents.

Closing that gap safely would need invalidation to cascade: `mark_invalid`
would also invalidate the block's nephews via the `Uncles` index, so every node
converges on the same verdict whenever it learns. That makes invalidation
recursive over the DAG and needs its own bounding; it is not implemented.

## Future Additions

### Header Sync / Block Fetch Separation
- Header sync can send `OrganiseEvent::Header` events to build the candidate chain
- Block fetch can send `OrganiseEvent::Block` events to promote candidates to confirmed
- These can operate independently and concurrently

## Files

- `p2poolv2_lib/src/node/emission_worker.rs`
- `p2poolv2_lib/src/node/validation_worker.rs` (ValidationWorker, schedule_dependents)
- `p2poolv2_lib/src/node/organise_worker.rs`
- `p2poolv2_lib/src/node/actor.rs`
- `p2poolv2_lib/src/node/request_response_handler/block_fetcher.rs` (BlockFetcher)
- `p2poolv2_lib/src/node/p2p_message_handlers/receivers/share_blocks.rs` (handle_share_block, dependency fetching)
- `p2poolv2_lib/src/shares/handle_stratum_share.rs`
- `p2poolv2_lib/src/shares/validation/mod.rs` (validate_share_block, validate_uncles, validate_bitcoin_payout)
- `p2poolv2_lib/src/accounting/payout/sharechain_pplns/pplns_window.rs` (PplnsWindow, get_distribution_from_start_hash, prev-anchored payout walk)
- `p2poolv2_lib/src/shares/chain/chain_store_handle.rs`
- `p2poolv2_lib/src/store/writer/mod.rs` (StoreWriter + WriteCommand)
- `p2poolv2_lib/src/store/writer/handle.rs` (StoreHandle)
- `p2poolv2_lib/src/store/organise/mod.rs` (candidate/confirmed index management)
- `p2poolv2_lib/src/store/organise/candidate.rs` (get_candidate_blocks_missing_data)
- `p2poolv2_lib/src/store/organise/organise_header.rs` (Store::organise_header, candidate chain logic)
- `p2poolv2_lib/src/store/organise/organise_block.rs` (Store::organise_block, confirmed promotion)
