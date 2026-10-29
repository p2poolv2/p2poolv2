---
name: Share Transaction Relay Mempool
description: Durable pool of unconfirmed share transactions and the batch discipline that maintains it
---

**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Share Transaction Relay Mempool

## Purpose

A share transaction reaches the node before the share block that carries it. The pool
holds those transactions until a share includes them or a limit removes them. It is
durable: a restart keeps the pool. It shares one RocksDB instance with the chain so that
a block confirmation and the removal of its transactions from the pool commit together.

Core keeps its pool in memory and writes a snapshot at shutdown. A crash between the
block write and the snapshot leaves confirmed transactions pooled and needs a full
revalidation to repair. One database and one batch remove that window.

## Invariants

1. **Durable.** Entries are rows and survive a restart.
2. **Atomic with confirmation.** A block and the removal of its transactions commit in
   one batch.
3. **First-seen wins.** A transaction spending an outpoint already spent by a pooled
   transaction is rejected. Across a reorg, the pooled transaction keeps its place.
4. **Strict parents.** Every input resolves against a confirmed output or a pooled
   parent. No orphans.
5. **Selection by fee rate.** Shares are assembled in descending sat/vb with
   dependencies respected. Age is not a selection input.
6. **Two limits.** Expiry at 72h from first seen and a 300 MiB size cap. Expiry uses
   age, size eviction uses fee rate, and neither blocks writes.

Admission enforces duplicate, conflict and size checks. Reads only expose state.

## Storage

Three column families in the chain database:

| CF | Key | Value | Purpose |
|---|---|---|---|
| `mempool` | sequence number, 8 bytes big-endian | consensus-encoded entry | The entry. Key order is insertion order. |
| `mempool_index` | txid, 32 raw bytes | sequence number, 8 bytes | txid to entry, and duplicate detection. |
| `mempool_spends` | `{txid}:{vout}` string | spender txid (32 bytes) + input index (u32) | At most one pooled spender per outpoint; the conflict index. |

An entry carries the transaction, its txid, the coinbase root height, the receipt time,
the serialized size, the fee in sats and the vsize. The txid and size are derived once at
construction so point lookups and size accounting never re-encode. The coinbase root
height records the spendability window and travels with the transaction into the share
that includes it. Fee and vsize are computed at admission while the inputs still resolve;
they drive selection and eviction.

## Ordering

### Storage order: the sequence number

The sequence number is monotonic and never reused. Keys are big-endian so lexicographic
order equals numeric order. Deleting leaves gaps, which costs nothing because order
matters and density does not.

Under strict parents a transaction can only be admitted after its parent, so insertion
order is topological order and a parent's row exists before its child's. That is what
lets a child's prevouts resolve from the pool. A reorg re-insertion takes fresh sequence
numbers in block order for the same reason.

### Selection order: sat/vb, descending

Per-transaction sat/vb does not reproduce a package score: a cheap child of a rich parent
scores badly on its own and well with its parent. Core computes an ancestor score on entry
and assembles from a fee-rate queue that holds children until their parent is selected.
The equivalent here is a fee-rate order over the pool with a dependency-aware walk: an
entry becomes eligible only once its parent is already selected or confirmed.

Package-level scoring is out of scope for this initial version. Ancestor scoring is the
upgrade path if package value turns out to matter.

Because the orders differ, assembly cannot walk the pool in sequence order. That order
governs storage and dependency only.

## Write paths

### Admission

1. txid already pooled: no-op, write nothing.
2. Entry larger than the cap: reject as full; it cannot fit an empty pool.
3. Check conflicts. An input whose outpoint already has a pooled spender rejects the
   admission. Check and write are one operation on the writer thread, so two concurrent
   conflicting spends cannot both pass.
4. Copy the counters; evict the lowest fee rate first, with pooled descendants, until the
   entry fits; write the three rows and the counters in one batch; commit; publish the
   counters.
5. Eviction runs before the insert so the pool never exceeds the cap between two
   commits. Core inserts first and evicts after.

Eviction removes the subtree. Evicting an ancestor takes its pooled descendants with it,
so no pooled entry is left without a resolvable parent.

### Confirmation

Confirmation removes the pool rows of every non-coinbase transaction in a promoted block,
in the same batch as the block's spends. Nothing cascades: a pooled child spending an
output that just became confirmed stays valid.

When a promotion carries no body, its transactions are cleared by txid from the block
index. A confirmed transaction must never remain selectable.

### Reorg

The disconnected blocks' non-coinbase transactions are collected in ascending height
order, fork point excluded, and re-pooled as fresh entries. An already pooled transaction
keeps its first-seen entry. A transaction conflicting with a pooled spender is dropped
with a warning. The rest are written with a fresh sequence number and a receipt time of
now, so the age limit treats them as new.

Reads during the reorg see the batch's own writes through an overlay, and conflict checks
cover the confirmed spends index as well as pooled spends. The size cap applies here too.
The path is best-effort: a transaction whose prevout no longer resolves is logged and
skipped, so the reorg completes and the pool loses one entry instead of the chain losing
a block.

### Expiry

A background sweep every 30s deletes entries first seen before the expiry window,
each with its pooled descendants. A failure shuts the node down through the error
shutdown reason. An expiring parent would strand its children under strict parents, which
is why the sweep takes the subtree with it.

### Counters

`count` and `total_bytes` track pool size. They commit in the same batch as the row
mutations, so a crash cannot leave them disagreeing with the rows. Readers use them for
sizing and never for correctness. A full scan on open is unnecessary except for read-only
opens, which skip it.

### Startup reconciliation

A transaction confirmed while the node was down would otherwise stay pooled after the
restart. At open, pooled txids present in the confirmed index are dropped. Revalidating
prevouts is the stronger version.

## Cost

Each admission is one batch over three column families on the single writer thread. That
thread also writes blocks and runs prune chunks, so pool traffic can queue ahead of block
writes. At the network's 100 tx/s cap the queue stays short. Coalescing admissions per
event-loop turn removes the queueing risk while keeping atomicity on confirmation, the
only place it matters.

Eviction uses in-memory ordered indexes, fee order for size and time order for expiry,
touched only when the cap is crossed. A full sort per admission would cost O(n log n) at a
million entries and grow with the cap.

## Where this differs from Core and libbitcoin

| Concern | Bitcoin Core | libbitcoin | Here |
|---|---|---|---|
| Storage | memory, dumped at shutdown | memory | RocksDB rows |
| Confirm plus clear | two steps, repaired by re-validation | not applicable | one batch |
| Orphans | bounded orphan pool | orphan pool | none, strict parents |
| Conflict index | one map under one lock | per-pool index | split across two CFs |
| Selection order | ancestor fee rate | arrival | sat/vb, dependency-aware |
| Eviction | mining score incl. descendants | arrival | fee rate |
| Reorg | drop conflicts and unavailable inputs | re-validate | re-pool disconnected transactions |

Fee-rate ordering follows Core's model rather than libbitcoin's arrival order. Against
Core, this layer gives up ancestor and descendant accounting, CPFP package value and
eviction by descendant score; a pooled transaction is scored on its own sat/vb until
ancestor scoring lands.

## Docs to update

The documents below predate the pool and would benefit from a pass once the design is
settled:

- `store-schema.md`: the three column families, their keys and values.
- `pruning.md`: the pool as a fourth data zone, pruned by size and age rather than by
  height.
- `store-architecture.md`: the four write command variants.
- `CHANGELOG.md`: the pool, the settings and the write commands.
- Metrics: pool count and bytes, admissions, evictions and expiries.
