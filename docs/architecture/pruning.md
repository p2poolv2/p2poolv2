# Pruning Architecture

This document describes how P2Poolv2 handles chain pruning: syncing
efficiently, validating blocks in two zones, and enforcing output
spendability rules.

## Overview

P2Poolv2 retains a rolling window of chain data. Old block bodies are
pruned while headers are kept indefinitely. The system uses two depth
constants:

- **PPLNS_DEPTH** (120,960 blocks, ~14 days): blocks within this
  window get full transaction validation and participate in payout
  accounting.
- **PRUNE_DEPTH** (241,920 blocks, ~28 days): blocks within this
  window have their bodies retained. Blocks between PRUNE_DEPTH and
  PPLNS_DEPTH get PoW-only body validation.

## Header Sync

Headers are always synced from genesis. The full header chain is
retained permanently (~276 bytes per header, ~4 GB after 5 years).

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
genesis. Once checkpoints are in place, headers below the latest
checkpoint can also be pruned. Not in the MVP.

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

### Prune zone (height <= tip - PPLNS_DEPTH)

`validate_below_pplns_depth` runs:
- Pool difficulty (PoW)
- Uncle validity
- Block size
- Transaction count

Skips: coinbase structure, merkle root, witness commitment,
transaction structure, script verification, prevout validation, MTP,
bitcoin coinbase payout verification.

### PPLNS zone (height > tip - PPLNS_DEPTH)

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

`validate_prevouts` computes `min_coinbase_root_height = tip_height -
PPLNS_DEPTH` and passes it to `check_prevouts_and_find_coinbase`.
Outputs with `coinbase_root_height < min_coinbase_root_height` are
rejected in the same batch read that checks output existence -- no
second pass needed.

### Why store-at-write, not walk-at-validation

A walk-at-validation approach was evaluated: walk the spending chain
back to the coinbase during `validate_prevouts`. Rejected because an
attacker can build spending chains up to ~12 million hops deep
(120,960 blocks x 99 txs/block), creating a DoS of ~24 seconds per
input validation. Store-at-write is O(1) at validation time and
O(inputs) at write time, bounded by block size (~5000 inputs max).

### Error handling

- `min_coinbase_root_height_for_inputs` returns `StoreError` if any
  input output is missing or undecodable (prevents persisting height 0
  which would make outputs permanently unspendable).
- `compute_block_height_from_parent` returns `StoreError` if parent
  metadata is missing (genesis is special-cased to height 0).
- `get_tip_height` errors in `validate_prevouts` are propagated (not
  silently defaulted to 0, which would disable the spend rule).

Relevant code:
- `store/transaction_store.rs` (`StoredTxOut`,
  `min_coinbase_root_height_for_inputs`,
  `check_prevouts_and_find_coinbase`)
- `store/share_store.rs` (`compute_block_height_from_parent`)
- `shares/validation/mod.rs` (`validate_prevouts`)

## Constants

| Constant | Value | Meaning |
|---|---|---|
| PPLNS_DEPTH | 120,960 | 14 days at 10s/block |
| PRUNE_DEPTH | 241,920 | 2 x PPLNS_DEPTH |
| PRUNE_INTERVAL | 360 | 1 hour of blocks |
| Block height | u32 | Overflows in ~1,361 years |

Defined in `accounting/payout/sharechain_pplns/pplns_window.rs`.

## Task 2: Actual Pruning (not yet implemented)

After Task 1 (two-zone validation + output spendability):

1. Pruning task: periodic every 360 blocks after is_current
2. Atomic batch deletion of block body CFs (BlockTxids, TxidsBlocks,
   BitcoinTxids, Inputs, Outputs, Tx, TemplateMerkleBranches,
   SpendsIndex). Headers and BlockMetadata retained.
3. Candidate chain pruning below prune boundary
4. Startup pruning + compaction
5. CLI manual prune command
