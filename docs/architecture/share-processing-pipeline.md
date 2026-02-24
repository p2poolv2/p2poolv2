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
4. Enable future additions (validation worker, peer-received share organisation)

## Data Flow Diagram

```
+-------------------+
|  Stratum Server   |
|  (miner submit)   |
+--------+----------+
         | Emission (mpsc channel)
         v
+--------------------------------------+
| EmissionWorker (tokio task)          |
|                                      |
| - Receives Emission from stratum     |
| - Calls handle_stratum_share()       |
| - On Ok(Some(share_block)):          |
|     sends Header event to organise   |
|     sends Block event to organise    |
|     sends original to swarm broadcast|
+-------+------------------+----------+
        |                  |
        v                  v
+----------------------------------------+
|       handle_stratum_share()           |
|                                        |
| - Builds ShareBlock from emission      |
| - Merkle tree + coinbase calculation   |
| - Stores via ChainStoreHandle          |
|   .add_share() (serialized write)      |
| - Returns Option<ShareBlock>           |
+----------------------------------------+
        |                         |
        | organise_tx             | swarm_tx
        | (mpsc, cap 256)         | (mpsc, cap 100)
        v                         v
+-------------------+       +-----------------+
| OrganiseWorker    |       |   NodeActor     |
| (tokio task)      |       |                 |
|                   |       | - Receives      |
| Two event types:  |       |   SwarmSend::   |
|                   |       |   Broadcast     |
| Header(ShareHdr): |       | - Sends to all  |
|   organise_header |       |   peers         |
|   -> candidate    |       +-----------------+
|   chain updates   |
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
- Calls `handle_stratum_share()` which builds and stores the share
- On success with `Some(ShareBlock)`:
  - Sends `OrganiseEvent::Header(header)` for candidate chain building
  - Sends `OrganiseEvent::Block(share_block)` for confirmed promotion
  - Sends original to `swarm_tx` for peer broadcast
- On success with `None`: solo mode, no broadcast or organisation needed

### handle_stratum_share (`shares/handle_stratum_share.rs`)
- Async function that processes emissions
- P2P mode (share commitment present): builds `ShareBlock`, stores via `ChainStoreHandle::add_share()`, returns `Some(ShareBlock)`
- Solo mode (no commitment): stores PPLNS share via `ChainStoreHandle::add_pplns_share()`, returns `None`

### OrganiseWorker (`node/organise_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `OrganiseEvent` via bounded mpsc channel (capacity 256)
- Matches on event type:
  - `Header(header)`: calls `ChainStoreHandle::organise_header(header)`
  - `Block(share_block)`: calls `ChainStoreHandle::organise_block()`
- Error handling:
  - `StoreError::ChannelClosed` is fatal -- returns `Err(OrganiseError)`, triggers node shutdown
  - Other errors are logged, worker continues
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
| organise_tx/rx | tokio mpsc | 256 | EmissionWorker -> OrganiseWorker |
| swarm_tx/rx | tokio mpsc | 100 | EmissionWorker -> NodeActor (broadcast) |
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
   - `get_branch_to_candidates` walks backward from the new share to find the branch point (first ancestor with `Candidate` status)
   - `get_candidates_chain` fetches the old candidate entries from the branch point to the top
   - Old entries are deleted and reorged-out shares have their metadata set to `Status::Valid` (so `is_candidate()` stays correct for future branch point lookups)
   - New branch entries are written and their metadata set to `Status::Candidate`
   - Top candidate height is set once at the end

3. **No-op**: Header doesn't extend or outwork the current candidate chain.

### Store::organise_block (confirmed promotion)

`organise_block` reads the committed candidate and confirmed chain state and checks:

1. **Extend confirmed chain** (`should_extend_confirmed`): If the candidate chain extends the confirmed chain at the next height with the same prefix, promote all candidates to confirmed.

2. **Reorg confirmed chain** (`should_reorg_confirmed`): If the candidate chain has more work than the confirmed chain, replace the confirmed chain with the candidate chain.

3. **No-op**: No promotion conditions met.

All writes go into a single `WriteBatch` for atomicity.

### WriteBatch stale-read pattern

Within a single `WriteBatch`, reads from the DB return pre-batch (committed) state. The reorg logic avoids this by using direct batch helpers (`set_top_candidate_height`, `put_candidate_entry`, `delete_candidate_entry`) that write without validating against DB state, and setting the final top height once rather than incrementing/decrementing per entry.

## Future Additions

### Validation Worker
- Insert between EmissionWorker and OrganiseWorker
- Validates PoW, share structure before organisation
- `OrganiseSender` is `Clone`, so the validation worker can send to the same channel

### Header Sync / Block Fetch Separation
- Header sync can send `OrganiseEvent::Header` events to build the candidate chain
- Block fetch can send `OrganiseEvent::Block` events to promote candidates to confirmed
- These can operate independently and concurrently

### Peer-received Share Organisation
- Shares received from peers via p2p will also need organisation
- Pass an `OrganiseSender` clone through the peer handling path

## Files

- `p2poolv2_lib/src/node/emission_worker.rs`
- `p2poolv2_lib/src/node/organise_worker.rs`
- `p2poolv2_lib/src/node/actor.rs`
- `p2poolv2_lib/src/shares/handle_stratum_share.rs`
- `p2poolv2_lib/src/shares/chain/chain_store_handle.rs`
- `p2poolv2_lib/src/store/writer/mod.rs` (StoreWriter + WriteCommand)
- `p2poolv2_lib/src/store/writer/handle.rs` (StoreHandle)
- `p2poolv2_lib/src/store/organise/mod.rs` (candidate/confirmed index management)
- `p2poolv2_lib/src/store/organise/organise_header.rs` (Store::organise_header, candidate chain logic)
- `p2poolv2_lib/src/store/organise/organise_block.rs` (Store::organise_block, confirmed promotion)
