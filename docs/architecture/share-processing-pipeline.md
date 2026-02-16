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
3. Decouple share organisation from share storage and broadcast
4. Enable future additions (validation worker, peer-received share organisation)

## Data Flow Diagram

```
┌─────────────────┐
│  Stratum Server │
│  (miner submit) │
└────────┬────────┘
         │ Emission (mpsc channel)
         ▼
┌──────────────────────────────────────┐
│ EmissionWorker (tokio task)          │
│                                      │
│ - Receives Emission from stratum     │
│ - Calls handle_stratum_share()       │
│ - On Ok(Some(share_block)):          │
│     sends clone to OrganiseWorker    │
│     sends original to swarm broadcast│
└───────┬──────────────────┬───────────┘
        │                  │
        ▼                  ▼
┌────────────────────────────────────────┐
│       handle_stratum_share()           │
│                                        │
│ - Builds ShareBlock from emission      │
│ - Merkle tree + coinbase calculation   │
│ - Stores via ChainStoreHandle          │
│   .add_share() (serialized write)      │
│ - Returns Option<ShareBlock>           │
└────────────────────────────────────────┘
        │                         │
        │ organise_tx             │ swarm_tx
        │ (mpsc, cap 256)        │ (mpsc, cap 100)
        ▼                         ▼
┌─────────────────┐       ┌─────────────────┐
│ OrganiseWorker  │       │   NodeActor     │
│ (tokio task)    │       │                 │
│                 │       │ - Receives      │
│ - Receives      │       │   SwarmSend::   │
│   ShareBlock    │       │   Broadcast     │
│ - Calls chain   │       │ - Sends to all  │
│   _store_handle │       │   peers         │
│   .organise_    │       └─────────────────┘
│   share()       │
│ - Fatal errors  │
│   stop the node │
└────────┬────────┘
         │ WriteCommand::OrganiseShare
         │ (via StoreHandle oneshot pattern)
         ▼
┌─────────────────────────────────────┐
│ StoreWriter (dedicated OS thread)   │
│                                     │
│ - Receives WriteCommands via        │
│   std::sync::mpsc (unbounded)       │
│ - Processes sequentially            │
│ - OrganiseShare: calls              │
│   Store::organise_share() with      │
│   single WriteBatch (atomic)        │
└────────┬────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│      Store (RocksDB)                 │
│                                      │
│ - organise_share()                   │
│   - extends_chain() → append         │
│   - should_reorg_candidate() → reorg │
│ - reorg_candidate()                  │
│ - add_share()                        │
│ - reorg_confirmed()  (future)        │
└──────────────────────────────────────┘
```

## Key Components

### EmissionWorker (`node/emission_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `Emission` from stratum server via `EmissionReceiver`
- Calls `handle_stratum_share()` which builds and stores the share
- On success with `Some(ShareBlock)`:
  - Sends clone to `organise_tx` for candidate/confirmed indexing
  - Sends original to `swarm_tx` for peer broadcast
- On success with `None`: solo mode, no broadcast or organisation needed

### handle_stratum_share (`shares/handle_stratum_share.rs`)
- Async function that processes emissions
- P2P mode (share commitment present): builds `ShareBlock`, stores via `ChainStoreHandle::add_share()`, returns `Some(ShareBlock)`
- Solo mode (no commitment): stores PPLNS share via `ChainStoreHandle::add_pplns_share()`, returns `None`

### OrganiseWorker (`node/organise_worker.rs`)
- Runs in dedicated tokio task, spawned by NodeActor
- Receives `ShareBlock` via bounded mpsc channel (capacity 256)
- Calls `ChainStoreHandle::organise_share(blockhash)` for each share
- Error handling:
  - `StoreError::ChannelClosed` is fatal -- returns `Err(OrganiseError)`, triggers node shutdown
  - Other errors are logged, worker continues
  - Channel close (all senders dropped) is clean shutdown
- `Store::organise_share()` updates candidate indexes atomically in a single WriteBatch (extend or reorg)

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
- `WriteCommand::OrganiseShare` calls `Store::organise_share()` with a single batch for atomic candidate chain updates

### ChainStoreHandle (`shares/chain/chain_store_handle.rs`)
- Wraps `StoreHandle` with chain-level logic (height calculation, chain work)
- Async writes (e.g. `add_share`, `organise_share`) go through serialized write channel
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

## Organisation Logic (Store::organise_share)

`organise_share` processes a share through three paths, checked in order:

1. **Extend candidate chain** (`extends_chain`): If the share's `prev_share_blockhash` matches the top candidate (or top confirmed as fallback), height is consecutive, and chain work is greater, it appends to the candidate index via `append_to_candidates`.

2. **Reorg candidate chain** (`should_reorg_candidate` / `reorg_candidate`): If the share has more cumulative work than the current top candidate but doesn't extend it, the candidate chain is replaced:
   - `get_branch_to_candidates` walks backward from the new share to find the branch point (first ancestor with `Candidate` status)
   - `get_candidates_chain` fetches the old candidate entries from the branch point to the top
   - Old entries are deleted and reorged-out shares have their metadata set to `Status::Valid` (so `is_candidate()` stays correct for future branch point lookups)
   - New branch entries are written and their metadata set to `Status::Candidate`
   - Top candidate height is set once at the end

3. **No-op**: Share doesn't extend or outwork the current candidate chain.

All writes go into a single `WriteBatch` for atomicity.

### WriteBatch stale-read pattern

Within a single `WriteBatch`, reads from the DB return pre-batch (committed) state. The reorg logic avoids this by using direct batch helpers (`set_top_candidate_height`, `put_candidate_entry`, `delete_candidate_entry`) that write without validating against DB state, and setting the final top height once rather than incrementing/decrementing per entry.

## Future Additions

### Validation Worker
- Insert between EmissionWorker and OrganiseWorker
- Validates PoW, share structure before organisation
- `OrganiseSender` is `Clone`, so the validation worker can send to the same channel

### Confirmed Chain Reorg
- `organise_share` currently only handles candidate chain organisation
- Confirmed chain advancement and reorg will follow the same WriteBatch pattern
- Must track `effective_top_confirmed` locally to avoid stale reads within the batch

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
- `p2poolv2_lib/src/store/organise/organise_share.rs` (Store::organise_share, reorg logic)
