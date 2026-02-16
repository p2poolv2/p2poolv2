---
name: Chain Store RocksDB Schema
description: Captures the rocksdb schema design currently in use
---

# Chain Store RocksDB Schema

This document captures the RocksDB storage schema used by `Store` and `ChainStore` in P2Poolv2.

## Overview

- **Database**: RocksDB with column families for independent compaction
- **Serialization**: Bitcoin consensus encoding for most types
- **Location**: `p2poolv2_lib/src/store/` and `p2poolv2_lib/src/shares/chain/chain_store.rs`

## Architecture

```
ChainStore (high-level chain operations)
    └── Store (low-level RocksDB operations)
            └── RocksDB (column families)
```

### Chain State (in-memory, thread-safe)

Managed by `Store` using `Arc<RwLock<T>>`:

| Field                | Type                 | Description                         |
|----------------------|----------------------|-------------------------------------|
| `genesis_block_hash` | `Option<BlockHash>`  | Hash of genesis block               |
| `chain_tip`          | `BlockHash`          | Current chain tip (highest work)    |
| `tips`               | `HashSet<BlockHash>` | All current chain tips (DAG leaves) |

---

## Column Families

### 1. `Block` - Share Blocks

Stores share block headers (without transactions).

| Key                    | Value                            | Notes                                    |
|------------------------|----------------------------------|------------------------------------------|
| `blockhash` (32 bytes) | `StorageShareBlock` (serialized) | Block header only, txs stored separately |
| `blockhash` + `_md`    | `BlockMetadata` (serialized)     | Height and chain_work                    |

**BlockMetadata Structure:**
```rust
pub struct BlockMetadata {
    pub height: Option<u32>,      // Block height in chain
    pub chain_work: Work,         // Cumulative chain work (32 bytes LE)
}
```

---

### 2. `BlockIndex` - Parent→Children Index

Tracks parent-to-children relationships for DAG traversal. Uses merge operator for atomic appends.

| Key                 | Value                         |
|---------------------|-------------------------------|
| `blockhash` + `_bi` | `Vec<BlockHash>` (serialized) |

---

### 3. `BlockHeight` - Height→Blockhashes Index

Maps heights to all blocks at that height (multiple due to uncles). Uses merge operator.

| Key                   | Value                         |
|-----------------------|-------------------------------|
| `height` (4 bytes BE) | `Vec<BlockHash>` (serialized) |

---

### 4. `BlockTxids` - Block→Transaction IDs

Maps share blocks to their sharechain transaction IDs.

| Key                    | Value                          |
|------------------------|--------------------------------|
| `blockhash` + `_txids` | `Txids` (Vec<Txid> serialized) |

---

### 5. `BitcoinTxids` - Block→Bitcoin Transaction IDs

Maps share blocks to their Bitcoin transaction IDs (separate from sharechain txs).

| Key                            | Value                          |
|--------------------------------|--------------------------------|
| `blockhash` + `_bitcoin_txids` | `Txids` (Vec<Txid> serialized) |

---

### 6. `Tx` - Transaction Metadata

Stores transaction metadata (not full tx data).

| Key               | Value                     |
|-------------------|---------------------------|
| `txid` (32 bytes) | `TxMetadata` (serialized) |

**TxMetadata Structure:**
```rust
pub struct TxMetadata {
    pub txid: Txid,
    pub version: transaction::Version,
    pub lock_time: absolute::LockTime,
    pub input_count: u32,
    pub output_count: u32,
    pub validated: bool,              // Script validation passed
}
```

---

### 7. `Inputs` - Transaction Inputs

Stores individual transaction inputs.

| Key                       | Value               |
|---------------------------|---------------------|
| `{txid}:{index}` (string) | `TxIn` (serialized) |

---

### 8. `Outputs` - Transaction Outputs

Stores individual transaction outputs.

| Key                       | Value                |
|---------------------------|----------------------|
| `{txid}:{index}` (string) | `TxOut` (serialized) |

---

### 9. `UnspentOutputs` - UTXO Set

Tracks unspent outputs for the sharechain.

| Key                       | Value            |
|---------------------------|------------------|
| `{txid}:{index}` (string) | empty bytes `[]` |

---

### 10. `Share` - PPLNS Shares

Stores local miner PPLNS shares for reward tracking.

| Key (24 bytes)                                                      | Value                           |
|---------------------------------------------------------------------|---------------------------------|
| `n_time` (8 bytes BE) + `user_id` (8 bytes BE) + `seq` (8 bytes BE) | `SimplePplnsShare` (serialized) |

**SimplePplnsShare Structure:**
```rust
pub struct SimplePplnsShare {
    pub user_id: u64,           // Internal user ID
    pub difficulty: u64,        // Share difficulty
    pub btcaddress: Option<String>,  // Skipped in serialization
    pub workername: Option<String>,  // Skipped in serialization
    pub n_time: u64,            // Mining timestamp
    pub job_id: String,         // Job ID
    pub extranonce2: String,    // Extranonce2 from submit
    pub nonce: String,          // Nonce from submit
}
```

---

### 11. `User` - User Registry

Stores user data indexed by internal ID.

| Key                    | Value                     |
|------------------------|---------------------------|
| `user_id` (8 bytes BE) | `StoredUser` (serialized) |

**StoredUser Structure:**
```rust
pub struct StoredUser {
    pub user_id: u64,           // Internal unique ID
    pub btcaddress: String,     // Bitcoin address
    pub created_at: u64,        // Timestamp (seconds since epoch)
}
```

---

### 12. `UserIndex` - BTC Address→User ID

Secondary index for looking up users by Bitcoin address.

| Key                   | Value                  |
|-----------------------|------------------------|
| `btcaddress` (string) | `user_id` (8 bytes BE) |

---

### 13. `Job` - Mining Jobs

Stores stratum mining jobs with timestamp-based keys.

| Key                             | Value                              |
|---------------------------------|------------------------------------|
| `timestamp_micros` (8 bytes BE) | `serialized_notify` (string bytes) |

---

### 14. `Metadata` - General Metadata

Reserved for general metadata storage.

| Key | Value |
|-----|-------|
| TBD | TBD   |

---

## Key Constants

```rust
// From chain_store.rs
const MIN_CONFIRMATION_DEPTH: usize = 100;   // Shares needed to confirm
const MAX_UNCLE_DEPTH: usize = 3;            // Max uncle inclusion depth
const COMMON_ANCESTOR_DEPTH: usize = 2160;   // Ancestor search depth (6 hours)
const PPLNS_WINDOW: usize = 2160;            // PPLNS window in shares
```

---

## Key Operations

### Adding a Share

1. Store transactions in `Inputs`, `Outputs`, `Tx`, and add to `UnspentOutputs`
2. Store `blockhash → txids` in `BlockTxids`
3. Store `blockhash → bitcoin_txids` in `BitcoinTxids`
4. Update `BlockIndex` (parent→child relationship)
5. Update `BlockHeight` (height→blockhash mapping)
6. Store `BlockMetadata` (height + chain_work)
7. Store `StorageShareBlock` in `Block`
8. Handle reorg if new chain has more work

### Reorg Logic

- Find common ancestor with current tip
- If shares have common ancestor: compare cumulative `chain_work`
- If disjoint chains: compare work over PPLNS window
- Update tips: remove prev_share_blockhash and uncles from tips

---

## File Locations

| Component          | Path                                              | Description                              |
|--------------------|---------------------------------------------------|------------------------------------------|
| Store (main)       | `p2poolv2_lib/src/store/mod.rs`                   | Core Store struct, chain state, genesis  |
| Column Families    | `p2poolv2_lib/src/store/column_families.rs`       | ColumnFamily enum definitions            |
| Block/Tx Metadata  | `p2poolv2_lib/src/store/block_tx_metadata.rs`     | BlockMetadata, TxMetadata structs        |
| DAG Store          | `p2poolv2_lib/src/store/dag_store.rs`             | DAG traversal, common ancestor, locators |
| Share Store        | `p2poolv2_lib/src/store/share_store.rs`           | Share block storage and retrieval        |
| Transaction Store  | `p2poolv2_lib/src/store/transaction_store.rs`     | Transaction storage, inputs, outputs     |
| Job Store          | `p2poolv2_lib/src/store/job_store.rs`             | Mining job storage and queries           |
| User Store         | `p2poolv2_lib/src/store/user.rs`                  | User CRUD operations                     |
| StoredUser         | `p2poolv2_lib/src/store/stored_user.rs`           | StoredUser struct definition             |
| PPLNS Shares       | `p2poolv2_lib/src/store/pplns_shares.rs`          | PPLNS share storage and filtering        |
| Background Tasks   | `p2poolv2_lib/src/store/background_tasks.rs`      | Async background operations              |
| ChainStore         | `p2poolv2_lib/src/shares/chain/chain_store.rs`    | High-level chain operations              |
| SimplePplnsShare   | `p2poolv2_lib/src/accounting/simple_pplns/mod.rs` | PPLNS share struct definition            |
