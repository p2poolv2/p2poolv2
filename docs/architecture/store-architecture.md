# Store Architecture: ChainStoreHandle, StoreHandle, and StoreWriter

## Overview

The store layer uses a three-tier architecture that separates concerns and ensures database writes don't block tokio threads:

```
┌─────────────────────────┐
│   ChainStoreHandle      │  Chain-level logic (heights, work, reorgs)
├─────────────────────────┤
│     StoreHandle         │  Direct reads + serialized writes via channel
├─────────────────────────┤
│ StoreWriter (blocking)  │  Sequential write processing on dedicated thread
├─────────────────────────┤
│    Arc<Store>           │  RocksDB operations
└─────────────────────────┘
```

## Components

### 1. StoreWriter (`store/writer/mod.rs`)

A dedicated blocking thread that processes all database write operations sequentially.

**Purpose:** Avoid RocksDB write stalls blocking tokio async worker threads (highly recommended pattern in tokio/rocksdb community).

**Key elements:**
- Runs on dedicated OS thread via `tokio::task::spawn_blocking(move || store_writer.run())`
- Synchronous `run()` method with blocking `recv()` on command channel
- Uses `std::sync::mpsc` for command channel (sync send, blocking recv)
- Uses `tokio::sync::oneshot` for reply channels (clients can `.await` without blocking)
- Fire-and-forget commands (chain tip updates) don't need responses

```rust
pub struct StoreWriter {
    store: Arc<Store>,
    command_rx: WriteReceiver,  // std::sync::mpsc::Receiver
}

// Synchronous run method - blocks on recv()
impl StoreWriter {
    pub fn run(self) {
        while let Ok(cmd) = self.command_rx.recv() {
            self.handle_command(cmd);
        }
    }
}

pub enum WriteCommand {
    AddShare { share, height, chain_work, confirm_txs, reply },
    SetupGenesis { genesis, reply },
    AddPplnsShare { pplns_share, reply },
    SetChainTip { hash },  // Fire-and-forget
    // ... more commands
}
```

### 2. StoreHandle (`store/writer/handle.rs`)

Combines direct read access with serialized write access.

**Purpose:** Provide a convenient API that hides the channel complexity while keeping clients async.

**Key design:**
- **Reads:** Synchronous, direct via `Arc<Store>` (may briefly block)
- **Writes:** Async methods that send sync, await reply async
- **Chain state updates:** Sync, in-memory RwLock (no DB write needed)

```rust
#[derive(Clone)]
pub struct StoreHandle {
    store: Arc<Store>,      // Direct reads
    write_tx: WriteSender,  // std::sync::mpsc::Sender (sync send)
}

impl StoreHandle {
    // DIRECT READS - synchronous
    pub fn get_share(&self, blockhash: &BlockHash) -> Option<ShareBlock>
    pub fn get_chain_tip(&self) -> BlockHash

    // SERIALIZED WRITES - async (sync send, async reply await)
    pub async fn add_share(&self, share: ShareBlock, ...) -> Result<(), StoreError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx.send(WriteCommand::AddShare { ..., reply: reply_tx })
            .map_err(|_| StoreError::ChannelClosed)?;  // sync send, no .await
        reply_rx.await.map_err(|_| StoreError::ChannelClosed)?  // async await reply
    }

    // SYNC CHAIN STATE - in-memory only
    pub fn set_chain_tip(&self, hash: BlockHash)
}
```

### 3. ChainStoreHandle (`shares/chain/chain_store_handle.rs`)

Wraps `StoreHandle` with chain-level logic.

**Purpose:** Add blockchain semantics (heights, chain work, reorgs, PPLNS) on top of raw storage.

**Key responsibilities:**
- Height calculation for new shares
- Chain work accumulation
- Genesis initialization
- Locator/header queries for P2P sync
- PPLNS window management

```rust
#[derive(Clone)]
pub struct ChainStoreHandle {
    store_handle: StoreHandle,
    network: bitcoin::Network,
}

impl ChainStoreHandle {
    pub async fn init_or_setup_genesis(&self, genesis: ShareBlock) -> Result<()>
    pub async fn add_share(&self, share: &ShareBlock, confirm_txs: bool) -> Result<()>
    pub fn get_headers_for_locator(&self, ...) -> Result<Vec<ShareHeader>>
    pub fn build_locator(&self) -> Result<Vec<BlockHash>>
}
```

## Channel Design: Mixed Sync/Async

The key insight is using different channel types for commands vs replies:

| Channel | Type | Why |
|---------|------|-----|
| Command | `std::sync::mpsc` | StoreWriter can be sync with blocking `recv()` |
| Reply | `tokio::sync::oneshot` | Clients can `.await` without blocking tokio threads |

**Data flow:**
```
┌─────────────────────────────────────────────────────────────────────┐
│  Client (tokio async thread)                                        │
│                                                                     │
│  1. Create oneshot reply channel                                    │
│  2. write_tx.send(cmd) ──────────► std::sync::mpsc (non-blocking)  │
│  3. reply_rx.await ◄─────────────── tokio::oneshot (async wait)    │
└─────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  StoreWriter (dedicated blocking thread via spawn_blocking)         │
│                                                                     │
│  while let Ok(cmd) = command_rx.recv() {  // blocking recv         │
│      // Process RocksDB write (may stall - won't block tokio)      │
│      reply.send(result);  // oneshot send is sync                  │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Initialization Pattern

```rust
// 1. Create the store
let store = Arc::new(Store::new(path, read_only)?);

// 2. Create write channel (std::sync::mpsc, unbounded)
let (write_tx, write_rx) = write_channel();

// 3. Spawn the store writer on dedicated blocking thread
let store_writer = StoreWriter::new(store.clone(), write_rx);
tokio::task::spawn_blocking(move || store_writer.run());

// 4. Create handles
let store_handle = StoreHandle::new(store, write_tx);
let chain_store_handle = ChainStoreHandle::new(store_handle, network);

// 5. Initialize genesis
let genesis = ShareBlock::build_genesis_for_network(network);
chain_store_handle.init_or_setup_genesis(genesis).await?;
```

## Testing with Mocks

Both `StoreHandle` and `ChainStoreHandle` have mock implementations via `mockall::mock!`.

**Usage pattern:**
```rust
// In module that uses ChainStoreHandle:
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;

// In tests:
let mut mock = ChainStoreHandle::default();
mock.expect_get_share().returning(|_| Some(share));
mock.expect_clone().returning(ChainStoreHandle::default);
```

**Important:** When the mock is cloned, you must set up `expect_clone()`:
```rust
mock.expect_clone().returning(ChainStoreHandle::default);
// Or for chained mocks:
mock.expect_clone().return_once(move || other_mock);
```

## Test Utilities

For integration tests that need real storage:

```rust
use crate::test_utils::setup_test_chain_store_handle;

#[tokio::test]
async fn test_with_real_store() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle().await;
    // _temp_dir must stay in scope to keep the directory alive
}
```

Note: `setup_test_chain_store_handle` requires the `test-utils` feature for external crates.

## Key Design Decisions

1. **Reads are synchronous:** RocksDB reads are fast enough that brief blocking is acceptable. This simplifies the API significantly.

2. **StoreWriter runs on blocking thread:** Using `spawn_blocking` ensures RocksDB write stalls never block tokio's async worker threads. This is critical for maintaining responsiveness under load.

3. **Mixed channel types:** `std::sync::mpsc` for commands allows sync `run()`, while `tokio::sync::oneshot` for replies lets clients await without blocking.

4. **Chain state is in-memory:** Chain tip, tips set, and genesis hash are cached in `RwLock` for fast access. Only persisted data goes through the write channel.

5. **Fire-and-forget for state updates:** Commands like `SetChainTip` don't need responses since they're in-memory updates that can't fail.

6. **Batch writes:** The `StoreWriter` uses RocksDB `WriteBatch` for atomic multi-key updates.

## File Locations

- `p2poolv2_lib/src/store/writer/mod.rs` - StoreWriter and WriteCommand
- `p2poolv2_lib/src/store/writer/handle.rs` - StoreHandle
- `p2poolv2_lib/src/shares/chain/chain_store_handle.rs` - ChainStoreHandle
- `p2poolv2_lib/src/store/mod.rs` - Store (RocksDB wrapper)