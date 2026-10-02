**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Async Flow and Concurrency Model

## The Node Actor Loop

`NodeActor::run` (`node/actor.rs`) owns the libp2p `Swarm` and is the only
task that polls it or calls it. It is a **non-blocking dispatcher**:

> Every `select!` arm body is a short synchronous handler. It either calls the
> `Swarm` directly (the loop owns it) or hands work to a worker through a
> bounded channel with `try_send`. No arm body awaits.

The arms:

| Source | Handler | What it does |
|---|---|---|
| `swarm.select_next_some()` | `Node::handle_swarm_event` | Connection lifecycle, identify/ping/kademlia, request-response dispatch |
| `swarm_rx` (outbound ops) | `on_swarm_send` | Executes `SwarmSend` from workers: `send_request`, `send_response`, block broadcast, disconnect |
| `command_rx` (control plane) | `on_command` | `GetPeers`, `SendToPeer`, `BlockIp`, `Shutdown`, ... answered on oneshot replies |
| `workers.join_next_with_id()` | `on_worker_exit` | Supervision: a fatal error or panic in any worker stops the node |
| reconnect / sync-retry / kademlia intervals | inline / `on_sync_retry_tick` | Periodic swarm maintenance |

The invariant is enforced by types: `handle_swarm_event` and the
request-response handlers are plain `fn`s, so an `.await` on a channel send
inside them does not compile. Code on the loop sends on the swarm through the
`RequestSender` trait (`send_request`, `disconnect_peer`) and builds messages
with the synchronous `build_handshake_message` / `build_getheaders_message`.
A non-async `#[test]` calling `dispatch_response` guards this.

**Why it matters.** The loop is the sole consumer of `swarm_tx`. If an arm
awaited a send on `swarm_tx` while the channel was full, nothing would drain
it and the node would stop answering P2P traffic and commands entirely -- the
2026-09-19 deadlock. With synchronous arms the loop drains `swarm_tx` every
iteration, so producers sending on it see bounded backpressure that always
completes.

**What may still run inline.** Driver-owned state (`connection_tracker`,
`peer_reconnector`, peer block knowledge) is updated in place; it has a single
owner and needs no lock. Three low-frequency handlers read the store on the
loop: the handshake on connection, the sync-retry locator, and
`Command::GetPplnsShares`. They are infrequent, so the read is accepted; if
profiling ever shows loop stalls, move them to `spawn_blocking` or a worker.

**Shutdown.** Every exit breaks the loop with a `StopReason` and runs one
teardown, `shut_down`: it stops all workers (`JoinSet::shutdown`) and only
then answers `Command::Shutdown`, or, for a fatal stop (worker failure, closed
command channel), signals `stopping_tx`, which the node binary treats as an
error exit. Workers are cancelled at their current await point; durable
effects go through the StoreWriter's atomic batches and in-memory state is
rebuilt on restart, so there is nothing to clean up.

## Workers and Channels

Heavy work runs on dedicated tasks, all spawned into the actor's `JoinSet`
except the per-peer services and the StoreWriter thread:

- **ResponseWorker** -- runs `handle_response` for inbound responses
  (`ShareHeaders` can mean up to 1500 `organise_header` calls). One task, FIFO,
  so each peer's header batches stay in order.
- **Per-peer service tasks** -- Tower stack (rate limit, inactivity) running
  inbound request handlers; one per connected peer.
- **BlockReceiver** -- persists received share blocks, resolves dependencies,
  queues validation.
- **BlockFetcher** -- distributes `GetData` requests across peers with timeouts.
- **ValidationWorker** -- context-free validation, one spawned task per block,
  concurrency capped by a semaphore sized to the CPU count.
- **OrganiseWorker** -- serial candidate-to-confirmed promotion.
- **EmissionWorker** -- turns stratum shares into share blocks.
- **StoreWriter** -- serializes all RocksDB writes on a `spawn_blocking` thread.

Every channel is bounded, and every edge has an explicit policy:

| From -> To | Capacity | Policy on full |
|---|---|---|
| Actor -> per-peer service | max(rps, 16) | `try_send`; disconnect the peer |
| Actor -> ResponseWorker | 1024 | `try_send`; warn and drop (header sync re-requests, fetcher times out) |
| Actor -> BlockFetcher (`PeerRemoved`) | 8192 | `try_send`; warn (in-flight requests time out) |
| Workers / services -> Actor (`swarm_tx`) | 100 | awaited send; bounded because the actor always drains |
| ResponseWorker -> BlockReceiver | 8192 | awaited send |
| BlockReceiver -> ValidationWorker | 8192 | awaited send |
| BlockReceiver -> BlockFetcher | 8192 | awaited send |
| EmissionWorker -> ValidationWorker | 8192 | awaited send |
| ValidationWorker -> OrganiseWorker | 512 | awaited send, holding the validation permit |
| OrganiseWorker -> ValidationWorker (stranded re-drive, startup seed) | 8192 | `try_send`; skip (next arrival re-drives) |

**The cycle rule.** The channel graph must have no cycle of awaited sends.
Where a cycle is unavoidable, at least one edge in it is non-blocking:

- `swarm_tx` <-> actor: the actor never awaits; it drains `swarm_tx` and
  hands inbound work out with `try_send`.
- Validation <-> Organise: validation awaits `organise_tx`; organise reaches
  validation only through `try_send`.

**Validation permits.** A validation task holds its semaphore permit until it
finishes, including the broadcast send on `swarm_tx`. The permit therefore also
bounds how many validated blocks can wait on a full `swarm_tx`. Releasing it
before the broadcast would let tasks pile up without limit, so do not.

When adding a channel, add it to this table with its capacity and policy, and
check that it does not close a cycle of awaited sends.

## RocksDB Reads in Request Handlers

Request handlers (`getheaders`, `getblocks`, `getdata_block`) call
`ChainStoreHandle` methods that read RocksDB synchronously on the tokio
thread. These do NOT need `spawn_blocking` because:

1. RocksDB checks memtable then block cache before touching disk
2. At P2Pool scale, the working set of recent shares and headers fits
   comfortably in the block cache and OS page cache
3. Reads complete in single-digit microseconds in the common case
4. `spawn_blocking` overhead (thread scheduling, context switch, future
   wakeup) would cost more than the reads themselves

Write operations correctly use async channels to the StoreWriter thread
because they involve compaction-visible mutations and batch commits.

## Memory Budget: Two Weeks at One Share per 10 Seconds

The chain retains two weeks of shares: 1,209,600 seconds / 10 = ~121,000 shares.

Per-share storage breakdown:

| Component               | Per share  | 121K shares |
|-------------------------|------------|-------------|
| ShareHeader (with uncles) | ~282 B   | ~34 MB      |
| BlockMetadata           | 38 B       | ~4.6 MB     |
| Indexes (height, children) | ~64 B   | ~7.7 MB     |
| Coinbase tx + share txids | ~120 B   | ~14.5 MB    |
| Bitcoin txids (~2000/share) | ~64 KB  | ~7.7 GB     |

Bitcoin transaction bodies are deduplicated across shares (~60 shares per
bitcoin block). Over two weeks that is ~2016 bitcoin blocks at ~1 MB each
= ~2 GB.

Totals:

- Core share chain (headers + metadata + indexes): ~60 MB
- Bitcoin txid lists per share: ~7.7 GB
- Deduplicated bitcoin tx bodies: ~2 GB
- Total on disk: ~10 GB

The core share chain (~60 MB) fits easily in the RocksDB block cache, so
`getheaders` and `getblocks` reads stay in memory. `getdata_block` serves
full shares including bitcoin txids (~7.7 GB total) which will not all fit
in a typical block cache (256 MB - 1 GB). Serving old shares may hit disk,
but this is acceptable because block fetching is decoupled to the
BlockFetcher worker and is not latency-critical.

## When to Revisit

- If the share chain grows large enough to exceed available memory
- If RocksDB compaction stalls become measurable under load
- If peer counts increase significantly beyond current expectations
