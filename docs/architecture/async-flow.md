# Async Flow and Concurrency Model

## Event Handling Pipeline

The request/response pipeline is sequential async:

```
handle_event() -> dispatch_request/response() -> handler (getheaders, share_block, etc.)
```

This is intentional. Spawning tasks at the dispatch level would bypass the
Tower service stack's rate limiting and backpressure, and would not improve
throughput for our workload.

## Where Concurrency Lives

Heavy work is offloaded to dedicated spawned workers via bounded channels:

- **OrganiseWorker** -- candidate-to-confirmed chain promotion
- **BlockFetcher** -- distributes GetData requests across peers with timeouts
- **EmissionWorker** -- processes stratum shares (CPU-intensive merkle work)
- **StoreWriter** -- serializes all RocksDB writes on a `spawn_blocking` thread

Request handlers enqueue work to these workers and return quickly.

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
