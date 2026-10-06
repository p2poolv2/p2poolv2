**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Metrics and Prometheus exposition

How P2Poolv2 exposes operational metrics to Prometheus/Grafana, where
each metric's data comes from, and the Grafana panel recommended for
each one.

## Model: pull-based exposition

Metrics are pull-based. Prometheus scrapes `GET /metrics` on the API
server (`p2poolv2_api/src/api/server.rs`), which returns a plain-text
Prometheus exposition. There is no push path; every value is either
accumulated in the metrics actor or computed live at scrape time.

The response is assembled from two kinds of source:

1. **Accumulated state** in the `MetricsActor`
   (`p2poolv2_lib/src/accounting/stats/metrics.rs`). Counters and gauges
   updated as shares are submitted and blocks are found. The actor owns
   a `PoolMetrics` struct; `PoolMetrics::get_exposition()`
   (`accounting/stats/prom.rs`) renders it to exposition text. This
   state is periodically persisted to `pool/pool_stats.json` under the
   log dir (`pool_local_stats.rs`) and reloaded on restart.

2. **Live scrape-time reads** added in the `/metrics` handler. These
   pull from other subsystems that already hold the data, so nothing
   needs to be duplicated into the metrics actor. Currently the coinbase
   reward distribution and the network difficulty are read live from the
   `JobTracker` (latest job template), the found bitcoin blocks and
   confirmed chain work are read from the store, and the P2P health
   counters are read from the node actor (`NodeHandle::get_p2p_health`).

```
mining.submit ---> MetricsActor (accumulated counters/gauges) --.
organise/confirm -> MetricsActor (effort accumulator) ----------|
                                                                 |
JobTracker (latest job template) --- live read at scrape -------+--> GET /metrics
confirmed chain work (get_total_work) --- live read at scrape --|
FoundBlocks CF (get_found_blocks) --- live read at scrape ------|
node actor (Command::GetP2pHealth) --- live read at scrape -----|
                                                                 |
PplnsWindow (planned) --- live read at scrape ------------------'
```

## Cardinality rules

Prometheus creates one time series per unique label set. To keep the
series count bounded:

- **Never** put an unbounded, high-churn value (per-share hash, per-job
  id) in a label.
- Address- and worker-labeled series (`user_shares_valid_total`,
  `worker_*`, `coinbase_output`, and the planned
  `pplns_hashrate_distribution`) are bounded by the number of pool
  participants. Acceptable, but watch the active worker count.
- Block hashes are exposed only through `bitcoin_block_found_time_seconds`,
  one series per bitcoin block the pool has found. Blocks are rare, so
  this stays small while letting Grafana list every block with explorer
  links.

## Metric reference

### Share accounting (existing)

| Metric | Type | Source | Notes |
|---|---|---|---|
| `shares_accepted_total` | counter | actor | Accepted share count |
| `accepted_difficulty_total` | counter | actor | Sum of accepted share difficulty |
| `shares_rejected_total` | counter | actor | Rejected share count |
| `best_share` / `best_share_ever` | gauge | actor | Highest true difficulty (session / all-time) |
| `pool_difficulty` | gauge | actor | Current pool difficulty |
| `start_time_seconds` / `last_update_seconds` | gauge | actor | Unix timestamps |
| `user_shares_valid_total{btcaddress}` | counter | actor | Per-user valid shares (scaled by 2^32) |
| `worker_shares_valid_total{btcaddress,workername}` | counter | actor | Per-worker valid shares |
| `worker_best_share*{btcaddress,workername}` | gauge | actor | Per-worker best difficulty |
| `worker_last_share_at{btcaddress,workername}` | gauge | actor | Per-worker last submission timestamp |

### Coinbase reward distribution (existing) -- pool item #3

| Metric | Type | Source |
|---|---|---|
| `coinbase_output{index,address}` | gauge | live read of latest job coinbase |
| `coinbase_total` | gauge | live read of latest job template |

Emitted by `parse_coinbase::get_distribution()` at scrape time. Value is
per-output satoshis of the current job's coinbase.

**Grafana:** Pie chart, one slice per `address`. This is the intended
payout distribution for the next block. Compare visually with
`pplns_hashrate_distribution` (planned) to confirm payouts track
contributed work.

### Bitcoin blocks found (Release 1) -- pool item #1

| Metric | Type | Source |
|---|---|---|
| `bitcoin_blocks_found_total` | counter | live read of `FoundBlocks` CF |
| `bitcoin_block_found_time_seconds{blockhash,height,miner}` | gauge | live read of `FoundBlocks` CF |

Derived from the share chain and persisted in the store
(`store/found_block.rs`, see `store-schema.md`). When `confirm_blocks`
confirms a share, it checks the share's header and the headers of its
uncles; each one whose bitcoin header meets the bitcoin network target
(`ShareHeader::meets_bitcoin_difficulty`) is written to the `FoundBlocks`
column family in the same batch as the confirmation. This records blocks
found by any node's miners, not just locally connected ones, including
blocks carried by uncles.

- **Restart-safe and node-consistent.** The list lives in RocksDB and is
  derived from the chain, so every node reports the same blocks.
- **Rebuilt on sync.** Only header data is read, so header-only
  confirmation below the prune height records the same entries; a fresh
  node rebuilds the list as it syncs. No `is_current` gate is needed
  because the gauge value is the bitcoin header time, not now(). A node
  upgraded in place only records blocks confirmed after the upgrade.
- **Never deleted.** A share chain reorg does not undo a bitcoin block,
  so entries are kept and the counter is monotonic. Whether a block
  stayed on the bitcoin main chain is left to the block explorer.
- **Not limited by Prometheus retention.** Every scrape carries the full
  list, so an instant query always shows every found block.

The stratum submit handler still submits the block to bitcoind on a local
find; it records nothing.

**Grafana:**
- *Blocks found*: Stat of `bitcoin_blocks_found_total` (instant).
- *Found blocks table*: a Table panel over
  `bitcoin_block_found_time_seconds * 1000` (Instant query, Format =
  Table, value unit `dateTimeAsIso`). A data link on the `blockhash`
  field points at `${explorer}/block/${__data.fields.blockhash}`, where
  `explorer` is a dashboard variable choosing mempool.space for mainnet,
  testnet4 or signet.

### Pool-wide sharechain hashrate (Release 2) -- pool item #2

| Metric | Type | Source |
|---|---|---|
| `sharechain_work_total` | counter | live read of `get_total_work()` |

The cumulative confirmed-chain work at the tip, read live from the store
(`ChainStoreHandle::get_total_work`) and converted from the 256-bit
`bitcoin::Work` to an f64 (`work_to_f64` in `server.rs`). Chain work is
measured in expected hashes, so pool hashrate is just
`rate(sharechain_work_total[window])` -- no scaling factor.

Why the confirmed-chain work and not a per-share accumulator:

- **Reorg-safe.** The value always reflects the canonical confirmed
  tip, so a reorg to a higher-work tip is naturally accounted for; there
  is no double-counting from re-promoted blocks.
- **Restart-safe and node-consistent.** `chain_work` is persisted in
  block metadata and is deterministic from the chain (like Bitcoin's
  chainwork), so it survives restarts and agrees across nodes. It also
  survives pruning, since the tip metadata carries the cumulative scalar
  rather than re-summing shares.
- **Excludes uncle work.** `chain_work` sums only main-chain share work,
  so this measures confirmed-chain hashrate and undercounts total pool
  hashrate by the uncle/orphan rate. This mirrors how Bitcoin network
  hashrate is estimated from chainwork and is the accepted trade-off for
  reorg-safety.

**Only emitted while the chain is current** (`ChainStoreHandle::is_current`
-- confirmed tip within `MAX_TIP_AGE_SECS` = 300s of now). During sync the
confirmed tip advances by the whole backlog in a short wall-clock window,
which would make `rate()` report replay speed as an inflated hashrate.
Suppressing the sample during sync leaves a gap instead; because the 300s
threshold matches Prometheus's default staleness, `rate()` does not bridge
the sync jump when work resumes. A quiet pool (no shares for >5 min) also
gaps out, which is the honest reading -- no recent work, no hashrate.

**Grafana:** Time series of `rate(sharechain_work_total[1h])` (hashes/s).
This measures the whole pool (every node sees the full confirmed chain),
not just locally connected miners. Expect gaps during sync and idle
periods.

### Block effort (Release 1 + 2) -- pool item #5

| Metric | Type | Source |
|---|---|---|
| `work_since_last_block` | gauge | actor (organise/confirm path) |
| `network_difficulty` | gauge | live read of latest job template |

`work_since_last_block` accumulates the pool difficulty of each confirmed
sharechain share (via `MetricsMessage::RecordConfirmedShare` from the
organise worker's `record_confirmed_block`) and resets to zero
(`MetricsMessage::ResetBlockEffort`) when the **pool** finds a bitcoin
block. The reset is driven by a pool-wide share-chain signal (a confirmed
share that meets the bitcoin target), so it fires for a block found by any node's miners,
not just local ones -- this makes it a true pool "round luck" metric
(>100% means the pool is overdue for a block). It is runtime-only (not
persisted): a fresh or pruned node cannot reconstruct
work-since-last-block from history. Uncles are excluded so it tracks the
same confirmed-chain work basis as `sharechain_work_total`.
`network_difficulty` is the
mainnet-relative difficulty (`difficulty_float`) from the latest job
template `bits`, sharing units with the accumulated share difficulty. The
numerator and denominator are emitted separately so the effort formula
lives in Grafana.

Accumulation is **skipped while syncing** (`is_current` is false): during
sync `record_confirmed_block` replays the whole backlog and `work_since_last_block`
never resets (no real bitcoin block is found during replay), so it would
balloon to the entire chain's work and report an absurd effort. Only
real-time confirmed shares count.

**Grafana:** Gauge or Bar gauge of
`work_since_last_block / network_difficulty`. Values around 1.0 (100%)
are expected luck; higher means the pool is running "unlucky" on the
current block.

### P2P health

| Metric | Type | Source |
|---|---|---|
| `p2p_connected_peers` | gauge | live read of node connection tracker |
| `p2p_connections_total` | counter | node connection tracker |
| `p2p_ping_failures_total` | counter | node connection tracker |
| `p2p_connections_closed_unresponsive_total` | counter | node connection tracker |
| `p2p_outbound_failures_total` | counter | node request-response handler |
| `p2p_inbound_failures_total` | counter | node request-response handler |
| `p2p_responses_dropped_total` | counter | node request-response handler |
| `p2p_response_queue_depth` | gauge | live read of response worker queue |

The counters are plain integers kept where their events happen and updated
on the node actor loop. They are **not** sent to the `MetricsActor`: every
`MetricsHandle` call awaits a reply, and the node actor loop must never await
(see `async-flow.md`). The `/metrics` handler asks the node for a
`P2pHealth` snapshot (`node/p2p_health.rs`) with a 1 s timeout and appends
its exposition; if the node does not answer, the P2P series are omitted from
that scrape. The counters are runtime-only and reset on restart, which
`rate()` and `increase()` handle. There are no labels: peer ids are
unbounded and churn.

`p2p_connections_closed_unresponsive_total` counts connections closed after
`PING_FAILURE_THRESHOLD` consecutive ping failures -- a connection that
negotiated but could not exchange messages (the 2026-09-17 fork).

**Grafana / alerting:**
- *P2P is up but broken* -- the signature of the 2026-09-17 incident:
  `rate(p2p_outbound_failures_total[5m]) > 0 and p2p_connected_peers > 0`
  sustained for 10 minutes.
- *Unresponsive connections*: `increase(p2p_connections_closed_unresponsive_total[1h])`
  as a stat; occasional closes are recovery working, a steady rate means a
  flaky link.
- *Response backlog*: `p2p_response_queue_depth` and
  `rate(p2p_responses_dropped_total[5m])`; drops during catch-up mean the
  response worker is falling behind.

## Planned metrics (later releases)

These are documented here so the design is visible; they are not yet
emitted.

### Miner hashrate distribution from PPLNS (Release 3) -- pool item #4

`pplns_hashrate_distribution{address}` (gauge): each miner's weighted
difficulty over the PPLNS window, read live from `PplnsWindow` at scrape
time. Grafana renders it as a pie chart that cross-checks against the
coinbase distribution.

## Adding a metric

- If the value is naturally accumulated as shares/blocks are processed,
  add it to `PoolMetrics`, update it via a `MetricsMessage`, and render
  it in `get_exposition()`. Remember to persist it in
  `pool_local_stats.rs` (both the `FilteredPoolMetrics` serializer and
  `PoolMetrics::load_existing`) if it must survive restarts.
- If the value already lives in another subsystem, read it live in the
  `/metrics` handler instead of duplicating it into the actor.
- Keep label sets bounded. Document the new metric in this file with its
  type, source, and Grafana panel.
- Follow Prometheus naming conventions:
  - Counters (monotonic) end in `_total` as the trailing token
    (`sharechain_work_total`, not `sharechain_total_work`).
  - Use base-unit suffixes: `_seconds` for times/timestamps
    (`bitcoin_block_found_time_seconds`), `_bytes` for sizes.
  - `_count`, `_sum`, `_bucket` are reserved for histogram/summary
    components -- do not use them on plain counters or gauges.
  - `_info` is for info metrics whose value is always `1` and whose data
    lives in labels; do not use it for a gauge that carries a real value.
  - Gauges take no `_total` suffix.
