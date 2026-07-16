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
   `JobTracker` (latest job template).

```
mining.submit ---> MetricsActor (accumulated counters/gauges) --.
organise/confirm -> MetricsActor (effort accumulator) ----------|
                                                                 |
JobTracker (latest job template) --- live read at scrape -------+--> GET /metrics
confirmed chain work (get_total_work) --- live read at scrape --|
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
  whose series count is bounded by `MAX_BLOCKS_FOUND_TRACKED` (a ring of
  the most recent finds). Blocks are rare, so this stays tiny while
  still letting Grafana build explorer links.

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
| `bitcoin_blocks_found_total` | counter | actor |
| `bitcoin_block_found_time_seconds{blockhash,height}` | gauge | actor |

Recorded in the stratum submit handler
(`stratum/message_handlers/submit.rs`) right after a share meets the
bitcoin network target and the block is submitted to bitcoind. The
counter is monotonic; the info gauge holds the Unix timestamp the block
was found and carries `blockhash` and `height` labels. The set of info
series is bounded by `MAX_BLOCKS_FOUND_TRACKED`
(`accounting/stats/metrics.rs`) and persists across restarts.

**Grafana:**
- *Block-find timeline*: a Time series or State timeline of
  `increase(bitcoin_blocks_found_total[$__interval])` to show when
  blocks were found.
- *Block table with links*: a Table panel over `bitcoin_block_found_time_seconds`
  (Instant query, Format = Table). Add a data link on the `blockhash`
  field pointing at a block explorer, e.g.
  `https://mempool.space/block/${__data.fields.blockhash}` (use the
  testnet/signet host for non-mainnet deployments). Because the series
  count is bounded and blocks are rare, this carries links without a
  cardinality problem.

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
organise worker's `post_promote`) and resets to zero when a bitcoin block
is found. It is runtime-only (not persisted): a fresh or pruned node
cannot reconstruct work-since-last-block from history, and it resets each
block anyway. Uncles are excluded so it tracks the same confirmed-chain
work basis as `sharechain_work_total`. `network_difficulty` is the
mainnet-relative difficulty (`difficulty_float`) from the latest job
template `bits`, sharing units with the accumulated share difficulty. The
numerator and denominator are emitted separately so the effort formula
lives in Grafana.

Accumulation is **skipped while syncing** (`is_current` is false): during
sync `post_promote` replays the whole backlog and `work_since_last_block`
never resets (no real bitcoin block is found during replay), so it would
balloon to the entire chain's work and report an absurd effort. Only
real-time confirmed shares count.

**Grafana:** Gauge or Bar gauge of
`work_since_last_block / network_difficulty`. Values around 1.0 (100%)
are expected luck; higher means the pool is running "unlucky" on the
current block.

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
