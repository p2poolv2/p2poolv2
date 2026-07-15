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
                                                                 |
JobTracker (latest job template) --- live read at scrape -------+--> GET /metrics
                                                                 |
PplnsWindow / share chain (planned) --- live read at scrape ----'
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
- Block hashes are exposed only through `bitcoin_block_found_info`,
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
| `bitcoin_block_found_info{blockhash,height}` | gauge | actor |

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
- *Block table with links*: a Table panel over `bitcoin_block_found_info`
  (Instant query, Format = Table). Add a data link on the `blockhash`
  field pointing at a block explorer, e.g.
  `https://mempool.space/block/${__data.fields.blockhash}` (use the
  testnet/signet host for non-mainnet deployments). Because the series
  count is bounded and blocks are rare, this carries links without a
  cardinality problem.

### Block effort (Release 1) -- pool item #5

| Metric | Type | Source |
|---|---|---|
| `work_since_last_block` | gauge | actor |
| `network_difficulty` | gauge | live read of latest job template |

`work_since_last_block` accumulates accepted share difficulty and resets
to zero when a block is found. `network_difficulty` is the mainnet-
relative difficulty (`difficulty_float`) derived from the latest job
template `bits`, so it shares units with the accumulated share
difficulty. The numerator and denominator are emitted separately so the
effort formula lives in Grafana, not the binary.

**Grafana:** Gauge or Bar gauge of
`work_since_last_block / network_difficulty`. Values around 1.0 (100%)
are expected luck; higher means the pool is running "unlucky" on the
current block.

## Planned metrics (later releases)

These are documented here so the design is visible; they are not yet
emitted.

### Pool-wide sharechain hashrate (Release 2) -- pool item #2

`sharechain_difficulty_total` (counter): pool difficulty summed over
every confirmed sharechain share and its uncles, emitted from the
organise/confirm path. Grafana computes hashrate as
`rate(sharechain_difficulty_total[1h]) * 2^32`. This measures the whole
pool (all nodes see the full share chain), not just locally connected
miners. A per-node contribution split is a possible later addition.

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
