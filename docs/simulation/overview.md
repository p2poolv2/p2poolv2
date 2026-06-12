# No-PoW Load-Test Simulation Overview

## Goal

Load-test the **share-chain / p2p / payout machinery** of p2poolv2 with many
peers (target ~1k) on one (or few) machines, **without spending CPU on
proof-of-work**. Though it isn't always going to be clear what this kind of test does and does not cover, it opens the possibility of testing the effect of network latency at larger scales, as well as other things as mentioned below.

## Guiding principle

What are we testing? **ASERT** pool-difficulty and **re-notify on tip/confirmation** run on share *metadata and timing*, not on whether the nonce is real. So:

- Replace the continuous physical process (competitive mining) with a
  **timed emitter**.
- Replace the rare physical event (a Bitcoin block) with a **per-node statistical
  block-find** that submits a real (trivially-valid) regtest block carrying the
  real PPLNS coinbase.
- Keep **every other code path as real as possible** (validation structure, propagation,
  organise/reorg, PPLNS, payout, confirmation).
- The simulation is **local to each node**: the emitter and the block-find
  decision live inside the node, behind a `sim` cargo feature.

There are doubtless a number of "vectors of artificiality" here but the goal is to be able to track things like:

* uncle rates for different network latences and network latency variation
* how payouts track mining concentration (again, it may not catch every vector, but perhaps the main ones?).
* the functioning of basic mechanics like output distribution (payouts) in the coinbase, at large numbers
* it can greatly help testing new features that are more global in nature

... and obviously, trying to avoid needing a large amount of hardware to do it (ideally to be able to do all of it on a high quality laptop, or a well provisioned VPS).

## Architecture

```
 N real p2poolv2 nodes (one host, distinct ports, dial_peers topology)
   each node, built with --features sim:
     ├─ real libp2p swarm, organise_worker, validation_worker, store   ← under test
     ├─ sim emitter task (NEW): Poisson share emission,
     │     closed-loop on ASERT difficulty × this node's modeled hashrate Hᵢ,
     │     stamps per-share difficulty (bits) → models heterogeneous miners
     ├─ per-share Bernoulli block-find (NEW): p = 1/block_to_share_ratio
     │     on hit → build PPLNS coinbase + assemble regtest block + submitblock
     └─ PoW `is_met_by` checks + auto-submit cfg-gated off (sim)
   shared regtest bitcoind (rpcport 19443, ZMQ 28332) — executes payouts
   harness: launches N nodes + topology, scrapes metrics
   real clock; density now bounded by store/p2p/CPU-of-real-code, not hashing
```

## What `--features sim` changes

The actual PoW verification is the `target.is_met_by(bitcoin_block_hash)`
comparison (and `header.validate_pow`). Centralize via one helper and swap it at
each site:

```rust
// p2poolv2_lib/src/shares/validation/mod.rs (or a small sim module)
#[cfg(feature = "sim")]
#[inline] pub(crate) fn pow_meets(_t: bitcoin::Target, _h: bitcoin::BlockHash) -> bool { true }
#[cfg(not(feature = "sim"))]
#[inline] pub(crate) fn pow_meets(t: bitcoin::Target, h: bitcoin::BlockHash) -> bool { t.is_met_by(h) }
```



### Auto-submit is disabled under sim
Kind of a technical detail, but worth mentioning:

- `stratum/message_handlers/submit.rs:120-128` — the `meets_bitcoin_difficulty →
  build_full_block → submit_block` branch. Wrap in `#[cfg(not(feature = "sim"))]`.
  Reason: on regtest the Bitcoin target ≈ 2²⁵⁵, so a *random* header meets it ~50%
  of the time; left enabled, synthetic shares would spam spurious block
  submissions.

All test nodes must be built with `--features sim` (a synthetic share rejected by
a non-sim receiver would never propagate).


### Realism features

The harness models a heterogeneous, regulated network:

- **Heterogeneous hashrate** (`HASHRATE_DIST=zipf`, default): per-node power-law,
  total preserved — a few big miners + a long tail. Emission tracks hashrate.
- **Heterogeneous + jittered latency** (`LATENCY_DIST=spread` + per-broadcast
  ±50% jitter): uncles arise from propagation *variance*, per-node.
- **Regulated rate** (`ASERT_ANCHOR`): ASERT holds ~the 10s target (above).
- **Metrics** (`metrics.sh` + per-node `sim stats` log): emission-vs-hashrate,
  ASERT difficulty trajectory, main-chain rate vs target.

### Running a single sim node (Phase 1)

Needs a local regtest `bitcoind` (rpc + `zmqpubhashblock`) with some blocks
mined. Build and run with the `sim` feature and a `[sim]` config section:

```toml
[sim]
enabled = true
miner_address = "bcrt1q..."   # this node's payout identity (regtest address)
hashrate = 1.0e12             # modeled Hᵢ; sets emission rate (≈ D·2³²/H per share)
block_to_share_ratio = 10000  # 1-in-N shares is a (future) block-find
seed = 1                      # per-node; differ per node in multi-node runs
```

```sh
cargo build -p p2poolv2_node --features sim
# fresh store via env override so existing dev data is untouched:
P2POOL_STORE_PATH=/tmp/store-sim-test.db \
  ./target/debug/p2poolv2 --config config-dev.toml
```

Watch the log for `Promoted block … to confirmed height N` climbing.

### Running a swarm (Phase 2)

See the associated RUNBOOK.md for detailed instructions. Here's a simple overview:

`load-tests/sim/` drives a multi-process swarm against the same regtest
bitcoind. Each node gets its own config (distinct ports, distinct seed, fresh
store) and a `dial_peers` topology (each dials `DIAL_FANOUT` earlier nodes).

```sh
load-tests/sim/run-swarm.sh 20     # build (release) + launch 20 nodes
load-tests/sim/observe.sh          # LIVE snapshot: tip/convergence (logs), peer count (API)
load-tests/sim/metrics.sh          # authoritative LOG-based summary: convergence, rate,
                                   # difficulty, emission∝hashrate, uncles, block-finds
load-tests/sim/plot-metrics.sh     # PNG time-series (share rate, difficulty, uncle rate,
                                   # block-finds, hashrate bars) → RUN_DIR/metrics.png
load-tests/sim/stop-swarm.sh       # stop all (incl. orphans matching this RUN_DIR)
```

Configs/stores/logs land in `RUN_DIR` (default `/tmp/p2pool-sim`). Tunables via
env: `RUN_DIR`, `BASE_P2P`/`BASE_STRATUM`/`BASE_API`, `RPC_*`, `ZMQ`,
`MINER_ADDRESS`, `HASHRATE` + `HASHRATE_DIST`(equal|zipf) + `ZIPF_ALPHA`,
`RATIO`, `WINDOW_SHARES`, `LATENCY_MS` + `LATENCY_DIST`(equal|spread),
`ASERT_ANCHOR` (shared anchor, default launch time), `NETWORK_HASHRATE` (shared,
default `N*HASHRATE`; anchors genesis at the steady-state difficulty so there's
no ASERT warmup), `IDEAL_BLOCK_TIME` (default 10s; lower = time-compressed run —
more blocks/min for faster data, auto-scales `LATENCY_MS`), `DIST_SEED`, `DISTINCT_ADDR`,
`POOL_SIGNATURE` (must match across nodes), `DIAL_FANOUT`, `PROFILE`. Convergence
shows as `distinct tips: 1` (a snapshot may straddle the latest 1–2 heights while
the frontier propagates). Run release; always `stop-swarm.sh` before relaunching
(orphans hold ports — `run-swarm.sh` now also clears its RUN_DIR's leftovers).

