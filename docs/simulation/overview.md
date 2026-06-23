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
 N p2poolv2_sim binaries (one host, distinct ports, dial_peers topology)
   each built with: cargo build -p p2poolv2_sim --features sim
     +-- real libp2p swarm, organise_worker, validation_worker, store  <-- under test
     +-- sim emitter task: Poisson share emission,
     |     closed-loop on ASERT difficulty x this node's modeled hashrate Hi,
     |     stamps per-share difficulty (bits) -> models heterogeneous miners
     +-- per-share Bernoulli block-find: p = 1/block_to_share_ratio
     |     on hit -> build PPLNS coinbase + assemble regtest block + submitblock
     +-- PoW is_met_by checks + auto-submit cfg-gated off (sim)
   shared regtest bitcoind (rpcport 19443, ZMQ 28332) -- executes payouts
   harness: launches N nodes + topology, scrapes metrics
   real clock; density now bounded by store/p2p/CPU-of-real-code, not hashing
```

## What `--features sim` changes

All sim/production behavioral differences are centralized in
`p2poolv2_lib/src/sim_overrides.rs`. The bridge functions inline to constants
or no-ops in production builds (zero overhead). Key overrides:

- **PoW verification**: `sim_overrides::pow_meets()` always returns true (sim)
  vs real `target.is_met_by(hash)` (production).
- **ASERT timing**: `sim_overrides::ideal_block_time()` and `half_life()` can
  be overridden for time-compressed runs.
- **Genesis anchoring**: `sim_overrides::genesis_timestamp()` and
  `anchor_target()` anchor ASERT at launch time and steady-state difficulty.
- **PPLNS window**: `sim_overrides::pplns_total_difficulty()` uses
  `MAX_PPLNS_WINDOW_SHARES` for a realistic multi-miner coinbase on regtest.
- **Propagation delay**: `sim_overrides::spawn_delayed_broadcast()` models
  network latency with per-broadcast jitter.
- **Auto-submit**: disabled under sim (regtest headers meet bitcoin target ~50%
  of the time, which would spam spurious block submissions).

All sim nodes must be built with `--features sim` (a synthetic share rejected by
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
cargo build -p p2poolv2_sim --features sim
# fresh store via env override so existing dev data is untouched:
P2POOL_STORE_PATH=/tmp/store-sim-test.db \
  ./target/debug/p2poolv2_sim --config config-dev.toml
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
`SHARES_PER_BLOCK`, `WINDOW_SHARES`, `LATENCY_MS` + `LATENCY_DIST`(equal|spread),
`ASERT_ANCHOR` (shared anchor, default launch time), `NETWORK_HASHRATE` (shared,
default `N*HASHRATE`; anchors genesis at the steady-state difficulty so there's
no ASERT warmup), `IDEAL_BLOCK_TIME` (default 10s; lower = time-compressed run —
more blocks/min for faster data, auto-scales `LATENCY_MS`), `DIST_SEED`, `DISTINCT_ADDR`,
`POOL_SIGNATURE` (must match across nodes), `DIAL_FANOUT`, `PROFILE`. Convergence
shows as `distinct tips: 1` (a snapshot may straddle the latest 1–2 heights while
the frontier propagates). Run release; always `stop-swarm.sh` before relaunching
(orphans hold ports — `run-swarm.sh` now also clears its RUN_DIR's leftovers).

