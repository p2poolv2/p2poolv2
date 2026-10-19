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
- **Short depths**: the sim build compiles shorter consensus depths under
  `cfg(feature = "sim")` in `pplns_window.rs`, so the fast sim chain exercises
  payout maturity, output expiry, the full-validation boundary and block body
  pruning in every scenario:

  | Constant | Production | Sim |
  |---|---|---|
  | `COINBASE_MATURITY` | 6,048 | 20 |
  | `PPLNS_WINDOW_SHARES` | 120,960 | 80 |
  | `PAYOUT_DEPTH` | 127,008 | 100 |
  | `PRUNE_DEPTH` | 254,016 | 200 |
  | `PRUNE_INTERVAL` | 360 | 20 |
  | window eviction buffer | 1,210 | 20 |
  | `BACKGROUND_TASK_INTERVAL` (node) | 6 h | 30 s |

  They are constants, not config, so every node built from one binary agrees
  on them. The eviction buffer is raised to a quarter of the window (1% of 80
  would be one entry, and shares built behind the tip under propagation delay
  would be dropped). The reorg depth limit sits at the prune target, 220
  shares below the tip, which keeps it well above the forks the failure
  scenarios create (a 90s partition is 18 shares at 5s blocks). The cost is
  that sim no longer runs a production-size PPLNS window; `cargo bench --bench
  pplns_window` covers its compute cost.
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
share_address = "rp2pool1..." # this node's share chain identity; REQUIRED, and
                              # not derivable from miner_address -- different
                              # chain, different key. Without it the emitter
                              # refuses to start and the node emits nothing.
hashrate = 1.0e12             # modeled Hᵢ; sets emission rate (≈ D·2³²/H per share)
block_to_share_ratio = 10000  # 1-in-N shares is a (future) block-find
seed = 1                      # per-node; differ per node in multi-node runs
```

```sh
cargo build -p p2poolv2_sim --features sim
# fresh store via env override so existing dev data is untouched:
P2POOL_STORE__PATH=/tmp/store-sim-test.db \
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
load-tests/sim/failures.sh S       # inject failure scenario S into the running swarm
load-tests/sim/stop-swarm.sh       # stop all (incl. orphans matching this RUN_DIR)
```

Configs/stores/logs land in `RUN_DIR` (default `/tmp/p2pool-sim`). Tunables via
env: `RUN_DIR`, `BASE_P2P`/`BASE_STRATUM`/`BASE_API`, `RPC_*`, `ZMQ`,
`MINER_ADDRESS`, `HASHRATE` + `HASHRATE_DIST`(equal|zipf) + `ZIPF_ALPHA`,
`SHARES_PER_BLOCK`, `LATENCY_MS` + `LATENCY_DIST`(equal|spread),
`ASERT_ANCHOR` (shared anchor, default launch time), `NETWORK_HASHRATE` (shared,
default `N*HASHRATE`; anchors genesis at the steady-state difficulty so there's
no ASERT warmup), `IDEAL_BLOCK_TIME` (default 10s; lower = time-compressed run —
more blocks/min for faster data, auto-scales `LATENCY_MS`), `DIST_SEED`, `DISTINCT_ADDR`,
`POOL_SIGNATURE_PREFIX` (node `i` signs as prefix + `i`; signatures differ per
node because they are not consensus), `DIAL_FANOUT`, `PROFILE`. Convergence
shows as `distinct tips: 1` (a snapshot may straddle the latest 1–2 heights while
the frontier propagates). Run release; always `stop-swarm.sh` before relaunching
(orphans hold ports — `run-swarm.sh` now also clears its RUN_DIR's leftovers).

### Failure scenarios (Phase 4)

`failures.sh` injects one named failure mode into a running swarm, kills nodes
with `SIGKILL`, brings them back against the *same* config and store, and
verifies each one rejoins and catches up to the rest of the swarm. `nightly.sh`
takes the same scenario name (`nightly.sh restart-delayed`, or `SCENARIO=...`),
and the nightly workflow runs it once per scenario so a failing night names the
failure mode that caused it.

| Scenario | What it exercises |
|---|---|
| `clean` | nothing; the baseline run |
| `restart-fast` | a node fails and comes back immediately |
| `restart-delayed` | a node fails and comes back after `FAILURE_SLOW_DOWN` (default 330s). That crosses the 300s `MAX_TIP_AGE_SECS` threshold, so the node rejoins *not* current: inv gossip is ignored and it must bulk-sync via `getheaders` and block fetch |
| `partition` | `DIAL_FANOUT` consecutive nodes fail at once, cutting the dial chain, then all come back |
| `late-miner` | payout maturity: node `LATE_MINER` starts with its emitter off and starts mining once the chain is two maturity depths deep; `maturity_check.py` checks against the regtest coinbases that it is paid only once its shares are mature. Needs `LATE_MINER`; not part of `all` (RUNBOOK Test G) |
| `pruned-join` | block body pruning: once the swarm is past the sim prune target and every node has pruned, one node's store is wiped and it rejoins as a fresh node. It must catch up, agree with node 0 on confirmed hashes below and above its prune height, never get a not-found reply (it never asks for a body its peers deleted), and never fail to store a block. Runs time-compressed; not part of `all` (RUNBOOK Test H) |
| `deep-fork-refused` | reorg depth limit: the swarm is launched split (`FORK_GROUP_FROM`), so the chain forks at genesis. Once every node has pruned, the first minority node reconnects to node 0. The majority chain has more work, but its fork point is below the minority's prune target, so the node must log the refusal, keep its confirmed chain and keep confirming, while the majority keeps advancing. The nightly convergence check is skipped: two chains are the expected outcome. Not part of `all` (RUNBOOK Test I) |
| `shallow-fork-reorged` | control for `deep-fork-refused`: the same split, but the reconnect happens at height 60, below the prune target, and the minority must reorg onto the majority (the convergence check applies). Not part of `all` (RUNBOOK Test I) |
| `all` | the three failure scenarios in sequence (local use) |

Tunables: `FAILURE_SEED` (target selection; targets are printed so a failing
run is reproducible), `FAILURE_WARMUP`, `FAILURE_FAST_DOWN`,
`FAILURE_SLOW_DOWN`, `FAILURE_PARTITION_DOWN`, `FAILURE_CATCHUP_TIMEOUT`.

Two things to know about `partition`. First, it is a *topology* cut: it removes
the nodes that bridge the `dial_peers` chain, but Kademlia discovers and dials
peers that were never in `dial_peers`, so the two sides may well stay connected.
The summary records which happened, by counting outbound connections that cross
the cut (`cross-side links at +15s: lower_to_upper=0 upper_to_lower=0` means it
really was a partition). Second, a restarted node comes back with a **new
PeerId** — the libp2p keypair is generated per process start, not persisted — so
rejoining looks to its peers like a new node arriving.

Node 0 is never a target: `metrics.sh` derives the share rate and uncle rate
from `node-0.log` alone, so killing it would corrupt the run's own metrics.

