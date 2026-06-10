# No-PoW Load-Test Simulation — Implementation Plan

Branch: `regtest-local-testing`

## Goal

Load-test the **share-chain / p2p / payout machinery** of p2poolv2 with many
peers (target ~1k) on one (or few) machines, **without spending CPU on
proof-of-work**. Real PoW — even "trivial" PoW — is per-share CPU that does not
amortize and is what previously forced spreading load across ~4 machines just to
reach 1k peers. Removing it is the whole point.

## Guiding principle

PoW is an **authentication** check, not a feedback loop. In a cooperative load
test there is no adversary, so verifying it buys nothing. The loops that actually
shape behaviour — **ASERT** pool-difficulty and **re-notify on tip/confirmation**
— run on share *metadata and timing*, not on whether the nonce is real. So:

- Replace the continuous physical process (competitive mining) with a
  **closed-loop timed emitter** that stamps honest difficulty/timestamps.
- Replace the rare physical event (a Bitcoin block) with a **per-node statistical
  block-find** that submits a real (trivially-valid) regtest block carrying the
  real PPLNS coinbase.
- Keep **every other code path real** (validation structure, propagation,
  organise/reorg, PPLNS, payout, confirmation).
- The simulation is **local to each node**: the emitter and the block-find
  decision live inside the node, behind a `sim` cargo feature.

Fidelity = how many real loops stay closed. The only consequential
artificialities are: nothing authenticates shares, and the block:share ratio is a
config knob rather than emergent. Neither touches the code under test.

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

## The cfg surface (what `--features sim` changes)

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

### Sites to gate (skip the PoW comparison only)
- `stratum/work/difficulty/validate.rs:135-144` — `validate_bitcoin_difficulty`
  → `header.validate_pow(target)`. Under sim, treat as meeting the *pool* target
  but NOT bitcoin (so auto-submit stays off). (Stratum path; only needed if we
  also drive synthetic shares through stratum — likely not, see C2.)
- `stratum/message_handlers/submit.rs:132-145` — pool-target `is_met_by` →
  `LowDifficultyShare`. (Stratum path; same caveat.)
- `shares/validation/mod.rs:760` — `validate_with_pool_difficulty`, the **main p2p
  pool-difficulty check**. Gate the `is_met_by`.
- `shares/validation/mod.rs:790` — `validate_header_minimum_difficulty`, the
  `declared_target.is_met_by`. Gate the `is_met_by`.
- `node/p2p_message_handlers/receivers/share_blocks.rs:85` — `validate_share_header`
  DoS gate (depends on the two above; verify it inherits the gate).
- `node/p2p_message_handlers/receivers/share_headers.rs:366` — calls
  `validate_header_minimum_difficulty` (inherits :790 gate).

### Auto-submit (disable under sim)
- `stratum/message_handlers/submit.rs:120-128` — the `meets_bitcoin_difficulty →
  build_full_block → submit_block` branch. Wrap in `#[cfg(not(feature = "sim"))]`.
  Reason: on regtest the Bitcoin target ≈ 2²⁵⁵, so a *random* header meets it ~50%
  of the time; left enabled, synthetic shares would spam spurious block
  submissions and (via confirmation→re-notify) flatten the uncle rate. Block-finds
  must go only through C3.

### Sites to KEEP real (do NOT gate)
- `share_headers.rs:382-389` — ASERT `bits != expected_bits` (`AsertMismatch`).
  The emitter produces correct `bits` via `calculate_target_clamped`, so this
  check *validates the emitter* and remains a real test of ASERT.
- Uncle-count ≤ MAX_UNCLES and `target ≤ MAX_POOL_TARGET` structural checks in
  `validate_header_minimum_difficulty` — structural, emitter satisfies them.
- All of organise/reorg, PPLNS window, payout distribution, coinbase assembly.

All test nodes must be built with `--features sim` (a synthetic share rejected by
a non-sim receiver would never propagate).

## Components

### C0 — `sim` cargo feature + config
- `p2poolv2_lib/Cargo.toml`: add `[features] sim = []` (pattern: existing
  `hydrapool-pplns-accounting`, `test-utils`).
- `p2poolv2_node/Cargo.toml`: add `sim = ["p2poolv2_lib/sim"]` (pattern: existing
  `debug-tools`).
- Config (`p2poolv2_config/src/lib.rs`, top-level `Config` at ~387): add
  `#[serde(default)] pub sim: Option<SimConfig>` (unconditional field, harmless in
  prod; only *acted on* under the feature). New `SimConfig`:
  ```toml
  [sim]
  enabled = true
  miner_address = "bcrt1q..."     # this node's payout identity (distinct per node)
  hashrate = 1.0e12               # modeled Hᵢ (hashes/sec) — sets emission rate
  block_to_share_ratio = 10000    # expected shares per block (global, same on all nodes)
  seed = 1                        # per-node RNG seed; MUST differ per node so
                                  # timelines decorrelate (e.g. base_seed + node
                                  # index, or omit for from_entropy()). Cheap RNG
                                  # is fine — this is a sim, not entropy for money.
  ```
- Env override works automatically via `P2POOL_SIM_*` (config crate, `with_prefix`).

### C1 — PoW gating
Implement `pow_meets` helper and swap the sites listed above; wrap auto-submit in
`#[cfg(not(feature = "sim"))]`. Smallest possible diff; this is the only change to
consensus-path code.

### C2 — Sim share emitter (the core of the work)
A new task `sim/emitter.rs` spawned in `NodeActor::run()`
(`node/actor.rs:420-429`, alongside `EmissionWorker`) under
`#[cfg(feature = "sim")]` when `sim.enabled`. It is handed: a clone of the
`emissions` sender, `chain_store_handle`, the `PoolDifficulty`, the latest
`BlockTemplate` (watch/JobTracker), and `SimConfig`.

**Inject at the `Emission` channel** — reuse the whole existing pipeline
(`emission_worker.rs:71-102` → `handle_stratum_share` → ShareBlock → chain →
`SwarmSend::Inv` broadcast). The emitter does NOT call the store directly.

Per iteration:
1. `chain_store_handle.get_chain_tip_and_uncles()` → `prev_share_blockhash`, `uncles`.
2. `chain_store_handle.get_tip_height_and_time()` → parent height/time.
3. `pool_difficulty.calculate_target_clamped(parent_time, parent_height)` → `bits`.
4. Build `ShareCommitment { prev_share_blockhash, uncles, miner_bitcoin_address,
   bits, time = now, donation/fee, coinbase_value }` (`shares/share_commitment.rs`).
5. Build a **structurally-consistent** bitcoin coinbase (commitment hash in
   scriptSig, via `stratum/work/coinbase.rs`) → merkle root → `bitcoin::Header`
   (prev/version/bits/time from template, arbitrary nonce — PoW NOT satisfied).
6. Build `SimplePplnsShare` + `Emission { pplns, header, blocktemplate,
   share_commitment: Some(..), coinbase_nsecs, template_merkle_branches,
   extranonce }` (`stratum/emission.rs:27-38`) and send it.
7. **Closed-loop sleep**: `mean_interval = difficulty(bits) · 2³² / Hᵢ`; draw
   exponential(mean) from the seeded RNG. When ASERT raises difficulty, the
   emitter slows down on its own — the controller is genuinely under test.
8. Bernoulli(p = 1/block_to_share_ratio) → if hit, hand off to C3.

> Risk to verify while building: how strict is commitment/merkle consistency in
> the receive-side validation (does it recompute the merkle root vs the coinbase
> carrying the commitment?). Step 5 must satisfy whatever it checks. Confirm by
> running one synthetic share between two sim nodes before scaling.

### C3 — Statistical block-find + payout
On a Bernoulli hit, the node itself (decentralized, per the design) submits a
real regtest block carrying the real PPLNS payout:
1. Grab the latest template (`JobTracker.get_latest_job_id → get_job`,
   `stratum/work/tracker/mod.rs`) or a fresh `getblocktemplate`.
2. Build the **bitcoin PPLNS coinbase**: reuse
   `validation/mod.rs:675 build_expected_outputs` (donation/fee cuts + PPLNS
   distribution from the window) → `stratum/work/coinbase.rs:112
   build_bitcoin_coinbase_transaction`.
3. Assemble the `bitcoin::Block` (reuse `submit.rs:242 build_full_block` shape),
   grind the nonce to meet regtest's trivial target (≈1–2 hashes), and submit via
   `bitcoindrpc submit_block(&block)` (`bitcoindrpc/src/lib.rs:329`).
4. Let the real path run: ZMQ `hashblock` (`stratum/zmq_listener.rs`) → GBT
   refresh → confirmation/organise (`store/organise/confirmed.rs`) → payout is
   deterministic from the window (`validate_bitcoin_payout`,
   `validation/mod.rs:610`).

This exercises payout distribution (the ~500-output concern), coinbase assembly,
submitblock, and the confirmation/re-notify coupling for real.

**Cost & determinism (the Bernoulli is not a hidden PoW).** Worth being explicit,
because the worry "does the block-find decision cost like a small PoW?" is natural
but the shapes are not comparable:
- PoW is a **busy grind loop** — millions of header hashes *between* emissions,
  welding share-rate to CPU. The Bernoulli is **one O(1) draw per share**, and it
  sits *behind the closed-loop sleep* (C2 step 7): `sleep → emit → draw`. There is
  no hot loop anywhere in C2/C3, so the decision cannot cost "like a small PoW" —
  it's ~10ns gated by a sleep orders of magnitude longer.
- The cost that *does* scale to 1k is not the decision but its **consequence**: a
  hit submits a real block to the **single shared bitcoind**, whose ZMQ
  `hashblock` then fans out a re-template to **all N nodes**. At ~`shares/s ÷
  block_to_share_ratio` blocks/s that fanout — not the draw — is the load. That is
  exactly the coupling we want to measure, so it's by design, not waste.
- **RNG: keep it cheap, don't over-engineer.** This is a sim, not money — no
  entropy quality is needed. In the multi-process layout (C4) nodes are separate
  processes, so there is no shared RNG to contend on at all; each just needs a seed
  that *differs* per node so timelines decorrelate (seed from node index/port, or
  `from_entropy()`). A per-node `SmallRng` is plenty; the only thing to avoid is
  one shared `Mutex<Rng>` behind all nodes in the *in-process* harness.
- **Optional precomputed-schedule mode.** "Caching the choices upfront" saves no
  CPU (the draw is already free and sleep-gated), but a *seeded* RNG already buys
  reproducible runs, and a precomputed per-node (emit-time, is-block) schedule
  additionally buys **exact experimental control** — inject precisely M blocks at
  chosen times instead of relying on the statistics. Baseline = seeded per-node
  Bernoulli; add the schedule mode only if a controlled experiment needs it.
- **Trap to avoid:** do *not* decide block-finds by hashing the header against the
  network target. On regtest that's a ~50% coin-flip per hash (the original
  inversion trap) and elsewhere it needlessly reintroduces a hash on the hot path.
  Use a Bernoulli with the correct `p`.

### C4 — Multi-node harness

**Process model is a spectrum, not a binary — and it should be a *launcher*
choice, not baked into the node.** Do not commit to "one child process per node"
up front. Make the node **embeddable** (spawnable as a set of tasks from a config,
with no reliance on process-global state — see open question below), and then the
same code runs in any of these layouts:

1. **1 node / process** (N processes) — max realism + fault isolation (real
   sockets, separate RocksDB, a panic can't cross nodes), zero node changes. But
   each process carries a full tokio runtime (`num_cpus` worker threads by
   default), so 1k processes ≈ thousands of runtime threads + 1k RocksDB caches +
   a large FD/ulimit footprint. Heavy. If used, give each process a
   `current_thread`/tiny runtime and a small RocksDB cache.
2. **K nodes / process, M processes** (M×K = N) — the load-test sweet spot. Caps
   the number of runtimes, amortizes per-process overhead, *keeps* fault isolation
   and free multi-machine spread. Requires the embeddable node.
3. **All N in one process** — the existing `node_swarm_test.rs` model. Max density,
   fewest threads, best instrumentation/assertions; max shared-fate and most
   exposed to any process-global singleton.

**What decides where we sit** (none of which we know yet — measure in Phase 1):
- **Per-node memory** (dominated by RocksDB block cache) — the single number that
  says whether one machine reaches 1k. The "measure where one machine tops out"
  step below *is* the process-model decision; pull it forward.
- **Threads** — strongly favors fewer runtimes (layouts 2/3).
- **Process-global state in the node** — the real gate on in-process density
  (layouts 2/3). The swarm test proves a handful of in-process nodes work; it does
  not prove 1k does. Audit before relying on it (open question below).

**Recommendation by phase:**
- Phases 0–2 (single, then small multi-node with tight assertions): **in-process**
  via `p2poolv2_tests/src/node_swarm_test.rs` (spawns nodes on
  `/ip4/127.0.0.1/tcp/PORT`, auto-generated ed25519 identities, `dial_peers`
  wiring, `default_test_config()` builder) — cheapest and most instrumentable.
- The 1k push: **shard (layout 2)** across a few processes / machines.
- Keep **1-per-process via config files** (generator script: emit N configs +
  ring/mesh/random topology, all pointing at the shared regtest bitcoind, launch,
  collect logs/stats) as a **fidelity reference** — run a smaller N this way to
  confirm dense results aren't hiding co-tenancy artifacts.
- Use tmpfs for stores throughout.

### C5 — Metrics & observability
- Reuse `logging.stats_dir` dumps and the API (`:46884`).
- Add sim counters: shares emitted/accepted/rejected, **uncle rate**, reorg
  depth/frequency, blocks found, PPLNS window size, payout output count & latency,
  p2p bytes/sec, store write latency. Uncle-rate-vs-latency is the headline output.

## Phasing (build order, each reuses the last)

| Phase | Scope | Acceptance criteria |
|---|---|---|
| **0 ✅** | C0 + C1 | `--features sim` compiles; non-sim build unchanged; PoW checks no-op only under sim. `cargo test` green both ways. **DONE** (`b0b8a02`). |
| **1 ✅** | C2 on a **single** sim node | Emitter grows the share chain at the closed-loop rate; ASERT difficulty responds; `bits` pass `AsertMismatch`. Measure ingestion/store/PPLNS-window cost as window → 133k. No p2p, no blocks. **DONE** (`3778350`): verified live on regtest — 26 confirmed promotions at ~4–5 s/share (matches `D≈1000·2³²/1e12`), zero validation/AsertMismatch errors, clean shutdown. (Window-cost-to-133k measurement still to run.) |
| **2 ✅** | C4 (N nodes) + propagation | 2→N sim nodes connected; synthetic shares propagate; **uncles appear** and uncle rate tracks injected latency. Reorg/organise under load. **DONE**: 20/20 nodes (release) full mesh (19 peers each), converge on one chain, 0 panics. Latency injection (`[sim].propagation_delay_ms`) produces uncles, and **uncle rate tracks latency**: 0 ms → ~0%, 200 ms → 36%, 750 ms → 50% (measured on node 0 via the `sim-uncle` log). |
| **3 ✅** | C3 block-finds | Per-node Bernoulli block-finds submit valid regtest blocks with PPLNS coinbase; payout distribution + confirmation run; measure payout path under load. **DONE**: on a block-find the emitter reuses the share's already-built PPLNS coinbase, grinds the trivial regtest nonce (~1–2 hashes) and submits via `bitcoindrpc`. Verified live (20 nodes, `RATIO=20`): regtest height climbed 104→109, 5/5 submits accepted, 0 failures; the accepted coinbase pays the PPLNS distribution (subsidy → miner address + witness-commitment output); ZMQ→GBT refresh kept the share chain advancing on each new bitcoin tip. **Multi-way payout demonstrated**: each node gets a distinct payout address (`DISTINCT_ADDR=1`, via RPC `getnewaddress`), `solo`/`bootstrap` stay on a shared fallback. With the regtest window fix (below), a 20-node run produced coinbases paying **17–19 distinct miners**, each proportional to its share weight (e.g. 3.60 / 2.40 / 2.10 / … / 0.50 BTC summing to the subsidy) — a mainnet-like distribution, with 0 payout/merkle rejections. |
| **4** | Scale + harden | Push toward ~1k peers on one machine; find the real bottleneck (store? libp2p? organise?); document density ceiling. |

(Orthogonal: the existing `load-tests/jmeter` + `mock-bitcoind` covers pure
stratum-frontend throughput if we ever want axis A.)

### Findings from the swarm runs

- **Run release for swarms.** `libp2p-request-response` has a `debug_assert_eq!`
  in `on_connection_closed` (lib.rs:651) that fires under the connection churn of
  a 20-node swarm and aborts the process (15/20 nodes died in a debug run). It is
  compiled out in release; a 20-node **release** run had 0 panics. The harness
  builds release by default. (This is a debug-only third-party assertion, not a
  sim-logic bug; worth reporting upstream / pinning a note.)
- **Uncles need injected latency (implemented).** Over loopback, share
  propagation (~sub-ms) beats the inter-block time, so without help the chain
  stays near-linear. `[sim].propagation_delay_ms` delays each node's outbound
  `Inv` announcement (sim-gated, via a process-global atomic read in
  `emission_worker`), widening the concurrent-emission window. Measured uncle
  rate on node 0: 0 ms → ~0%, 200 ms → 36%, 750 ms → 50% — monotonic, and
  saturating at high latency. Set with `LATENCY_MS=… run-swarm.sh`.
- **Timestamp == MTP rejections at high rate.** The emitter stamps `ntime = now`
  (1 s granularity); when the chain advances faster than 1 block/s, a share's
  timestamp can equal the median-time-past of recent ancestors and
  `validate_timestamp` rejects it (~66 rejections vs thousands of promotions in
  the 20-node run). Minor throughput loss; a future emitter tweak can stamp
  `max(now, parent_mtp + 1)`.

- **Regtest difficulty collapses the PPLNS payout window — fixed.** The payout
  window spans `total_difficulty / share_difficulty` shares, where
  `total_difficulty = bitcoin_block_difficulty × difficulty_multiplier`. On
  regtest the bitcoin block sits at the pow-limit so its difficulty (network-
  relative) is exactly **1**, while a share's difficulty is ≈ **2⁴¹ ≈ 2×10¹²**
  (regtest pow-limit ÷ the ASERT pool target). So the window collapses to a
  single share → single-payee coinbases. Fix (sim-only): a process-global
  `pplns_window_shares = N` (set from `[sim].pplns_window_shares`, default
  `block_to_share_ratio`) makes both the build-side (`notify.rs`) and validate-
  side (`validate_bitcoin_payout`) compute `total_difficulty = (pool-target
  difficulty) × N`, so the window spans ~N shares regardless of ASERT — mainnet-
  like. Both sides use the same pool target (the tip's ASERT target, which
  becomes the share's `bits`), so they stay consistent (verified: 0 merkle
  rejections). Falls back to the production formula when unset.
- **Uncle reward weighting (verified):** a confirmed share (nephew) weighs
  `difficulty × 10`; an uncle weighs `× 9` (`UNCLE_SCALED_WEIGHT`); the nephew
  gets `+ × 1` per uncle (`NEPHEW_SCALED_BONUS`). So with equal difficulties:
  1 uncle → nephew:uncle = 11:9 = **55/45**; 2 uncles → 12:9:9 = **40/30/30**.
  Confirmed against live blocks. (The uncle keeps ~90%, not 10% — the 10% is the
  finder's bonus to the nephew.) Uncle count per block ≈ `U/(1−U)` (≈ orphan
  rate), so `MAX_UNCLES = 3` (and the 3-generation `MAX_UNCLES_DEPTH` window)
  never binds at realistic `U`; both are dormant safety bounds that only bite at
  high `U`.
- **ASERT never reaches steady state on regtest — fixed (sim).** ASERT anchors
  on the genesis timestamp (`PoolDifficulty::build` → `genesis_header.time`), and
  the fixed regtest genesis is dated ~47 days in the past, so the chain is
  permanently "behind schedule": difficulty stays floored at the easy clamp and
  the chain **races at ~36× the 0.1/s target** (difficulty dead-pinned at 1164
  over 244s/15 samples). Fix (sim-only): override the genesis share timestamp to
  a shared ~launch time (`[sim].asert_anchor_time`, written once by the harness),
  so the anchor is ~now and ASERT regulates. **And start at the steady state:**
  climbing from the easy clamp to the operating difficulty still took ~15-20 min
  (the half-life) — unrealistic/wasteful — so the genesis bits (the ASERT anchor
  *target*) are also set to the steady-state difficulty
  `D* = total_hashrate · 10s / 2^32` (from `[sim].network_hashrate`, written once
  by the harness). Verified: difficulty starts at **47106 ≈ D*=46566** (not the
  1164 clamp) and the rate is **0.113/s vs the 0.100/s target from block 1**, no
  warmup, **0** AsertMismatch/merkle rejections (shared genesis → identical
  ASERT). The timestamp==MTP rejections also vanish once the rate is regulated
  (shares land ~10s apart).

### Realism knobs (done)

The harness now models a heterogeneous, regulated network rather than identical
nodes racing:
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

Watch the log for `Promoted block … to confirmed height N` climbing at the
closed-loop rate. The `sim` feature must never be enabled in a release build.

### Running a swarm (Phase 2)

`load-tests/sim/` drives a multi-process swarm against the same regtest
bitcoind. Each node gets its own config (distinct ports, distinct seed, fresh
store) and a `dial_peers` topology (each dials `DIAL_FANOUT` earlier nodes).

```sh
load-tests/sim/run-swarm.sh 20     # build (release) + launch 20 nodes
load-tests/sim/observe.sh          # per-node tip height, peers, convergence, uncle rate
load-tests/sim/metrics.sh          # text: emission∝hashrate, ASERT trajectory, rate
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
no ASERT warmup), `DIST_SEED`, `DISTINCT_ADDR`,
`POOL_SIGNATURE` (must match across nodes), `DIAL_FANOUT`, `PROFILE`. Convergence
shows as `distinct tips: 1` (a snapshot may straddle the latest 1–2 heights while
the frontier propagates). Run release; always `stop-swarm.sh` before relaunching
(orphans hold ports — `run-swarm.sh` now also clears its RUN_DIR's leftovers).

## Open questions to resolve during the build
1. ~~**Commitment/merkle strictness** on the receive path (C2 step 5) — the single
   biggest integration risk.~~ **RESOLVED.** Receive-side `validate_bitcoin_payout`
   recomputes the bitcoin header merkle root from a coinbase reconstructed from
   the commitment + `template_merkle_branches`. `sim::share::build_sim_emission`
   builds the header from the same job components, and a unit test
   (`emission_merkle_root_matches_validation_reconstruction`) plus the live
   single-node run (no validation rejections through the real organise path)
   confirm synthetic shares pass. Still to verify explicitly across **two** nodes
   in Phase 2.
2. Does `share_blocks.rs:85 validate_share_header` need its own gate or does it
   inherit from `validate_with_pool_difficulty`? Confirm by reading the call tree.
3. Whether the emitter should inject via the `Emission` channel (preferred) vs.
   `add_share_block_and_organise_header` directly — confirm `handle_stratum_share`
   p2p path produces an identical ShareBlock to a real stratum submission.
4. Exact confirmation trigger semantics (candidate→confirmed vs bitcoin-block
   arrival) so Phase 3 measures the intended path.
5. **Process-global state audit** — decides whether in-process density (C4 layouts
   2/3) is viable at scale. Check for singletons that N "nodes" in one process
   would collide on: global tracing-subscriber init, any metrics/exporter bound to
   a fixed port, `OnceCell`/`static`/`lazy_static`, hardcoded paths. Per-node
   RocksDB path and ed25519 identity are already config/auto-gen, so those are
   fine. Run this before committing to a process model.

## Out of scope / non-goals
- Adversarial behaviour (equivocation, invalid shares) — this harness is
  cooperative by construction.
- Accelerated virtual-time simulation — incompatible with real libp2p; if needed,
  it's a *separate* single-process tool (mock network + `TestTimeProvider`).
- Shipping any of this in a release binary — `sim` feature must never be enabled
  in production builds.
