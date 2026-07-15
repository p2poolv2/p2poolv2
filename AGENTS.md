This file provides guidance to AI coding agents working with code in this repository.

## Project overview

P2Poolv2 is a peer-to-peer Bitcoin mining pool where miners coordinate
directly without centralized operators. Miners submit shares via
Stratum, which form a DAG-based share chain with uncle support. Payouts
are calculated via PPLNS and paid directly from coinbase transactions.

Project name is P2Poolv2 (no whitespace). Rust edition 2024, minimum
rust-version 1.88.

## Build and test commands

```sh
cargo build --workspace                     # Use --workspace unless working on a single crate.
cargo nextest run --workspace               # always use nextest, not cargo test
cargo nextest run --workspace test_name     # single test by name substring
cargo nextest run -p p2poolv2_lib           # single crate
cargo clippy --workspace --all-targets      # must pass with zero warnings
cargo fmt --all -- --check                  # must pass
cargo bench -p p2poolv2_lib --bench pplns_window --features test-utils
cargo build -p p2poolv2_sim --features sim  # sim binary
```

A task is not done until `cargo clippy --workspace --all-targets` and
`cargo fmt --all -- --check` both pass cleanly (no new warnings, zero
errors).

## Architecture docs

Read `docs/architecture/` when working in the relevant area:

- `share-processing-pipeline.md` -- emission through validation,
  organization, and P2P broadcast
- `async-flow.md` -- worker tasks, channel topology, backpressure
- `store-schema.md` -- RocksDB column families, key encoding, merge ops
- `store-architecture.md` -- read/write separation, StoreWriter thread
- `pruning.md` -- TTL-based share pruning
- `metrics.md` -- Prometheus exposition, metric sources, Grafana panels

Also: `docs/simulation/` (sim feature), `docs/difficulty_adjustment/`
(ASERT algorithm).

Never infer architecture from filenames alone. Read the relevant architecture document first.

## Workspace crates

| Crate | Purpose |
|---|---|
| `p2poolv2_lib` | Core library: shares, P2P, stratum, storage, validation, accounting |
| `p2poolv2_node` | Main binary: builds and runs the full node |
| `p2poolv2_cli` | CLI utilities: share queries, address generation, auth signing |
| `p2poolv2_api` | REST API + WebSocket server (axum) |
| `p2poolv2_config` | TOML config parsing with phantom-type state machine (Raw -> Parsed) |
| `p2poolv2_tests` | Integration tests (multi-node P2P, stratum, API) |
| `p2poolv2_sim` | No-PoW load-test simulation binary (feature-gated with `sim`) |
| `bitcoindrpc` | JSON-RPC 1.0 client for Bitcoin Core |

## Key entry points in p2poolv2_lib

Most modules are discoverable by name; these are the non-obvious ones:

- `node/actor.rs` -- NodeActor: main event loop driving libp2p swarm
  and orchestrating all workers
- `shares/handle_stratum_share.rs` -- converts a stratum Emission into
  a ShareBlock; the bridge between stratum and the share chain
- `store/writer/` -- all RocksDB writes are serialized through a
  dedicated OS thread; reads bypass it
- `store/organise/` -- candidate/confirmed chain indexing, reorg logic,
  WriteBatch atomicity
- `shares/chain/chain_store_handle.rs` -- async trait over chain ops;
  the seam used for mocking in tests

## Domain concepts

- **Share chain**: DAG of share blocks with parent + uncle references.
  Uncle is an ancestor (not sibling) that is NOT on the confirmed chain.
- **Candidate chain**: best-work chain of share headers, updated on
  each new header
- **Confirmed chain**: subset of candidate chain promoted after block
  validation
- **Emission**: a stratum share submission packaged for the node
  pipeline (defined in `stratum/emission.rs`)
- **ASERT**: difficulty adjustment algorithm for share target
- **PPLNS**: pay-per-last-N-shares payout scheme
- **Pool modes**: P2Poolv2 (sharechain PPLNS) vs Hydrapool (time-window
  PPLNS)

## Testing

- Set mock expectations inline in each test -- no mock setup helpers.
  This keeps each test self-contained and readable.
- Test helpers belong in `test_utils` module only if they are generic
  and reusable. No helpers local to a test module -- they inevitably
  diverge and hide setup differences between tests.
- `TestShareBlockBuilder` for constructing test shares; well-known
  pubkeys `PUBKEY_G` through `PUBKEY_5G` in test_utils.
- Feature `test-utils` gates shared test infrastructure.

## Do not touch

- Fixture JSON files in `p2poolv2_tests/test_data/`. Override values in test code instead.
- Genesis block definitions in `shares/genesis/`. Genesis shares
  define a share chain starting point.

## Workflow

- For multi-step plans, ask to commit after each step.
- Never create commits yourself. After completing a logical step, ask the user to review and commit before continuing.
- Code reviews stay local -- do not post to GitHub.

## Rust conventions

- **Imports:** All `use` declarations at top of module (or top of
  `#[cfg(test)] mod tests`). Never inside function bodies. Import items
  and refer by short name; at most `parent_module::function`, never
  full crate paths inline.
- **Preallocate collections:** Use `HashMap::with_capacity(n)` /
  `Vec::with_capacity(n)` when the size is known or estimable at
  construction. Flag bare `HashMap::new()` as a potential problem.
- **Error handling:** Do not replace fallible operations with default
  values unless that behaviour is explicitly intended. If error
  handling is unclear, ask.
- Update docstrings for changed functions.

### Hard constraints

- **No `unsafe`.**
- **ASCII only** in all src and comments (no unicode emdashes, arrows, etc.).

### Preferred style

- **No abbreviations or single-character variable names.**
- **Concurrency:** Prefer the actor/channel pattern over locks. If you
  must lock, evaluate deadlock risk and document lock ordering.
- **Functions:** One function does one thing. Extract when a block
  needs a comment to explain it, unless extraction forces lifetimes or
  unnecessary copies.
- Avoid continue/break. Prefer structured control flow because the distributed
  algorithms are easier to reason about without non-local jumps.

## Prefer existing code

Before introducing a new utility, helper, or dependency:

- search the workspace for an existing implementation
- reuse existing abstractions
- avoid duplicate helper functions

## Performance matters.

- Avoid unnecessary cloning, temporary allocations, and repeated RocksDB lookups.
- When performance and readability conflict, ask before making a large refactor.
