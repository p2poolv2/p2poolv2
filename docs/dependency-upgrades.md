# Dependency upgrades

How to take a dependency upgrade in this repo, and why some of them are not
ordinary. Written after the libp2p 0.53 -> 0.56 / RocksDB 10 -> 11 upgrade;
`.github/dependabot.yml` points here.

## Routine upgrades

Semver-compatible bumps arrive as one grouped Dependabot PR each week. Majors
for most crates also arrive as Dependabot PRs. For either, the bar is the
standard gate:

```sh
just preflight        # fmt, clippy --workspace --all-targets --all-features, tests
just deny             # licences, duplicate versions, sources -- blocking in CI
just advisories       # RustSec advisories -- non-blocking in CI, informational
```

`cargo build --workspace --release` is worth adding when the change touches
anything with C sources or unwinding behaviour: the release profile sets
`lto = "fat"`, `codegen-units = 1` and `panic = "abort"`.

## Upgrades that are not routine

Four crates are in the Dependabot `ignore` list. Merging one of these without
coordinating a release breaks the network or the on-disk store, so they are
migrated by hand.

| Crate | Why |
|---|---|
| `libp2p` | p2p wire protocol. Nodes on different majors may negotiate the transport and then fail, which presents as a sync or peer-scoring bug rather than a version mismatch. |
| `rocksdb` | on-disk format and the merge operator contract. |
| `bitcoin` | consensus serialization, which is both the p2p wire format and the RocksDB key encoding. Ignored at **minor** too, because 0.32 -> 0.33 is semver-minor under cargo's 0.x rules. |
| `bitcoinconsensus` | script validation. |

For these, the gate above is necessary but not sufficient. Add:

1. **The sim swarm**, which is the only automated coverage of reconnection,
   catch-up and partition recovery:
   ```sh
   NODE_COUNT=10 ./load-tests/sim/nightly.sh all
   ```
   `restart-delayed` is the scenario that matters most: it takes a node down
   past the 300s tip-age threshold. Check `verify_chain: PASS (10/10)` in the
   summary, which validates every node's store, not just that the nodes stayed
   up.
2. **A testnet4 soak** before tagging a release. At least 48 hours on a fresh
   chain with two upgraded nodes, watching share propagation, peer count,
   memory and store size. The sim runs no-PoW against regtest, so it cannot
   catch what only shows up under real proof-of-work over time.

## Deliberately held back

`sha2` and `hmac` are pinned to the digest 0.10 generation. Upgrading while
`libp2p-identity` still pins the older stack through `ed25519-dalek`, `hkdf`
and `curve25519-dalek` compiles both and adds seven duplicate crates for no
functional gain. The reason and the removal condition are recorded above the
entries in the root `Cargo.toml`. The known-answer tests in
`p2poolv2_lib/src/auth.rs` pin the output, so the upgrade is safe whenever
`libp2p-identity` moves.

Advisories that cannot be fixed here are listed in `deny.toml`, each with the
upstream blocker and the condition for removing the entry. An ignore list
without removal conditions becomes permanent.

## Things that have bitten us

- **A local build may not use the vendored RocksDB.** If the machine has
  `/usr/lib/librocksdb.so`, `librocksdb-sys` links it, so local testing
  exercises a different engine version than CI ships. Check the store `LOG`
  for `RocksDB version:` and compare against the `librocksdb-sys` version, or
  verify in the container instead.
- **`--help` is not a smoke test.** The reqwest 0.13 upgrade left the container
  unable to construct an HTTP client at all, because rustls loads the platform
  trust store at construction and the runtime image had no `ca-certificates`.
  `--help` never builds a client, so it passed. Run an actual node.
- **`taiki-e/install-action` selects the tool from the git ref.** Pinning it by
  SHA silently breaks that; pass `with: tool: <name>` as well.
- **`publish = false` in `[workspace.package]` only applies where a member opts
  in** with `publish.workspace = true`. It also hides packages from cargo-dist,
  which then needs `dist = true` in that package's `dist.toml`.
- **A new transitive dependency can break unrelated code.** config 0.15 pulls
  `winnow`, whose `impl AsRef<BStr> for [u8]` made several `.as_ref()` calls
  ambiguous in the store.
- **Environment overrides use `__`** between a config section and its key. A
  single underscore cannot address a field whose own name contains one, and the
  override is silently discarded rather than reported. See the `env_override`
  tests in `p2poolv2_config`.
