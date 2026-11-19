---
name: Store Schema Migrations
description: How the RocksDB store records its layout version and migrates automatically on upgrade
---

**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Store Schema Migrations

The store records the version of its on-disk layout. When a node starts on
a store written by an older binary, it migrates the store to the current
layout before anything else reads or writes it. Operators run no commands
and do not resync.

Code: `p2poolv2_lib/src/store/migrations/mod.rs`.

## Version record

- Key `schema_version` in the `Metadata` column family, value a big-endian
  `u32`.
- `CURRENT_SCHEMA_VERSION` is the version this binary reads and writes.
- When the key is missing, the store is classified by whether it has a
  genesis confirmed at height 0:
  - **Fresh** -- no genesis. The store is stamped with
    `CURRENT_SCHEMA_VERSION`; there is nothing to migrate.
  - **Unversioned** -- a genesis. The store predates versioning and is at
    version 1.
- Every pool mode, Hydrapool included, confirms a genesis on startup before
  writing anything else (`ChainStoreHandle::init_for_mode`), so a store
  holding data has one.
- The genesis is read with a frozen copy of the version 1 key
  (`VERSION_1_CONFIRMED_GENESIS_KEY`: height 0 as 4 big-endian bytes, then
  `:f`, in `BlockHeight`), not the store's current key helper. Only stores
  from before versioning are checked this way, and they are always in the
  version 1 layout. If a later migration changed the height key encoding,
  the current helper would miss their genesis, call them fresh, and skip
  every migration.

## When it runs

`Store::new` checks the version straight after opening the database, so
every caller -- node, CLI, tests -- gets it, and nothing can use a store
laid out for another version.

| Open      | Store version    | Result                                        |
|-----------|------------------|-----------------------------------------------|
| writable  | fresh            | stamped with the current version              |
| writable  | older            | pending migrations run, then the store opens  |
| writable  | unversioned, no pending migration | stamped, then opens          |
| writable  | current          | opens                                         |
| writable  | newer            | refused (`StoreError::Migration`)             |
| writable  | below version 1  | refused; no migration starts there            |
| read-only | current or fresh | opens                                         |
| read-only | any other        | refused; a read-only open cannot migrate      |

In the node, `Store::new` runs before the StoreWriter thread starts
(`p2poolv2_node/src/lib.rs`), so a migration is the only writer and writes
to the database directly. A refused open logs the error and exits with a
failure code.

## Migrations

```rust
pub(crate) struct Migration {
    pub(crate) to_version: u32,
    pub(crate) name: &'static str,
    pub(crate) run: fn(&DB, &mut WriteBatch) -> Result<(), StoreError>,
}
const MIGRATIONS: &[Migration] = &[ /* ... */ ];
```

- `MIGRATIONS` steps one version at a time from version 2 up to
  `CURRENT_SCHEMA_VERSION`. `validate_migration_chain` checks this on every
  writable open and in a unit test, so a store can never skip a migration.
- Pending migrations run in order.

### Atomicity

- `run` reads the old layout and puts every write into the batch it is
  given; it never writes to the database itself.
- The framework adds `schema_version = to_version` to that batch and
  commits it with one write. A migration lands whole or not at all.
- A crash, kill or error before the commit leaves the store untouched at
  its old version. The node exits with the error, the old binary still
  runs on the store, and the next start runs the migration again from the
  beginning.
- With several pending migrations, each commits separately, so a failure
  in a later one leaves the store at the version the earlier ones reached.
- A future migration too large for one batch must add its own chunking.
  The framework does not checkpoint or resume.

### Frozen encodings

A migration keeps its own copy of every key and value encoding it reads,
and does not call current store helpers. Store helpers change over time; a
migration must keep reading exactly the layout it was written for.

## Adding a migration

1. Add a module under `store/migrations/` with a `run` function that reads
   the old layout (using its own copies of the old encodings) and fills
   the batch.
2. Append a `Migration` with `to_version = CURRENT_SCHEMA_VERSION + 1` to
   `MIGRATIONS`, and bump `CURRENT_SCHEMA_VERSION`.
3. Test it by writing an old-layout store with the module's own copy of
   the old encodings, opening it with `Store::new`, and asserting the new
   layout and version. Also build the same data on a fresh store with the
   current code and check it matches the migrated store.
4. Update `store-schema.md` for the layout change.

A migration must never be the only code that produces some data. A fresh
store is stamped with the current version and skips every migration, so
whatever a migration creates for existing stores, the normal code paths
must create for new ones too.

The step-by-step guide with the rules for `run` is in the module docs of
`store/migrations/mod.rs`.

## Last resort

A store that cannot be migrated can be deleted and resynced from peers.
That does not hold for Hydrapool mode's `Share` and `User` column families,
which are local accounting no peer has; a migration touching them needs
extra care.

## Operator tools

`p2poolv2_cli --db-path <path> db version` opens the store read-only and
prints its schema version and the binary's. When they differ the open
fails with an error naming both.
