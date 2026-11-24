// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Store schema versioning and migrations.
//!
//! The store records its layout version under `SCHEMA_VERSION_KEY` in the
//! `Metadata` column family. `Store::new` updates a writable store up to
//! `CURRENT_SCHEMA_VERSION` before anything else touches it.
//!
//! It refuses a read-only open of a store at any other version, so no
//! code path reads or writes a layout it was not written for.
//!
//! Each migration fills one `WriteBatch` and the version bump is added to
//! that batch, so a migration commits whole or not at all. A crash or error
//! before the commit leaves the store at its old version, and the next start
//! runs the migration again. See `docs/architecture/store-migrations.md`.
//!
//! # Adding a migration
//!
//! Add one whenever a change alters how existing data is laid out on disk:
//! a key or value encoding, which column family something lives in, or data
//! that existing stores must gain. A new column family whose rows the code
//! fills as it runs needs no migration.
//!
//! 1. Create a module under `store/migrations/`, named for the change, with a
//!    `run` function:
//!
//!    ```ignore
//!    pub(super) fn run(db: &DB, batch: &mut WriteBatch) -> Result<(), StoreError> {
//!        // Read rows in the old layout with this module's own copy of the
//!        // old encoding, and put each rewritten row into `batch`.
//!    }
//!    ```
//!
//! 2. Append it to `MIGRATIONS` with `to_version` one above the current
//!    version, and bump `CURRENT_SCHEMA_VERSION` to match. A gap or a
//!    mismatch fails every writable open (`validate_migration_chain`).
//!
//!    ```ignore
//!    const MIGRATIONS: &[Migration] = &[Migration {
//!        to_version: 2,
//!        name: "key share transactions by wtxid",
//!        run: key_by_wtxid::run,
//!    }];
//!    ```
//!
//! 3. Update `docs/architecture/store-schema.md` for the new layout.
//!
//! Rules for `run`:
//!
//! - **Only write to `batch`.** Never write to `db` directly. The framework
//!   adds the version bump to the batch and commits it, which is what makes
//!   the migration all or nothing.
//! - **Keep your own copy of every old encoding you read.** Do not call
//!   store helpers to build keys or decode values: they follow the current
//!   layout and will change again, while a migration must always read the
//!   layout it was written for.
//! - **Never be the only code that produces some data.** A fresh store is
//!   stamped with `CURRENT_SCHEMA_VERSION` and skips every migration, so
//!   whatever a migration creates for existing stores, the normal code paths
//!   must also create for new ones. A migration only converts what is
//!   already there.
//! - **Fit in one batch.** The whole migration is held in memory until the
//!   commit. A migration too large for that has to add its own chunking;
//!   this framework does not checkpoint or resume.
//! - **Expect to run again from the start.** A crash or error before the
//!   commit leaves nothing written, and the next start runs `run` again on
//!   the same old-layout store.
//!
//! Tests for a migration, in its module:
//!
//! - Write a store in the old layout using the module's copy of the old
//!   encoding, open it with `Store::new`, and assert the new layout and
//!   `CURRENT_SCHEMA_VERSION`.
//! - Build the same data on a fresh store with the current code and check
//!   it matches what the migration produced, which catches a migration that
//!   creates data the normal code paths do not.

mod key_by_wtxid;

use crate::store::column_families::ColumnFamily;
use crate::store::writer::StoreError;
use rocksdb::{DB, WriteBatch};
use tracing::info;

/// The schema version this binary reads and writes.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// The version of a store written before schema versioning existed. Such a
/// store has data but no `SCHEMA_VERSION_KEY`.
const UNVERSIONED_SCHEMA_VERSION: u32 = 1;

/// Key in the `Metadata` column family holding the schema version as a
/// big-endian u32.
const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

/// Key in the `BlockHeight` column family of the confirmed block at height
/// 0, the genesis, in the version 1 layout: the height as 4 big-endian bytes
/// followed by `:f`.
///
/// Frozen here rather than built with the store's current key helper: it is
/// only read from stores that predate versioning, which are always in the
/// version 1 layout. If a later migration changes the height key encoding,
/// the current helper would miss genesis in such a store, call it fresh, and
/// skip every migration.
const VERSION_1_CONFIRMED_GENESIS_KEY: &[u8] = b"\0\0\0\0:f";

/// One step that rewrites the store from `to_version - 1` to `to_version`.
///
/// `run` reads the old layout from the database and puts every write into
/// the batch it is given. It must not write to the database directly: the
/// framework adds the version bump to the same batch and commits it, which is
/// what makes the migration atomic. Each migration keeps its own copy of the
/// key and value encodings it reads, so later changes to store helpers never
/// change what an old migration does.
pub(crate) struct Migration {
    pub(crate) to_version: u32,
    pub(crate) name: &'static str,
    pub(crate) run: fn(&DB, &mut WriteBatch) -> Result<(), StoreError>,
}

/// Every migration, in order. Each `to_version` is one more than the
/// previous, starting at `UNVERSIONED_SCHEMA_VERSION + 1` and ending at
/// `CURRENT_SCHEMA_VERSION`.
const MIGRATIONS: &[Migration] = &[Migration {
    to_version: 2,
    name: "key share transactions by wtxid",
    run: key_by_wtxid::run,
}];

/// The schema version a store is at, as found when it is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredSchemaVersion {
    /// No genesis: a store being created, with nothing to migrate.
    Fresh,
    /// A store with data, at this version. A store with a genesis but no
    /// version key is at `UNVERSIONED_SCHEMA_VERSION`.
    Version(u32),
}

/// Bring a writable store up to `CURRENT_SCHEMA_VERSION`.
///
/// Stamps a fresh store with the current version. Runs every pending
/// migration on an older store, committing each one with its version bump.
/// Refuses a store written by a newer binary, and one at a version below
/// `UNVERSIONED_SCHEMA_VERSION`, which no migration starts from.
pub(crate) fn ensure_current(db: &DB) -> Result<(), StoreError> {
    ensure_version(db, MIGRATIONS, CURRENT_SCHEMA_VERSION)
}

/// Check that a store opened read-only is at `CURRENT_SCHEMA_VERSION`.
///
/// A read-only open cannot migrate, so any other version is an error. An
/// older store can be migrated by starting the node; a newer one needs the
/// newer binary that wrote it. A fresh store passes: it has no genesis, so
/// no data in any layout.
pub(crate) fn check_current(db: &DB) -> Result<(), StoreError> {
    match read_stored_schema_version(db)? {
        StoredSchemaVersion::Fresh => Ok(()),
        StoredSchemaVersion::Version(version) if version == CURRENT_SCHEMA_VERSION => Ok(()),
        StoredSchemaVersion::Version(version) if version > CURRENT_SCHEMA_VERSION => {
            Err(StoreError::Migration(format!(
                "store is at schema version {version}. {version} is newer than {CURRENT_SCHEMA_VERSION} that \
                 this binary supports. The version was written by a newer P2Poolv2, use a binary for \
                 version {version} to continue."
            )))
        }
        StoredSchemaVersion::Version(version) => Err(StoreError::Migration(format!(
            "store is at schema version {version}, this binary needs {CURRENT_SCHEMA_VERSION}; \
             start the node once to migrate it, or use a binary for version {version}"
        ))),
    }
}

/// Read the schema version a store is at.
///
/// Without a version key, a store with a genesis predates versioning and one
/// without is fresh. Every pool mode confirms a genesis at height 0 on
/// startup before writing anything else, so a store holding data has one.
pub(crate) fn read_stored_schema_version(db: &DB) -> Result<StoredSchemaVersion, StoreError> {
    if let Some(version) = read_schema_version_key(db)? {
        return Ok(StoredSchemaVersion::Version(version));
    }
    if has_genesis(db)? {
        Ok(StoredSchemaVersion::Version(UNVERSIONED_SCHEMA_VERSION))
    } else {
        Ok(StoredSchemaVersion::Fresh)
    }
}

/// Bring the store up to `target_version` using `migrations`.
///
/// A store from before versioning that needs no migration still gets its
/// version written, so later opens read it instead of inferring it.
///
/// Split from `ensure_current` so tests can supply their own migrations.
fn ensure_version(
    db: &DB,
    migrations: &[Migration],
    target_version: u32,
) -> Result<(), StoreError> {
    validate_migration_chain(migrations, target_version)?;

    match read_stored_schema_version(db)? {
        // A new store, directly write the current version as there is no data to migrate.
        StoredSchemaVersion::Fresh => {
            info!("Creating store at schema version {target_version}");
            write_schema_version(db, target_version)
        }
        // Store has a version higer than target version, disallow such downgrades
        StoredSchemaVersion::Version(version) if version > target_version => {
            Err(StoreError::Migration(format!(
                "store is at schema version {version}, newer than {target_version} which this \
                 binary supports; it was written by a newer P2Poolv2"
            )))
        }
        StoredSchemaVersion::Version(version) if version < UNVERSIONED_SCHEMA_VERSION => {
            Err(StoreError::Migration(format!(
                "store is at schema version {version}, older than {UNVERSIONED_SCHEMA_VERSION} \
                 which every migration starts from; this binary cannot migrate it"
            )))
        }
        StoredSchemaVersion::Version(version) => {
            run_pending_migrations(db, migrations, version)?;
            if read_schema_version_key(db)?.is_none() {
                write_schema_version(db, target_version)?;
            }
            Ok(())
        }
    }
}

/// Run each migration above `stored_version`, in order, committing each one
/// together with its version bump.
fn run_pending_migrations(
    db: &DB,
    migrations: &[Migration],
    stored_version: u32,
) -> Result<(), StoreError> {
    let metadata_cf = db.cf_handle(&ColumnFamily::Metadata).unwrap();
    for migration in migrations
        .iter()
        .filter(|migration| migration.to_version > stored_version)
    {
        info!(
            "Migrating store to schema version {}: {}",
            migration.to_version, migration.name
        );
        let mut batch = WriteBatch::default();
        (migration.run)(db, &mut batch).map_err(|error| {
            StoreError::Migration(format!(
                "migration to schema version {} ({}) failed, store left at version {}: {error}",
                migration.to_version,
                migration.name,
                migration.to_version - 1
            ))
        })?;
        batch.put_cf(
            &metadata_cf,
            SCHEMA_VERSION_KEY,
            migration.to_version.to_be_bytes(),
        );
        db.write(batch)?;
        info!("Store migrated to schema version {}", migration.to_version);
    }
    Ok(())
}

/// Check that `migrations` step one version at a time from
/// `UNVERSIONED_SCHEMA_VERSION` to `target_version`, so no store can skip a
/// migration or end at the wrong version.
fn validate_migration_chain(
    migrations: &[Migration],
    target_version: u32,
) -> Result<(), StoreError> {
    let mut expected_version = UNVERSIONED_SCHEMA_VERSION + 1;
    for migration in migrations {
        if migration.to_version != expected_version {
            return Err(StoreError::Migration(format!(
                "migration {} targets schema version {}, expected {expected_version}",
                migration.name, migration.to_version
            )));
        }
        expected_version += 1;
    }
    let last_version = expected_version - 1;
    if last_version != target_version {
        return Err(StoreError::Migration(format!(
            "migrations end at schema version {last_version}, expected {target_version}"
        )));
    }
    Ok(())
}

/// Read `SCHEMA_VERSION_KEY`, or `None` when it has never been written.
fn read_schema_version_key(db: &DB) -> Result<Option<u32>, StoreError> {
    let metadata_cf = db.cf_handle(&ColumnFamily::Metadata).unwrap();
    let Some(bytes) = db.get_cf(&metadata_cf, SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    let version_bytes: [u8; 4] = bytes.as_slice().try_into().map_err(|_| {
        StoreError::Serialization(format!(
            "schema version is {} bytes, expected 4",
            bytes.len()
        ))
    })?;
    Ok(Some(u32::from_be_bytes(version_bytes)))
}

/// Write `version` as the store's schema version.
fn write_schema_version(db: &DB, version: u32) -> Result<(), StoreError> {
    let metadata_cf = db.cf_handle(&ColumnFamily::Metadata).unwrap();
    db.put_cf(&metadata_cf, SCHEMA_VERSION_KEY, version.to_be_bytes())?;
    Ok(())
}

/// Whether the store has a genesis confirmed at height 0, read with the
/// frozen version 1 key (see `VERSION_1_CONFIRMED_GENESIS_KEY`).
fn has_genesis(db: &DB) -> Result<bool, StoreError> {
    let block_height_cf = db.cf_handle(&ColumnFamily::BlockHeight).unwrap();
    Ok(db
        .get_cf(&block_height_cf, VERSION_1_CONFIRMED_GENESIS_KEY)?
        .is_some())
}

/// One raw row of a column family: its key and value.
#[cfg(test)]
type KeyValue = (Box<[u8]>, Box<[u8]>);

/// Every key and value of `column_family`, in key order, for migration tests
/// that compare a column family's whole contents.
#[cfg(test)]
fn column_family_contents(db: &DB, column_family: ColumnFamily) -> Vec<KeyValue> {
    let handle = db.cf_handle(&column_family).unwrap();
    db.iterator_cf(&handle, rocksdb::IteratorMode::Start)
        .map(|entry| entry.unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::test_utils::genesis_for_tests;
    use tempfile::tempdir;

    const MARKER_KEY: &[u8] = b"test_migration_marker";

    /// Test migration that records it ran by writing `MARKER_KEY`.
    fn write_marker(db: &DB, batch: &mut WriteBatch) -> Result<(), StoreError> {
        let metadata_cf = db.cf_handle(&ColumnFamily::Metadata).unwrap();
        batch.put_cf(&metadata_cf, MARKER_KEY, b"migrated");
        Ok(())
    }

    /// Test migration that writes `MARKER_KEY` to its batch, then fails.
    fn write_marker_then_fail(db: &DB, batch: &mut WriteBatch) -> Result<(), StoreError> {
        let metadata_cf = db.cf_handle(&ColumnFamily::Metadata).unwrap();
        batch.put_cf(&metadata_cf, MARKER_KEY, b"migrated");
        Err(StoreError::Database("injected failure".to_string()))
    }

    #[test]
    fn test_fresh_store_is_stamped_with_current_version() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        assert_eq!(
            read_schema_version_key(&store.db).unwrap(),
            Some(CURRENT_SCHEMA_VERSION)
        );
        assert_eq!(
            store.schema_version().unwrap(),
            StoredSchemaVersion::Version(CURRENT_SCHEMA_VERSION)
        );
    }

    /// A store with no data in any column family has nothing to migrate, so
    /// it is stamped with the target version and no migration runs.
    #[test]
    fn test_fresh_store_skips_migrations() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        //* Remove the stamp Store::new wrote, leaving every column family empty.
        let metadata_cf = store.db.cf_handle(&ColumnFamily::Metadata).unwrap();
        store
            .db
            .delete_cf(&metadata_cf, SCHEMA_VERSION_KEY)
            .unwrap();
        let migrations = [Migration {
            to_version: 2,
            name: "write marker",
            run: write_marker,
        }];

        ensure_version(&store.db, &migrations, 2).unwrap();

        assert_eq!(store.db.get_cf(&metadata_cf, MARKER_KEY).unwrap(), None);
        assert_eq!(read_schema_version_key(&store.db).unwrap(), Some(2));
    }

    /// A store with a genesis but no version key predates versioning, so it
    /// is at version 1 and every migration from there runs.
    #[test]
    fn test_unversioned_store_with_data_runs_migrations_from_version_one() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        //* Simulate a pre-versioning store: a genesis, no version stamp.
        let metadata_cf = store.db.cf_handle(&ColumnFamily::Metadata).unwrap();
        store
            .db
            .delete_cf(&metadata_cf, SCHEMA_VERSION_KEY)
            .unwrap();
        let mut batch = Store::get_write_batch();
        store
            .setup_genesis(&genesis_for_tests(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();
        let migrations = [Migration {
            to_version: 2,
            name: "write marker",
            run: write_marker,
        }];

        ensure_version(&store.db, &migrations, 2).unwrap();

        assert_eq!(
            store.db.get_cf(&metadata_cf, MARKER_KEY).unwrap(),
            Some(b"migrated".to_vec())
        );
        assert_eq!(read_schema_version_key(&store.db).unwrap(), Some(2));
    }

    /// A pre-versioning store already at the target version needs no
    /// migration but still gets its version written.
    #[test]
    fn test_unversioned_store_without_pending_migrations_is_stamped() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        //* Simulate a pre-versioning store: a genesis, no version stamp.
        let metadata_cf = store.db.cf_handle(&ColumnFamily::Metadata).unwrap();
        store
            .db
            .delete_cf(&metadata_cf, SCHEMA_VERSION_KEY)
            .unwrap();
        let mut batch = Store::get_write_batch();
        store
            .setup_genesis(&genesis_for_tests(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        ensure_version(&store.db, &[], UNVERSIONED_SCHEMA_VERSION).unwrap();

        assert_eq!(
            read_schema_version_key(&store.db).unwrap(),
            Some(UNVERSIONED_SCHEMA_VERSION)
        );
    }

    /// A failed migration commits nothing: neither its own writes nor the
    /// version bump.
    #[test]
    fn test_failing_migration_leaves_store_and_version_unchanged() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        write_schema_version(&store.db, 1).unwrap();
        let migrations = [Migration {
            to_version: 2,
            name: "write marker then fail",
            run: write_marker_then_fail,
        }];

        let error = ensure_version(&store.db, &migrations, 2).unwrap_err();

        let metadata_cf = store.db.cf_handle(&ColumnFamily::Metadata).unwrap();
        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert_eq!(store.db.get_cf(&metadata_cf, MARKER_KEY).unwrap(), None);
        assert_eq!(read_schema_version_key(&store.db).unwrap(), Some(1));
    }

    /// Migrations commit one at a time, so a failure in a later one keeps
    /// the earlier one and leaves the store at the version it reached.
    #[test]
    fn test_failing_second_migration_keeps_first() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        write_schema_version(&store.db, 1).unwrap();
        let migrations = [
            Migration {
                to_version: 2,
                name: "write marker",
                run: write_marker,
            },
            Migration {
                to_version: 3,
                name: "fail",
                run: write_marker_then_fail,
            },
        ];

        ensure_version(&store.db, &migrations, 3).unwrap_err();

        let metadata_cf = store.db.cf_handle(&ColumnFamily::Metadata).unwrap();
        assert_eq!(
            store.db.get_cf(&metadata_cf, MARKER_KEY).unwrap(),
            Some(b"migrated".to_vec())
        );
        assert_eq!(read_schema_version_key(&store.db).unwrap(), Some(2));
    }

    #[test]
    fn test_writable_open_refuses_newer_store() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let store = Store::new(path.clone(), false).unwrap();
        write_schema_version(&store.db, CURRENT_SCHEMA_VERSION + 1).unwrap();
        drop(store);

        let error = Store::new(path, false).err().unwrap();

        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert!(error.to_string().contains("newer"), "{error}");
    }

    /// A version below the one stores from before versioning are at is not
    /// one any migration starts from, so a writable open must refuse it
    /// rather than open the store as current or run migrations written for
    /// another layout.
    #[test]
    fn test_writable_open_refuses_version_below_baseline() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let store = Store::new(path.clone(), false).unwrap();
        write_schema_version(&store.db, UNVERSIONED_SCHEMA_VERSION - 1).unwrap();
        drop(store);

        let error = Store::new(path, false).err().unwrap();

        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert!(error.to_string().contains("older than"), "{error}");
    }

    #[test]
    fn test_read_only_open_refuses_older_store() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let store = Store::new(path.clone(), false).unwrap();
        write_schema_version(&store.db, CURRENT_SCHEMA_VERSION - 1).unwrap();
        drop(store);

        let error = Store::new(path, true).err().unwrap();

        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert!(error.to_string().contains("start the node"), "{error}");
    }

    #[test]
    fn test_read_only_open_refuses_newer_store() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        let store = Store::new(path.clone(), false).unwrap();
        write_schema_version(&store.db, CURRENT_SCHEMA_VERSION + 1).unwrap();
        drop(store);

        let error = Store::new(path, true).err().unwrap();

        assert!(matches!(error, StoreError::Migration(_)), "{error}");
        assert!(error.to_string().contains("newer"), "{error}");
        assert!(!error.to_string().contains("start the node"), "{error}");
    }

    #[test]
    fn test_read_only_open_accepts_current_store() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_str().unwrap().to_string();
        drop(Store::new(path.clone(), false).unwrap());

        let store = Store::new(path, true).unwrap();

        assert_eq!(
            store.schema_version().unwrap(),
            StoredSchemaVersion::Version(CURRENT_SCHEMA_VERSION)
        );
    }

    #[test]
    fn test_production_migrations_chain_to_current_version() {
        validate_migration_chain(MIGRATIONS, CURRENT_SCHEMA_VERSION).unwrap();
    }

    #[test]
    fn test_migration_chain_with_gap_is_rejected() {
        let migrations = [
            Migration {
                to_version: 2,
                name: "first",
                run: write_marker,
            },
            Migration {
                to_version: 4,
                name: "skips three",
                run: write_marker,
            },
        ];

        let error = validate_migration_chain(&migrations, 4).unwrap_err();

        assert!(error.to_string().contains("expected 3"), "{error}");
    }

    #[test]
    fn test_migration_chain_ending_below_target_is_rejected() {
        let migrations = [Migration {
            to_version: 2,
            name: "first",
            run: write_marker,
        }];

        let error = validate_migration_chain(&migrations, 3).unwrap_err();

        assert!(
            error.to_string().contains("end at schema version 2"),
            "{error}"
        );
    }

    /// The frozen key must be the one the version 1 layout writes for
    /// genesis, or every pre-versioning store would look fresh and skip its
    /// migrations.
    #[test]
    fn test_has_genesis_reads_the_key_setup_genesis_writes() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
        assert!(!has_genesis(&store.db).unwrap());

        let mut batch = Store::get_write_batch();
        store
            .setup_genesis(&genesis_for_tests(), &mut batch)
            .unwrap();
        store.commit_batch(batch).unwrap();

        assert!(has_genesis(&store.db).unwrap());
    }
}
