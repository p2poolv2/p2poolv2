// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Taproot descriptor wallets saved in SQLite.

use crate::{AddressError, expected_hrp};
use bdk_wallet::descriptor::{DescriptorError, ExtendedDescriptor, IntoWalletDescriptor};
use bdk_wallet::miniscript::descriptor::KeyMap;
use bdk_wallet::rusqlite::{Connection, Error as SqliteError, ErrorCode, OpenFlags};
use bdk_wallet::{
    CreateParams, CreateWithPersistError, KeychainKind, LoadError, LoadWithPersistError,
    PersistedWallet, Wallet as BdkWallet,
};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{BlockHash, Network};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

/// SQLite `application_id` marking a complete P2Poolv2 wallet database
/// ("P2PW"). bdk leaves this header field unset.
const WALLET_APPLICATION_ID: i32 = 0x5032_5057;

/// Permissions of a new wallet database file: owner read and write only.
#[cfg(unix)]
const DATABASE_FILE_MODE: u32 = 0o600;

/// The network and share chain a wallet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIdentity {
    /// Network of the wallet's addresses and descriptor keys.
    pub network: Network,
    /// Hash of the share chain genesis block.
    pub sharechain_genesis_hash: BlockHash,
}

/// The two keychains of a wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keychain {
    /// Addresses handed out to receive payments.
    Receive,
    /// Addresses that receive the change from the wallet's own transactions.
    Change,
}

/// From, To and Fmt for Keychain. We want them private so we don't
/// use the Into Trait.
impl Keychain {
    /// The bdk keychain this keychain corresponds to.
    fn to_keychain_kind(self) -> KeychainKind {
        match self {
            Keychain::Receive => KeychainKind::External,
            Keychain::Change => KeychainKind::Internal,
        }
    }

    /// The keychain a bdk keychain corresponds to.
    fn from_keychain_kind(keychain_kind: KeychainKind) -> Self {
        match keychain_kind {
            KeychainKind::External => Keychain::Receive,
            KeychainKind::Internal => Keychain::Change,
        }
    }
}

impl fmt::Display for Keychain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Keychain::Receive => formatter.write_str("receive"),
            Keychain::Change => formatter.write_str("change"),
        }
    }
}

/// Errors produced when creating, opening or saving a wallet.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The address network is unsupported.
    #[error(transparent)]
    Address(#[from] AddressError),
    /// A descriptor could not be parsed or accepted by the wallet.
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
    /// A descriptor does not produce taproot outputs.
    #[error("The {0} descriptor must use taproot")]
    UnsupportedDescriptor(Keychain),
    /// A file already exists at the database path.
    #[error("A file already exists at this database path")]
    AlreadyExists,
    /// No file exists at the database path.
    #[error("No wallet exists at this database path")]
    NotFound,
    /// The file at the database path is not a complete P2Poolv2 wallet.
    #[error("The file at this database path is not a P2Poolv2 wallet")]
    NotAWallet,
    /// Another connection, in this or another process, holds the wallet open.
    #[error("The wallet is already open elsewhere")]
    InUse,
    /// Persisted wallet state is invalid or differs from the expected chain.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// SQLite could not read or write wallet state.
    #[error(transparent)]
    Storage(#[from] SqliteError),
    /// The database path could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Writing a new wallet failed and its database file could not be removed.
    #[error("{error}; the new database file could not be removed: {removal}")]
    PartialDatabase {
        /// The error that stopped the wallet from being written.
        error: Box<WalletError>,
        /// The error from removing the new database file.
        removal: io::Error,
    },
}

/// A share chain descriptor wallet and its SQLite connection.
///
/// `Wallet` wraps a bdk wallet. bdk is a bitcoin wallet and does the descriptor
/// work: deriving keys, tracking wallet state and saving it as `ChangeSet`s.
/// `Wallet` adds the P2Poolv2 rules bdk does not know about, and keeps bdk
/// types out of its callers. Its responsibilities are:
///
/// * Accept only networks that have a share chain address prefix.
/// * Accept only taproot descriptors, both when creating a wallet and when
///   opening a database another tool may have written.
/// * Pin the wallet to a network and share chain genesis hash, and refuse to
///   open it for any other chain.
/// * Own the database file: never overwrite an existing file, create it
///   owner-only, mark a complete wallet with the P2Poolv2 application id,
///   remove the file when a create fails, and never create a file on open.
/// * Refuse to open a file without the application id, before bdk can add its
///   tables to it.
/// * Hold an exclusive lock on the database while the wallet is open, so two
///   processes cannot hand out the same address.
/// * Keep the bdk wallet paired with the connection it was created or loaded
///   from, so staged changes are always saved to the same database.
///
/// The database stores public descriptors and wallet state, not signing keys.
/// Imported private descriptor keys remain in the newly created wallet's
/// memory.
pub struct Wallet {
    inner: PersistedWallet<Connection>,
    connection: Connection,
}

impl Wallet {
    /// Create a wallet in a new database file at `database_path`, failing if
    /// any file already exists there.
    ///
    /// A two-path descriptor supplies both keychains when `change_descriptor`
    /// is `None`. The parent directory must exist. If the wallet cannot be
    /// written, the new database file is removed.
    pub fn create(
        database_path: &Path,
        descriptor: &str,
        change_descriptor: Option<&str>,
        chain: ChainIdentity,
    ) -> Result<Self, WalletError> {
        //* Reject a network with no share chain prefix and a non-taproot receive descriptor.
        expected_hrp(chain.network)?;
        let secp256k1_context = Secp256k1::new();
        let external = parse_descriptor(
            &secp256k1_context,
            descriptor,
            chain.network,
            Keychain::Receive,
        )?;
        //* Pick the keychain layout and pin the network and share chain genesis.
        let create_parameters = match change_descriptor {
            Some(change_descriptor) => {
                let internal = parse_descriptor(
                    &secp256k1_context,
                    change_descriptor,
                    chain.network,
                    Keychain::Change,
                )?;
                BdkWallet::create(external, internal)
            }
            None if external.0.is_multipath() => {
                BdkWallet::create_from_two_path_descriptor(external)
            }
            None => BdkWallet::create_single(external),
        }
        .network(chain.network)
        .genesis_hash(chain.sharechain_genesis_hash);

        //* Write the wallet into a new database file, removing the file on failure.
        create_database_file(database_path)?;
        match write_new_wallet(database_path, create_parameters) {
            Ok((inner, connection)) => Ok(Self { inner, connection }),
            Err(error) => Err(remove_partial_database(database_path, error)),
        }
    }

    /// Open the wallet at `database_path`, failing unless it belongs to
    /// `expected_chain`.
    ///
    /// A missing file is reported as `NotFound`, never created. A file without
    /// the P2Poolv2 wallet application id is reported as `NotAWallet` and left
    /// unchanged. The wallet holds the database locked until it is dropped.
    pub fn open(database_path: &Path, expected_chain: ChainIdentity) -> Result<Self, WalletError> {
        //* Reject an unsupported network, and report a missing file as `NotFound`.
        expected_hrp(expected_chain.network)?;
        if !database_path.try_exists()? {
            return Err(WalletError::NotFound);
        }
        //* Refuse the file unless it is marked as a complete wallet, then lock it.
        let mut connection = open_database_file(database_path)?;
        if read_application_id(&connection)? != WALLET_APPLICATION_ID {
            return Err(WalletError::NotAWallet);
        }
        lock_database(&connection)?;
        //* Load the wallet, failing if its stored network or genesis hash differs.
        let inner = BdkWallet::load()
            .check_network(expected_chain.network)
            .check_genesis_hash(expected_chain.sharechain_genesis_hash)
            .load_wallet(&mut connection)
            .map_err(|error| match error {
                LoadWithPersistError::Persist(error) => WalletError::Storage(error),
                LoadWithPersistError::InvalidChangeSet(error) => WalletError::Load(error),
            })?
            .ok_or(WalletError::NotFound)?;
        //* Reject non-taproot keychains, which a database written by another tool can hold.
        inner
            .keychains()
            .try_for_each(|(keychain_kind, descriptor)| {
                require_taproot(descriptor, Keychain::from_keychain_kind(keychain_kind))
            })?;
        Ok(Self { inner, connection })
    }

    /// The network and share chain this wallet belongs to.
    pub fn chain(&self) -> ChainIdentity {
        ChainIdentity {
            network: self.inner.network(),
            sharechain_genesis_hash: self.inner.local_chain().genesis_hash(),
        }
    }

    /// The public descriptor for `keychain`, with its checksum.
    ///
    /// A single-descriptor wallet uses its receive descriptor for both keychains.
    pub fn public_descriptor(&self, keychain: Keychain) -> String {
        self.inner
            .public_descriptor(keychain.to_keychain_kind())
            .to_string()
    }

    /// Save staged changes, returning whether anything was written.
    ///
    /// A failed write keeps the changes staged, so a later call retries them.
    pub fn persist(&mut self) -> Result<bool, WalletError> {
        Ok(self.inner.persist(&mut self.connection)?)
    }
}

/// Create an empty database file at `database_path`, failing if any file
/// already exists there.
///
/// On unix the file is readable and writable by its owner only, because its
/// public descriptors reveal every wallet address. SQLite gives its journal
/// files the same permissions.
fn create_database_file(database_path: &Path) -> Result<(), WalletError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(DATABASE_FILE_MODE);
    match options.open(database_path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Err(WalletError::AlreadyExists),
        Err(error) => Err(WalletError::Io(error)),
    }
}

/// Open an existing database file for reading and writing, never creating
/// it, in exclusive locking mode.
///
/// In exclusive locking mode SQLite keeps every lock it takes until the
/// connection closes. Lock waits fail at once instead of retrying, so a
/// database held by another connection is reported as `InUse` without delay.
/// Nothing is read or written yet.
fn open_database_file(database_path: &Path) -> Result<Connection, WalletError> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.execute_batch("PRAGMA locking_mode = EXCLUSIVE;")?;
    Ok(connection)
}

/// Take an exclusive lock on the database, held until `connection` closes,
/// failing with `InUse` if another connection holds a lock on it.
///
/// An empty exclusive transaction acquires the lock. On an empty file it
/// writes the SQLite header, so `open` checks the application id first.
fn lock_database(connection: &Connection) -> Result<(), WalletError> {
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .map_err(classify_open_error)
}

/// Read the SQLite `application_id` of the database, failing with
/// `NotAWallet` if the file is not an SQLite database. This never writes.
fn read_application_id(connection: &Connection) -> Result<i32, WalletError> {
    connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(classify_open_error)
}

/// Map an SQLite error from opening a database to `InUse` when another
/// connection holds the lock, `NotAWallet` when the file is not an SQLite
/// database, or `Storage` otherwise.
fn classify_open_error(error: SqliteError) -> WalletError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy) => WalletError::InUse,
        Some(ErrorCode::NotADatabase) => WalletError::NotAWallet,
        _ => WalletError::Storage(error),
    }
}

/// Write a new wallet into the empty database file at `database_path`, then
/// mark the file with the P2Poolv2 wallet application id.
///
/// bdk commits its tables and the wallet in separate transactions, so the
/// application id is written last: a file without it never holds a complete
/// wallet, whether the write failed or the process stopped part way.
fn write_new_wallet(
    database_path: &Path,
    create_parameters: CreateParams,
) -> Result<(PersistedWallet<Connection>, Connection), WalletError> {
    let mut connection = open_database_file(database_path)?;
    lock_database(&connection)?;
    let inner = create_parameters
        .create_wallet(&mut connection)
        .map_err(|error| match error {
            CreateWithPersistError::DataAlreadyExists(_) => WalletError::AlreadyExists,
            CreateWithPersistError::Descriptor(error) => WalletError::Descriptor(error),
            CreateWithPersistError::Persist(error) => WalletError::Storage(error),
        })?;
    connection.pragma_update(None, "application_id", WALLET_APPLICATION_ID)?;
    Ok((inner, connection))
}

/// Remove the database file left by a failed create, returning `error`, or
/// `PartialDatabase` if the file cannot be removed.
fn remove_partial_database(database_path: &Path, error: WalletError) -> WalletError {
    match fs::remove_file(database_path) {
        Ok(()) => error,
        Err(removal) => WalletError::PartialDatabase {
            error: Box::new(error),
            removal,
        },
    }
}

/// Parse a descriptor for `network` with the caller's `secp256k1_context`,
/// rejecting one that is not taproot.
///
/// bdk requires a full signing and verification context here, so `create`
/// builds one and shares it across both of its descriptors.
fn parse_descriptor(
    secp256k1_context: &Secp256k1<All>,
    descriptor: &str,
    network: Network,
    keychain: Keychain,
) -> Result<(ExtendedDescriptor, KeyMap), WalletError> {
    let parsed = descriptor.into_wallet_descriptor(secp256k1_context, network.into())?;
    require_taproot(&parsed.0, keychain)?;
    Ok(parsed)
}

/// Fail with `UnsupportedDescriptor` for `keychain` unless `descriptor`
/// produces taproot outputs, the only kind a share chain address can hold.
fn require_taproot(descriptor: &ExtendedDescriptor, keychain: Keychain) -> Result<(), WalletError> {
    match descriptor {
        ExtendedDescriptor::Tr(_) => Ok(()),
        _ => Err(WalletError::UnsupportedDescriptor(keychain)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::LoadMismatch;
    use bitcoin::hashes::Hash;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    const CHANGE: &str = "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const SEGWIT: &str = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    const TWO_PATH: &str = "tr(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/<0;1>/*)";
    const RECEIVE_BRANCH: &str = "tr(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/0/*)";
    const CHANGE_BRANCH: &str = "tr(tpubD6NzVbkrYhZ4XHndKkuB8FifXm8r5FQHwrN6oZuWCz13qb93rtgKvD4PQsqC4HP4yhV3tA2fqr2RbY5mNXfM7RxXUoeABoDtsFUq2zJq6YK/1/*)";

    #[test]
    fn wallet_reopen_preserves_descriptors_and_rejects_identity_conflicts() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Opening a path with no file reports NotFound and does not create one.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotFound)
        ));
        assert!(!path.exists());
        //* Create a wallet with separate receive and change descriptors and keep its public descriptors.
        let wallet = Wallet::create(&path, RECEIVE, Some(CHANGE), chain).unwrap();
        let external = wallet.public_descriptor(Keychain::Receive);
        let internal = wallet.public_descriptor(Keychain::Change);
        assert_ne!(external, internal);
        drop(wallet);

        //* A second create at the same path is refused.
        assert!(matches!(
            Wallet::create(&path, CHANGE, None, chain),
            Err(WalletError::AlreadyExists)
        ));
        //* Opening for another share chain or another network is refused.
        let wrong_genesis = ChainIdentity {
            sharechain_genesis_hash: BlockHash::from_byte_array([43; 32]),
            ..chain
        };
        assert!(matches!(
            Wallet::open(&path, wrong_genesis),
            Err(WalletError::Load(LoadError::Mismatch(
                LoadMismatch::Genesis { .. }
            )))
        ));
        let wrong_network = ChainIdentity {
            network: Network::Regtest,
            ..chain
        };
        assert!(matches!(
            Wallet::open(&path, wrong_network),
            Err(WalletError::Load(LoadError::Mismatch(
                LoadMismatch::Network { .. }
            )))
        ));

        //* Reopening for the right chain restores the chain identity and both descriptors.
        let reopened = Wallet::open(&path, chain).unwrap();
        assert_eq!(reopened.chain(), chain);
        assert_eq!(reopened.public_descriptor(Keychain::Receive), external);
        assert_eq!(reopened.public_descriptor(Keychain::Change), internal);
    }

    #[test]
    fn wallet_create_writes_an_owner_only_file_marked_as_a_p2pool_wallet() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Create a wallet and close it so the file can be inspected directly.
        drop(Wallet::create(&path, RECEIVE, Some(CHANGE), chain).unwrap());

        //* The file header carries the P2PW application id.
        let connection = Connection::open(&path).unwrap();
        let application_id: i32 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(application_id, WALLET_APPLICATION_ID);
        //* On unix only the owner can read or write the file.
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            DATABASE_FILE_MODE
        );
    }

    #[test]
    fn wallet_create_refuses_existing_file_and_leaves_it_unchanged() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Put an unrelated file at the wallet path.
        fs::write(&path, b"not a wallet").unwrap();
        //* Create refuses the path, and the file keeps its original contents.
        assert!(matches!(
            Wallet::create(&path, RECEIVE, Some(CHANGE), chain),
            Err(WalletError::AlreadyExists)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"not a wallet");
    }

    #[test]
    fn wallet_enforces_p2pool_network_and_taproot_descriptors() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* A network with no share chain address prefix is refused.
        let unsupported = ChainIdentity {
            network: Network::Testnet,
            ..chain
        };
        assert!(matches!(
            Wallet::create(&path, RECEIVE, None, unsupported),
            Err(WalletError::Address(AddressError::UnsupportedNetwork(
                Network::Testnet
            )))
        ));
        //* A non-taproot receive or change descriptor is refused before any file is created.
        assert!(matches!(
            Wallet::create(&path, SEGWIT, None, chain),
            Err(WalletError::UnsupportedDescriptor(Keychain::Receive))
        ));
        assert!(matches!(
            Wallet::create(&path, RECEIVE, Some(SEGWIT), chain),
            Err(WalletError::UnsupportedDescriptor(Keychain::Change))
        ));
        assert!(!path.exists());
        //* Identical receive and change descriptors pass our parsing but bdk rejects them after the file exists; create removes the file.
        assert!(matches!(
            Wallet::create(&path, RECEIVE, Some(RECEIVE), chain),
            Err(WalletError::Descriptor(
                DescriptorError::ExternalAndInternalAreTheSame
            ))
        ));
        assert!(!path.exists());

        //* Write a marked segwit wallet with bdk directly, as another tool could, and check open refuses its descriptor.
        let mut connection = Connection::open(&path).unwrap();
        BdkWallet::create_single(SEGWIT)
            .network(chain.network)
            .genesis_hash(chain.sharechain_genesis_hash)
            .create_wallet(&mut connection)
            .unwrap();
        connection
            .pragma_update(None, "application_id", WALLET_APPLICATION_ID)
            .unwrap();
        drop(connection);
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::UnsupportedDescriptor(Keychain::Receive))
        ));
    }

    #[test]
    fn wallet_open_refuses_another_sqlite_database_without_adding_tables() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("other.sqlite");
        //* Create another application's SQLite database: one unrelated table and no P2PW application id.
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE notes (body TEXT NOT NULL);")
            .unwrap();
        drop(connection);

        //* Open refuses it because the application id is not P2PW.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotAWallet)
        ));
        //* The database still holds only its own table, so bdk added none of its tables before the refusal.
        let connection = Connection::open(&path).unwrap();
        let tables: Vec<String> = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(tables, vec!["notes".to_string()]);
    }

    #[test]
    fn wallet_open_refuses_a_bdk_wallet_without_the_application_id() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Write a complete bdk wallet without the P2PW application id, as a create that stopped before marking the file leaves it.
        let mut connection = Connection::open(&path).unwrap();
        BdkWallet::create(RECEIVE, CHANGE)
            .network(chain.network)
            .genesis_hash(chain.sharechain_genesis_hash)
            .create_wallet(&mut connection)
            .unwrap();
        drop(connection);

        //* Open refuses it even though bdk could load it.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotAWallet)
        ));
    }

    #[test]
    fn wallet_open_refuses_an_empty_file_and_leaves_it_empty() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Leave a zero-length file at the wallet path, as a create that stopped right after making the file does.
        fs::write(&path, b"").unwrap();

        //* Open refuses it, and taking no lock means SQLite wrote no header into it.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotAWallet)
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn wallet_open_refuses_a_file_that_is_not_sqlite_and_leaves_it_unchanged() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Put a file at the wallet path whose bytes are not an SQLite database.
        let contents = vec![7u8; 4096];
        fs::write(&path, &contents).unwrap();

        //* Open refuses it and leaves its bytes unchanged.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotAWallet)
        ));
        assert_eq!(fs::read(&path).unwrap(), contents);
    }

    #[test]
    fn wallet_open_refuses_a_wallet_held_open_by_another_wallet() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        //* Keep a newly created wallet open; it holds the exclusive lock.
        let created = Wallet::create(&path, RECEIVE, Some(CHANGE), chain).unwrap();

        //* A second open fails at once while the created wallet holds the lock.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::InUse)
        ));
        //* Closing the created wallet releases the lock, so open succeeds and now holds it.
        drop(created);
        let opened = Wallet::open(&path, chain).unwrap();
        //* A further open fails while the opened wallet holds the lock.
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::InUse)
        ));
        drop(opened);
    }

    #[test]
    fn wallet_create_splits_a_two_path_descriptor_into_receive_and_change() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let receive_branch = RECEIVE_BRANCH
            .parse::<ExtendedDescriptor>()
            .unwrap()
            .to_string();
        let change_branch = CHANGE_BRANCH
            .parse::<ExtendedDescriptor>()
            .unwrap()
            .to_string();

        //* Create from one `<0;1>` descriptor with no change descriptor.
        let wallet = Wallet::create(&path, TWO_PATH, None, chain).unwrap();
        //* Path 0 becomes the receive keychain and path 1 the change keychain.
        assert_eq!(wallet.public_descriptor(Keychain::Receive), receive_branch);
        assert_eq!(wallet.public_descriptor(Keychain::Change), change_branch);
        drop(wallet);

        //* Reopening restores both single-path keychains from the database.
        let reopened = Wallet::open(&path, chain).unwrap();
        assert_eq!(
            reopened.public_descriptor(Keychain::Receive),
            receive_branch
        );
        assert_eq!(reopened.public_descriptor(Keychain::Change), change_branch);
    }

    #[test]
    fn wallet_create_refuses_a_two_path_receive_descriptor_with_a_change_descriptor() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");

        //* A `<0;1>` receive descriptor already holds the change path, so bdk
        //* rejects an extra change descriptor after the file exists.
        assert!(matches!(
            Wallet::create(&path, TWO_PATH, Some(CHANGE_BRANCH), chain),
            Err(WalletError::Descriptor(DescriptorError::Miniscript(_)))
        ));
        //* Create removed the file it made.
        assert!(!path.exists());
    }

    #[test]
    fn wallet_create_refuses_a_two_path_change_descriptor() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");

        //* A change descriptor must be single-path, so bdk rejects a `<0;1>` one
        //* after the file exists.
        assert!(matches!(
            Wallet::create(&path, RECEIVE_BRANCH, Some(TWO_PATH), chain),
            Err(WalletError::Descriptor(DescriptorError::Miniscript(_)))
        ));
        //* Create removed the file it made.
        assert!(!path.exists());
    }
}
