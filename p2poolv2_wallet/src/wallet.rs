// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Taproot descriptor wallets saved in SQLite.

use crate::{AddressError, expected_hrp};
use bdk_wallet::descriptor::{DescriptorError, ExtendedDescriptor, IntoWalletDescriptor};
use bdk_wallet::miniscript::descriptor::KeyMap;
use bdk_wallet::rusqlite::{Connection, Error as SqliteError, OpenFlags};
use bdk_wallet::{
    CreateWithPersistError, KeychainKind, LoadError, LoadWithPersistError, PersistedWallet,
    Wallet as BdkWallet,
};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, Network};
use std::io;
use std::path::Path;

/// The network and share chain a wallet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIdentity {
    /// Network of the wallet's addresses and descriptor keys.
    pub network: Network,
    /// Hash of the share chain genesis block.
    pub sharechain_genesis_hash: BlockHash,
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
    #[error("The {0:?} descriptor must use taproot")]
    UnsupportedDescriptor(KeychainKind),
    /// The database already contains a wallet.
    #[error("A wallet already exists in this database")]
    AlreadyExists,
    /// The database file or its wallet state does not exist.
    #[error("No wallet exists at this database path")]
    NotFound,
    /// Persisted wallet state is invalid or differs from the expected chain.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// SQLite could not read or write wallet state.
    #[error(transparent)]
    Storage(#[from] SqliteError),
    /// The database path could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A descriptor wallet and its SQLite connection.
///
/// The database stores public descriptors and wallet state, not signing keys.
/// Imported private descriptor keys remain in the newly created wallet's
/// memory.
pub struct Wallet {
    inner: PersistedWallet<Connection>,
    connection: Connection,
}

impl Wallet {
    /// Create a wallet at `database_path`, failing if one already exists there.
    ///
    /// A two-path descriptor supplies both keychains when `change_descriptor`
    /// is `None`. The parent directory must exist.
    pub fn create(
        database_path: &Path,
        descriptor: &str,
        change_descriptor: Option<&str>,
        chain: ChainIdentity,
    ) -> Result<Self, WalletError> {
        //* Reject a network with no share chain prefix and a non-taproot receive descriptor.
        expected_hrp(chain.network)?;
        let external = parse_descriptor(descriptor, chain.network, KeychainKind::External)?;
        //* Pick the keychain layout and pin the network and share chain genesis.
        let params = match change_descriptor {
            Some(change_descriptor) => {
                let internal =
                    parse_descriptor(change_descriptor, chain.network, KeychainKind::Internal)?;
                BdkWallet::create(external, internal)
            }
            None if external.0.is_multipath() => {
                BdkWallet::create_from_two_path_descriptor(external)
            }
            None => BdkWallet::create_single(external),
        }
        .network(chain.network)
        .genesis_hash(chain.sharechain_genesis_hash);

        //* Write the wallet to SQLite, refusing a database that already holds one.
        let mut connection = Connection::open(database_path)?;
        let inner = params
            .create_wallet(&mut connection)
            .map_err(|error| match error {
                CreateWithPersistError::DataAlreadyExists(_) => WalletError::AlreadyExists,
                CreateWithPersistError::Descriptor(error) => WalletError::Descriptor(error),
                CreateWithPersistError::Persist(error) => WalletError::Storage(error),
            })?;
        Ok(Self { inner, connection })
    }

    /// Open the wallet at `database_path`, failing unless it belongs to
    /// `expected_chain`.
    ///
    /// A missing file is reported as `NotFound`, never created.
    pub fn open(database_path: &Path, expected_chain: ChainIdentity) -> Result<Self, WalletError> {
        //* Reject an unsupported network, and report a missing file as `NotFound`.
        expected_hrp(expected_chain.network)?;
        if !database_path.try_exists()? {
            return Err(WalletError::NotFound);
        }
        //* Load the wallet, failing if its stored network or genesis hash differs.
        let mut connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
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
        for (keychain, descriptor) in inner.keychains() {
            if !matches!(descriptor, ExtendedDescriptor::Tr(_)) {
                return Err(WalletError::UnsupportedDescriptor(keychain));
            }
        }
        Ok(Self { inner, connection })
    }

    /// The network and share chain this wallet belongs to.
    pub fn chain(&self) -> ChainIdentity {
        ChainIdentity {
            network: self.inner.network(),
            sharechain_genesis_hash: self.inner.local_chain().genesis_hash(),
        }
    }

    /// The public descriptor for `keychain`.
    ///
    /// A single-descriptor wallet uses its external descriptor for both keychains.
    pub fn public_descriptor(&self, keychain: KeychainKind) -> &ExtendedDescriptor {
        self.inner.public_descriptor(keychain)
    }

    /// Save staged changes, returning whether anything was written.
    ///
    /// A failed write keeps the changes staged, so a later call retries them.
    pub fn persist(&mut self) -> Result<bool, WalletError> {
        Ok(self.inner.persist(&mut self.connection)?)
    }
}

/// Parse a descriptor for `network`, rejecting one that is not taproot.
fn parse_descriptor(
    descriptor: &str,
    network: Network,
    keychain: KeychainKind,
) -> Result<(ExtendedDescriptor, KeyMap), WalletError> {
    let parsed = descriptor.into_wallet_descriptor(&Secp256k1::new(), network.into())?;
    if !matches!(parsed.0, ExtendedDescriptor::Tr(_)) {
        return Err(WalletError::UnsupportedDescriptor(keychain));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::LoadMismatch;
    use bitcoin::hashes::Hash;
    use tempfile::tempdir;

    const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    const CHANGE: &str = "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const SEGWIT: &str = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";

    #[test]
    fn wallet_reopen_preserves_descriptors_and_rejects_identity_conflicts() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::NotFound)
        ));
        assert!(!path.exists());
        let wallet = Wallet::create(&path, RECEIVE, Some(CHANGE), chain).unwrap();
        let external = wallet.public_descriptor(KeychainKind::External).clone();
        let internal = wallet.public_descriptor(KeychainKind::Internal).clone();
        assert_ne!(external, internal);
        drop(wallet);

        assert!(matches!(
            Wallet::create(&path, CHANGE, None, chain),
            Err(WalletError::AlreadyExists)
        ));
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

        let reopened = Wallet::open(&path, chain).unwrap();
        assert_eq!(reopened.chain(), chain);
        assert_eq!(
            reopened.public_descriptor(KeychainKind::External),
            &external
        );
        assert_eq!(
            reopened.public_descriptor(KeychainKind::Internal),
            &internal
        );
    }

    #[test]
    fn wallet_enforces_p2pool_network_and_taproot_descriptors() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
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
        assert!(matches!(
            Wallet::create(&path, SEGWIT, None, chain),
            Err(WalletError::UnsupportedDescriptor(KeychainKind::External))
        ));
        assert!(matches!(
            Wallet::create(&path, RECEIVE, Some(SEGWIT), chain),
            Err(WalletError::UnsupportedDescriptor(KeychainKind::Internal))
        ));
        assert!(!path.exists());

        let mut connection = Connection::open(&path).unwrap();
        BdkWallet::create_single(SEGWIT)
            .network(chain.network)
            .genesis_hash(chain.sharechain_genesis_hash)
            .create_wallet(&mut connection)
            .unwrap();
        drop(connection);
        assert!(matches!(
            Wallet::open(&path, chain),
            Err(WalletError::UnsupportedDescriptor(KeychainKind::External))
        ));
    }
}
