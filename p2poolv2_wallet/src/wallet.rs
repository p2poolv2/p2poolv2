// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Persistent Taproot descriptor wallets for the sharechain.

use crate::{Address, AddressError, expected_hrp};
use bdk_wallet::descriptor::{DescriptorError, ExtendedDescriptor, IntoWalletDescriptor};
use bdk_wallet::miniscript::descriptor::KeyMap;
use bdk_wallet::rusqlite::{Connection, Error as SqliteError, OpenFlags};
use bdk_wallet::{
    AddressInfo as BdkAddressInfo, CreateWithPersistError, KeychainKind, LoadError,
    LoadWithPersistError, PersistedWallet, Wallet as BdkWallet,
};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{BlockHash, Network, ScriptBuf};
use std::fmt;
use std::io;
use std::ops::Deref;
use std::path::Path;

/// P2Pool network selection and sharechain identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainIdentity {
    /// Selects the corresponding P2Pool address prefix and descriptor key network.
    /// Each supported Bitcoin network selects one default P2Pool network.
    pub network: Network,
    /// Hash of the sharechain genesis block.
    pub sharechain_genesis_hash: BlockHash,
}

/// A derived P2Pool address, its child index and keychain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressInfo {
    /// Child index used to derive the address.
    pub index: u32,
    /// Taproot address encoded for the P2Pool network.
    pub address: Address,
    /// Keychain used to derive the address.
    pub keychain: KeychainKind,
}

impl AddressInfo {
    /// Encode a derived address for the selected P2Pool network.
    fn from_bdk(derived: BdkAddressInfo, network: Network) -> Result<Self, WalletError> {
        let program = derived
            .address
            .witness_program()
            .ok_or(WalletError::UnsupportedDescriptor(derived.keychain))?;
        let address = Address::from_witness_program(program, network)?;
        Ok(Self {
            index: derived.index,
            address,
            keychain: derived.keychain,
        })
    }
}

impl Deref for AddressInfo {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl fmt::Display for AddressInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.address.fmt(formatter)
    }
}

/// Errors from wallet creation, loading and persistence.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The network or witness program cannot form a P2Pool address.
    #[error(transparent)]
    Address(#[from] AddressError),
    /// A descriptor could not be parsed or accepted by the wallet.
    #[error(transparent)]
    Descriptor(#[from] DescriptorError),
    /// A descriptor does not produce Taproot outputs.
    #[error("The {0:?} descriptor must use Taproot")]
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
/// memory. Signing material must be supplied separately after reopening.
pub struct Wallet {
    inner: PersistedWallet<Connection>,
    connection: Connection,
}

impl Wallet {
    /// Create and persist a Taproot wallet without overwriting an existing wallet.
    ///
    /// Accepts a receiving descriptor and optional change descriptor. A two-path
    /// descriptor supplies both keychains when `change_descriptor` is absent.
    /// The parent directory must exist. The caller supplies the sharechain
    /// genesis hash; this operation does not connect to a backend.
    pub fn create(
        database_path: &Path,
        descriptor: &str,
        change_descriptor: Option<&str>,
        chain: ChainIdentity,
    ) -> Result<Self, WalletError> {
        expected_hrp(chain.network)?;
        let external = parse_descriptor(descriptor, chain.network, KeychainKind::External)?;
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

    /// Open a saved Taproot wallet and verify its network and genesis hash.
    ///
    /// A missing file is not created. Stored private keys are not loaded because
    /// signing material is not part of the persisted wallet state.
    pub fn open(database_path: &Path, expected_chain: ChainIdentity) -> Result<Self, WalletError> {
        expected_hrp(expected_chain.network)?;
        if !database_path.try_exists()? {
            return Err(WalletError::NotFound);
        }
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
        for (keychain, descriptor) in inner.keychains() {
            if !matches!(descriptor, ExtendedDescriptor::Tr(_)) {
                return Err(WalletError::UnsupportedDescriptor(keychain));
            }
        }
        Ok(Self { inner, connection })
    }

    /// Return the wallet's persisted chain identity.
    pub fn chain(&self) -> ChainIdentity {
        ChainIdentity {
            network: self.inner.network(),
            sharechain_genesis_hash: self.inner.local_chain().genesis_hash(),
        }
    }

    /// Return the public descriptor for a keychain.
    ///
    /// A single-descriptor wallet uses its external descriptor for both keychains.
    pub fn public_descriptor(&self, keychain: KeychainKind) -> &ExtendedDescriptor {
        self.inner.public_descriptor(keychain)
    }

    /// Derive a P2Pool address without revealing it or writing wallet state.
    ///
    /// A single-descriptor wallet maps the internal keychain to the external
    /// keychain. Descriptors without a wildcard return their address at index 0
    /// regardless of the requested index.
    ///
    /// # Panics
    ///
    /// Panics if a wildcard descriptor is requested at an index above 2^31 - 1.
    pub fn peek_address(
        &self,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<AddressInfo, WalletError> {
        AddressInfo::from_bdk(
            self.inner.peek_address(keychain, index),
            self.inner.network(),
        )
    }

    /// Reveal the next Taproot address and persist its index before returning it.
    ///
    /// A single-descriptor wallet maps the internal keychain to the external
    /// keychain. Descriptors without a wildcard return the same address on
    /// repeated calls. Exhausted keychains return their last address.
    ///
    /// A failed write returns an error and retains the staged derivation. A
    /// subsequent call can skip that index because no address was returned.
    pub fn reveal_next_address(
        &mut self,
        keychain: KeychainKind,
    ) -> Result<AddressInfo, WalletError> {
        let derived = self.inner.reveal_next_address(keychain);
        self.persist_address(derived)
    }

    /// Reveal addresses through `index` and persist before returning newly revealed addresses.
    ///
    /// Returns an empty collection when the requested range is already revealed.
    /// Fixed descriptors reveal only index 0. Unreachable targets reveal through
    /// the last possible index. A single-descriptor wallet maps the internal
    /// keychain to the external keychain.
    ///
    /// Failed writes retain staged changes. A retry persists them but returns
    /// only addresses newly revealed by that call.
    pub fn reveal_addresses_to(
        &mut self,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<Vec<AddressInfo>, WalletError> {
        let network = self.inner.network();
        let addresses = self
            .inner
            .reveal_addresses_to(keychain, index)
            .map(|derived| AddressInfo::from_bdk(derived, network))
            .collect::<Result<Vec<_>, _>>()?;
        self.persist()?;
        Ok(addresses)
    }

    /// Return the lowest-index unused address and persist any newly revealed index.
    ///
    /// Usage is based on transactions known to this wallet. This method does not
    /// sync with a backend or reserve the address. Repeated calls can return the
    /// same address until a transaction uses it. If all revealed addresses are
    /// used, the next address is revealed.
    ///
    /// Single-descriptor wallets map the internal keychain to the external one.
    /// Fixed descriptors and exhausted keychains return their last address even
    /// if it has been used. Failed writes retain staged changes for a later retry.
    pub fn next_unused_address(
        &mut self,
        keychain: KeychainKind,
    ) -> Result<AddressInfo, WalletError> {
        let derived = self.inner.next_unused_address(keychain);
        self.persist_address(derived)
    }

    /// Iterate over revealed addresses with no known usage or temporary reservation.
    ///
    /// This does not reveal addresses, sync with a backend or write wallet state.
    pub fn list_unused_addresses(
        &self,
        keychain: KeychainKind,
    ) -> impl DoubleEndedIterator<Item = Result<AddressInfo, WalletError>> + '_ {
        self.inner
            .list_unused_addresses(keychain)
            .map(|derived| AddressInfo::from_bdk(derived, self.inner.network()))
    }

    /// Return whether a script is in the wallet's index, including lookahead scripts.
    pub fn is_mine(&self, script: ScriptBuf) -> bool {
        self.inner.is_mine(script)
    }

    /// Return the keychain and child index of an indexed script, including lookahead.
    pub fn derivation_of_spk(&self, script: ScriptBuf) -> Option<(KeychainKind, u32)> {
        self.inner.derivation_of_spk(script)
    }

    /// Return the highest revealed index, or None for an unrevealed or absent keychain.
    pub fn derivation_index(&self, keychain: KeychainKind) -> Option<u32> {
        self.inner.derivation_index(keychain)
    }

    /// Return the index that the next reveal would use without changing wallet state.
    ///
    /// Fixed descriptors return 0. Exhausted keychains return their last index.
    /// A single-descriptor wallet maps the internal keychain to the external one.
    pub fn next_derivation_index(&self, keychain: KeychainKind) -> u32 {
        self.inner.next_derivation_index(keychain)
    }

    /// Temporarily reserve an indexed address on the specified keychain.
    ///
    /// Returns true if the address was removed from the unused set. Returns false
    /// if the keychain or index is absent, or the address is already used.
    /// Reservations are memory-only and are not saved by `persist`.
    pub fn mark_used(&mut self, keychain: KeychainKind, index: u32) -> bool {
        self.inner.mark_used(keychain, index)
    }

    /// Release a temporary reservation, returning whether the address became unused.
    ///
    /// An address with an indexed transaction output cannot be made unused.
    /// This changes only the in-memory reservation state.
    pub fn unmark_used(&mut self, keychain: KeychainKind, index: u32) -> bool {
        self.inner.unmark_used(keychain, index)
    }

    /// Encode a derived address for P2Pool and persist wallet state before returning it.
    fn persist_address(&mut self, derived: BdkAddressInfo) -> Result<AddressInfo, WalletError> {
        let address = AddressInfo::from_bdk(derived, self.inner.network())?;
        self.persist()?;
        Ok(address)
    }

    /// Persist staged wallet changes, returning whether anything was written.
    ///
    /// Failed writes retain staged changes for a later retry.
    pub fn persist(&mut self) -> Result<bool, WalletError> {
        Ok(self.inner.persist(&mut self.connection)?)
    }
}

/// Parse and validate a Taproot descriptor for the selected key network.
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
    use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid, absolute, transaction};
    use tempfile::tempdir;

    const RECEIVE: &str = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    const CHANGE: &str = "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    const SEGWIT: &str = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    const TEST_PUBLIC_KEY: &str = "tpubD6NzVbkrYhZ4Y55A58Gv9RSNF5hy84b5AJqYy7sCcjFrkcLpPre8kmgfit6kY1Zs3BLgeypTDBZJM222guPpdz7Cup5yzaMu62u7mYGbwFL";

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

    #[test]
    fn address_derivation_preserves_taproot_scripts_and_saved_indices() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let descriptor = format!(
            "tr({TEST_PUBLIC_KEY}/<0;1>/*,pk(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))"
        );
        let mut wallet = Wallet::create(&path, &descriptor, None, chain).unwrap();
        let peeked = wallet.peek_address(KeychainKind::External, 2).unwrap();
        assert_eq!(
            peeked.script_pubkey(),
            wallet
                .inner
                .peek_address(KeychainKind::External, 2)
                .script_pubkey()
        );
        assert!(peeked.to_string().starts_with("sp2pool1p"));
        assert!(wallet.is_mine(peeked.script_pubkey()));
        assert_eq!(
            wallet.derivation_of_spk(peeked.script_pubkey()),
            Some((KeychainKind::External, 2))
        );
        assert!(!wallet.is_mine(ScriptBuf::new()));
        assert_eq!(wallet.derivation_index(KeychainKind::External), None);
        assert!(!wallet.persist().unwrap());

        let first = wallet.reveal_next_address(KeychainKind::External).unwrap();
        assert_eq!(first.index, 0);
        let remaining = wallet
            .reveal_addresses_to(KeychainKind::External, 2)
            .unwrap();
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].index, 1);
        assert_eq!(remaining[1], peeked);
        let change = wallet.reveal_next_address(KeychainKind::Internal).unwrap();
        assert_eq!(change.keychain, KeychainKind::Internal);
        assert_eq!(change.index, 0);
        assert_ne!(change.address, first.address);
        drop(wallet);

        let mut reopened = Wallet::open(&path, chain).unwrap();
        assert_eq!(
            reopened.peek_address(KeychainKind::External, 2).unwrap(),
            peeked
        );
        assert_eq!(reopened.derivation_index(KeychainKind::External), Some(2));
        assert_eq!(reopened.next_derivation_index(KeychainKind::External), 3);
        assert_eq!(reopened.next_derivation_index(KeychainKind::Internal), 1);
        assert!(
            reopened
                .reveal_addresses_to(KeychainKind::External, 2)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reopened
                .next_unused_address(KeychainKind::External)
                .unwrap(),
            first
        );
        assert_eq!(
            reopened
                .list_unused_addresses(KeychainKind::Internal)
                .next()
                .unwrap()
                .unwrap(),
            change
        );
    }

    #[test]
    fn address_usage_persists_transactions_but_not_reservations() {
        let chain = ChainIdentity {
            network: Network::Regtest,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let descriptor = format!("tr({TEST_PUBLIC_KEY}/0/*)");
        let mut wallet = Wallet::create(&path, &descriptor, None, chain).unwrap();
        let addresses = wallet
            .reveal_addresses_to(KeychainKind::External, 2)
            .unwrap();
        assert!(wallet.mark_used(KeychainKind::External, 1));
        assert_eq!(
            wallet
                .list_unused_addresses(KeychainKind::External)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![addresses[0].clone(), addresses[2].clone()]
        );
        assert!(wallet.unmark_used(KeychainKind::External, 1));
        assert!(wallet.mark_used(KeychainKind::External, 1));
        let payment = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([43; 32]),
                    vout: 0,
                },
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000_000),
                script_pubkey: addresses[0].script_pubkey(),
            }],
        };
        wallet.inner.apply_unconfirmed_txs([(payment, 1)]);
        assert!(!wallet.unmark_used(KeychainKind::External, 0));
        assert_eq!(
            wallet.next_unused_address(KeychainKind::External).unwrap(),
            addresses[2]
        );
        drop(wallet);

        let mut reopened = Wallet::open(&path, chain).unwrap();
        assert!(!reopened.unmark_used(KeychainKind::External, 0));
        assert_eq!(
            reopened
                .next_unused_address(KeychainKind::External)
                .unwrap(),
            addresses[1]
        );
        assert_eq!(
            reopened
                .list_unused_addresses(KeychainKind::External)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            addresses[1..]
        );
    }

    #[test]
    fn failed_address_write_retains_changes_for_retry() {
        let chain = ChainIdentity {
            network: Network::Signet,
            sharechain_genesis_hash: BlockHash::from_byte_array([42; 32]),
        };
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.sqlite");
        let descriptor = format!("tr({TEST_PUBLIC_KEY}/0/*)");
        let mut wallet = Wallet::create(&path, &descriptor, None, chain).unwrap();
        wallet
            .connection
            .pragma_update(None, "query_only", true)
            .unwrap();
        assert!(matches!(
            wallet.reveal_addresses_to(KeychainKind::External, 2),
            Err(WalletError::Storage(_))
        ));
        assert!(matches!(
            wallet.next_unused_address(KeychainKind::External),
            Err(WalletError::Storage(_))
        ));
        assert_eq!(
            wallet
                .peek_address(KeychainKind::External, 2)
                .unwrap()
                .index,
            2
        );
        let saved = Wallet::open(&path, chain).unwrap();
        assert_eq!(saved.derivation_index(KeychainKind::External), None);
        drop(saved);

        wallet
            .connection
            .pragma_update(None, "query_only", false)
            .unwrap();
        assert!(
            wallet
                .reveal_addresses_to(KeychainKind::External, 2)
                .unwrap()
                .is_empty()
        );
        drop(wallet);
        let reopened = Wallet::open(&path, chain).unwrap();
        assert_eq!(reopened.derivation_index(KeychainKind::External), Some(2));
        assert_eq!(reopened.next_derivation_index(KeychainKind::External), 3);
    }
}
