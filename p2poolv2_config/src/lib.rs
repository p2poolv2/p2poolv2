// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

mod cashaddr;

use bitcoin::address::NetworkChecked;
use bitcoin::base58;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Address, Network, PubkeyHash};
use bitcoindrpc::BitcoinRpcConfig;
use p2poolv2_wallet::Address as ShareAddress;
use p2poolv2_wallet::bch_share::{self, BchShareAddress, BchShareNetwork};
use serde::Deserialize;
use std::marker::PhantomData;
use std::str::FromStr;

/// Default version mask for BIP 323 version rolling.
pub const DEFAULT_VERSION_MASK: i32 = 0x1fffe000;

/// One hundred percent, in basis points.
pub const MAX_BASIS_POINTS: u16 = 10_000;

/// P2Poolv2 Bitcoin Cash donation address, as shown on mainnet.
///
/// A Bitcoin Cash node pays its donation here. The address is fixed: the
/// share chain rejects a Bitcoin Cash share whose donation output pays any
/// other script, so an operator who wants a cut of their own uses
/// `fee_address` and `fee` instead.
pub const BITCOIN_CASH_DONATION_ADDRESS: &str =
    "bitcoincash:qze95tc2dqrnltvxfa5yhunwx5952f34fvw4g6365k";

/// The 20-byte public key hash [`BITCOIN_CASH_DONATION_ADDRESS`] encodes.
///
/// The same key is paid on chipnet (`bchtest:`) and regtest (`bchreg:`), so
/// the donation path is exercised on test networks too.
pub const BITCOIN_CASH_DONATION_PUBKEY_HASH: [u8; 20] = [
    0xb2, 0x5a, 0x2f, 0x0a, 0x68, 0x07, 0x3f, 0xad, 0x86, 0x4f, 0x68, 0x4b, 0xf2, 0x6e, 0x35, 0x0b,
    0x45, 0x26, 0x35, 0x4b,
];

/// Donation a Bitcoin Cash node makes when `donation` is not configured:
/// 1.5%. An operator may raise it, lower it, or set 0 to opt out.
pub const DEFAULT_BITCOIN_CASH_DONATION: u16 = 150;

/// Most a Bitcoin Cash share may take before the PPLNS split: donation plus
/// fee, 10%.
///
/// The share chain enforces this on every Bitcoin Cash share. Without it a
/// node could set a 100% fee to itself and keep the whole reward of every
/// block it finds, while its shares still earn a slice of everyone else's.
pub const MAX_BITCOIN_CASH_POOL_CUT: u16 = 1_000;

/// [`BITCOIN_CASH_DONATION_ADDRESS`] under a network's CashAddr prefix, for
/// logs and documentation. Each string decodes to
/// [`bitcoin_cash_donation_address`] for that network.
pub fn bitcoin_cash_donation_cashaddr(network: BitcoinCashNetwork) -> &'static str {
    match network {
        BitcoinCashNetwork::Mainnet => BITCOIN_CASH_DONATION_ADDRESS,
        BitcoinCashNetwork::Chipnet => "bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2",
        BitcoinCashNetwork::Regtest => "bchreg:qze95tc2dqrnltvxfa5yhunwx5952f34fvsm6us7sv",
    }
}

/// Donation output for a Bitcoin Cash network: P2PKH to
/// [`BITCOIN_CASH_DONATION_PUBKEY_HASH`].
pub fn bitcoin_cash_donation_address(network: BitcoinCashNetwork) -> Address {
    Address::p2pkh(
        PubkeyHash::from_byte_array(BITCOIN_CASH_DONATION_PUBKEY_HASH),
        network.legacy_network(),
    )
}

/// Error type for configuration parsing and validation.
#[derive(Debug, Clone)]
pub struct ConfigError {
    pub message: String,
}

impl std::error::Error for ConfigError {}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

/// Parse a payout address for the chain this node is configured to mine.
///
/// Bitcoin keeps the existing address parser. Bitcoin Cash accepts only a
/// CashAddr whose prefix matches `bitcoin_cash_network`, and returns the
/// legacy script those bytes encode.
pub fn parse_payout_address(
    address: &str,
    chain: Chain,
    network: Network,
    bitcoin_cash_network: Option<BitcoinCashNetwork>,
) -> Result<Address, ConfigError> {
    match chain {
        Chain::Bitcoin => parse_address(address, network),
        Chain::BitcoinCash => {
            let bitcoin_cash_network = bitcoin_cash_network.ok_or_else(|| ConfigError {
                message: "bitcoin_cash_network is required when chain is bitcoin-cash".to_string(),
            })?;
            cashaddr::decode(address, bitcoin_cash_network)
                .map(|decoded| decoded.to_address())
                .map_err(|error| ConfigError {
                    message: format!("Invalid Bitcoin Cash payout address: {error}"),
                })
        }
    }
}

/// Parse and validate a bitcoin address string for a given network.
pub fn parse_address(address: &str, network: Network) -> Result<Address, ConfigError> {
    let parsed_address = Address::from_str(address).map_err(|error| ConfigError {
        message: format!("Invalid address: {error}"),
    })?;

    parsed_address
        .require_network(network)
        .map_err(|_| ConfigError {
            message: format!("Address does not match network: {network}"),
        })
}

/// Parse and validate a share chain address string for a given network.
///
/// Kept separate from [`parse_address`] because the two live on different
/// chains: this one owns share coinbase outputs, that one receives bitcoin.
pub fn parse_share_address(address: &str, network: Network) -> Result<ShareAddress, ConfigError> {
    ShareAddress::from_str(address)
        .map_err(|error| ConfigError {
            message: format!("Invalid share chain address: {error}"),
        })?
        .require_network(network)
        .map_err(|error| ConfigError {
            message: format!("Invalid share chain address: {error}"),
        })
}

/// Max length for pool signature P2Poolv2 + 8 more bytes for users to add
const MAX_POOL_SIGNATURE_LENGTH: usize = 16;

/// Pool operating mode.
///
/// P2Poolv2 mode runs the full share chain with ASERT difficulty and
/// P2P networking.  Hydrapool mode runs a standalone PPLNS pool where
/// the share chain ASERT difficulty is not enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PoolMode {
    /// Full P2Poolv2 share chain mode (default)
    #[serde(alias = "P2Poolv2", alias = "p2poolv2")]
    #[default]
    P2poolv2,
    /// Standalone PPLNS pool mode
    #[serde(alias = "Hydrapool", alias = "hydrapool")]
    Hydrapool,
}

/// Block chain that supplies work templates and coinbase payout scripts.
///
/// Existing configurations omit this field and stay on Bitcoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Chain {
    /// Bitcoin. Template requests include SegWit, and Signet when selected.
    #[default]
    Bitcoin,
    /// Bitcoin Cash. Template requests omit Bitcoin-only rules and are
    /// validated before a job is built. Payout addresses are CashAddr.
    BitcoinCash,
}

/// Bitcoin Cash network selected by the operator.
///
/// Chipnet uses the `bchtest` CashAddr prefix. BCHN uses that same prefix for
/// its other test networks, so the prefix does not distinguish chipnet from
/// testnet3 or testnet4. The RPC URL has to point at the network named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinCashNetwork {
    /// Bitcoin Cash mainnet. CashAddr prefix `bitcoincash`.
    #[serde(alias = "main")]
    Mainnet,
    /// Bitcoin Cash chipnet. CashAddr prefix `bchtest`.
    Chipnet,
    /// Bitcoin Cash regtest. CashAddr prefix `bchreg`.
    Regtest,
}

/// Which Bitcoin Cash share chain this node extends.
///
/// Main and mini are different genesis shares, so they do not reorg into
/// each other. Mini's anchor target is 256 times easier than the main
/// ceiling, which is the existing `MAX_POOL_TARGET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BchShareChain {
    /// Share target ceiling `0x1b384bd7`, anchor `0x1b4188f5`.
    #[default]
    Main,
    /// Share target ceiling and anchor `0x1c384bd7` (256 times easier).
    Mini,
}

impl BitcoinCashNetwork {
    /// Human-readable prefix covered by the CashAddr checksum.
    pub fn cashaddr_prefix(self) -> &'static str {
        match self {
            BitcoinCashNetwork::Mainnet => "bitcoincash",
            BitcoinCashNetwork::Chipnet => "bchtest",
            BitcoinCashNetwork::Regtest => "bchreg",
        }
    }

    /// Share address network (`p2pool`, `tp2pool`, `rp2pool`) for this
    /// Bitcoin Cash network.
    pub fn share_network(self) -> BchShareNetwork {
        match self {
            BitcoinCashNetwork::Mainnet => BchShareNetwork::Mainnet,
            BitcoinCashNetwork::Chipnet => BchShareNetwork::Chipnet,
            BitcoinCashNetwork::Regtest => BchShareNetwork::Regtest,
        }
    }

    /// The Bitcoin Cash network a share address network belongs to.
    ///
    /// Share addresses (`p2pool`, `tp2pool`, `rp2pool`) and payout addresses
    /// (`bitcoincash`, `bchtest`, `bchreg`) name the same three networks.
    pub fn from_share_network(share_network: BchShareNetwork) -> Self {
        match share_network {
            BchShareNetwork::Mainnet => BitcoinCashNetwork::Mainnet,
            BchShareNetwork::Chipnet => BitcoinCashNetwork::Chipnet,
            BchShareNetwork::Regtest => BitcoinCashNetwork::Regtest,
        }
    }

    /// Bitcoin network whose base58 version bytes and proof-of-work limit
    /// match this Bitcoin Cash network: mainnet `0x1d00ffff`, chipnet
    /// `0x1d00ffff` (as testnet), regtest `0x207fffff`. It lets
    /// `bitcoin::Address` carry a decoded CashAddr script, and it is the
    /// `stratum.network` a Bitcoin Cash node uses for difficulty and its P2P
    /// protocol id.
    pub fn legacy_network(self) -> Network {
        match self {
            BitcoinCashNetwork::Mainnet => Network::Bitcoin,
            BitcoinCashNetwork::Chipnet => Network::Testnet,
            BitcoinCashNetwork::Regtest => Network::Regtest,
        }
    }
}

/// Marker type for raw (unparsed) StratumConfig state
#[derive(Debug, Clone, Default)]
pub struct Raw;

/// Marker type for parsed (validated) StratumConfig state
#[derive(Debug, Clone)]
pub struct Parsed;

#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = "State: Default"))]
pub struct StratumConfig<State = Raw> {
    /// The hostname for the Stratum server
    pub hostname: String,
    /// The port for the Stratum server
    pub port: u16,
    /// The start difficulty for all miners that connect to the server
    pub start_difficulty: u64,
    /// The minimum difficulty for the pool
    pub minimum_difficulty: u64,
    /// The maximum difficulty for the pool, if set to None, it is not enforced
    pub maximum_difficulty: Option<u64>,
    /// The address for solo mining payouts
    pub solo_address: Option<String>,
    /// The ZMQ publisher address for block hashes
    pub zmqpubhashblock: String,
    /// The bitcoin address to use for first jobs when there are no shares (string in Raw state)
    pub bootstrap_address: String,
    /// The donation address for developers (string in Raw state).
    ///
    /// On Bitcoin it is required whenever `donation` is set. On Bitcoin Cash
    /// it may be omitted; if given it must be [`BITCOIN_CASH_DONATION_ADDRESS`]
    /// under the prefix for `bitcoin_cash_network`.
    pub donation_address: Option<String>,
    /// The donation basis points.
    ///
    /// In the Raw state this is what the operator wrote. After parsing it is
    /// the donation actually paid: on Bitcoin Cash an unset value becomes
    /// [`DEFAULT_BITCOIN_CASH_DONATION`], and 0 becomes `None` (no donation).
    pub donation: Option<u16>,
    /// The fee address (string in Raw state). A pool operator's own cut.
    pub fee_address: Option<String>,
    /// The fee basis points, taken after the donation.
    pub fee: Option<u16>,
    /// Share chain address owning every share this pool mines (string in Raw
    /// state). When set, miners need not send `p2p=` in the stratum password,
    /// and one that disagrees with this address is rejected at authorize.
    /// P2Poolv2 mode only; Hydrapool builds no share commitment.
    pub miner_address: Option<String>,
    /// The network can be "main", "testnet4" or "signet".
    /// On Bitcoin this is also the share-address prefix. On Bitcoin Cash it is
    /// ignored: [`Config::load`] and [`StratumConfig::parse`] replace it with
    /// [`StratumConfig::effective_network`], derived from
    /// `bitcoin_cash_network`.
    #[serde(deserialize_with = "deserialize_network")]
    pub network: bitcoin::Network,
    /// Block chain that supplies work templates and payout scripts.
    /// Defaults to Bitcoin so existing configurations keep their behavior.
    #[serde(default)]
    pub chain: Chain,
    /// Required when `chain` is `bitcoin-cash`. Accepted values are
    /// `mainnet` (alias `main`), `chipnet`, and `regtest`.
    #[serde(default)]
    pub bitcoin_cash_network: Option<BitcoinCashNetwork>,
    /// Main or mini Bitcoin Cash share chain. Ignored unless `chain` is
    /// `bitcoin-cash`. `mini` on a Bitcoin node is rejected.
    #[serde(default)]
    pub bch_share_chain: BchShareChain,
    /// Stratum V2 listen port. Absent means the node does not open an SV2
    /// socket, which is what every existing configuration does.
    #[serde(default)]
    pub sv2_port: Option<u16>,
    /// Stratum V2 authority public key, in the Stratum V2 reference
    /// implementation's text form (Base58Check of version `[1, 0]` and the
    /// 32-byte x-only key). With `sv2_authority_secret_key`, every SV2
    /// connection must complete the Noise NX handshake before any message.
    /// The keys come from an external tool; this node never generates one.
    #[serde(default)]
    pub sv2_authority_public_key: Option<String>,
    /// Stratum V2 authority secret key (Base58Check of the 32 bytes). Prefer
    /// `P2POOL__STRATUM__SV2_AUTHORITY_SECRET_KEY` over the file.
    #[serde(default)]
    pub sv2_authority_secret_key: Option<String>,
    /// Seconds a Noise certificate signed by the authority key stays valid.
    /// Defaults to [`DEFAULT_SV2_CERT_VALIDITY_SECS`].
    #[serde(default)]
    pub sv2_cert_validity_secs: Option<u64>,
    /// Where block templates come from. `rpc`, the default and what every
    /// existing configuration uses, asks the node in `[bitcoinrpc]`. `sv2`
    /// takes them from a Stratum V2 Template Provider at
    /// `template_provider_address` and sends found blocks back to it.
    #[serde(default)]
    pub template_source: TemplateSource,
    /// `HOST:PORT` of the Stratum V2 Template Provider. Needs
    /// `template_source = "sv2"`.
    #[serde(default)]
    pub template_provider_address: Option<String>,
    /// The Template Provider's authority public key, in the text form of
    /// `sv2_authority_public_key`. With it the connection runs the Noise NX
    /// handshake and accepts only a certificate this key signed. Required
    /// unless the provider listens on this computer (a loopback address).
    #[serde(default)]
    pub template_provider_authority_public_key: Option<String>,
    /// The version mask to use for version-rolling
    #[serde(deserialize_with = "deserialize_version_mask")]
    pub version_mask: i32,
    /// Test config to ignore difficulty
    pub ignore_difficulty: Option<bool>,
    /// Optional pool signature to include in coinbase
    pub pool_signature: Option<String>,
    /// Maximum concurrent stratum connections. Default: 90% of OS fd limit.
    pub max_connections: Option<u32>,
    /// Wait for the share chain to be current before accepting stratum
    /// connections. Set to false when bootstrapping a new network.
    #[serde(default = "default_wait_for_chain_sync")]
    pub wait_for_chain_sync: bool,
    /// Pool operating mode. Defaults to P2Poolv2 when not specified.
    #[serde(default)]
    pub mode: PoolMode,

    // Parsed addresses - only available when State = Parsed
    #[serde(skip)]
    pub bootstrap_address_parsed: Option<Address<NetworkChecked>>,
    #[serde(skip)]
    pub donation_address_parsed: Option<Address<NetworkChecked>>,
    #[serde(skip)]
    pub fee_address_parsed: Option<Address<NetworkChecked>>,
    #[serde(skip)]
    pub miner_address_parsed: Option<ShareAddress>,
    /// Bitcoin Cash share owner, set only when `chain` is bitcoin-cash.
    #[serde(skip)]
    pub bch_miner_address: Option<BchShareAddress>,
    /// Decoded Stratum V2 authority keys, when both are configured.
    #[serde(skip)]
    pub sv2_authority: Option<Sv2Authority>,
    /// The checked Template Provider, set when `template_source` is `sv2`.
    #[serde(skip)]
    pub template_provider: Option<TemplateProvider>,

    #[serde(skip)]
    #[serde(default)]
    _state: PhantomData<State>,
}

impl<State> StratumConfig<State> {
    /// The network difficulty, P2P protocol id, and payout parsing use.
    ///
    /// Bitcoin uses `network` as configured. Bitcoin Cash uses the network
    /// implied by `bitcoin_cash_network`, whatever `network` says, so every
    /// node on one Bitcoin Cash network computes the same difficulty and
    /// speaks the same protocol id. Without `bitcoin_cash_network`, `network`
    /// is returned and parsing rejects the configuration.
    pub fn effective_network(&self) -> Network {
        match (self.chain, self.bitcoin_cash_network) {
            (Chain::BitcoinCash, Some(bitcoin_cash_network)) => {
                bitcoin_cash_network.legacy_network()
            }
            (Chain::Bitcoin, _) | (Chain::BitcoinCash, None) => self.network,
        }
    }
}

impl StratumConfig<Raw> {
    /// Parse and validate addresses, converting from Raw to Parsed state.
    ///
    /// On Bitcoin Cash the parsed `network` is [`Self::effective_network`].
    pub fn parse(mut self) -> Result<StratumConfig<Parsed>, ConfigError> {
        self.network = self.effective_network();
        if self.pool_signature.clone().unwrap_or("".to_string()).len() > MAX_POOL_SIGNATURE_LENGTH {
            return Err(ConfigError {
                message: format!("Pool signature length is limited to {MAX_POOL_SIGNATURE_LENGTH}"),
            });
        }

        // Bitcoin Cash has a built-in donation address, so `donation` alone is
        // enough there. Bitcoin has none.
        if self.chain == Chain::Bitcoin
            && self.donation_address.is_some() != self.donation.is_some()
        {
            return Err(ConfigError {
                message: "donation_address and donation must both be set or both be unset"
                    .to_string(),
            });
        }

        if self.fee_address.is_some() != self.fee.is_some() {
            return Err(ConfigError {
                message: "fee_address and fee must both be set or both be unset".to_string(),
            });
        }

        // Hydrapool never builds a share commitment, so a share chain address
        // could not be used there. Fail at startup rather than let an operator
        // believe their shares are being assigned to it.
        if self.miner_address.is_some() && self.mode == PoolMode::Hydrapool {
            return Err(ConfigError {
                message:
                    "miner_address cannot be set when mode is hydrapool, which has no share chain"
                        .to_string(),
            });
        }

        match (self.chain, self.bitcoin_cash_network) {
            (Chain::Bitcoin, Some(_)) => {
                return Err(ConfigError {
                    message: "bitcoin_cash_network is only valid when chain is bitcoin-cash"
                        .to_string(),
                });
            }
            (Chain::BitcoinCash, None) => {
                return Err(ConfigError {
                    message: "bitcoin_cash_network is required when chain is bitcoin-cash"
                        .to_string(),
                });
            }
            (Chain::Bitcoin, None) | (Chain::BitcoinCash, Some(_)) => {}
        }

        if self.chain == Chain::Bitcoin && self.bch_share_chain == BchShareChain::Mini {
            return Err(ConfigError {
                message: "bch_share_chain = mini is only valid when chain is bitcoin-cash"
                    .to_string(),
            });
        }

        if self.chain == Chain::BitcoinCash
            && let Some(solo_address) = &self.solo_address
        {
            parse_payout_address(
                solo_address,
                self.chain,
                self.network,
                self.bitcoin_cash_network,
            )?;
        }

        // Bitcoin share addresses use this network's bech32m prefix. Bitcoin
        // Cash share addresses use bitcoin_cash_network, so that chain does
        // not have to name a Bitcoin share prefix. Genesis still reads network.
        if self.mode == PoolMode::P2poolv2 && self.chain == Chain::Bitcoin {
            p2poolv2_wallet::expected_hrp(self.network).map_err(|error| ConfigError {
                message: format!(
                    "Network {} cannot be used for a share chain: {error}",
                    self.network
                ),
            })?;
        }

        let bootstrap_address_parsed = parse_payout_address(
            &self.bootstrap_address,
            self.chain,
            self.network,
            self.bitcoin_cash_network,
        )?;

        let (miner_address_parsed, bch_miner_address) = match self.chain {
            Chain::Bitcoin => (
                self.miner_address
                    .as_ref()
                    .map(|address| parse_share_address(address, self.network))
                    .transpose()?,
                None,
            ),
            Chain::BitcoinCash => {
                let bitcoin_cash_network =
                    self.bitcoin_cash_network.ok_or_else(|| ConfigError {
                        message: "bitcoin_cash_network is required when chain is bitcoin-cash"
                            .to_string(),
                    })?;
                let parsed = self
                    .miner_address
                    .as_ref()
                    .map(|address| bch_share::parse(address, bitcoin_cash_network.share_network()))
                    .transpose()
                    .map_err(|error| ConfigError {
                        message: format!("Invalid Bitcoin Cash share address: {error}"),
                    })?;
                (None, parsed)
            }
        };

        let (donation_address_parsed, donation) = resolve_donation(
            self.chain,
            self.network,
            self.bitcoin_cash_network,
            self.donation_address.as_deref(),
            self.donation,
        )?;

        let fee_address_parsed = self
            .fee_address
            .as_ref()
            .map(|addr| {
                parse_payout_address(addr, self.chain, self.network, self.bitcoin_cash_network)
            })
            .transpose()?;

        validate_cuts(self.chain, donation, self.fee)?;

        let sv2_authority = parse_sv2_authority(
            self.sv2_port,
            self.sv2_authority_public_key.as_deref(),
            self.sv2_authority_secret_key.as_deref(),
            self.sv2_cert_validity_secs,
        )?;
        let template_provider = parse_template_provider(
            self.chain,
            self.bitcoin_cash_network,
            self.template_source,
            self.template_provider_address.as_deref(),
            self.template_provider_authority_public_key.as_deref(),
        )?;

        Ok(StratumConfig {
            hostname: self.hostname,
            port: self.port,
            start_difficulty: self.start_difficulty,
            minimum_difficulty: self.minimum_difficulty,
            maximum_difficulty: self.maximum_difficulty,
            solo_address: self.solo_address,
            zmqpubhashblock: self.zmqpubhashblock,
            bootstrap_address: self.bootstrap_address,
            donation_address: self.donation_address,
            donation,
            fee_address: self.fee_address,
            fee: self.fee,
            miner_address: self.miner_address,
            network: self.network,
            chain: self.chain,
            bitcoin_cash_network: self.bitcoin_cash_network,
            bch_share_chain: self.bch_share_chain,
            sv2_port: self.sv2_port,
            sv2_authority_public_key: self.sv2_authority_public_key,
            sv2_authority_secret_key: self.sv2_authority_secret_key,
            sv2_cert_validity_secs: self.sv2_cert_validity_secs,
            template_source: self.template_source,
            template_provider_address: self.template_provider_address,
            template_provider_authority_public_key: self.template_provider_authority_public_key,
            version_mask: self.version_mask,
            ignore_difficulty: self.ignore_difficulty,
            pool_signature: self.pool_signature,
            max_connections: self.max_connections,
            wait_for_chain_sync: self.wait_for_chain_sync,
            mode: self.mode,
            bootstrap_address_parsed: Some(bootstrap_address_parsed),
            donation_address_parsed,
            fee_address_parsed,
            miner_address_parsed,
            bch_miner_address,
            sv2_authority,
            template_provider,
            _state: PhantomData,
        })
    }
}

impl StratumConfig<Parsed> {
    /// Get the parsed and validated bootstrap address
    pub fn bootstrap_address(&self) -> &Address<NetworkChecked> {
        self.bootstrap_address_parsed
            .as_ref()
            .expect("bootstrap_address_parsed should always be Some in Parsed state")
    }

    /// Get the parsed and validated donation address, if any
    pub fn donation_address(&self) -> Option<&Address<NetworkChecked>> {
        self.donation_address_parsed.as_ref()
    }

    /// Get the parsed and validated fee address, if any
    pub fn fee_address(&self) -> Option<&Address<NetworkChecked>> {
        self.fee_address_parsed.as_ref()
    }

    /// Get the pool wide share chain address, if the operator configured one.
    ///
    /// When present every share this pool mines is owned by this address, and a
    /// miner supplying a different one in `p2p=` is rejected at authorize.
    pub fn miner_address(&self) -> Option<ShareAddress> {
        self.miner_address_parsed
    }

    /// Bitcoin Cash share address configured for this pool, if any.
    pub fn bch_miner_address(&self) -> Option<BchShareAddress> {
        self.bch_miner_address
    }

    /// Stratum V2 authority keys, when the operator configured them.
    pub fn sv2_authority(&self) -> Option<Sv2Authority> {
        self.sv2_authority
    }

    /// The Stratum V2 Template Provider templates come from, when
    /// `template_source` is `sv2`. `None` means templates come over RPC.
    pub fn template_provider(&self) -> Option<&TemplateProvider> {
        self.template_provider.as_ref()
    }
}

/// Where the node gets its block templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateSource {
    /// `getblocktemplate` from the node in `[bitcoinrpc]`.
    #[default]
    Rpc,
    /// A Stratum V2 Template Provider, over the Template Distribution
    /// Protocol.
    Sv2,
}

/// A checked Stratum V2 Template Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateProvider {
    /// `HOST:PORT` to connect to.
    pub address: String,
    /// The provider's 32-byte x-only authority key, pinned for the Noise
    /// handshake. `None` only for a provider on a loopback address, which
    /// is then spoken to without encryption.
    pub authority_public_key: Option<[u8; 32]>,
    /// The Bitcoin Cash network its templates must be for.
    pub network: BitcoinCashNetwork,
}

impl TemplateProvider {
    /// The provider a `Reconnect` from this one names: `host` and `port`,
    /// or this provider's own when `host` is empty or `port` is 0.
    ///
    /// The pinned key and the network carry over, so a provider spoken to
    /// without encryption may only redirect to this computer.
    pub fn redirected(&self, host: &str, port: u16) -> Result<TemplateProvider, ConfigError> {
        let (current_host, current_port) = self
            .address
            .rsplit_once(':')
            .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
            .ok_or_else(|| ConfigError {
                message: format!(
                    "template provider address {} is not HOST:PORT",
                    self.address
                ),
            })?;
        let host = if host.is_empty() { current_host } else { host };
        let port = if port == 0 { current_port } else { port };
        if self.authority_public_key.is_none() && !is_loopback_host(host) {
            return Err(ConfigError {
                message: format!(
                    "an unencrypted Template Provider may not redirect to another computer ({host})"
                ),
            });
        }
        let address = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Ok(TemplateProvider {
            address,
            authority_public_key: self.authority_public_key,
            network: self.network,
        })
    }
}

/// Check the Template Provider settings against `template_source`.
///
/// `rpc` takes no provider settings, so a provider address left in a
/// configuration cannot be silently ignored. `sv2` needs an address, works
/// only on Bitcoin Cash (a Bitcoin provider's required segwit commitment
/// output is not mapped), and needs the provider's key unless it is on this
/// computer: the specification allows unencrypted frames only between local
/// roles, and an unauthenticated provider could keep every found block.
fn parse_template_provider(
    chain: Chain,
    bitcoin_cash_network: Option<BitcoinCashNetwork>,
    source: TemplateSource,
    address: Option<&str>,
    authority_public_key: Option<&str>,
) -> Result<Option<TemplateProvider>, ConfigError> {
    if source == TemplateSource::Rpc {
        if address.is_some() || authority_public_key.is_some() {
            return Err(ConfigError {
                message: "template_provider_address and template_provider_authority_public_key need template_source = \"sv2\"".to_string(),
            });
        }
        return Ok(None);
    }
    let network = match (chain, bitcoin_cash_network) {
        (Chain::BitcoinCash, Some(network)) => network,
        _ => {
            return Err(ConfigError {
                message:
                    "template_source = \"sv2\" is supported only with chain = \"bitcoin-cash\""
                        .to_string(),
            });
        }
    };
    let address = address.ok_or_else(|| ConfigError {
        message: "template_source = \"sv2\" needs template_provider_address".to_string(),
    })?;
    let host = address
        .rsplit_once(':')
        .filter(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
        .map(|(host, _)| host)
        .ok_or_else(|| ConfigError {
            message: format!("template_provider_address must be HOST:PORT, got {address}"),
        })?;
    let authority_public_key = authority_public_key
        .map(|text| decode_sv2_public_key(text, "template_provider_authority_public_key"))
        .transpose()?;
    if authority_public_key.is_none() && !is_loopback_host(host) {
        return Err(ConfigError {
            message: format!(
                "template_provider_authority_public_key is required for a Template Provider on another computer ({address})"
            ),
        });
    }
    Ok(Some(TemplateProvider {
        address: address.to_string(),
        authority_public_key,
        network,
    }))
}

/// Whether `host` names this computer: `localhost` or a loopback IP,
/// bracketed or not.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Decode a Stratum V2 public key in the reference implementation's text
/// form: Base58Check of version `[1, 0]` and the 32-byte x-only key.
/// `field` names the setting in the error.
fn decode_sv2_public_key(text: &str, field: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = base58::decode_check(text).map_err(|error| ConfigError {
        message: format!("Invalid {field}: {error}"),
    })?;
    match bytes.split_first_chunk::<2>() {
        Some((version, key)) if *version == SV2_PUBLIC_KEY_VERSION => {
            key.try_into().map_err(|_| ConfigError {
                message: format!("Invalid {field}: expected version 1 and a 32-byte key"),
            })
        }
        _ => Err(ConfigError {
            message: format!("Invalid {field}: expected version 1 and a 32-byte key"),
        }),
    }
}

/// Seconds a Noise certificate signed by the Stratum V2 authority key stays
/// valid when `sv2_cert_validity_secs` is not set.
pub const DEFAULT_SV2_CERT_VALIDITY_SECS: u64 = 3600;

/// Version prefix of a Stratum V2 authority public key in the reference
/// implementation's text form: little-endian `1`.
const SV2_PUBLIC_KEY_VERSION: [u8; 2] = [1, 0];

/// Stratum V2 authority keys that sign the Noise certificate.
///
/// Debug output never shows the secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sv2Authority {
    /// 32-byte x-only public key miners pin.
    pub public_key: [u8; 32],
    /// 32-byte secret key.
    pub secret_key: [u8; 32],
    /// Seconds each Noise certificate stays valid.
    pub cert_validity_secs: u64,
}

impl std::fmt::Debug for Sv2Authority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sv2Authority")
            .field("public_key", &self.public_key)
            .field("secret_key", &"<redacted>")
            .field("cert_validity_secs", &self.cert_validity_secs)
            .finish()
    }
}

/// Decode the configured Stratum V2 authority keys, if any.
///
/// Both keys or neither; they need `sv2_port`; and the public key must be
/// the one the secret key derives, so a typo cannot make every miner's
/// handshake fail against a key the operator did not mean to publish.
fn parse_sv2_authority(
    sv2_port: Option<u16>,
    public_key: Option<&str>,
    secret_key: Option<&str>,
    cert_validity_secs: Option<u64>,
) -> Result<Option<Sv2Authority>, ConfigError> {
    let (public_text, secret_text) = match (public_key, secret_key) {
        (None, None) => return Ok(None),
        (Some(public_text), Some(secret_text)) => (public_text, secret_text),
        _ => {
            return Err(ConfigError {
                message: "sv2_authority_public_key and sv2_authority_secret_key must both be set or both be unset".to_string(),
            });
        }
    };
    if sv2_port.is_none() {
        return Err(ConfigError {
            message: "sv2_authority keys need sv2_port".to_string(),
        });
    }
    let public_key = decode_sv2_public_key(public_text, "sv2_authority_public_key")?;
    let secret_bytes = base58::decode_check(secret_text).map_err(|_| ConfigError {
        message: "Invalid sv2_authority_secret_key: not Base58Check".to_string(),
    })?;
    let secret = SecretKey::from_slice(&secret_bytes).map_err(|_| ConfigError {
        message: "Invalid sv2_authority_secret_key: not a 32-byte secp256k1 secret key".to_string(),
    })?;
    let derived = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
        .x_only_public_key()
        .0
        .serialize();
    if derived != public_key {
        return Err(ConfigError {
            message: "sv2_authority_public_key is not the key sv2_authority_secret_key derives"
                .to_string(),
        });
    }
    // The certificate stores its validity window in 32-bit seconds; a longer
    // value would wrap, and 0 would expire every certificate as it is issued.
    let cert_validity_secs = cert_validity_secs.unwrap_or(DEFAULT_SV2_CERT_VALIDITY_SECS);
    if cert_validity_secs == 0 || cert_validity_secs > u64::from(u32::MAX) {
        return Err(ConfigError {
            message: format!(
                "sv2_cert_validity_secs must be between 1 and {}, got {cert_validity_secs}",
                u32::MAX
            ),
        });
    }
    Ok(Some(Sv2Authority {
        public_key: derived,
        secret_key: secret.secret_bytes(),
        cert_validity_secs,
    }))
}

/// Donation output and basis points this node puts in the shares it mines.
///
/// Bitcoin keeps the upstream rule: both fields or neither, and any address.
/// Bitcoin Cash pays [`bitcoin_cash_donation_address`]: `donation` defaults
/// to [`DEFAULT_BITCOIN_CASH_DONATION`], 0 opts out, and a configured
/// `donation_address` must name that same key.
fn resolve_donation(
    chain: Chain,
    network: Network,
    bitcoin_cash_network: Option<BitcoinCashNetwork>,
    donation_address: Option<&str>,
    donation: Option<u16>,
) -> Result<(Option<Address>, Option<u16>), ConfigError> {
    match chain {
        Chain::Bitcoin => {
            let parsed = donation_address
                .map(|address| parse_payout_address(address, chain, network, None))
                .transpose()?;
            Ok((parsed, donation))
        }
        Chain::BitcoinCash => {
            let bitcoin_cash_network = bitcoin_cash_network.ok_or_else(|| ConfigError {
                message: "bitcoin_cash_network is required when chain is bitcoin-cash".to_string(),
            })?;
            let built_in = bitcoin_cash_donation_address(bitcoin_cash_network);
            if let Some(address) = donation_address {
                let configured =
                    parse_payout_address(address, chain, network, Some(bitcoin_cash_network))?;
                if configured.script_pubkey() != built_in.script_pubkey() {
                    return Err(ConfigError {
                        message: format!(
                            "donation_address on bitcoin-cash is fixed to {BITCOIN_CASH_DONATION_ADDRESS} \
                             (this network's prefix). Remove donation_address, set donation = 0 to \
                             opt out, or use fee_address and fee for your own pool fee"
                        ),
                    });
                }
            }
            match donation.unwrap_or(DEFAULT_BITCOIN_CASH_DONATION) {
                0 => Ok((None, None)),
                basis_points => Ok((Some(built_in), Some(basis_points))),
            }
        }
    }
}

/// Reject donation and fee basis points the payout cannot honor.
///
/// Each cut is a share of what is left, so each must be at most 100%. A
/// Bitcoin Cash node must also stay within [`MAX_BITCOIN_CASH_POOL_CUT`],
/// which its peers enforce on every share it mines.
fn validate_cuts(chain: Chain, donation: Option<u16>, fee: Option<u16>) -> Result<(), ConfigError> {
    let donation = donation.unwrap_or(0);
    let fee = fee.unwrap_or(0);
    if donation > MAX_BASIS_POINTS || fee > MAX_BASIS_POINTS {
        return Err(ConfigError {
            message: format!(
                "donation and fee are basis points and must each be at most {MAX_BASIS_POINTS}"
            ),
        });
    }
    if chain == Chain::BitcoinCash
        && u32::from(donation) + u32::from(fee) > u32::from(MAX_BITCOIN_CASH_POOL_CUT)
    {
        return Err(ConfigError {
            message: format!(
                "donation ({donation}) plus fee ({fee}) on bitcoin-cash must be at most \
                 {MAX_BITCOIN_CASH_POOL_CUT} basis points; peers reject shares above it"
            ),
        });
    }
    Ok(())
}

#[cfg(any(test, feature = "test-utils"))]
impl StratumConfig<Raw> {
    /// Helper for tests to create a basic StratumConfig
    /// Uses regtest network by default with a valid regtest address
    pub fn new_for_test_default() -> Self {
        StratumConfig {
            hostname: "127.0.0.1".to_string(),
            port: 3333,
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: Some(1000),
            solo_address: None,
            zmqpubhashblock: "tcp://127.0.0.1:28332".to_string(),
            bootstrap_address: "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string(),
            donation_address: None,
            donation: None,
            fee_address: None,
            fee: None,
            miner_address: None,
            network: bitcoin::Network::Signet,
            chain: Chain::Bitcoin,
            bitcoin_cash_network: None,
            bch_share_chain: BchShareChain::Main,
            sv2_port: None,
            sv2_authority_public_key: None,
            sv2_authority_secret_key: None,
            sv2_cert_validity_secs: None,
            template_source: TemplateSource::Rpc,
            template_provider_address: None,
            template_provider_authority_public_key: None,
            version_mask: DEFAULT_VERSION_MASK,
            ignore_difficulty: None,
            pool_signature: None,
            max_connections: None,
            wait_for_chain_sync: true,
            mode: PoolMode::default(),
            bootstrap_address_parsed: None,
            donation_address_parsed: None,
            fee_address_parsed: None,
            miner_address_parsed: None,
            bch_miner_address: None,
            sv2_authority: None,
            template_provider: None,
            _state: PhantomData,
        }
    }
}

/// Helper function to deserialize the network from the config file.
/// Possible values are: main, test, testnet4, signet, regtest
fn deserialize_network<'de, D>(deserializer: D) -> Result<bitcoin::Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let network_string: String = serde::Deserialize::deserialize(deserializer)?;
    bitcoin::Network::from_core_arg(&network_string).map_err(serde::de::Error::custom)
}

fn deserialize_version_mask<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_string: String = serde::Deserialize::deserialize(deserializer)?;
    i32::from_str_radix(&hex_string, 16).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub listen_address: String,
    pub dial_peers: Vec<String>,
    pub max_pending_incoming: u32,
    pub max_pending_outgoing: u32,
    pub max_established_incoming: u32,
    pub max_established_outgoing: u32,
    pub max_established_per_peer: u32,
    pub max_workbase_per_second: u32,
    pub max_userworkbase_per_second: u32,
    pub max_miningshare_per_second: u32,
    pub max_inventory_per_second: u32,
    pub max_transaction_per_second: u32,
    pub max_requests_per_second: u64,
    pub dial_timeout_secs: u64,
    /// IP addresses to block from connecting. Connections from these IPs
    /// are immediately disconnected.
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    /// Optional external address override for nodes behind NAT.
    /// If set, this address is advertised to peers via the identify protocol.
    /// Format: Multiaddr string, e.g. "/ip4/203.0.113.1/tcp/6884"
    #[serde(default)]
    pub external_address: Option<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_address: "".to_string(),
            dial_peers: vec![],
            max_pending_incoming: 10,
            max_pending_outgoing: 10,
            max_established_incoming: 50,
            max_established_outgoing: 50,
            // Two, not one: when two nodes dial each other at the same moment
            // each can keep its own outbound connection and refuse the other's
            // inbound one, so with a limit of one both connections close and
            // they retry. A second slot lets both survive. More only duplicates
            // traffic, as libp2p multiplexes every protocol over one connection.
            max_established_per_peer: 2,
            max_workbase_per_second: 10,
            max_userworkbase_per_second: 10,
            max_miningshare_per_second: 100,
            max_inventory_per_second: 100,
            max_transaction_per_second: 100,
            max_requests_per_second: 100,
            dial_timeout_secs: 30,
            blocked_ips: vec![],
            external_address: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoreConfig {
    pub path: String,
    /// How often to run background cleanup tasks (in hours)
    #[serde(default = "default_background_task_frequency_hours")]
    pub background_task_frequency_hours: u64,
    /// Time-to-live for PPLNS shares (in days)
    #[serde(default = "default_pplns_ttl_days")]
    pub pplns_ttl_days: u64,
}

fn default_wait_for_chain_sync() -> bool {
    true
}

fn default_background_task_frequency_hours() -> u64 {
    1
}

fn default_pplns_ttl_days() -> u64 {
    7
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct LoggingConfig {
    /// Log to file if specified
    pub file: Option<String>,
    /// Log level (defaults to "info")
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Directory for stats
    #[serde(default = "default_stats_dir")]
    pub stats_dir: String,
    /// Log to stdout if `true`
    #[serde(default = "default_log_console")]
    pub console: Option<bool>,
}

fn default_log_console() -> Option<bool> {
    Some(true)
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_stats_dir() -> String {
    "./logs/stats".to_string()
}

#[derive(Deserialize, Clone)]
pub struct ApiConfig {
    /// The hostname for the API server
    pub hostname: String,
    /// The port for the API server
    pub port: u16,
    /// Optional authentication username
    pub auth_user: Option<String>,
    /// Optional authentication token (salt$hmac format, used by the server)
    pub auth_token: Option<String>,
    /// Optional raw password for CLI client authentication (not used by server)
    pub auth_password: Option<String>,
    /// Enable permissive CORS for the API server
    #[serde(default)]
    pub cors_allowed: bool,
    /// Serve the dashboard, a `web_root` frontend and the read-only share
    /// chain routes they read without the API's authentication, for a
    /// public node. The node's own routes (`/metrics`, `/peers`,
    /// `/blocked_ips`) keep requiring `auth_user`.
    #[serde(default)]
    pub public_dashboard: bool,
    /// A folder holding a self-hosted frontend's build, served for every
    /// path no API route takes. Any frontend that builds to static files
    /// works, such as TypeScript or Rust compiled to WebAssembly.
    pub web_root: Option<String>,
}

/// Custom Debug to redact password
impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiConfig")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("auth_user", &self.auth_user)
            .field("auth_token", &"[redacted]")
            .field("auth_password", &"[redacted]")
            .field("cors_allowed", &self.cors_allowed)
            .field("public_dashboard", &self.public_dashboard)
            .field("web_root", &self.web_root)
            .finish()
    }
}

/// Configuration for the no-PoW load-test simulation.
///
/// Only acted upon when a binary is built with the `sim` cargo feature; the
/// field is always present in `Config` so non-sim builds parse the same config
/// files without error.
/// See docs/simulation/load-test-plan.md.
#[derive(Debug, Deserialize, Clone)]
pub struct SimConfig {
    /// Master switch for this node's sim emitter / statistical block-find.
    #[serde(default)]
    pub enabled: bool,
    /// This node's payout identity (bitcoin address); should be distinct per node.
    pub miner_address: String,
    /// This node's share chain identity. Cannot be derived from `miner_address`
    /// -- different chain, different key -- so it is supplied separately.
    /// Falls back to `[stratum] miner_address` when omitted.
    #[serde(default)]
    pub share_address: Option<String>,
    /// Modeled hashrate Hᵢ in hashes/sec; sets the emission rate.
    pub hashrate: f64,
    /// Expected number of shares per bitcoin block (global; same on all nodes).
    pub block_to_share_ratio: u64,
    /// Per-node RNG seed for reproducible emission/block-find. Should differ per
    /// node so timelines decorrelate; omit for a nondeterministic seed. A cheap
    /// RNG is fine — this is a simulation, not entropy that guards funds.
    #[serde(default)]
    pub seed: Option<u64>,
    /// Artificial delay (milliseconds) applied to this node's outbound share
    /// announcements, modeling network latency. Over loopback, propagation is
    /// otherwise near-instant and the chain stays linear; a non-zero delay
    /// widens the window for concurrent emission, so uncles appear and uncle
    /// rate tracks this value. Default 0 (no delay).
    #[serde(default)]
    pub propagation_delay_ms: Option<u64>,
    /// Unix time (seconds) to use as the ASERT difficulty anchor instead of the
    /// genesis timestamp. The fixed regtest genesis is dated in the past, so the
    /// share chain is permanently "behind schedule" and ASERT stays floored at
    /// the easy clamp (the chain races, never reaching a steady rate). Setting
    /// this to ~launch time lets ASERT regulate around the 10s target. MUST be
    /// identical across all nodes (the harness writes one shared value) or their
    /// ASERT targets diverge and shares are rejected.
    #[serde(default)]
    pub asert_anchor_time: Option<u64>,
    /// Total network hashrate (hashes/sec) = sum over all nodes. Used to anchor
    /// the genesis difficulty at the steady-state value (`hashrate · 10s / 2^32`)
    /// so the chain starts regulated instead of climbing from the easy clamp for
    /// ~15-20 min. MUST be identical across nodes (it sets the genesis target,
    /// hence the genesis hash). Omit to keep the fixed genesis target.
    #[serde(default)]
    pub network_hashrate: Option<u64>,
    /// Sim-only override of the ASERT ideal block time (seconds). Smaller =
    /// more blocks per minute (time-compressed runs for faster data). MUST be
    /// identical across nodes (ASERT consensus). Omit for the default 10s.
    #[serde(default)]
    pub ideal_block_time_secs: Option<u32>,
    /// Sim-only override of the coinbase maturity depth (shares), which sets
    /// both when a share coinbase can be spent and when a share can be paid.
    /// Smaller = a short run reaches the payout maturity skip. MUST be
    /// identical across nodes (consensus). Omit for the production 6,048.
    #[serde(default)]
    pub coinbase_maturity: Option<usize>,
}

/// Config for p2poolv2 nodes
///
/// The network config switches to defaults if not provided. This is
/// the case for standalone PPLNS pools like Hydrapool.
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    pub store: StoreConfig,
    pub stratum: StratumConfig,
    pub bitcoinrpc: BitcoinRpcConfig,
    pub logging: LoggingConfig,
    pub api: ApiConfig,
}

#[allow(dead_code)]
impl Config {
    /// Load the configuration file at `path`, with `P2POOL__` environment
    /// overrides.
    ///
    /// On Bitcoin Cash, `stratum.network` is replaced by the network implied
    /// by `bitcoin_cash_network` (see [`BitcoinCashNetwork::legacy_network`]).
    /// The P2P protocol id and every difficulty calculation read that field,
    /// so two Bitcoin Cash nodes on the same network must not disagree on it
    /// because one left a Bitcoin value such as `signet` in its file.
    pub fn load(path: &str) -> Result<Self, config::ConfigError> {
        let loaded: Self = config::Config::builder()
            .add_source(config::File::with_name(path))
            // Nesting uses `__` so that a single `_` stays part of a field name.
            // With a single-underscore separator, P2POOL_STORE_PPLNS_TTL_DAYS
            // addresses store.pplns.ttl.days, which does not exist, and the
            // override is silently discarded. See the env_override tests.
            .add_source(
                config::Environment::with_prefix("P2POOL")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()?;
        Ok(loaded.with_bitcoin_cash_network_derived())
    }

    /// Set `stratum.network` from `bitcoin_cash_network` on a Bitcoin Cash
    /// node. Bitcoin configurations are returned unchanged.
    pub fn with_bitcoin_cash_network_derived(mut self) -> Self {
        self.stratum.network = self.stratum.effective_network();
        self
    }

    pub fn with_listen_address(mut self, listen_address: String) -> Self {
        self.network.listen_address = listen_address;
        self
    }

    pub fn with_dial_peers(mut self, dial_peers: Vec<String>) -> Self {
        self.network.dial_peers = dial_peers;
        self
    }

    pub fn with_max_pending_incoming(mut self, max_pending_incoming: u32) -> Self {
        self.network.max_pending_incoming = max_pending_incoming;
        self
    }

    pub fn with_max_pending_outgoing(mut self, max_pending_outgoing: u32) -> Self {
        self.network.max_pending_outgoing = max_pending_outgoing;
        self
    }

    pub fn with_max_established_incoming(mut self, max_established_incoming: u32) -> Self {
        self.network.max_established_incoming = max_established_incoming;
        self
    }

    pub fn with_max_established_outgoing(mut self, max_established_outgoing: u32) -> Self {
        self.network.max_established_outgoing = max_established_outgoing;
        self
    }

    pub fn with_max_established_per_peer(mut self, max_established_per_peer: u32) -> Self {
        self.network.max_established_per_peer = max_established_per_peer;
        self
    }

    pub fn with_store_path(mut self, store_path: String) -> Self {
        self.store.path = store_path;
        self
    }

    pub fn with_background_task_frequency_hours(mut self, hours: u64) -> Self {
        self.store.background_task_frequency_hours = hours;
        self
    }

    pub fn with_pplns_ttl_days(mut self, days: u64) -> Self {
        self.store.pplns_ttl_days = days;
        self
    }

    pub fn with_stratum_hostname(mut self, stratum_hostname: String) -> Self {
        self.stratum.hostname = stratum_hostname;
        self
    }

    pub fn with_stratum_port(mut self, stratum_port: u16) -> Self {
        self.stratum.port = stratum_port;
        self
    }

    pub fn with_stratum_solo_address(mut self, solo_address: String) -> Self {
        self.stratum.solo_address = Some(solo_address);
        self
    }

    pub fn with_stratum_zmqpubhashblock(mut self, zmqpubhashblock: String) -> Self {
        self.stratum.zmqpubhashblock = zmqpubhashblock;
        self
    }

    pub fn with_stratum_bootstrap_address(mut self, bootstrap_address: String) -> Self {
        self.stratum.bootstrap_address = bootstrap_address;
        self
    }

    pub fn with_start_difficulty(mut self, start_difficulty: u64) -> Self {
        self.stratum.start_difficulty = start_difficulty;
        self
    }

    pub fn with_minimum_difficulty(mut self, minimum_difficulty: u64) -> Self {
        self.stratum.minimum_difficulty = minimum_difficulty;
        self
    }

    pub fn with_maximum_difficulty(mut self, maximum_difficulty: Option<u64>) -> Self {
        self.stratum.maximum_difficulty = maximum_difficulty;
        self
    }

    pub fn with_ignore_difficulty(mut self, ignore_difficulty: Option<bool>) -> Self {
        self.stratum.ignore_difficulty = ignore_difficulty;
        self
    }

    pub fn with_pool_signature(mut self, pool_signature: Option<String>) -> Self {
        self.stratum.pool_signature = pool_signature;
        self
    }

    pub fn with_bitcoinrpc_url(mut self, bitcoin_url: String) -> Self {
        self.bitcoinrpc.url = bitcoin_url;
        self
    }

    pub fn with_bitcoinrpc_username(mut self, bitcoin_username: String) -> Self {
        self.bitcoinrpc.username = bitcoin_username;
        self
    }

    pub fn with_bitcoinrpc_password(mut self, bitcoin_password: String) -> Self {
        self.bitcoinrpc.password = bitcoin_password;
        self
    }

    pub fn with_bitcoin_network(mut self, network: bitcoin::Network) -> Self {
        self.stratum.network = network;
        self
    }

    pub fn with_stats_dir(mut self, stats_dir: String) -> Self {
        self.logging.stats_dir = stats_dir;
        self
    }

    pub fn with_api_hostname(mut self, hostname: String) -> Self {
        self.api.hostname = hostname;
        self
    }

    pub fn with_api_port(mut self, port: u16) -> Self {
        self.api.port = port;
        self
    }

    pub fn with_api_auth_user(mut self, auth_user: Option<String>) -> Self {
        self.api.auth_user = auth_user;
        self
    }

    pub fn with_api_auth_token(mut self, auth_token: Option<String>) -> Self {
        self.api.auth_token = auth_token;
        self
    }

    pub fn with_max_requests_per_second(mut self, max_requests_per_second: u64) -> Self {
        self.network.max_requests_per_second = max_requests_per_second;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_wallet::bch_share::{BchShareAddress, BchShareNetwork};
    use temp_env::with_var;
    use tokio_test::assert_err;

    #[test]
    fn test_config_builder() {
        let config = Config::load("../config.sample.toml").unwrap();
        let config = config
            .with_listen_address("127.0.0.1:8080".to_string())
            .with_dial_peers(vec![
                "peer1.example.com".to_string(),
                "peer2.example.com".to_string(),
            ])
            .with_max_pending_incoming(10)
            .with_max_pending_outgoing(10)
            .with_max_established_incoming(50)
            .with_max_established_outgoing(50)
            .with_max_established_per_peer(1)
            .with_store_path("/tmp/store".to_string())
            .with_stratum_hostname("stratum.example.com".to_string())
            .with_stratum_port(3333)
            .with_stratum_solo_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string())
            .with_stratum_zmqpubhashblock("tcp://127.0.0.1:28332".to_string())
            .with_stratum_bootstrap_address("bcrt1qxyz123example456bitcoin789address".to_string())
            .with_start_difficulty(1)
            .with_minimum_difficulty(1)
            .with_maximum_difficulty(Some(100))
            .with_ignore_difficulty(Some(true))
            .with_bitcoinrpc_url("http://localhost:8332".to_string())
            .with_bitcoinrpc_username("testuser".to_string())
            .with_bitcoinrpc_password("testpass".to_string())
            .with_bitcoin_network(bitcoin::Network::Signet)
            .with_stats_dir("./logs/stats".to_string())
            .with_api_hostname("127.0.0.1".to_string())
            .with_api_port(3000)
            .with_api_auth_user(Some("admin".to_string()))
            .with_api_auth_token(Some("secret_token".to_string()));

        assert_eq!(config.network.listen_address, "127.0.0.1:8080");
        assert_eq!(
            config.network.dial_peers,
            vec!["peer1.example.com", "peer2.example.com"]
        );
        assert_eq!(config.store.path, "/tmp/store");

        assert_eq!(config.stratum.hostname, "stratum.example.com");
        assert_eq!(config.stratum.port, 3333);
        assert_eq!(config.stratum.start_difficulty, 1);
        assert_eq!(config.stratum.minimum_difficulty, 1);
        assert_eq!(config.stratum.maximum_difficulty, Some(100));
        assert!(config.stratum.ignore_difficulty.unwrap());
        assert_eq!(
            config.stratum.solo_address,
            Some("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string())
        );
        assert_eq!(
            config.stratum.zmqpubhashblock,
            "tcp://127.0.0.1:28332".to_string()
        );
        assert_eq!(
            config.stratum.bootstrap_address.to_string(),
            "bcrt1qxyz123example456bitcoin789address".to_string()
        );

        assert_eq!(config.bitcoinrpc.url, "http://localhost:8332");
        assert_eq!(config.bitcoinrpc.username, "testuser");
        assert_eq!(config.bitcoinrpc.password, "testpass");

        assert_eq!(config.network.max_pending_incoming, 10);
        assert_eq!(config.network.max_pending_outgoing, 10);
        assert_eq!(config.network.max_established_incoming, 50);
        assert_eq!(config.network.max_established_outgoing, 50);
        assert_eq!(config.network.max_established_per_peer, 1);
        assert_eq!(config.logging.stats_dir, "./logs/stats");

        // Test API config
        assert_eq!(config.api.hostname, "127.0.0.1");
        assert_eq!(config.api.port, 3000);
        assert_eq!(config.api.auth_user, Some("admin".to_string()));
        assert_eq!(config.api.auth_token, Some("secret_token".to_string()));

        // Test values from config.sample.toml
        assert_eq!(config.store.background_task_frequency_hours, 24);
        assert_eq!(config.store.pplns_ttl_days, 7);
    }

    #[test]
    fn test_config_store_background_settings() {
        let config = Config::load("../config.sample.toml")
            .unwrap()
            .with_background_task_frequency_hours(2)
            .with_pplns_ttl_days(7);

        assert_eq!(config.store.background_task_frequency_hours, 2);
        assert_eq!(config.store.pplns_ttl_days, 7);
    }

    /// Characterisation tests for environment-variable overrides.
    ///
    /// `Config::load` layers `config::Environment` with prefix `P2POOL` and
    /// separator `_` over the TOML file. The separator is also what appears
    /// inside many field names, so which keys are reachable is not obvious.
    /// These tests pin the behaviour, because getting it wrong starts the node
    /// with the wrong settings rather than failing.
    #[test]
    fn env_override_applies_to_a_nested_string_field() {
        with_var("P2POOL_LOGGING__LEVEL", Some("trace"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_eq!(config.logging.level, "trace");
        });
    }

    /// Integers arrive from the environment as strings and have to be coerced.
    #[test]
    fn env_override_applies_to_a_nested_integer_field() {
        with_var("P2POOL_API__PORT", Some("59999"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_eq!(config.api.port, 59999);
        });
    }

    /// Booleans are coerced from strings the same way integers are.
    #[test]
    fn env_override_applies_to_a_nested_bool_field() {
        with_var("P2POOL_LOGGING__CONSOLE", Some("false"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_eq!(config.logging.console, Some(false));
        });
    }

    /// An Option<String> field is populated, not left None.
    #[test]
    fn env_override_applies_to_a_nested_option_field() {
        with_var("P2POOL_LOGGING__FILE", Some("/tmp/env.log"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_eq!(config.logging.file, Some("/tmp/env.log".to_string()));
        });
    }

    /// A field whose own name contains an underscore is reachable, because the
    /// nesting separator is `__` and single underscores stay part of the key.
    ///
    /// With a single-underscore separator this override was silently discarded:
    /// `P2POOL_STORE_PPLNS_TTL_DAYS` addressed `store.pplns.ttl.days`, which
    /// does not exist, so the file value survived and nothing reported it.
    #[test]
    fn env_override_reaches_a_field_whose_name_contains_an_underscore() {
        with_var("P2POOL_STORE__PPLNS_TTL_DAYS", Some("99"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_eq!(config.store.pplns_ttl_days, 99);
        });
    }

    /// The listen address is the other field docker-compose sets that a
    /// single-underscore separator could not reach.
    #[test]
    fn env_override_reaches_the_network_listen_address() {
        with_var(
            "P2POOL_NETWORK__LISTEN_ADDRESS",
            Some("/ip4/10.0.0.1/tcp/6884"),
            || {
                let config = Config::load("../config.sample.toml").unwrap();
                assert_eq!(config.network.listen_address, "/ip4/10.0.0.1/tcp/6884");
            },
        );
    }

    /// A single-underscore key no longer resolves, so an operator carrying the
    /// old spelling forward gets the file value rather than a silent surprise
    /// in a different field.
    #[test]
    fn env_override_ignores_the_old_single_underscore_spelling() {
        with_var("P2POOL_API_PORT", Some("59999"), || {
            let config = Config::load("../config.sample.toml").unwrap();
            assert_ne!(config.api.port, 59999);
        });
    }

    /// The exact keys docker/docker-compose.p2poolv2.yml sets, asserted
    /// together so the container and the config schema cannot drift apart.
    ///
    /// Compose deliberately does not set `stratum.network` or
    /// `bitcoinrpc.url`. Those are the operator's, from the mounted
    /// config.toml: an override here would silently contradict that file and
    /// fail late, either on the wrong chain or against the wrong bitcoind.
    /// `env_override_reaches_the_network_listen_address` covers the one key
    /// that used to be unreachable and now applies.
    #[test]
    fn env_overrides_used_by_docker_compose_all_apply() {
        temp_env::with_vars(
            [
                ("P2POOL_STORE__PATH", Some("/p2poolv2/data/signet")),
                ("P2POOL_STRATUM__PORT", Some("3333")),
                ("P2POOL_API__PORT", Some("46884")),
                (
                    "P2POOL_NETWORK__LISTEN_ADDRESS",
                    Some("/ip4/0.0.0.0/tcp/6884"),
                ),
            ],
            || {
                let config = Config::load("../config.sample.toml").unwrap();
                assert_eq!(config.store.path, "/p2poolv2/data/signet");
                assert_eq!(config.stratum.port, 3333);
                assert_eq!(config.api.port, 46884);
                assert_eq!(config.network.listen_address, "/ip4/0.0.0.0/tcp/6884");
            },
        );
    }

    /// The bitcoind endpoint must stay a passthrough in compose, never a
    /// forced value.
    #[test]
    fn docker_compose_passes_the_bitcoind_endpoint_through_without_a_default() {
        let entries: Vec<&str> = include_str!("../../docker/docker-compose.p2poolv2.yml")
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("- P2POOL_"))
            .collect();
        let endpoint = entries
            .iter()
            .find(|line| line.contains("BITCOINRPC__URL"))
            .expect("compose should pass the bitcoind endpoint through");
        assert_eq!(
            *endpoint, "- P2POOL_BITCOINRPC__URL",
            "must be a bare passthrough, with no value or default"
        );
    }

    /// NETWORK drives both the chain and the store directory, and is required
    /// rather than defaulted.
    #[test]
    fn docker_compose_requires_network_and_uses_it_for_chain_and_store() {
        let entries: Vec<&str> = include_str!("../../docker/docker-compose.p2poolv2.yml")
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("- P2POOL_"))
            .collect();
        let chain = entries
            .iter()
            .find(|line| line.contains("STRATUM__NETWORK"))
            .expect("compose should set the chain from NETWORK");
        assert!(
            chain.contains("${NETWORK:?"),
            "NETWORK must be required, not defaulted: {chain}"
        );
        let store = entries
            .iter()
            .find(|line| line.contains("STORE__PATH"))
            .expect("compose should set the store path");
        assert!(
            store.contains("${NETWORK}"),
            "store path must follow the same NETWORK as the chain: {store}"
        );
    }

    #[test]
    fn test_config_from_env_vars() {
        with_var(
            "P2POOL_BITCOINRPC__URL",
            Some("http://bitcoin-from-env:8332"),
            || {
                // Load config from file first
                let config = Config::load("../config.sample.toml").unwrap();

                // Check that the environment variable overrides the config file value
                assert_eq!(config.bitcoinrpc.url, "http://bitcoin-from-env:8332");
            },
        );
    }

    #[test]
    fn test_default_network_config() {
        let config = NetworkConfig::default();
        assert!(config.listen_address.is_empty());
    }

    /// A share address belongs to a network exactly when its prefix is the one
    /// that network expects, so a network with no prefix can never accept one.
    /// Caught at startup: otherwise the node runs and rejects every authorize,
    /// forever, for a reason no miner can fix.
    ///
    /// `miner_address` is unset here, which is an ordinary p2poolv2 setup --
    /// miners supply their own with `p2p=`. So the network cannot be validated
    /// through a configured address; it has to be checked on its own.
    #[test]
    fn parse_rejects_a_network_with_no_share_address_prefix() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.network = Network::Testnet;
        config.mode = PoolMode::P2poolv2;
        assert!(config.miner_address.is_none());

        let error = config.parse().expect_err("testnet v3 has no share prefix");
        assert!(
            error.message.contains("cannot be used for a share chain"),
            "unexpected message: {}",
            error.message
        );
    }

    /// Hydrapool builds no share commitment, so it needs no share address and
    /// must not be held to a rule that does not apply to it.
    #[test]
    fn parse_allows_an_unusable_network_in_hydrapool_mode() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.network = Network::Testnet;
        config.mode = PoolMode::Hydrapool;
        config.miner_address = None;

        assert!(config.parse().is_ok());
    }

    #[test]
    fn test_pool_signature_option() {
        // Test with None
        let config = StratumConfig::<Raw>::new_for_test_default();
        assert_eq!(config.pool_signature, None);

        // Test parsing preserves pool_signature
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.pool_signature, None);

        // Test with Some value
        let mut config_with_sig = StratumConfig::<Raw>::new_for_test_default();
        config_with_sig.pool_signature = Some("MyPool/1.0".to_string());
        assert_eq!(
            config_with_sig.pool_signature,
            Some("MyPool/1.0".to_string())
        );

        // Test parsing preserves Some value
        let parsed_with_sig = config_with_sig.parse().unwrap();
        assert_eq!(
            parsed_with_sig.pool_signature,
            Some("MyPool/1.0".to_string())
        );

        // Test sig length limit
        let mut config_with_sig = StratumConfig::<Raw>::new_for_test_default();
        config_with_sig.pool_signature = Some("MyPool/1.0 and some more bytes....".to_string());
        assert_err!(config_with_sig.parse());
    }

    #[test]
    fn test_parse_fails_donation_address_without_amount() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.donation_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.donation = None;
        let result = config.parse();
        assert_err!(&result);
        assert!(
            result
                .unwrap_err()
                .message
                .contains("donation_address and donation")
        );
    }

    #[test]
    fn test_parse_fails_donation_amount_without_address() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.donation_address = None;
        config.donation = Some(50);
        let result = config.parse();
        assert_err!(&result);
        assert!(
            result
                .unwrap_err()
                .message
                .contains("donation_address and donation")
        );
    }

    #[test]
    fn test_parse_fails_fee_address_without_amount() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.fee_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.fee = None;
        let result = config.parse();
        assert_err!(&result);
        assert!(result.unwrap_err().message.contains("fee_address and fee"));
    }

    #[test]
    fn test_parse_fails_fee_amount_without_address() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.fee_address = None;
        config.fee = Some(200);
        let result = config.parse();
        assert_err!(&result);
        assert!(result.unwrap_err().message.contains("fee_address and fee"));
    }

    #[test]
    fn test_parse_succeeds_with_both_donation_fields() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.donation_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.donation = Some(50);
        let parsed = config.parse().unwrap();
        assert!(parsed.donation_address_parsed.is_some());
        assert_eq!(parsed.donation, Some(50));
    }

    #[test]
    fn test_parse_succeeds_with_both_fee_fields() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.fee_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.fee = Some(200);
        let parsed = config.parse().unwrap();
        assert!(parsed.fee_address_parsed.is_some());
        assert_eq!(parsed.fee, Some(200));
    }

    #[test]
    fn test_parse_succeeds_with_neither_donation_nor_fee() {
        let config = StratumConfig::<Raw>::new_for_test_default();
        assert!(config.donation_address.is_none());
        assert!(config.donation.is_none());
        assert!(config.fee_address.is_none());
        assert!(config.fee.is_none());
        let parsed = config.parse().unwrap();
        assert!(parsed.donation_address_parsed.is_none());
        assert!(parsed.fee_address_parsed.is_none());
    }

    #[test]
    fn test_pool_mode_defaults_to_p2poolv2_when_absent() {
        let config = Config::load("../config.sample.toml").unwrap();
        assert_eq!(config.stratum.mode, PoolMode::P2poolv2);
    }

    #[test]
    fn test_pool_mode_defaults_to_p2poolv2_in_test_helper() {
        let config = StratumConfig::<Raw>::new_for_test_default();
        assert_eq!(config.mode, PoolMode::P2poolv2);
    }

    #[test]
    fn test_pool_mode_survives_parse() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.mode = PoolMode::Hydrapool;
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.mode, PoolMode::Hydrapool);
    }

    #[test]
    fn absent_chain_stays_on_bitcoin() {
        let config = Config::load("../config.sample.toml").unwrap();
        assert_eq!(config.stratum.chain, Chain::Bitcoin);
        assert_eq!(config.stratum.bitcoin_cash_network, None);
    }

    #[test]
    fn bitcoin_cash_chipnet_accepts_a_matching_cashaddr_payout() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t".to_string();

        let parsed = config.parse().unwrap();
        assert_eq!(parsed.chain, Chain::BitcoinCash);
        assert_eq!(
            parsed.bitcoin_cash_network,
            Some(BitcoinCashNetwork::Chipnet)
        );
        assert_eq!(
            parsed.bootstrap_address().script_pubkey().as_bytes(),
            [
                0xa9, 0x14, 0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c, 0xca,
                0x47, 0x93, 0xf8, 0xeb, 0x2b, 0x6c, 0xda, 0xc9, 0x87,
            ]
        );
    }

    #[test]
    fn bitcoin_cash_accepts_a_share_address_and_rejects_a_payout_address() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t".to_string();
        config.miner_address =
            Some(BchShareAddress::new(BchShareNetwork::Chipnet, [0x22; 20]).encode());
        let parsed = config.parse().unwrap();
        assert_eq!(
            parsed.bch_miner_address().map(|address| address.hash),
            Some([0x22; 20])
        );
        assert!(parsed.miner_address().is_none());

        let mut payout_as_share = StratumConfig::<Raw>::new_for_test_default();
        payout_as_share.chain = Chain::BitcoinCash;
        payout_as_share.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        payout_as_share.bootstrap_address =
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t".to_string();
        payout_as_share.miner_address =
            Some("bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t".to_string());
        assert!(payout_as_share.parse().is_err());
    }

    #[test]
    fn bitcoin_cash_rejects_a_bitcoin_witness_payout() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Regtest);

        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("Invalid Bitcoin Cash payout address"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_cash_requires_its_network() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;

        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("bitcoin_cash_network is required when chain is bitcoin-cash"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_rejects_a_bitcoin_cash_network() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Mainnet);

        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("bitcoin_cash_network is only valid when chain is bitcoin-cash"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_rejects_a_mini_share_chain() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.bch_share_chain = BchShareChain::Mini;

        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("bch_share_chain = mini is only valid when chain is bitcoin-cash"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_cash_regtest_parses_on_the_regtest_network_whatever_network_says() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Regtest);
        config.network = Network::Signet;
        config.bootstrap_address = "bchreg:qqzldt8u5mafprrw6uljppyqg30uhl97ey890dqm34".to_string();
        assert_eq!(config.effective_network(), Network::Regtest);
        assert_eq!(config.parse().unwrap().network, Network::Regtest);
    }

    #[test]
    fn bitcoin_cash_mainnet_uses_the_bitcoin_network() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Mainnet);
        config.network = Network::Signet;
        assert_eq!(config.effective_network(), Network::Bitcoin);
    }

    #[test]
    fn bitcoin_cash_chipnet_uses_the_testnet_network() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.network = Network::Signet;
        assert_eq!(config.effective_network(), Network::Testnet);
    }

    #[test]
    fn bitcoin_keeps_its_configured_network() {
        let config = StratumConfig::<Raw>::new_for_test_default();
        assert_eq!(config.effective_network(), Network::Signet);
    }

    #[test]
    fn bitcoin_cash_accepts_the_mini_share_chain() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t".to_string();
        config.bch_share_chain = BchShareChain::Mini;

        let parsed = config.parse().unwrap();
        assert_eq!(parsed.bch_share_chain, BchShareChain::Mini);
    }
}

#[cfg(test)]
mod bitcoin_cash_donation_tests {
    use super::*;

    const CHIPNET_BOOTSTRAP: &str = "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t";
    const MAINNET_BOOTSTRAP: &str = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";

    #[test]
    fn mainnet_donation_string_decodes_to_the_built_in_key() {
        let decoded = cashaddr::decode(BITCOIN_CASH_DONATION_ADDRESS, BitcoinCashNetwork::Mainnet)
            .unwrap()
            .to_address();
        assert_eq!(
            decoded,
            bitcoin_cash_donation_address(BitcoinCashNetwork::Mainnet)
        );
    }

    #[test]
    fn chipnet_donation_string_decodes_to_the_built_in_key() {
        let decoded = cashaddr::decode(
            bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet),
            BitcoinCashNetwork::Chipnet,
        )
        .unwrap()
        .to_address();
        assert_eq!(
            decoded,
            bitcoin_cash_donation_address(BitcoinCashNetwork::Chipnet)
        );
    }

    #[test]
    fn regtest_donation_string_decodes_to_the_built_in_key() {
        let decoded = cashaddr::decode(
            bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Regtest),
            BitcoinCashNetwork::Regtest,
        )
        .unwrap()
        .to_address();
        assert_eq!(
            decoded,
            bitcoin_cash_donation_address(BitcoinCashNetwork::Regtest)
        );
    }

    #[test]
    fn bitcoin_cash_donates_one_and_a_half_percent_by_default() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, Some(150));
        assert_eq!(
            parsed.donation_address(),
            Some(&bitcoin_cash_donation_address(BitcoinCashNetwork::Chipnet))
        );
    }

    #[test]
    fn bitcoin_cash_mainnet_default_pays_the_published_address() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Mainnet);
        config.bootstrap_address = MAINNET_BOOTSTRAP.to_string();
        let parsed = config.parse().unwrap();
        let published =
            cashaddr::decode(BITCOIN_CASH_DONATION_ADDRESS, BitcoinCashNetwork::Mainnet)
                .unwrap()
                .to_address();
        assert_eq!(parsed.donation, Some(DEFAULT_BITCOIN_CASH_DONATION));
        assert_eq!(parsed.donation_address(), Some(&published));
    }

    #[test]
    fn bitcoin_cash_donation_can_be_raised() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation = Some(300);
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, Some(300));
        assert!(parsed.donation_address().is_some());
    }

    #[test]
    fn bitcoin_cash_donation_can_be_lowered() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation = Some(50);
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, Some(50));
        assert!(parsed.donation_address().is_some());
    }

    #[test]
    fn bitcoin_cash_donation_of_zero_opts_out() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation = Some(0);
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, None);
        assert!(parsed.donation_address().is_none());
    }

    #[test]
    fn bitcoin_cash_accepts_the_built_in_donation_address_written_out() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation_address =
            Some(bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet).to_string());
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, Some(DEFAULT_BITCOIN_CASH_DONATION));
        assert_eq!(
            parsed.donation_address(),
            Some(&bitcoin_cash_donation_address(BitcoinCashNetwork::Chipnet))
        );
    }

    #[test]
    fn bitcoin_cash_rejects_another_donation_address() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation_address = Some(CHIPNET_BOOTSTRAP.to_string());
        config.donation = Some(150);
        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("donation_address on bitcoin-cash is fixed"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_cash_pays_an_operator_fee_beside_the_donation() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.fee_address = Some(CHIPNET_BOOTSTRAP.to_string());
        config.fee = Some(100);
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, Some(DEFAULT_BITCOIN_CASH_DONATION));
        assert_eq!(parsed.fee, Some(100));
        assert!(parsed.fee_address().is_some());
    }

    #[test]
    fn bitcoin_cash_accepts_cuts_at_the_share_chain_cap() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.fee_address = Some(CHIPNET_BOOTSTRAP.to_string());
        config.fee = Some(MAX_BITCOIN_CASH_POOL_CUT - DEFAULT_BITCOIN_CASH_DONATION);
        assert!(config.parse().is_ok());
    }

    #[test]
    fn bitcoin_cash_rejects_cuts_above_the_share_chain_cap() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.fee_address = Some(CHIPNET_BOOTSTRAP.to_string());
        config.fee = Some(MAX_BITCOIN_CASH_POOL_CUT - DEFAULT_BITCOIN_CASH_DONATION + 1);
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("must be at most 1000 basis points"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_cash_fee_may_use_the_whole_cap_when_the_donation_is_off() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Chipnet);
        config.bootstrap_address = CHIPNET_BOOTSTRAP.to_string();
        config.donation = Some(0);
        config.fee_address = Some(CHIPNET_BOOTSTRAP.to_string());
        config.fee = Some(MAX_BITCOIN_CASH_POOL_CUT);
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.donation, None);
        assert_eq!(parsed.fee, Some(MAX_BITCOIN_CASH_POOL_CUT));
    }

    #[test]
    fn bitcoin_has_no_default_donation() {
        let parsed = StratumConfig::<Raw>::new_for_test_default()
            .parse()
            .unwrap();
        assert_eq!(parsed.donation, None);
        assert!(parsed.donation_address().is_none());
    }

    #[test]
    fn bitcoin_rejects_a_donation_above_one_hundred_percent() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.donation_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.donation = Some(MAX_BASIS_POINTS + 1);
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("must each be at most 10000"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_rejects_a_fee_above_one_hundred_percent() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.fee_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.fee = Some(MAX_BASIS_POINTS + 1);
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("must each be at most 10000"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn bitcoin_still_accepts_a_full_donation() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.donation_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());
        config.donation = Some(MAX_BASIS_POINTS);
        assert_eq!(config.parse().unwrap().donation, Some(MAX_BASIS_POINTS));
    }
}

#[cfg(test)]
mod sv2_authority_tests {
    use super::*;

    /// Test vectors from the Stratum V2 reference implementation's
    /// key-utils crate: a secret key and the public key it derives.
    const SECRET_KEY: &str = "zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi";
    const PUBLIC_KEY: &str = "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan";

    #[test]
    fn reference_implementation_key_pair_parses() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        let authority = config.parse().unwrap().sv2_authority().unwrap();
        assert_eq!(authority.cert_validity_secs, DEFAULT_SV2_CERT_VALIDITY_SECS);
        assert!(!format!("{authority:?}").contains(&format!("{:?}", authority.secret_key)));
    }

    #[test]
    fn a_certificate_validity_that_does_not_fit_32_bits_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        config.sv2_cert_validity_secs = Some(u64::from(u32::MAX) + 1);
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("sv2_cert_validity_secs"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_zero_certificate_validity_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        config.sv2_cert_validity_secs = Some(0);
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("sv2_cert_validity_secs"),
            "{}",
            error.message
        );
    }

    #[test]
    fn no_keys_means_no_noise() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        assert!(config.parse().unwrap().sv2_authority().is_none());
    }

    #[test]
    fn a_public_key_alone_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("both be set"), "{}", error.message);
    }

    #[test]
    fn keys_without_an_sv2_port_are_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("need sv2_port"), "{}", error.message);
    }

    #[test]
    fn a_corrupted_public_key_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        // The reference implementation's bad-checksum vector.
        config.sv2_authority_public_key =
            Some("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnam".to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        assert!(config.parse().is_err());
    }

    #[test]
    fn a_public_key_of_another_version_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        // The reference implementation's version-12 vector.
        config.sv2_authority_public_key =
            Some("2myPhc5vkPzuC5FXNK5tee79WmP7uoLh55SxezoF8iqwF3E3rnPY".to_string());
        config.sv2_authority_secret_key = Some(SECRET_KEY.to_string());
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("version 1"), "{}", error.message);
    }

    #[test]
    fn a_secret_key_for_another_public_key_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key = Some(PUBLIC_KEY.to_string());
        // Base58Check of 32 bytes of 0x01: a valid secret for another key.
        config.sv2_authority_secret_key = Some(base58::encode_check(&[1u8; 32]));
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("derives"), "{}", error.message);
    }
}

#[cfg(test)]
mod template_provider_tests {
    use super::*;
    use temp_env::with_vars;

    /// The Stratum V2 reference implementation's key-utils vectors.
    const SECRET_KEY: &str = "zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi";
    const PUBLIC_KEY: &str = "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan";

    fn bitcoin_cash_config() -> StratumConfig<Raw> {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.chain = Chain::BitcoinCash;
        config.bitcoin_cash_network = Some(BitcoinCashNetwork::Regtest);
        config.bootstrap_address = "bchreg:qqzldt8u5mafprrw6uljppyqg30uhl97ey890dqm34".to_string();
        config
    }

    #[test]
    fn absent_template_source_takes_templates_over_rpc() {
        let parsed = bitcoin_cash_config().parse().unwrap();
        assert_eq!(parsed.template_source, TemplateSource::Rpc);
        assert!(parsed.template_provider().is_none());
    }

    #[test]
    fn the_sample_configuration_takes_templates_over_rpc() {
        let config = Config::load("../config.sample.toml").unwrap();
        assert_eq!(config.stratum.template_source, TemplateSource::Rpc);
        assert_eq!(config.stratum.template_provider_address, None);
    }

    #[test]
    fn template_source_sv2_deserializes_with_its_provider_address() {
        with_vars(
            [
                ("P2POOL_STRATUM__TEMPLATE_SOURCE", Some("sv2")),
                (
                    "P2POOL_STRATUM__TEMPLATE_PROVIDER_ADDRESS",
                    Some("127.0.0.1:8442"),
                ),
            ],
            || {
                let config = Config::load("../config.sample.toml").unwrap();
                assert_eq!(config.stratum.template_source, TemplateSource::Sv2);
                assert_eq!(
                    config.stratum.template_provider_address.as_deref(),
                    Some("127.0.0.1:8442")
                );
            },
        );
    }

    #[test]
    fn a_loopback_provider_without_a_key_is_spoken_to_unencrypted() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("127.0.0.1:8442".to_string());
        let parsed = config.parse().unwrap();
        assert_eq!(
            parsed.template_provider(),
            Some(&TemplateProvider {
                address: "127.0.0.1:8442".to_string(),
                authority_public_key: None,
                network: BitcoinCashNetwork::Regtest,
            })
        );
    }

    #[test]
    fn localhost_counts_as_a_loopback_provider() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("localhost:8442".to_string());
        assert!(config.parse().unwrap().template_provider().is_some());
    }

    #[test]
    fn a_bracketed_ipv6_loopback_provider_needs_no_key() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("[::1]:8442".to_string());
        assert!(config.parse().unwrap().template_provider().is_some());
    }

    #[test]
    fn a_remote_provider_with_its_key_pins_that_key() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("node.example:8442".to_string());
        config.template_provider_authority_public_key = Some(PUBLIC_KEY.to_string());
        let parsed = config.parse().unwrap();
        let secret = SecretKey::from_slice(&base58::decode_check(SECRET_KEY).unwrap()).unwrap();
        let expected = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
            .x_only_public_key()
            .0
            .serialize();
        assert_eq!(
            parsed.template_provider().unwrap().authority_public_key,
            Some(expected)
        );
    }

    #[test]
    fn a_remote_provider_without_a_key_is_rejected() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("192.0.2.7:8442".to_string());
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("another computer"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_corrupted_provider_key_is_rejected() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("127.0.0.1:8442".to_string());
        // The reference implementation's bad-checksum vector.
        config.template_provider_authority_public_key =
            Some("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnam".to_string());
        let error = config.parse().unwrap_err();
        assert!(
            error
                .message
                .contains("template_provider_authority_public_key"),
            "{}",
            error.message
        );
    }

    #[test]
    fn sv2_templates_without_a_provider_address_are_rejected() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("needs template_provider_address"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_provider_address_without_a_port_is_rejected() {
        let mut config = bitcoin_cash_config();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("127.0.0.1".to_string());
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("HOST:PORT"), "{}", error.message);
    }

    #[test]
    fn sv2_templates_on_bitcoin_are_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.template_source = TemplateSource::Sv2;
        config.template_provider_address = Some("127.0.0.1:8442".to_string());
        let error = config.parse().unwrap_err();
        assert!(error.message.contains("bitcoin-cash"), "{}", error.message);
    }

    #[test]
    fn a_reconnect_without_host_or_port_keeps_the_provider() {
        let provider = TemplateProvider {
            address: "127.0.0.1:8442".to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        assert_eq!(provider.redirected("", 0).unwrap(), provider);
    }

    #[test]
    fn an_unencrypted_provider_may_redirect_to_another_port_on_this_computer() {
        let provider = TemplateProvider {
            address: "127.0.0.1:8442".to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        assert_eq!(
            provider.redirected("::1", 8443).unwrap().address,
            "[::1]:8443"
        );
    }

    #[test]
    fn an_unencrypted_provider_may_not_redirect_to_another_computer() {
        let provider = TemplateProvider {
            address: "127.0.0.1:8442".to_string(),
            authority_public_key: None,
            network: BitcoinCashNetwork::Regtest,
        };
        let error = provider.redirected("192.0.2.7", 8442).unwrap_err();
        assert!(
            error.message.contains("another computer"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_pinned_provider_keeps_its_key_when_it_redirects_to_another_computer() {
        let provider = TemplateProvider {
            address: "127.0.0.1:8442".to_string(),
            authority_public_key: Some([7; 32]),
            network: BitcoinCashNetwork::Regtest,
        };
        assert_eq!(
            provider.redirected("node.example", 0).unwrap(),
            TemplateProvider {
                address: "node.example:8442".to_string(),
                authority_public_key: Some([7; 32]),
                network: BitcoinCashNetwork::Regtest,
            }
        );
    }

    #[test]
    fn a_provider_address_with_rpc_templates_is_rejected() {
        let mut config = bitcoin_cash_config();
        config.template_provider_address = Some("127.0.0.1:8442".to_string());
        let error = config.parse().unwrap_err();
        assert!(
            error.message.contains("need template_source"),
            "{}",
            error.message
        );
    }
}

#[cfg(test)]
mod miner_address_tests {
    use super::*;

    /// BIP086 output key of the genesis NUMS pubkey, encoded for each network.
    /// The test helper config uses Signet.
    const SIGNET_ADDRESS: &str =
        "sp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls4zffd6";
    const TESTNET4_ADDRESS: &str =
        "tp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls3qc3th";

    /// A p2poolv2 pool with no configured address is a normal setup, not an
    /// edge case: each miner supplies its own with `p2p=`. The mode is set
    /// explicitly rather than left to `PoolMode::default()`, so this keeps
    /// covering p2poolv2 even if that default ever changes.
    #[test]
    fn absent_miner_address_parses_to_none() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.mode = PoolMode::P2poolv2;

        let parsed = config.parse().unwrap();
        assert!(parsed.miner_address().is_none());
        assert_eq!(parsed.mode, PoolMode::P2poolv2);
    }

    #[test]
    fn valid_miner_address_is_parsed_and_exposed() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some(SIGNET_ADDRESS.to_string());

        let parsed = config.parse().unwrap();

        assert_eq!(
            parsed.miner_address().map(|address| address.to_string()),
            Some(SIGNET_ADDRESS.to_string())
        );
        assert_eq!(parsed.miner_address().unwrap().network(), Network::Signet);
    }

    /// A share address for another network must be rejected at config parse,
    /// so the node fails at startup rather than assigning every share on the
    /// pool to an address the operator cannot use.
    #[test]
    fn miner_address_for_another_network_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some(TESTNET4_ADDRESS.to_string());

        let error = config.parse().unwrap_err();

        assert!(
            error.message.contains("share chain address"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn malformed_miner_address_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some("not-a-share-address".to_string());

        let error = config.parse().unwrap_err();

        assert!(
            error.message.contains("share chain address"),
            "unexpected message: {}",
            error.message
        );
    }

    /// A bitcoin address here is the mistake the whole address type exists to
    /// prevent, so it must fail loudly at startup.
    #[test]
    fn bitcoin_address_as_miner_address_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some("tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk".to_string());

        assert!(config.parse().is_err());
    }

    /// Hydrapool builds no share commitment, so the field could never be used.
    #[test]
    fn miner_address_with_hydrapool_mode_is_rejected() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some(SIGNET_ADDRESS.to_string());
        config.mode = PoolMode::Hydrapool;

        let error = config.parse().unwrap_err();

        assert!(
            error.message.contains("hydrapool"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn hydrapool_without_a_miner_address_still_parses() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.mode = PoolMode::Hydrapool;

        assert!(config.parse().is_ok());
    }

    #[test]
    fn miner_address_with_p2poolv2_mode_is_accepted() {
        let mut config = StratumConfig::<Raw>::new_for_test_default();
        config.miner_address = Some(SIGNET_ADDRESS.to_string());
        config.mode = PoolMode::P2poolv2;

        assert!(config.parse().is_ok());
    }
}
