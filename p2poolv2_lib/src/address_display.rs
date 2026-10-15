// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Display forms of the store's share types, carrying the miner address.
//!
//! A miner address is stored as the bare witness program it encodes: that is
//! what `ShareHeader` commits to, and it carries no network because the
//! network is not consensus data. Anything showing a miner address to a person
//! wants the bech32m form, and only the layers holding the configured network
//! -- the API and the CLI -- can build one.
//!
//! A payout address has the same problem on a Bitcoin Cash node. It is held
//! as a `bitcoin::Address` under the legacy network whose base58 version bytes
//! match (see `BitcoinCashNetwork::legacy_network`), so its `Display` is the
//! right key hash in Bitcoin's spelling. [`payout_address_string`] spells it
//! as the CashAddr the operator configured.
//!
//! These are the shapes those layers serve. They exist as their own types
//! rather than as a rewrite of serialized store types, so a response stays a
//! typed contract: adding a field to `ShareInfo` does not silently change the
//! wire, and removing one is a compile error here rather than a surprise for a
//! consumer.
//!
//! Both binaries share them because the CLI reads the store directly in
//! `--db-path` mode and never goes through the API, so each would otherwise
//! carry its own copy of the same mapping.

use crate::config::BitcoinCashNetwork;
use crate::shares::share_block::ShareHeader;
use crate::store::dag_store::{DagEntry, ShareInfo, UncleInfo};
use bitcoin::address::AddressData;
use bitcoin::hashes::Hash;
use bitcoin::{Address, BlockHash, CompactTarget, Network};
use p2poolv2_wallet::bch_share::{BchShareNetwork, CashAddrType, encode_cashaddr};
use p2poolv2_wallet::share_owner::{self, ShareOwner};
use serde::Serialize;
use serde_json::Value;

/// What a DAG entry shows for a payout address when its header could not be
/// read.
const UNKNOWN_PAYOUT_ADDRESS: &str = "unknown";

/// Render a miner address for `network`, or the witness program hex when
/// there is no network to render one for.
///
/// The CLI reaches the second case: `--config` is optional beside
/// `--db-path`, and guessing a network would name a chain this node may not
/// be on.
fn address_for(
    owner: &ShareOwner,
    network: Option<Network>,
    cash_network: Option<BchShareNetwork>,
) -> String {
    match network {
        Some(network) => share_owner::to_address_string(owner, network, cash_network),
        None => share_owner::to_hex(owner),
    }
}

/// Render a payout address for the chain this node mines.
///
/// Without a cash network this is a Bitcoin node, and the address keeps its
/// own form. With one, a pay to public key hash or pay to script hash payout
/// is spelled as CashAddr under that network's prefix (`bitcoincash`,
/// `bchtest` or `bchreg`). A Bitcoin Cash payout is always one of those two:
/// any other address has no CashAddr form, so it keeps its own form rather
/// than being hidden.
pub fn payout_address_string(address: &Address, cash_network: Option<BchShareNetwork>) -> String {
    match cash_network {
        Some(cash_network) => {
            let prefix = BitcoinCashNetwork::from_share_network(cash_network).cashaddr_prefix();
            match address.to_address_data() {
                AddressData::P2pkh { pubkey_hash } => encode_cashaddr(
                    prefix,
                    CashAddrType::PayToPublicKeyHash,
                    pubkey_hash.as_byte_array(),
                ),
                AddressData::P2sh { script_hash } => encode_cashaddr(
                    prefix,
                    CashAddrType::PayToScriptHash,
                    script_hash.as_byte_array(),
                ),
                _ => address.to_string(),
            }
        }
        None => address.to_string(),
    }
}

/// A confirmed share as the API and CLI present it.
#[derive(Clone, Debug, Serialize)]
pub struct ShareInfoDisplay {
    pub blockhash: BlockHash,
    pub prev_blockhash: BlockHash,
    pub height: u32,
    /// Payout address, rendered for the configured chain.
    pub miner_bitcoin_address: String,
    /// Miner address, rendered for the configured network.
    pub miner_address: String,
    pub timestamp: u32,
    pub bits: CompactTarget,
    pub uncles: Vec<UncleInfoDisplay>,
}

impl ShareInfoDisplay {
    pub fn from_share_info(
        share: &ShareInfo,
        network: Option<Network>,
        cash_network: Option<BchShareNetwork>,
    ) -> Self {
        Self {
            blockhash: share.blockhash,
            prev_blockhash: share.prev_blockhash,
            height: share.height,
            miner_bitcoin_address: payout_address_string(
                &share.miner_bitcoin_address,
                cash_network,
            ),
            miner_address: address_for(&share.miner_address, network, cash_network),
            timestamp: share.timestamp,
            bits: share.bits,
            uncles: share
                .uncles
                .iter()
                .map(|uncle| UncleInfoDisplay::from_uncle_info(uncle, network, cash_network))
                .collect(),
        }
    }

    /// Convert a whole query result.
    pub fn from_share_infos(
        shares: &[ShareInfo],
        network: Option<Network>,
        cash_network: Option<BchShareNetwork>,
    ) -> Vec<Self> {
        shares
            .iter()
            .map(|share| Self::from_share_info(share, network, cash_network))
            .collect()
    }
}

/// An uncle as the API and CLI present it.
#[derive(Clone, Debug, Serialize)]
pub struct UncleInfoDisplay {
    pub blockhash: BlockHash,
    pub prev_blockhash: BlockHash,
    /// Payout address, rendered for the configured chain.
    pub miner_bitcoin_address: String,
    /// Miner address, rendered for the configured network.
    pub miner_address: String,
    pub timestamp: u32,
    pub height: Option<u32>,
}

impl UncleInfoDisplay {
    pub fn from_uncle_info(
        uncle: &UncleInfo,
        network: Option<Network>,
        cash_network: Option<BchShareNetwork>,
    ) -> Self {
        Self {
            blockhash: uncle.blockhash,
            prev_blockhash: uncle.prev_blockhash,
            miner_bitcoin_address: payout_address_string(
                &uncle.miner_bitcoin_address,
                cash_network,
            ),
            miner_address: address_for(&uncle.miner_address, network, cash_network),
            timestamp: uncle.timestamp,
            height: uncle.height,
        }
    }
}

/// A DAG entry as the API and CLI present it.
#[derive(Clone, Debug, Serialize)]
pub struct DagEntryDisplay {
    pub blockhash: BlockHash,
    pub height: u32,
    /// Validation state only. Chain position is reported separately in `chain`.
    pub validation_status: String,
    pub chain: String,
    pub parent: BlockHash,
    pub uncles: Vec<BlockHash>,
    /// Payout address, rendered for the configured chain, or `unknown` when
    /// the header could not be read.
    pub miner_bitcoin_address: String,
    /// Miner address, or `None` when the header could not be read. Kept as
    /// an absent value rather than a placeholder string, so a consumer can
    /// tell "no header" from an address that happens to read "unknown".
    pub miner_address: Option<String>,
    pub has_block_data: bool,
}

impl DagEntryDisplay {
    pub fn from_dag_entry(
        entry: &DagEntry,
        network: Option<Network>,
        cash_network: Option<BchShareNetwork>,
    ) -> Self {
        Self {
            blockhash: entry.blockhash,
            height: entry.height,
            validation_status: entry.validation_status.clone(),
            chain: entry.chain.clone(),
            parent: entry.parent,
            uncles: entry.uncles.clone(),
            miner_bitcoin_address: entry
                .miner_bitcoin_address
                .as_ref()
                .map(|address| payout_address_string(address, cash_network))
                .unwrap_or_else(|| UNKNOWN_PAYOUT_ADDRESS.to_string()),
            miner_address: entry
                .miner_address
                .as_ref()
                .map(|program| address_for(program, network, cash_network)),
            has_block_data: entry.has_block_data,
        }
    }

    /// Convert a whole query result.
    pub fn from_dag_entries(
        entries: &[DagEntry],
        network: Option<Network>,
        cash_network: Option<BchShareNetwork>,
    ) -> Vec<Self> {
        entries
            .iter()
            .map(|entry| Self::from_dag_entry(entry, network, cash_network))
            .collect()
    }
}

/// Render the addresses in a serialized array whose entries carry a share
/// header: the miner address, the payout address, and the donation and fee
/// addresses when the header has them.
///
/// The exception to the typed display shapes above, and deliberately so.
/// `/share_headers` returns the *raw* consensus header, so a display struct
/// mirroring `ShareHeader` would drop any consensus field added later from an
/// endpoint whose whole contract is to expose them all. Rewriting the fields
/// that need a network keeps every other field flowing through untouched.
///
/// `header_at` selects the header for each element, so this serves both a
/// bare array of headers and an array of wrappers that flatten one.
pub fn render_header_addresses<T>(
    value: &mut Value,
    entries: &[T],
    network: Network,
    cash_network: Option<BchShareNetwork>,
    header_at: impl Fn(&T) -> &ShareHeader,
) {
    for (index, entry) in entries.iter().enumerate() {
        let header = header_at(entry);
        let rendered = &mut value[index];
        rendered["miner_address"] = Value::String(share_owner::to_address_string(
            &header.miner_address,
            network,
            cash_network,
        ));
        rendered["miner_bitcoin_address"] = Value::String(payout_address_string(
            &header.miner_bitcoin_address,
            cash_network,
        ));
        if let Some(donation_address) = &header.donation_address {
            rendered["donation_address"] =
                Value::String(payout_address_string(donation_address, cash_network));
        }
        if let Some(fee_address) = &header.fee_address {
            rendered["fee_address"] =
                Value::String(payout_address_string(fee_address, cash_network));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{bitcoin_cash_donation_address, bitcoin_cash_donation_cashaddr};
    use crate::test_utils::{
        TestShareBlockBuilder, make_test_share_program, parse_address_from_string,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{PubkeyHash, ScriptHash};
    use p2poolv2_wallet::bch_share::BchShareNetwork;
    use p2poolv2_wallet::share_owner::ShareOwner;
    use p2poolv2_wallet::witness_program_codec::{to_address_string, to_hex};

    /// A chipnet payout as a Bitcoin Cash node holds it, under the legacy
    /// testnet network, so its `Display` is this base58 string. It is also a
    /// valid Bitcoin testnet address, which a Bitcoin node must keep as is.
    const CHIPNET_PAYOUT_BASE58: &str = "n28xPk5xbxNaaht399cZP9WDvyTMwaYaGe";

    /// The same key hash as the CashAddr the operator configured.
    const CHIPNET_PAYOUT_CASHADDR: &str = "bchtest:qr3rryn6ugv8qpk82ccaqzk4ras92vpluvr2yclquu";

    /// The CashAddr specification's 20-byte hash.
    const SPECIFICATION_HASH: [u8; 20] = [
        0xf5, 0xbf, 0x48, 0xb3, 0x97, 0xda, 0xe7, 0x0b, 0xe8, 0x2b, 0x3c, 0xca, 0x47, 0x93, 0xf8,
        0xeb, 0x2b, 0x6c, 0xda, 0xc9,
    ];

    fn share_info_with_uncle() -> ShareInfo {
        ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 2,
            miner_bitcoin_address: parse_address_from_string(
                "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f",
            ),
            miner_address: make_test_share_program(1).into(),
            timestamp: 200,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![UncleInfo {
                blockhash: BlockHash::all_zeros(),
                prev_blockhash: BlockHash::all_zeros(),
                miner_bitcoin_address: parse_address_from_string(
                    "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f",
                ),
                miner_address: make_test_share_program(2).into(),
                timestamp: 100,
                height: Some(1),
            }],
        }
    }

    /// Uncles are nested, so they are the case a conversion forgets.
    #[test]
    fn renders_the_address_of_a_share_and_of_its_uncles() {
        let display = ShareInfoDisplay::from_share_info(
            &share_info_with_uncle(),
            Some(Network::Signet),
            None,
        );

        assert_eq!(
            display.miner_address,
            to_address_string(&make_test_share_program(1), Network::Signet)
        );
        assert_eq!(
            display.uncles[0].miner_address,
            to_address_string(&make_test_share_program(2), Network::Signet)
        );
        assert!(display.miner_address.starts_with("sp2pool1"));
    }

    /// A cash owner on a signet share chain still spells the cash prefix the
    /// operator configured. Signet must not become chipnet.
    #[test]
    fn renders_a_cash_owner_with_the_cash_network() {
        let mut share = share_info_with_uncle();
        share.miner_address = ShareOwner::CashP2pkh([0x22; 20]);
        let display = ShareInfoDisplay::from_share_info(
            &share,
            Some(Network::Signet),
            Some(BchShareNetwork::Mainnet),
        );
        assert!(display.miner_address.starts_with("p2pool:"));
    }

    /// One miner address is spelled differently per network. That spelling is
    /// what the consensus encoding deliberately omits.
    #[test]
    fn renders_the_address_for_the_given_network() {
        let share = share_info_with_uncle();
        assert!(
            ShareInfoDisplay::from_share_info(&share, Some(Network::Bitcoin), None)
                .miner_address
                .starts_with("p2pool1")
        );
        assert!(
            ShareInfoDisplay::from_share_info(&share, Some(Network::Testnet4), None)
                .miner_address
                .starts_with("tp2pool1")
        );
    }

    /// Without a network there is no human readable part to choose.
    #[test]
    fn falls_back_to_the_witness_program_hex_without_a_network() {
        let display = ShareInfoDisplay::from_share_info(&share_info_with_uncle(), None, None);
        assert_eq!(display.miner_address, to_hex(&make_test_share_program(1)));
    }

    #[test]
    fn carries_every_other_field_across_unchanged() {
        let share = share_info_with_uncle();
        let display = ShareInfoDisplay::from_share_info(&share, Some(Network::Signet), None);

        assert_eq!(display.blockhash, share.blockhash);
        assert_eq!(display.prev_blockhash, share.prev_blockhash);
        assert_eq!(display.height, share.height);
        assert_eq!(
            display.miner_bitcoin_address,
            share.miner_bitcoin_address.to_string()
        );
        assert_eq!(display.timestamp, share.timestamp);
        assert_eq!(display.bits, share.bits);
        assert_eq!(display.uncles[0].height, share.uncles[0].height);
        assert_eq!(display.uncles[0].timestamp, share.uncles[0].timestamp);
    }

    #[test]
    fn renders_a_dag_entry_address() {
        let entry = DagEntry {
            blockhash: BlockHash::all_zeros(),
            height: 1,
            validation_status: "BlockValid".to_string(),
            chain: "Confirmed".to_string(),
            parent: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: Some(parse_address_from_string(
                "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f",
            )),
            miner_address: Some(make_test_share_program(1).into()),
            has_block_data: true,
        };
        let display = DagEntryDisplay::from_dag_entry(&entry, Some(Network::Signet), None);

        assert_eq!(
            display.miner_address.as_deref(),
            Some(to_address_string(&make_test_share_program(1), Network::Signet).as_str())
        );
    }

    /// An entry whose header could not be read has no address, and must
    /// stay absent rather than gain a placeholder.
    #[test]
    fn leaves_a_dag_entry_without_a_header_absent() {
        let entry = DagEntry {
            blockhash: BlockHash::all_zeros(),
            height: 2,
            validation_status: "Unknown".to_string(),
            chain: "Unknown".to_string(),
            parent: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: None,
            miner_address: None,
            has_block_data: false,
        };
        let display = DagEntryDisplay::from_dag_entry(&entry, Some(Network::Signet), None);

        assert_eq!(display.miner_address, None);
    }

    #[test]
    fn renders_addresses_on_share_headers() {
        let headers = vec![TestShareBlockBuilder::new().build().header];
        let mut value = serde_json::to_value(&headers).unwrap();
        render_header_addresses(&mut value, &headers, Network::Signet, None, |header| header);

        assert!(
            value[0]["miner_address"]
                .as_str()
                .unwrap()
                .starts_with("sp2pool1")
        );
    }

    /// The chipnet case: the key hash was right, only the spelling was not.
    #[test]
    fn renders_a_cash_payout_as_cashaddr_with_the_configured_prefix() {
        let mut share = share_info_with_uncle();
        share.miner_bitcoin_address = parse_address_from_string(CHIPNET_PAYOUT_BASE58);
        let display = ShareInfoDisplay::from_share_info(
            &share,
            Some(Network::Testnet),
            Some(BchShareNetwork::Chipnet),
        );

        assert_eq!(display.miner_bitcoin_address, CHIPNET_PAYOUT_CASHADDR);
    }

    /// Uncles are nested, so they are the case a conversion forgets.
    #[test]
    fn renders_the_cash_payout_of_an_uncle_as_cashaddr() {
        let mut share = share_info_with_uncle();
        share.uncles[0].miner_bitcoin_address = parse_address_from_string(CHIPNET_PAYOUT_BASE58);
        let display = ShareInfoDisplay::from_share_info(
            &share,
            Some(Network::Testnet),
            Some(BchShareNetwork::Chipnet),
        );

        assert_eq!(
            display.uncles[0].miner_bitcoin_address,
            CHIPNET_PAYOUT_CASHADDR
        );
    }

    /// A Bitcoin node has no cash network. Its pay to public key hash payout
    /// is a Bitcoin address and stays base58.
    #[test]
    fn keeps_a_bitcoin_public_key_hash_payout_in_base58() {
        let mut share = share_info_with_uncle();
        share.miner_bitcoin_address = parse_address_from_string(CHIPNET_PAYOUT_BASE58);
        let display = ShareInfoDisplay::from_share_info(&share, Some(Network::Testnet), None);

        assert_eq!(display.miner_bitcoin_address, CHIPNET_PAYOUT_BASE58);
    }

    #[test]
    fn keeps_a_bitcoin_segwit_payout_unchanged() {
        let display = ShareInfoDisplay::from_share_info(
            &share_info_with_uncle(),
            Some(Network::Signet),
            None,
        );

        assert_eq!(
            display.miner_bitcoin_address,
            "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f"
        );
    }

    #[test]
    fn renders_a_mainnet_cash_payout_with_the_mainnet_prefix() {
        let address = Address::p2pkh(
            PubkeyHash::from_byte_array(SPECIFICATION_HASH),
            Network::Bitcoin,
        );

        assert_eq!(
            payout_address_string(&address, Some(BchShareNetwork::Mainnet)),
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );
    }

    #[test]
    fn renders_a_cash_script_hash_payout_as_cashaddr() {
        let address = Address::p2sh_from_hash(
            ScriptHash::from_byte_array(SPECIFICATION_HASH),
            Network::Testnet,
        );

        assert_eq!(
            payout_address_string(&address, Some(BchShareNetwork::Chipnet)),
            "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t"
        );
    }

    #[test]
    fn renders_a_cash_dag_entry_payout_as_cashaddr() {
        let entry = DagEntry {
            blockhash: BlockHash::all_zeros(),
            height: 1,
            validation_status: "BlockValid".to_string(),
            chain: "Confirmed".to_string(),
            parent: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: Some(parse_address_from_string(CHIPNET_PAYOUT_BASE58)),
            miner_address: Some(ShareOwner::CashP2pkh([0x22; 20])),
            has_block_data: true,
        };
        let display = DagEntryDisplay::from_dag_entry(
            &entry,
            Some(Network::Testnet),
            Some(BchShareNetwork::Chipnet),
        );

        assert_eq!(display.miner_bitcoin_address, CHIPNET_PAYOUT_CASHADDR);
    }

    /// The placeholder a DAG entry without a header has always shown.
    #[test]
    fn shows_unknown_for_the_payout_of_a_dag_entry_without_a_header() {
        let entry = DagEntry {
            blockhash: BlockHash::all_zeros(),
            height: 2,
            validation_status: "Unknown".to_string(),
            chain: "Unknown".to_string(),
            parent: BlockHash::all_zeros(),
            uncles: vec![],
            miner_bitcoin_address: None,
            miner_address: None,
            has_block_data: false,
        };
        let display = DagEntryDisplay::from_dag_entry(&entry, Some(Network::Signet), None);

        assert_eq!(display.miner_bitcoin_address, "unknown");
    }

    /// `/share_headers` shows the raw header, donation and fee included.
    #[test]
    fn renders_cash_payout_donation_and_fee_addresses_on_share_headers() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.miner_bitcoin_address = parse_address_from_string(CHIPNET_PAYOUT_BASE58);
        header.donation_address = Some(bitcoin_cash_donation_address(BitcoinCashNetwork::Chipnet));
        header.fee_address = Some(parse_address_from_string(CHIPNET_PAYOUT_BASE58));
        let headers = vec![header];
        let mut value = serde_json::to_value(&headers).unwrap();
        render_header_addresses(
            &mut value,
            &headers,
            Network::Testnet,
            Some(BchShareNetwork::Chipnet),
            |header| header,
        );

        assert_eq!(value[0]["miner_bitcoin_address"], CHIPNET_PAYOUT_CASHADDR);
        assert_eq!(
            value[0]["donation_address"],
            bitcoin_cash_donation_cashaddr(BitcoinCashNetwork::Chipnet)
        );
        assert_eq!(value[0]["fee_address"], CHIPNET_PAYOUT_CASHADDR);
    }

    #[test]
    fn keeps_payout_donation_and_fee_addresses_on_bitcoin_share_headers() {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.donation_address = Some(parse_address_from_string(
            "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f",
        ));
        header.fee_address = Some(parse_address_from_string(CHIPNET_PAYOUT_BASE58));
        let headers = vec![header];
        let serialized = serde_json::to_value(&headers).unwrap();
        let mut value = serialized.clone();
        render_header_addresses(&mut value, &headers, Network::Signet, None, |header| header);

        assert_eq!(
            value[0]["miner_bitcoin_address"],
            serialized[0]["miner_bitcoin_address"]
        );
        assert_eq!(
            value[0]["donation_address"],
            serialized[0]["donation_address"]
        );
        assert_eq!(value[0]["fee_address"], CHIPNET_PAYOUT_BASE58);
    }

    /// A header without donation or fee keeps them null, rather than
    /// gaining an address.
    #[test]
    fn leaves_absent_donation_and_fee_addresses_null_on_share_headers() {
        let headers = vec![TestShareBlockBuilder::new().build().header];
        let mut value = serde_json::to_value(&headers).unwrap();
        render_header_addresses(
            &mut value,
            &headers,
            Network::Testnet,
            Some(BchShareNetwork::Chipnet),
            |header| header,
        );

        assert_eq!(value[0]["donation_address"], Value::Null);
        assert_eq!(value[0]["fee_address"], Value::Null);
    }
}
