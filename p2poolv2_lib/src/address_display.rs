// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

//! Display forms of the store's share types, carrying the miner address.
//!
//! A miner address is stored as the bare witness program it encodes: that is
//! what `ShareHeader` commits to, and it carries no network because the
//! network is not consensus data. Anything showing a miner address to a person
//! wants the bech32m form, and only the layers holding the configured network
//! -- the API and the CLI -- can build one.
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

use crate::store::dag_store::{DagEntry, ShareInfo, UncleInfo};
use bitcoin::{BlockHash, CompactTarget, Network, WitnessProgram};
use p2poolv2_address::witness_program_codec::{to_address_string, to_hex};
use serde::Serialize;

/// Render a miner address for `network`, or the witness program hex when
/// there is no network to render one for.
///
/// The CLI reaches the second case: `--config` is optional beside
/// `--db-path`, and guessing a network would name a chain this node may not
/// be on.
fn address_for(witness_program: &WitnessProgram, network: Option<Network>) -> String {
    match network {
        Some(network) => to_address_string(witness_program, network),
        None => to_hex(witness_program),
    }
}

/// A confirmed share as the API and CLI present it.
#[derive(Clone, Debug, Serialize)]
pub struct ShareInfoDisplay {
    pub blockhash: BlockHash,
    pub prev_blockhash: BlockHash,
    pub height: u32,
    pub miner_bitcoin_address: String,
    /// Miner address, rendered for the configured network.
    pub miner_address: String,
    pub timestamp: u32,
    pub bits: CompactTarget,
    pub uncles: Vec<UncleInfoDisplay>,
}

impl ShareInfoDisplay {
    pub fn from_share_info(share: &ShareInfo, network: Option<Network>) -> Self {
        Self {
            blockhash: share.blockhash,
            prev_blockhash: share.prev_blockhash,
            height: share.height,
            miner_bitcoin_address: share.miner_bitcoin_address.clone(),
            miner_address: address_for(&share.miner_address, network),
            timestamp: share.timestamp,
            bits: share.bits,
            uncles: share
                .uncles
                .iter()
                .map(|uncle| UncleInfoDisplay::from_uncle_info(uncle, network))
                .collect(),
        }
    }

    /// Convert a whole query result.
    pub fn from_share_infos(shares: &[ShareInfo], network: Option<Network>) -> Vec<Self> {
        shares
            .iter()
            .map(|share| Self::from_share_info(share, network))
            .collect()
    }
}

/// An uncle as the API and CLI present it.
#[derive(Clone, Debug, Serialize)]
pub struct UncleInfoDisplay {
    pub blockhash: BlockHash,
    pub prev_blockhash: BlockHash,
    pub miner_bitcoin_address: String,
    /// Miner address, rendered for the configured network.
    pub miner_address: String,
    pub timestamp: u32,
    pub height: Option<u32>,
}

impl UncleInfoDisplay {
    pub fn from_uncle_info(uncle: &UncleInfo, network: Option<Network>) -> Self {
        Self {
            blockhash: uncle.blockhash,
            prev_blockhash: uncle.prev_blockhash,
            miner_bitcoin_address: uncle.miner_bitcoin_address.clone(),
            miner_address: address_for(&uncle.miner_address, network),
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
    pub miner_bitcoin_address: String,
    /// Miner address, or `None` when the header could not be read. Kept as
    /// an absent value rather than a placeholder string, so a consumer can
    /// tell "no header" from an address that happens to read "unknown".
    pub miner_address: Option<String>,
    pub has_block_data: bool,
}

impl DagEntryDisplay {
    pub fn from_dag_entry(entry: &DagEntry, network: Option<Network>) -> Self {
        Self {
            blockhash: entry.blockhash,
            height: entry.height,
            validation_status: entry.validation_status.clone(),
            chain: entry.chain.clone(),
            parent: entry.parent,
            uncles: entry.uncles.clone(),
            miner_bitcoin_address: entry.miner_bitcoin_address.clone(),
            miner_address: entry
                .miner_address
                .as_ref()
                .map(|program| address_for(program, network)),
            has_block_data: entry.has_block_data,
        }
    }

    /// Convert a whole query result.
    pub fn from_dag_entries(entries: &[DagEntry], network: Option<Network>) -> Vec<Self> {
        entries
            .iter()
            .map(|entry| Self::from_dag_entry(entry, network))
            .collect()
    }
}

/// Render the miner address in a serialized array whose entries carry a
/// share header.
///
/// The exception to the typed display shapes above, and deliberately so.
/// `/share_headers` returns the *raw* consensus header, so a display struct
/// mirroring `ShareHeader` would drop any consensus field added later from an
/// endpoint whose whole contract is to expose them all. Rewriting the one
/// field that needs a network keeps every other field flowing through
/// untouched.
///
/// `header_at` selects the header for each element, so this serves both a
/// bare array of headers and an array of wrappers that flatten one.
pub fn render_header_addresses<T>(
    value: &mut serde_json::Value,
    entries: &[T],
    network: Network,
    header_at: impl Fn(&T) -> &crate::shares::share_block::ShareHeader,
) {
    for (index, entry) in entries.iter().enumerate() {
        value[index]["miner_address"] =
            serde_json::Value::String(to_address_string(&header_at(entry).miner_address, network));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestShareBlockBuilder, make_test_share_program};
    use bitcoin::hashes::Hash;

    fn share_info_with_uncle() -> ShareInfo {
        ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 2,
            miner_bitcoin_address: "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f".to_string(),
            miner_address: make_test_share_program(1),
            timestamp: 200,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![UncleInfo {
                blockhash: BlockHash::all_zeros(),
                prev_blockhash: BlockHash::all_zeros(),
                miner_bitcoin_address: "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f".to_string(),
                miner_address: make_test_share_program(2),
                timestamp: 100,
                height: Some(1),
            }],
        }
    }

    /// Uncles are nested, so they are the case a conversion forgets.
    #[test]
    fn renders_the_address_of_a_share_and_of_its_uncles() {
        let display =
            ShareInfoDisplay::from_share_info(&share_info_with_uncle(), Some(Network::Signet));

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

    /// One miner address is spelled differently per network. That spelling is
    /// what the consensus encoding deliberately omits.
    #[test]
    fn renders_the_address_for_the_given_network() {
        let share = share_info_with_uncle();
        assert!(
            ShareInfoDisplay::from_share_info(&share, Some(Network::Bitcoin))
                .miner_address
                .starts_with("p2pool1")
        );
        assert!(
            ShareInfoDisplay::from_share_info(&share, Some(Network::Testnet4))
                .miner_address
                .starts_with("tp2pool1")
        );
    }

    /// Without a network there is no human readable part to choose.
    #[test]
    fn falls_back_to_the_witness_program_hex_without_a_network() {
        let display = ShareInfoDisplay::from_share_info(&share_info_with_uncle(), None);
        assert_eq!(display.miner_address, to_hex(&make_test_share_program(1)));
    }

    #[test]
    fn carries_every_other_field_across_unchanged() {
        let share = share_info_with_uncle();
        let display = ShareInfoDisplay::from_share_info(&share, Some(Network::Signet));

        assert_eq!(display.blockhash, share.blockhash);
        assert_eq!(display.prev_blockhash, share.prev_blockhash);
        assert_eq!(display.height, share.height);
        assert_eq!(display.miner_bitcoin_address, share.miner_bitcoin_address);
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
            miner_bitcoin_address: "tb1qx6e0gj7q7xurl08cwnpmeve6w6zf4tw6vfwe3f".to_string(),
            miner_address: Some(make_test_share_program(1)),
            has_block_data: true,
        };
        let display = DagEntryDisplay::from_dag_entry(&entry, Some(Network::Signet));

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
            miner_bitcoin_address: "unknown".to_string(),
            miner_address: None,
            has_block_data: false,
        };
        let display = DagEntryDisplay::from_dag_entry(&entry, Some(Network::Signet));

        assert_eq!(display.miner_address, None);
    }

    #[test]
    fn renders_addresses_on_share_headers() {
        let headers = vec![TestShareBlockBuilder::new().build().header];
        let mut value = serde_json::to_value(&headers).unwrap();
        render_header_addresses(&mut value, &headers, Network::Signet, |header| header);

        assert!(
            value[0]["miner_address"]
                .as_str()
                .unwrap()
                .starts_with("sp2pool1")
        );
    }
}
