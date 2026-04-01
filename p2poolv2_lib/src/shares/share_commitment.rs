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

use super::address_serde;
use super::option_address_serde;
use super::share_block::ShareHeader;
use crate::pool_difficulty::PoolDifficulty;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::stratum::work::block_template::BlockTemplate;
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::io::Write;
use bitcoin::{Address, BlockHash, CompactTarget, hashes};
use serde::Serialize;
use std::error::Error;
use std::sync::Arc;

/// Share commitment created by miner and embedded in the bitcoin
/// coinbase to tie the share to the bitcoin weak block
///
/// When we need to build ShareHeader from the commitment, we move the
/// fields into the ShareHeader. This does mean there is some code
/// duplication, but we don't want to use indirection as
/// header.commitment.time.
///
/// Instead, we let the compiler catch discrepancies between the two
/// by implementing a From in ShareHeader
///
/// We only ever serialize received commitment to check against the
/// hash in coinbase input scriptsig. We therefore leave out
/// Deserialize, which Address<NetworkChecked> doesn't support.
#[derive(Clone, PartialEq, Debug, Serialize)]
pub struct ShareCommitment {
    /// The hash of the prev share block, will be None for genesis block
    pub prev_share_blockhash: BlockHash,
    /// The uncles of the share
    pub uncles: Vec<BlockHash>,
    /// Bitcoin address identifying the miner mining the share
    #[serde(serialize_with = "address_serde::serialize")]
    pub miner_bitcoin_address: Address,
    /// Share chain difficult as compact target
    pub bits: CompactTarget,
    /// Timestamp for the share, as set by the miner
    pub time: u32,
    /// Donation address for developers
    #[serde(serialize_with = "option_address_serde::serialize")]
    pub donation_address: Option<Address>,
    /// Donation in basis points
    pub donation: Option<u16>,
    /// Fee address for the pool operator
    #[serde(serialize_with = "option_address_serde::serialize")]
    pub fee_address: Option<Address>,
    /// Fee in basis points
    pub fee: Option<u16>,
    /// Total bitcoin coinbase value
    pub coinbase_value: u64,
}

impl ShareCommitment {
    /// Make a SHA256 hash for commitment using consensus encoding.
    ///
    /// Encodes all shared fields via consensus_encode, then appends
    /// the miner address script_pubkey and hashes the result.
    pub fn hash(&self) -> hashes::sha256::Hash {
        let mut serialized = Vec::new();
        self.consensus_encode(&mut serialized)
            .expect("encoding commitment should never fail");
        self.miner_bitcoin_address
            .script_pubkey()
            .consensus_encode(&mut serialized)
            .expect("encoding address script_pubkey should never fail");
        bitcoin::hashes::sha256::Hash::hash(&serialized)
    }

    /// Reconstruct a ShareCommitment from a ShareHeader.
    ///
    /// Copies all commitment fields from the header back into a
    /// ShareCommitment so that the commitment hash can be recomputed.
    pub fn from_share_header(header: &ShareHeader) -> Self {
        Self {
            prev_share_blockhash: header.prev_share_blockhash,
            uncles: header.uncles.clone(),
            miner_bitcoin_address: header.miner_bitcoin_address.clone(),
            bits: header.bits,
            time: header.time,
            donation_address: header.donation_address.clone(),
            donation: header.donation,
            fee_address: header.fee_address.clone(),
            fee: header.fee,
            coinbase_value: header.coinbase_value,
        }
    }
}

/// Encode an optional address as a bool flag followed by the address string when present.
fn encode_optional_address<W: Write + ?Sized>(
    address: &Option<Address>,
    writer: &mut W,
) -> Result<usize, bitcoin::io::Error> {
    let mut len = 0;
    match address {
        Some(addr) => {
            len += true.consensus_encode(writer)?;
            len += addr.to_string().consensus_encode(writer)?;
        }
        None => {
            len += false.consensus_encode(writer)?;
        }
    }
    Ok(len)
}

impl Encodable for ShareCommitment {
    /// Consensus-encode the shared fields of the commitment (excluding miner_bitcoin_address).
    ///
    /// Field order: prev_share_blockhash, uncles, bits, time,
    /// donation_address, donation, fee_address, fee.
    ///
    /// The miner_bitcoin_address is intentionally excluded so that the encoded bytes
    /// can be reused as a prefix across miners. Each miner only needs to
    /// append their address script_pubkey. The hash() method appends the
    /// script_pubkey before hashing.
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.prev_share_blockhash.consensus_encode(w)?;
        len += self.uncles.consensus_encode(w)?;
        len += self.bits.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;

        len += encode_optional_address(&self.donation_address, w)?;
        len += self.donation.unwrap_or(0).consensus_encode(w)?;
        len += encode_optional_address(&self.fee_address, w)?;
        len += self.fee.unwrap_or(0).consensus_encode(w)?;

        Ok(len)
    }
}

/// Build share commitment by querying the database for fields to set.
///
/// Computes the share chain target using the ASERT algorithm via
/// pool_difficulty, based on the current tip height and parent time.
/// Uses the current timestamp for the share.
pub(crate) fn build_share_commitment(
    chain_store_handle: &ChainStoreHandle,
    template: &Arc<BlockTemplate>,
    btcaddress: Option<Address>,
    pool_difficulty: &PoolDifficulty,
    donation_address: Option<Address>,
    donation: Option<u16>,
    fee_address: Option<Address>,
    fee: Option<u16>,
) -> Result<Option<ShareCommitment>, Box<dyn Error + Send + Sync>> {
    let (tip, uncles) = chain_store_handle.get_chain_tip_and_uncles()?;

    let (tip_height, parent_time) = chain_store_handle.get_tip_height_and_time()?;
    // tip_height is the parent height; ASERT internally adds 1 to height_delta
    let bitcoin_bits = bitcoin::CompactTarget::from_unprefixed_hex(&template.bits)
        .map_err(|error| format!("Failed to parse bitcoin bits from block template: {error}"))?;
    let target = pool_difficulty.calculate_target_clamped(parent_time, tip_height, bitcoin_bits);

    let time = SystemTimeProvider.seconds_since_epoch() as u32;

    match btcaddress {
        Some(address) => Ok(Some(ShareCommitment {
            prev_share_blockhash: tip,
            uncles: uncles.into_iter().collect(),
            miner_bitcoin_address: address,
            bits: target,
            time,
            donation_address,
            donation,
            fee_address,
            fee,
            coinbase_value: template.coinbasevalue,
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
    use crate::shares::witness_commitment::WitnessCommitment;
    use crate::store::writer::StoreError;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::test_utils::test_coinbase_transaction;
    use crate::test_utils::{TEST_TIP_TIME, create_test_commitment, on_schedule_pool_difficulty};
    use bitcoin::hashes::Hash;
    use bitcoin::{CompressedPublicKey, Network, TxMerkleNode};
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn test_hash_produces_valid_sha256() {
        let commitment = create_test_commitment();
        let hash = commitment.hash();

        // SHA256 hash should be 32 bytes
        assert_eq!(hash.as_byte_array().len(), 32);
        // Hash should not be all zeros
        assert_ne!(hash, hashes::sha256::Hash::all_zeros());
    }

    #[test]
    fn test_hash_determinism() {
        let commitment1 = create_test_commitment();
        let commitment2 = create_test_commitment();

        let hash1 = commitment1.hash();
        let hash2 = commitment2.hash();

        // Same commitment should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_uniqueness_different_prev_blockhash() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        commitment2.prev_share_blockhash =
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap();

        let hash1 = commitment1.hash();
        let hash2 = commitment2.hash();

        // Different commitments should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_uniqueness_different_btcaddress() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        let other_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        commitment2.miner_bitcoin_address = Address::p2wpkh(&other_pubkey, Network::Signet);

        let hash1 = commitment1.hash();
        let hash2 = commitment2.hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_uniqueness_different_time() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        commitment2.time = 1700000001;

        let hash1 = commitment1.hash();
        let hash2 = commitment2.hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_changes_with_different_fields() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        // Change each field and verify hash changes
        commitment2.bits = CompactTarget::from_consensus(0x20ffffff);
        assert_ne!(commitment1.hash(), commitment2.hash());

        let mut commitment3 = create_test_commitment();
        commitment3.uncles.push(BlockHash::all_zeros());
        assert_ne!(commitment1.hash(), commitment3.hash());
    }

    #[test]
    fn test_serialization_with_some_merkle_root() {
        let commitment = create_test_commitment();

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_serialization_without_merkle_root() {
        let commitment = create_test_commitment();

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_serialization_with_uncles() {
        let mut commitment = create_test_commitment();
        commitment.uncles.push(
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap(),
        );
        commitment.uncles.push(
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap(),
        );

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_build_share_commitment_success() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, Network::Signet);

        let pool_difficulty = on_schedule_pool_difficulty();

        let tip_hash =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();

        // Set up mock expectations
        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(move || Ok((tip_hash, HashSet::new())));

        chain_store_handle
            .expect_get_tip_height_and_time()
            .returning(|| Ok((0, TEST_TIP_TIME)));

        let result = build_share_commitment(
            &chain_store_handle,
            &template,
            Some(btcaddress.clone()),
            &pool_difficulty,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let commitment = result.unwrap().unwrap();

        // Verify fields are set correctly
        assert_eq!(
            commitment.prev_share_blockhash,
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap()
        );
        assert_eq!(commitment.uncles.len(), 0);
        assert_eq!(commitment.miner_bitcoin_address, btcaddress);
        // Pool ASERT target (0x1b4188f5) is harder than bitcoin target from
        // the template (0x1e0fffff), so the clamp returns bitcoin difficulty.
        let expected_bitcoin_bits =
            bitcoin::CompactTarget::from_unprefixed_hex(&template.bits).unwrap();
        assert_eq!(commitment.bits, expected_bitcoin_bits);
        // Time should be current, so just verify it's set
        assert!(commitment.time > 0);
    }

    #[test]
    fn test_build_share_commitment_with_uncles() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, Network::Signet);

        let pool_difficulty = on_schedule_pool_difficulty();

        let uncle1 =
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap();
        let uncle2 =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();

        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(move || {
                let uncles = HashSet::from([uncle1, uncle2]);
                Ok((BlockHash::all_zeros(), uncles))
            });

        chain_store_handle
            .expect_get_tip_height_and_time()
            .returning(|| Ok((0, TEST_TIP_TIME)));

        let result = build_share_commitment(
            &chain_store_handle,
            &template,
            Some(btcaddress),
            &pool_difficulty,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let commitment = result.unwrap().unwrap();

        // Verify uncles are set correctly
        assert_eq!(commitment.uncles.len(), 2);
        assert!(commitment.uncles.contains(&uncle1));
        assert!(commitment.uncles.contains(&uncle2));
    }

    #[test]
    fn test_build_share_commitment_error_on_chain_tip_failure() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let btcaddress = Address::p2wpkh(&pubkey, Network::Signet);

        let pool_difficulty = on_schedule_pool_difficulty();

        // Set up mock to return error on chain tip query
        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(|| Err(StoreError::Database("Failed to get chain tip".to_string())));

        let result = build_share_commitment(
            &chain_store_handle,
            &template,
            Some(btcaddress),
            &pool_difficulty,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_err());
    }

    #[test_log::test]
    fn test_build_share_commitment_with_none_btcaddress_returns_none() {
        let mut chain_store_handle = ChainStoreHandle::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let pool_difficulty = on_schedule_pool_difficulty();

        let uncle1 =
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap();
        let uncle2 =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();

        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(move || {
                let uncles = HashSet::from([uncle1, uncle2]);
                Ok((BlockHash::all_zeros(), uncles))
            });

        chain_store_handle
            .expect_get_tip_height_and_time()
            .returning(|| Ok((0, TEST_TIP_TIME)));

        let result = build_share_commitment(
            &chain_store_handle,
            &template,
            None,
            &pool_difficulty,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Build a ShareHeader from a commitment and a realistic bitcoin coinbase,
    /// returning both the header and the bitcoin transactions list.
    fn header_and_bitcoin_transactions_from_commitment(
        commitment: ShareCommitment,
    ) -> (ShareHeader, Vec<bitcoin::Transaction>) {
        let coinbase = test_coinbase_transaction(1);

        let share_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            [coinbase.clone()].iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();

        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template: BlockTemplate =
            serde_json::from_str(json_content).expect("Failed to parse template JSON");

        let mut bitcoin_transactions: Vec<bitcoin::Transaction> = template
            .transactions
            .iter()
            .map(bitcoin::Transaction::from)
            .collect();
        bitcoin_transactions.insert(0, coinbase);

        let template_merkle_root: TxMerkleNode = bitcoin::merkle_tree::calculate_root(
            bitcoin_transactions.iter().map(|tx| tx.compute_txid()),
        )
        .unwrap()
        .into();

        let bitcoin_header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(template.version),
            prev_blockhash: BlockHash::from_str(&template.previousblockhash).unwrap(),
            merkle_root: template_merkle_root,
            time: 1700000000,
            bits: CompactTarget::from_unprefixed_hex(&template.bits).unwrap(),
            nonce: 0,
        };

        let header = ShareHeader::from_commitment_and_header(
            commitment,
            bitcoin_header,
            share_merkle_root,
            template
                .coinbaseaux
                .get("flags")
                .and_then(|flags| hex::decode(flags).ok())
                .map(|bytes| CoinbaseAuxFlags::new(&bytes)),
            template
                .default_witness_commitment
                .as_deref()
                .and_then(|hex_str| WitnessCommitment::from_hex(hex_str).ok()),
            template.height as u64,
            0,
        );

        (header, bitcoin_transactions)
    }

    #[test]
    fn test_from_share_header_copies_header_fields() {
        let commitment = create_test_commitment();
        let expected_prev = commitment.prev_share_blockhash;
        let expected_uncles = commitment.uncles.clone();
        let expected_address = commitment.miner_bitcoin_address.clone();
        let expected_bits = commitment.bits;
        let expected_time = commitment.time;

        let (header, _bitcoin_transactions) =
            header_and_bitcoin_transactions_from_commitment(commitment);

        let reconstructed = ShareCommitment::from_share_header(&header);

        assert_eq!(reconstructed.prev_share_blockhash, expected_prev);
        assert_eq!(reconstructed.uncles, expected_uncles);
        assert_eq!(reconstructed.miner_bitcoin_address, expected_address);
        assert_eq!(reconstructed.bits, expected_bits);
        assert_eq!(reconstructed.time, expected_time);
    }

    #[test]
    fn test_from_share_header_hash_roundtrip() {
        // Build a commitment whose merkle_root matches the template transactions,
        // then verify from_share_header produces the same hash.
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template: BlockTemplate =
            serde_json::from_str(json_content).expect("Failed to parse template JSON");

        let commitment = create_test_commitment();
        let expected_hash = commitment.hash();

        let (header, _bitcoin_transactions) =
            header_and_bitcoin_transactions_from_commitment(commitment);

        let reconstructed = ShareCommitment::from_share_header(&header);

        assert_eq!(reconstructed.hash(), expected_hash);
    }

    #[test]
    fn test_hash_changes_with_donation_address() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        let donation_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        commitment2.donation_address = Some(Address::p2wpkh(&donation_pubkey, Network::Signet));
        commitment2.donation = Some(100);

        assert_ne!(commitment1.hash(), commitment2.hash());
    }

    #[test]
    fn test_hash_changes_with_fee_address() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        let fee_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        commitment2.fee_address = Some(Address::p2wpkh(&fee_pubkey, Network::Signet));
        commitment2.fee = Some(50);

        assert_ne!(commitment1.hash(), commitment2.hash());
    }

    #[test]
    fn test_hash_changes_with_different_donation_basis_points() {
        let donation_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let donation_address = Address::p2wpkh(&donation_pubkey, Network::Signet);

        let mut commitment1 = create_test_commitment();
        commitment1.donation_address = Some(donation_address.clone());
        commitment1.donation = Some(100);

        let mut commitment2 = create_test_commitment();
        commitment2.donation_address = Some(donation_address);
        commitment2.donation = Some(200);

        assert_ne!(commitment1.hash(), commitment2.hash());
    }

    #[test]
    fn test_from_share_header_copies_donation_and_fee_fields() {
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template: BlockTemplate =
            serde_json::from_str(json_content).expect("Failed to parse template JSON");

        let donation_pubkey = "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let donation_address = Address::p2wpkh(&donation_pubkey, Network::Signet);

        let fee_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let fee_address = Address::p2wpkh(&fee_pubkey, Network::Signet);

        let mut commitment = create_test_commitment();
        commitment.donation_address = Some(donation_address.clone());
        commitment.donation = Some(150);
        commitment.fee_address = Some(fee_address.clone());
        commitment.fee = Some(75);

        let expected_hash = commitment.hash();

        let (header, _bitcoin_transactions) =
            header_and_bitcoin_transactions_from_commitment(commitment);

        assert_eq!(header.donation_address, Some(donation_address));
        assert_eq!(header.donation, Some(150));
        assert_eq!(header.fee_address, Some(fee_address));
        assert_eq!(header.fee, Some(75));

        let reconstructed = ShareCommitment::from_share_header(&header);

        assert_eq!(reconstructed.hash(), expected_hash);
    }
}
