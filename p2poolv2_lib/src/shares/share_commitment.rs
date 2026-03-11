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
use bitcoin::{Address, BlockHash, CompactTarget, TxMerkleNode, hashes};
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
    pub miner_address: Address,
    /// Share block transactions merkle root. If there are no transactions, this is None.
    pub merkle_root: Option<TxMerkleNode>,
    /// Share chain difficult as compact target
    pub bits: CompactTarget,
    /// Timestamp for the share, as set by the miner
    pub time: u32,
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
        self.miner_address
            .script_pubkey()
            .consensus_encode(&mut serialized)
            .expect("encoding address script_pubkey should never fail");
        bitcoin::hashes::sha256::Hash::hash(&serialized)
    }
}

impl Encodable for ShareCommitment {
    /// Consensus-encode the shared fields of the commitment (excluding miner_address).
    ///
    /// Field order: prev_share_blockhash, uncles, merkle_root, bits, time.
    ///
    /// The miner_address is intentionally excluded so that the encoded bytes
    /// can be reused as a prefix across miners. Each miner only needs to
    /// append their address script_pubkey. The hash() method appends the
    /// script_pubkey before hashing.
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.prev_share_blockhash.consensus_encode(w)?;
        len += self.uncles.consensus_encode(w)?;

        match &self.merkle_root {
            Some(root) => {
                len += true.consensus_encode(w)?;
                len += root.consensus_encode(w)?;
            }
            None => {
                len += false.consensus_encode(w)?;
            }
        }

        len += self.bits.consensus_encode(w)?;
        len += self.time.consensus_encode(w)?;

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
) -> Result<Option<ShareCommitment>, Box<dyn Error + Send + Sync>> {
    let (tip, uncles) = chain_store_handle.get_chain_tip_and_uncles()?;

    let (tip_height, parent_time) = chain_store_handle.get_tip_height_and_time()?;
    // pass tip height, pool_difficulty adds 1 in the implementation
    let target = pool_difficulty.calculate_target(parent_time, tip_height);

    let merkle_root = template.get_merkle_root_without_coinbase();
    let time = SystemTimeProvider.seconds_since_epoch() as u32;

    match btcaddress {
        Some(address) => Ok(Some(ShareCommitment {
            prev_share_blockhash: tip,
            uncles: uncles.into_iter().collect(),
            miner_address: address,
            merkle_root,
            bits: target,
            time,
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::writer::StoreError;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::test_utils::{TEST_TIP_TIME, create_test_commitment, on_schedule_pool_difficulty};
    use bitcoin::hashes::Hash;
    use bitcoin::{CompressedPublicKey, Network};
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
        commitment2.miner_address = Address::p2wpkh(&other_pubkey, Network::Signet);

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

        let mut commitment4 = create_test_commitment();
        commitment4.merkle_root = None;
        assert_ne!(commitment1.hash(), commitment4.hash());
    }

    #[test]
    fn test_serialization_with_some_merkle_root() {
        let commitment = create_test_commitment();

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        assert!(!serialized.is_empty());
    }

    #[test]
    fn test_serialization_with_none_merkle_root() {
        let mut commitment = create_test_commitment();
        commitment.merkle_root = None;

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
        assert_eq!(commitment.miner_address, btcaddress);
        assert_eq!(commitment.bits, CompactTarget::from_consensus(0x1b4188f5));
        // Time should be current, so just verify it's set
        assert!(commitment.time > 0);
        // Merkle root should be None for template with no transactions
        assert_eq!(commitment.merkle_root, None);
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

        let result = build_share_commitment(&chain_store_handle, &template, None, &pool_difficulty);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
