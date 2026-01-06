// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::stratum::work::block_template::BlockTemplate;
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::io::{Read, Write};
use bitcoin::{BlockHash, CompactTarget, CompressedPublicKey, TxMerkleNode, hashes};
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
    /// Pubkey identifying the miner mining the share
    pub miner_pubkey: CompressedPublicKey,
    /// Share block transactions merkle root. If there are no transactions, this is None.
    pub merkle_root: Option<TxMerkleNode>,
    /// Share chain difficult as compact target
    pub bits: CompactTarget,
    /// Timestamp for the share, as set by the miner
    pub time: u32,
}

impl ShareCommitment {
    /// Make a SHA256 hash for commitment using consensus encoding
    pub fn hash(&self) -> hashes::sha256::Hash {
        let mut serialized = Vec::new();
        self.consensus_encode(&mut serialized)
            .expect("encoding commitment should never fail");
        bitcoin::hashes::sha256::Hash::hash(&serialized)
    }
}

impl Encodable for ShareCommitment {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.prev_share_blockhash.consensus_encode(w)?;
        len += self.uncles.consensus_encode(w)?;

        // Encode CompressedPublicKey using write_into
        self.miner_pubkey.write_into(w)?;
        len += 33;

        // Encode Option<TxMerkleNode> manually
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

impl Decodable for ShareCommitment {
    fn consensus_decode<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let prev_share_blockhash = BlockHash::consensus_decode(r)?;
        let uncles = Vec::<BlockHash>::consensus_decode(r)?;

        // Decode CompressedPublicKey using read_from
        let miner_pubkey = CompressedPublicKey::read_from(r)?;

        // Decode Option<TxMerkleNode> manually
        let has_merkle_root = bool::consensus_decode(r)?;
        let merkle_root = if has_merkle_root {
            Some(TxMerkleNode::consensus_decode(r)?)
        } else {
            None
        };

        let bits = CompactTarget::consensus_decode(r)?;
        let time = u32::consensus_decode(r)?;

        Ok(ShareCommitment {
            prev_share_blockhash,
            uncles,
            miner_pubkey,
            merkle_root,
            bits,
            time,
        })
    }
}

/// Build share commitment by querying the database for fields to set.
///
/// Query the chain store for previous share and uncles.
/// Uses the current timestamp
pub(crate) fn build_share_commitment(
    chain_store: &Arc<ChainStore>,
    template: &Arc<BlockTemplate>,
    miner_pubkey: Option<CompressedPublicKey>,
) -> Result<Option<ShareCommitment>, Box<dyn Error + Send + Sync>> {
    let target = match chain_store.get_current_target() {
        Ok(target) => target,
        Err(e) => return Err(format!("Failed to get current target: {e}").into()),
    };
    let (tip, uncles) = chain_store.get_chain_tip_and_uncles();
    let merkle_root = template.get_merkle_root_without_coinbase();
    let time = SystemTimeProvider.seconds_since_epoch() as u32;

    match miner_pubkey {
        Some(key) => Ok(Some(ShareCommitment {
            prev_share_blockhash: tip,
            uncles: uncles.into_iter().collect(),
            miner_pubkey: key,
            merkle_root,
            bits: CompactTarget::from_consensus(target),
            time,
        })),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::chain::chain_store::MockChainStore;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::test_utils::create_test_commitment;
    use bitcoin::hashes::Hash;
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;
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
    fn test_hash_uniqueness_different_miner_pubkey() {
        let commitment1 = create_test_commitment();
        let mut commitment2 = create_test_commitment();

        commitment2.miner_pubkey =
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d"
                .parse::<CompressedPublicKey>()
                .unwrap();

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
    fn test_consensus_encode_decode_roundtrip() {
        let commitment = create_test_commitment();

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        let decoded = ShareCommitment::consensus_decode(&mut &serialized[..]).unwrap();

        assert_eq!(decoded, commitment);
    }

    #[test]
    fn test_consensus_encode_decode_with_none_merkle_root() {
        let mut commitment = create_test_commitment();
        commitment.merkle_root = None;

        let mut serialized = Vec::new();
        commitment.consensus_encode(&mut serialized).unwrap();

        let decoded = ShareCommitment::consensus_decode(&mut &serialized[..]).unwrap();

        assert_eq!(decoded.merkle_root, None);
        assert_eq!(decoded, commitment);
    }

    #[test]
    fn test_consensus_encode_decode_with_uncles() {
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

        let decoded = ShareCommitment::consensus_decode(&mut &serialized[..]).unwrap();

        assert_eq!(decoded.uncles.len(), 2);
        assert_eq!(decoded, commitment);
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
        let mut mock_store = MockChainStore::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(&json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();

        // Set up mock expectations
        mock_store
            .expect_get_current_target()
            .returning(|| Ok(0x207fffff));

        mock_store.expect_get_chain_tip_and_uncles().returning(|| {
            (
                BlockHash::from_str(
                    "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4",
                )
                .unwrap(),
                HashSet::new(),
            )
        });

        let store = Arc::new(mock_store);
        let result = build_share_commitment(&store, &template, Some(miner_pubkey));

        assert!(result.is_ok());
        let commitment = result.unwrap().unwrap();

        // Verify fields are set correctly
        assert_eq!(
            commitment.prev_share_blockhash,
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap()
        );
        assert_eq!(commitment.uncles.len(), 0);
        assert_eq!(commitment.miner_pubkey, miner_pubkey);
        assert_eq!(commitment.bits, CompactTarget::from_consensus(0x207fffff));
        // Time should be current, so just verify it's set
        assert!(commitment.time > 0);
        // Merkle root should be None for template with no transactions
        assert_eq!(commitment.merkle_root, None);
    }

    #[test]
    fn test_build_share_commitment_with_uncles() {
        let mut mock_store = MockChainStore::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(&json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();

        // Set up mock expectations
        mock_store
            .expect_get_current_target()
            .returning(|| Ok(0x207fffff));

        let uncle1 =
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap();
        let uncle2 =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();

        mock_store
            .expect_get_chain_tip_and_uncles()
            .returning(move || {
                let uncles = HashSet::from([uncle1, uncle2]);
                (BlockHash::all_zeros(), uncles)
            });

        let store = Arc::new(mock_store);
        let result = build_share_commitment(&store, &template, Some(miner_pubkey));

        assert!(result.is_ok());
        let commitment = result.unwrap().unwrap();

        // Verify uncles are set correctly
        assert_eq!(commitment.uncles.len(), 2);
        assert!(commitment.uncles.contains(&uncle1));
        assert!(commitment.uncles.contains(&uncle2));
    }

    #[test]
    fn test_build_share_commitment_error_on_get_target_failure() {
        let mut mock_store = MockChainStore::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(&json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let miner_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();

        // Set up mock to return error
        mock_store
            .expect_get_current_target()
            .returning(|| Err("Failed to get target".into()));

        let store = Arc::new(mock_store);
        let result = build_share_commitment(&store, &template, Some(miner_pubkey));

        assert!(result.is_err());
    }

    #[test_log::test]
    fn test_build_share_commitment_with_none_miner_pubkey_returns_none() {
        let mut mock_store = MockChainStore::default();

        // Load template from file
        let json_content =
            include_str!("../../../p2poolv2_tests/test_data/validation/stratum/a/template.json");
        let template = Arc::new(
            serde_json::from_str::<BlockTemplate>(&json_content)
                .expect("Failed to parse JSON into BlockTemplate"),
        );

        let uncle1 =
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap();
        let uncle2 =
            BlockHash::from_str("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
                .unwrap();

        mock_store
            .expect_get_chain_tip_and_uncles()
            .returning(move || {
                let uncles = HashSet::from([uncle1, uncle2]);
                (BlockHash::all_zeros(), uncles)
            });

        mock_store
            .expect_get_current_target()
            .returning(|| Ok(0x207fffff));

        let store = Arc::new(mock_store);
        let result = build_share_commitment(&store, &template, None);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
