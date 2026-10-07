// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof that a share header's commitment is in its bitcoin block's coinbase.
//!
//! The bitcoin coinbase ends with the share commitment output and the locktime
//! (`stratum::work::coinbase::commitment_output`), and everything before them
//! is padded to a whole number of SHA256 blocks. A `CoinbaseProof` carries the
//! SHA256 midstate of that prefix. With the commitment hash rebuilt from the
//! header, the locktime from `bitcoin_height`, and the coinbase merkle branch,
//! a verifier finishes the hash to get the coinbase txid and folds the branch
//! up to the bitcoin header's merkle root -- without the payout outputs, the
//! share body, or the PPLNS window.
//!
//! The proof needs no trust: the merkle root is fixed by the bitcoin header's
//! proof of work, so any prefix, midstate or tail other than the real
//! coinbase's would be a SHA256 collision. A valid proof therefore shows the
//! real coinbase ends with this header's commitment, which only its builder
//! could have put there.

use crate::shares::share_block::ShareHeader;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::coinbase::{
    COMMITMENT_TAIL_LENGTH, SHA256_BLOCK_SIZE, commitment_output,
};
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{Decodable, Encodable, serialize};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::{Transaction, TxMerkleNode, Txid};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Most entries a coinbase merkle branch may have.
///
/// A branch has one entry per level of the bitcoin block's merkle tree. A
/// block of at most 4M weight units holds at most about 16.6k transactions
/// (about 240 weight units each at the smallest), a tree of depth 15, so 16
/// covers any bitcoin block while bounding what a peer can make a verifier
/// hash and how large a header batch can grow.
pub const MAX_COINBASE_MERKLE_BRANCH_LENGTH: usize = 16;

/// Error from building or verifying a `CoinbaseProof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseProofError(String);

impl fmt::Display for CoinbaseProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl std::error::Error for CoinbaseProofError {}

/// Midstate proof that a header's commitment ends its bitcoin coinbase.
///
/// The merkle branch is not part of the proof: shares mined on one block
/// template share a branch, so it travels separately -- in the block body, or
/// once per template in a header batch.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoinbaseProof {
    /// SHA256 midstate after the coinbase prefix: every serialized byte
    /// before the commitment output.
    pub midstate: [u8; 32],
    /// Length in bytes of the coinbase prefix, a multiple of
    /// `SHA256_BLOCK_SIZE`.
    pub prefix_length: u32,
    /// Merkle root over the share's non-coinbase transactions, the one
    /// commitment input not otherwise on the header.
    ///
    /// Carrying it unchecked is safe: it is part of the commitment preimage,
    /// so reusing a bitcoin header under other share fields would need a
    /// second preimage of the commitment hash. Body validation checks it
    /// against the transactions.
    pub non_coinbase_root: TxMerkleNode,
}

/// An empty proof: no prefix. It never verifies. The genesis share carries it,
/// and it is what fixtures without a proof deserialize to.
impl Default for CoinbaseProof {
    fn default() -> Self {
        Self {
            midstate: [0; 32],
            prefix_length: 0,
            non_coinbase_root: TxMerkleNode::all_zeros(),
        }
    }
}

impl CoinbaseProof {
    /// Build the proof from a bitcoin coinbase that ends with a commitment
    /// output, as built by `build_bitcoin_coinbase_transaction`.
    pub fn from_coinbase(
        coinbase: &Transaction,
        non_coinbase_root: TxMerkleNode,
    ) -> Result<Self, CoinbaseProofError> {
        let serialized = serialize(coinbase);
        let prefix_length = serialized
            .len()
            .checked_sub(COMMITMENT_TAIL_LENGTH)
            .ok_or_else(|| CoinbaseProofError("Coinbase shorter than its tail".into()))?;
        if prefix_length == 0 || !prefix_length.is_multiple_of(SHA256_BLOCK_SIZE) {
            return Err(CoinbaseProofError(format!(
                "Coinbase prefix of {prefix_length} bytes is not block aligned"
            )));
        }
        let mut engine = sha256::Hash::engine();
        engine.input(&serialized[..prefix_length]);
        Ok(Self {
            midstate: engine.midstate().to_byte_array(),
            prefix_length: prefix_length as u32,
            non_coinbase_root,
        })
    }

    /// Verify that `header`'s commitment ends the coinbase of
    /// `header.bitcoin_header`, using `branch` from the coinbase to the
    /// bitcoin merkle root.
    ///
    /// Nothing is exempt. The genesis share has no proof, because its coinbase
    /// predates the share chain, but it is built locally and never verified:
    /// header sync rejects its all-zeros parent and a re-sent genesis body is
    /// already in the store.
    pub fn verify(header: &ShareHeader, branch: &[TxMerkleNode]) -> Result<(), CoinbaseProofError> {
        let merkle_root = header.coinbase_proof.merkle_root(header, branch)?;
        if merkle_root != header.bitcoin_header.merkle_root {
            return Err(CoinbaseProofError(format!(
                "Coinbase proof gives merkle root {merkle_root}, bitcoin header has {}",
                header.bitcoin_header.merkle_root
            )));
        }
        Ok(())
    }

    /// The bitcoin merkle root this proof and `branch` give for `header`.
    pub fn merkle_root(
        &self,
        header: &ShareHeader,
        branch: &[TxMerkleNode],
    ) -> Result<TxMerkleNode, CoinbaseProofError> {
        if branch.len() > MAX_COINBASE_MERKLE_BRANCH_LENGTH {
            return Err(CoinbaseProofError(format!(
                "Coinbase merkle branch of {} entries exceeds {MAX_COINBASE_MERKLE_BRANCH_LENGTH}",
                branch.len()
            )));
        }
        let commitment_hash =
            ShareCommitment::from_share_header_and_root(header, self.non_coinbase_root).hash();
        let coinbase_txid = self.coinbase_txid(&commitment_hash, header.bitcoin_height)?;
        Ok(compute_merkle_root_from_branches(coinbase_txid, branch))
    }

    /// The coinbase txid: resume SHA256 from the midstate, hash the
    /// commitment output and locktime, and hash again.
    ///
    /// A prefix of zero bytes is rejected so the coinbase is longer than 64
    /// bytes; otherwise an inner merkle node, which is the double SHA256 of
    /// exactly 64 bytes, could pose as the coinbase under a shortened branch.
    fn coinbase_txid(
        &self,
        commitment_hash: &sha256::Hash,
        bitcoin_height: u64,
    ) -> Result<Txid, CoinbaseProofError> {
        let prefix_length = self.prefix_length as usize;
        if prefix_length == 0 || !prefix_length.is_multiple_of(SHA256_BLOCK_SIZE) {
            return Err(CoinbaseProofError(format!(
                "Coinbase prefix length {prefix_length} is not a positive multiple of {SHA256_BLOCK_SIZE}"
            )));
        }
        let lock_time = bitcoin_height
            .checked_sub(1)
            .and_then(|height| u32::try_from(height).ok())
            .and_then(|height| LockTime::from_height(height).ok())
            .ok_or_else(|| {
                CoinbaseProofError(format!(
                    "Invalid coinbase locktime for height {bitcoin_height}"
                ))
            })?;

        let mut engine = sha256::HashEngine::from_midstate(
            sha256::Midstate::from_byte_array(self.midstate),
            prefix_length,
        );
        engine.input(&serialize(&commitment_output(commitment_hash)));
        engine.input(&serialize(&lock_time));
        let txid_hash = sha256::Hash::from_engine(engine).hash_again();
        Ok(Txid::from_raw_hash(txid_hash))
    }
}

impl Encodable for CoinbaseProof {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut length = self.midstate.consensus_encode(writer)?;
        length += self.prefix_length.consensus_encode(writer)?;
        length += self.non_coinbase_root.consensus_encode(writer)?;
        Ok(length)
    }
}

impl Decodable for CoinbaseProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(Self {
            midstate: <[u8; 32]>::consensus_decode(reader)?,
            prefix_length: u32::consensus_decode(reader)?,
            non_coinbase_root: TxMerkleNode::consensus_decode(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
    use crate::test_utils::{TestShareBlockBuilder, create_test_commitment, make_test_address};
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, BlockHash};

    /// A share built the way a miner builds one: its bitcoin coinbase ends
    /// with its commitment, and the builder took the proof from that coinbase.
    fn non_genesis_share_header() -> ShareHeader {
        TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".to_string(),
            )
            .build()
            .header
    }

    #[test]
    fn test_coinbase_proof_verifies_honest_share() {
        let header = non_genesis_share_header();
        assert!(CoinbaseProof::verify(&header, &[]).is_ok());
    }

    #[test]
    fn test_coinbase_proof_rejects_changed_share_time() {
        let mut header = non_genesis_share_header();
        header.time += 1;
        assert!(CoinbaseProof::verify(&header, &[]).is_err());
    }

    #[test]
    fn test_coinbase_proof_rejects_forged_midstate() {
        let mut header = non_genesis_share_header();
        header.coinbase_proof.midstate[0] ^= 1;
        assert!(CoinbaseProof::verify(&header, &[]).is_err());
    }

    #[test]
    fn test_coinbase_proof_rejects_unaligned_prefix_length() {
        let mut header = non_genesis_share_header();
        header.coinbase_proof.prefix_length += 1;
        let error = CoinbaseProof::verify(&header, &[]).unwrap_err();
        assert!(error.to_string().contains("not a positive multiple"));
    }

    /// With no prefix the coinbase would be 47 bytes; refusing it keeps a
    /// 64-byte inner merkle node from posing as a coinbase.
    #[test]
    fn test_coinbase_proof_rejects_zero_prefix_length() {
        let mut header = non_genesis_share_header();
        header.coinbase_proof.prefix_length = 0;
        let error = CoinbaseProof::verify(&header, &[]).unwrap_err();
        assert!(error.to_string().contains("not a positive multiple"));
    }

    #[test]
    fn test_coinbase_proof_rejects_overlong_branch() {
        let header = non_genesis_share_header();
        let branch = vec![TxMerkleNode::all_zeros(); MAX_COINBASE_MERKLE_BRANCH_LENGTH + 1];
        let error = CoinbaseProof::verify(&header, &branch).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    /// A block with more than the coinbase verifies only with its branch:
    /// folding the right sibling reaches the root, and no branch does not.
    #[test]
    fn test_coinbase_proof_verifies_with_branch_and_rejects_without() {
        let mut header = non_genesis_share_header();
        let coinbase_txid_root = header.coinbase_proof.merkle_root(&header, &[]).unwrap();
        let sibling = TxMerkleNode::from_byte_array([0x42; 32]);
        let coinbase_txid = Txid::from_raw_hash(coinbase_txid_root.to_raw_hash());
        header.bitcoin_header.merkle_root =
            compute_merkle_root_from_branches(coinbase_txid, &[sibling]);

        assert!(CoinbaseProof::verify(&header, &[sibling]).is_ok());
        assert!(CoinbaseProof::verify(&header, &[]).is_err());
    }

    /// An all-zeros parent does not exempt a header from its proof. Only the
    /// network's own genesis has that parent, and it is built locally, never
    /// verified; a peer's header with that parent and no proof would otherwise
    /// pass under any share fields.
    #[test]
    fn test_coinbase_proof_rejects_terminal_parent_without_proof() {
        let mut header = non_genesis_share_header();
        header.prev_share_blockhash = BlockHash::all_zeros();
        header.coinbase_proof = CoinbaseProof::default();
        assert!(CoinbaseProof::verify(&header, &[]).is_err());
    }

    #[test]
    fn test_coinbase_proof_from_coinbase_rejects_coinbase_without_commitment() {
        let coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: make_test_address(1),
                amount: Amount::from_sat(5_000_000_000),
            }],
            100,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            None,
            0,
            None,
        )
        .unwrap();
        assert!(CoinbaseProof::from_coinbase(&coinbase, TxMerkleNode::all_zeros()).is_err());
    }

    /// The proof built from a coinbase reproduces that coinbase's txid.
    #[test]
    fn test_coinbase_proof_reproduces_coinbase_txid() {
        let commitment_hash = create_test_commitment().hash();
        let coinbase = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &[OutputPair {
                address: make_test_address(1),
                amount: Amount::from_sat(5_000_000_000),
            }],
            100,
            PushBytesBuf::from(&[0u8]),
            None,
            b"P2Poolv2",
            Some(commitment_hash),
            0,
            None,
        )
        .unwrap();
        let proof = CoinbaseProof::from_coinbase(&coinbase, TxMerkleNode::all_zeros()).unwrap();
        assert_eq!(
            proof.coinbase_txid(&commitment_hash, 100).unwrap(),
            coinbase.compute_txid()
        );
    }

    #[test]
    fn test_coinbase_proof_encoding_round_trip() {
        let proof = non_genesis_share_header().coinbase_proof;
        let decoded: CoinbaseProof = bitcoin::consensus::deserialize(&serialize(&proof)).unwrap();
        assert_eq!(decoded, proof);
    }
}
