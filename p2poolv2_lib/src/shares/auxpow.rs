// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded AuxPoW trees and proofs for the BCH coinbase commitment output.
//!
//! Token adapters supply the work hash, chain id and target from their own
//! covenant rules. This verifies committed work, not token emission rules or
//! acceptance of the parent as a complete BCH block.

use super::coinbase_proof::MAX_COINBASE_MERKLE_BRANCH_LENGTH;
use super::merge_mining::{AUXPOW_MAGIC, MergeMiningCommitment};
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use bitcoin::block::Header;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Target, Transaction, TxMerkleNode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Local work-selection budget; the tree itself may be sparse.
pub const MAX_AUXILIARY_CHAINS: usize = 64;
/// The commitment's maximum width is 2^30.
pub const MAX_AUXILIARY_BRANCH_LENGTH: usize = 30;
/// SV2's 65,535 output bytes plus at most 150 non-output coinbase bytes.
pub const MAX_AUXPOW_COINBASE_SIZE: usize = 65_685;

/// A token adapter's independently constructed work commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxiliaryWork {
    pub chain_id: u32,
    pub hash: sha256d::Hash,
}

/// Siblings, leaf first, at the slot determined by the chain id and nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxiliaryWorkProof {
    pub work: AuxiliaryWork,
    pub branch: Vec<sha256d::Hash>,
}

/// One commitment covering every selected work item, with individual proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxiliaryTree {
    pub commitment: MergeMiningCommitment,
    pub proofs: Vec<AuxiliaryWorkProof>,
}

impl AuxiliaryTree {
    /// Build the smallest collision-free tree, using zero hashes in unused slots.
    /// Sparse levels avoid allocating up to 2^30 leaf slots for just two chains.
    pub fn build(work: &[AuxiliaryWork], nonce: u32) -> Result<Self, &'static str> {
        if work.len() > MAX_AUXILIARY_CHAINS {
            return Err("too many auxiliary chains");
        }
        if work.is_empty() {
            return Ok(Self {
                commitment: MergeMiningCommitment::reserved(),
                proofs: Vec::new(),
            });
        }
        let mut identities = HashSet::with_capacity(work.len());
        if !work.iter().all(|item| identities.insert(item.chain_id)) {
            return Err("duplicate auxiliary chain id");
        }
        let height = (0..=MAX_AUXILIARY_BRANCH_LENGTH)
            .find(|height| {
                let mut slots = HashSet::with_capacity(work.len());
                work.iter()
                    .all(|item| slots.insert(auxiliary_slot(item.chain_id, nonce, 1 << height)))
            })
            .ok_or("auxiliary chain ids collide at every supported tree width")?;
        let tree_size = 1 << height;
        let mut nodes: BTreeMap<u32, sha256d::Hash> = work
            .iter()
            .map(|item| (auxiliary_slot(item.chain_id, nonce, tree_size), item.hash))
            .collect();
        let mut proofs: Vec<_> = work
            .iter()
            .map(|item| AuxiliaryWorkProof {
                work: *item,
                branch: Vec::with_capacity(height),
            })
            .collect();
        let mut empty = sha256d::Hash::all_zeros();
        for level in 0..height {
            for proof in &mut proofs {
                let index = auxiliary_slot(proof.work.chain_id, nonce, tree_size) >> level;
                proof
                    .branch
                    .push(*nodes.get(&(index ^ 1)).unwrap_or(&empty));
            }
            let mut parents = BTreeMap::new();
            for index in nodes.keys() {
                let parent = index / 2;
                parents.entry(parent).or_insert_with(|| {
                    hash_pair(
                        nodes.get(&(parent * 2)).unwrap_or(&empty),
                        nodes.get(&(parent * 2 + 1)).unwrap_or(&empty),
                    )
                });
            }
            nodes = parents;
            empty = hash_pair(&empty, &empty);
        }
        let mut merkle_root = nodes[&0].to_byte_array();
        merkle_root.reverse();
        Ok(Self {
            commitment: MergeMiningCommitment {
                merkle_root,
                tree_size,
                nonce,
            },
            proofs,
        })
    }
}

impl AuxiliaryWorkProof {
    /// Check identity, exact depth, deterministic slot and root against trusted work.
    pub fn verify(
        &self,
        commitment: MergeMiningCommitment,
        expected: AuxiliaryWork,
    ) -> Result<(), &'static str> {
        commitment.validate()?;
        if self.work != expected {
            return Err("auxiliary work differs from the requested work");
        }
        if commitment.tree_size == 0
            || self.branch.len() > MAX_AUXILIARY_BRANCH_LENGTH
            || self.branch.len() != commitment.tree_size.trailing_zeros() as usize
        {
            return Err("auxiliary branch does not match the committed tree width");
        }
        let mut index = auxiliary_slot(expected.chain_id, commitment.nonce, commitment.tree_size);
        let mut current = expected.hash;
        for sibling in &self.branch {
            current = if index & 1 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        let mut root = current.to_byte_array();
        root.reverse();
        if root != commitment.merkle_root {
            return Err("auxiliary branch does not match the committed root");
        }
        Ok(())
    }
}

/// Full coinbase proof for a token adapter; no SHA256 midstate is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxPowProof {
    pub parent_header: Header,
    pub coinbase: Transaction,
    pub coinbase_branch: Vec<TxMerkleNode>,
    pub auxiliary: AuxiliaryWorkProof,
}

impl AuxPowProof {
    /// Verify against the work and target supplied by the token's rules.
    /// The parent's advertised nBits is not an authority for the token's target.
    pub fn verify(&self, expected: AuxiliaryWork, target: Target) -> Result<(), &'static str> {
        if target == Target::ZERO {
            return Err("auxiliary target must be nonzero");
        }
        if self.coinbase_branch.len() > MAX_COINBASE_MERKLE_BRANCH_LENGTH
            || self.coinbase.total_size() > MAX_AUXPOW_COINBASE_SIZE
            || !self.coinbase.is_coinbase()
            || !self.coinbase.input[0].witness.is_empty()
            || !(2..=100).contains(&self.coinbase.input[0].script_sig.len())
        {
            return Err("invalid or oversized auxiliary coinbase proof");
        }
        let mut commitment = None;
        for output in &self.coinbase.output {
            let script = output.script_pubkey.as_bytes();
            if script.starts_with(&[0x6a, 44]) && script.get(2..6) == Some(AUXPOW_MAGIC.as_slice())
            {
                let decoded = MergeMiningCommitment::from_output(output)?;
                if commitment.replace(decoded).is_some() {
                    return Err("multiple auxiliary commitments in coinbase");
                }
            }
        }
        self.auxiliary.verify(
            commitment.ok_or("auxiliary commitment missing from coinbase")?,
            expected,
        )?;
        if compute_merkle_root_from_branches(self.coinbase.compute_txid(), &self.coinbase_branch)
            != self.parent_header.merkle_root
        {
            return Err("auxiliary coinbase is not in the parent header");
        }
        if !target.is_met_by(self.parent_header.block_hash()) {
            return Err("parent header does not meet the auxiliary target");
        }
        Ok(())
    }
}

fn hash_pair(left: &sha256d::Hash, right: &sha256d::Hash) -> sha256d::Hash {
    let mut pair = [0; 64];
    pair[..32].copy_from_slice(left.as_byte_array());
    pair[32..].copy_from_slice(right.as_byte_array());
    sha256d::Hash::hash(&pair)
}

fn auxiliary_slot(chain_id: u32, nonce: u32, tree_size: u32) -> u32 {
    nonce
        .wrapping_mul(1_103_515_245)
        .wrapping_add(12_345)
        .wrapping_add(chain_id)
        .wrapping_mul(1_103_515_245)
        .wrapping_add(12_345)
        % tree_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_bch_auxpow;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Witness};

    #[test]
    fn two_chains_match_an_independently_hashed_tree() {
        let first = AuxiliaryWork {
            chain_id: 1,
            hash: sha256d::Hash::hash(b"token-A"),
        };
        let second = AuxiliaryWork {
            chain_id: 2,
            hash: sha256d::Hash::hash(b"token-B"),
        };
        let tree = AuxiliaryTree::build(&[first, second], 0).unwrap();
        assert_eq!(auxiliary_slot(1, 0, 2), 1);
        assert_eq!(auxiliary_slot(2, 0, 2), 0);
        assert_eq!(tree.commitment.tree_size, 2);
        assert_eq!(
            hex::encode(tree.commitment.merkle_root),
            "d37b6e24f7874f8e72d5d05f41c80935b2aa0b58bddf767a65848fbc88e576d0"
        );
        tree.proofs[0].verify(tree.commitment, first).unwrap();
        tree.proofs[1].verify(tree.commitment, second).unwrap();
        assert_eq!(
            AuxiliaryTree::build(&[second, first], 0)
                .unwrap()
                .commitment,
            tree.commitment
        );
    }

    #[test]
    fn one_chain_reverses_the_root_and_empty_selection_reserves_the_output() {
        let work = AuxiliaryWork {
            chain_id: u32::MAX,
            hash: sha256d::Hash::hash(b"token-A"),
        };
        let tree = AuxiliaryTree::build(&[work], u32::MAX).unwrap();
        assert_eq!(tree.commitment.tree_size, 1);
        assert_eq!(
            hex::encode(tree.commitment.merkle_root),
            work.hash.to_string()
        );
        assert!(tree.proofs[0].branch.is_empty());
        tree.proofs[0].verify(tree.commitment, work).unwrap();
        let empty = AuxiliaryTree::build(&[], 99).unwrap();
        assert_eq!(empty.commitment, MergeMiningCommitment::reserved());
        assert!(empty.proofs.is_empty());
    }

    #[test]
    fn slot_collisions_grow_the_tree_without_nonce_retry() {
        let first = AuxiliaryWork {
            chain_id: 1,
            hash: sha256d::Hash::hash(b"token-A"),
        };
        let second = AuxiliaryWork {
            chain_id: 3,
            hash: sha256d::Hash::hash(b"token-B"),
        };
        let tree = AuxiliaryTree::build(&[first, second], 9).unwrap();
        assert_eq!(tree.commitment.tree_size, 4);
        assert_eq!(tree.proofs[0].branch.len(), 2);
        tree.proofs[0].verify(tree.commitment, first).unwrap();
        tree.proofs[1].verify(tree.commitment, second).unwrap();
    }

    #[test]
    fn sparse_maximum_width_does_not_allocate_a_billion_leaves() {
        let first = AuxiliaryWork {
            chain_id: 0,
            hash: sha256d::Hash::hash(b"token-A"),
        };
        let second = AuxiliaryWork {
            chain_id: 1 << 29,
            hash: sha256d::Hash::hash(b"token-B"),
        };
        let tree = AuxiliaryTree::build(&[first, second], u32::MAX).unwrap();
        assert_eq!(tree.commitment.tree_size, 1 << 30);
        assert_eq!(tree.proofs[0].branch.len(), 30);
        tree.proofs[0].verify(tree.commitment, first).unwrap();
        tree.proofs[1].verify(tree.commitment, second).unwrap();
    }

    #[test]
    fn duplicate_ids_and_permanent_slot_collisions_are_rejected() {
        let first = AuxiliaryWork {
            chain_id: 1,
            hash: sha256d::Hash::hash(b"token-A"),
        };
        let mut second = AuxiliaryWork {
            chain_id: 1,
            hash: sha256d::Hash::hash(b"token-B"),
        };
        assert!(
            AuxiliaryTree::build(&[first, second], 0)
                .unwrap_err()
                .contains("duplicate")
        );
        second.chain_id += 1 << 30;
        assert!(
            AuxiliaryTree::build(&[first, second], 0)
                .unwrap_err()
                .contains("collide")
        );
    }

    #[test]
    fn work_selection_budget_is_enforced() {
        let work: Vec<_> = (0..MAX_AUXILIARY_CHAINS as u32)
            .map(|chain_id| AuxiliaryWork {
                chain_id,
                hash: sha256d::Hash::all_zeros(),
            })
            .collect();
        assert_eq!(
            AuxiliaryTree::build(&work, 0).unwrap().proofs.len(),
            MAX_AUXILIARY_CHAINS
        );
        let mut excessive = work;
        excessive.push(AuxiliaryWork {
            chain_id: 100,
            hash: sha256d::Hash::all_zeros(),
        });
        assert!(AuxiliaryTree::build(&excessive, 0).is_err());
    }

    #[test]
    fn auxiliary_proof_binds_identity_depth_nonce_and_hash_order() {
        let (proof, expected) = test_bch_auxpow();
        let commitment = MergeMiningCommitment::from_output(&proof.coinbase.output[2]).unwrap();
        proof.auxiliary.verify(commitment, expected).unwrap();
        let wrong = AuxiliaryWork {
            chain_id: 9,
            ..expected
        };
        assert!(proof.auxiliary.verify(commitment, wrong).is_err());
        let mut changed = proof.auxiliary.clone();
        changed.branch[0] = sha256d::Hash::hash(b"wrong sibling");
        assert!(changed.verify(commitment, expected).is_err());
        changed = proof.auxiliary.clone();
        changed.branch.push(sha256d::Hash::all_zeros());
        assert!(changed.verify(commitment, expected).is_err());
        assert!(
            proof
                .auxiliary
                .verify(
                    MergeMiningCommitment {
                        nonce: 1,
                        ..commitment
                    },
                    expected
                )
                .is_err()
        );
        let mut reversed = commitment;
        reversed.merkle_root.reverse();
        assert!(proof.auxiliary.verify(reversed, expected).is_err());
    }

    #[test]
    fn full_proof_checks_trusted_target_and_parent_merkle_root() {
        let (mut proof, expected) = test_bch_auxpow();
        let target = proof.parent_header.target();
        proof.verify(expected, target).unwrap();
        assert!(proof.verify(expected, Target::ZERO).is_err());
        let mut minimum_target = [0; 32];
        minimum_target[31] = 1;
        assert!(
            proof
                .verify(expected, Target::from_be_bytes(minimum_target))
                .is_err()
        );
        proof.parent_header.merkle_root = TxMerkleNode::all_zeros();
        assert!(
            proof
                .verify(expected, target)
                .unwrap_err()
                .contains("parent header")
        );
    }

    #[test]
    fn full_proof_rejects_duplicate_and_paid_commitments() {
        let (mut proof, expected) = test_bch_auxpow();
        let target = proof.parent_header.target();
        proof.coinbase.output.push(proof.coinbase.output[2].clone());
        assert!(
            proof
                .verify(expected, target)
                .unwrap_err()
                .contains("multiple")
        );
        proof.coinbase.output.pop();
        proof.coinbase.output[2].value = Amount::from_sat(1);
        assert!(proof.verify(expected, target).is_err());
    }

    #[test]
    fn full_proof_rejects_non_coinbase_witness_and_resource_overruns() {
        let (mut proof, expected) = test_bch_auxpow();
        let target = proof.parent_header.target();
        proof.coinbase.input[0].previous_output.vout = 0;
        assert!(proof.verify(expected, target).is_err());
        proof.coinbase.input[0].previous_output = OutPoint::null();
        proof.coinbase.input[0].witness = Witness::from_slice(&[b"witness"]);
        assert!(proof.verify(expected, target).is_err());
        proof.coinbase.input[0].witness = Witness::new();
        proof.coinbase_branch = vec![TxMerkleNode::all_zeros(); 26];
        assert!(proof.verify(expected, target).is_err());
        proof.coinbase_branch.clear();
        proof.coinbase.output[0].script_pubkey =
            ScriptBuf::from_bytes(vec![0; MAX_AUXPOW_COINBASE_SIZE]);
        assert!(proof.verify(expected, target).is_err());
    }
}
